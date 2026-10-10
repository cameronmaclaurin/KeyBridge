/*
 * KeyBridge - Windows tray app.
 *
 * Receives keystrokes from the KeyBridge Mac app over an authenticated,
 * encrypted KBP2 connection (docs/PROTOCOL.md) and types them on this PC.
 *
 * Threads: the UI thread owns the hidden window, the tray icon and the
 * settings dialog; worker.c owns the connection and injects keys.
 */
#include "common.h"

#include <shellapi.h>
#include <commctrl.h>
#include <strsafe.h>

#include "resource.h"
#include "kbutil.h"
#include "crypto.h"
#include "kbp2.h"
#include "config.h"
#include "worker.h"

#ifdef KEYBRIDGE_SELFTEST
#error "main.c is the shipping app; the selftest build uses selftest.c instead"
#endif

#define KB_APP_NAME          L"KeyBridge"
#define KB_WINDOW_CLASS      L"KeyBridgeClientWnd"     /* installer.iss looks for this */
#define KB_MUTEX_NAME        L"Local\\KeyBridgeClient" /* installer.iss AppMutex */
#define KB_MSG_SHOW_SETTINGS L"KeyBridge.ShowSettings"

#define WM_KB_TRAY     (WM_APP + 1)
#define WM_KB_STATUS   (WM_APP + 2)
#define KB_TRAY_UID    1
#define KB_TIMER_TRAY  1
#define KB_TRAY_RETRY_MS 2000

#define IDM_STATUS     40001
#define IDM_SETTINGS   40002
#define IDM_AUTOSTART  40003
#define IDM_QUIT       40004

#ifndef NIF_SHOWTIP
#define NIF_SHOWTIP 0x00000080
#endif
#ifndef NIIF_LARGE_ICON
#define NIIF_LARGE_ICON 0x00000020
#endif
#ifndef NIIF_RESPECT_QUIET_TIME
#define NIIF_RESPECT_QUIET_TIME 0x00000080
#endif
#ifndef ENDSESSION_CLOSEAPP
#define ENDSESSION_CLOSEAPP 0x00000001
#endif

#define KB_GET_X(wp) ((int)(short)LOWORD(wp))
#define KB_GET_Y(wp) ((int)(short)HIWORD(wp))

#define KB_WHERE_TO_FIND \
    L"On your Mac, click the KeyBridge icon in the menu bar and choose " \
    L"\"Pair a Windows PC\x2026\" to see the address and pairing code."

static HINSTANCE g_inst;
static HWND      g_hwnd;
static HWND      g_dialog;
static UINT      g_msg_taskbar_created;
static UINT      g_msg_show_settings;
static BOOL      g_tray_added;
static BOOL      g_quitting;
static BOOL      g_bad_code_notified;
static kb_status g_status = KB_ST_NONE;
static wchar_t   g_address[KB_HOST_MAX + 1];
static HICON     g_icon_on;
static HICON     g_icon_off;
static HICON     g_icon_app_small;
static HICON     g_icon_app_large;

static INT_PTR show_settings(BOOL first_run);

/* ------------------------------------------------------------------------ */
/* Icons, status text                                                       */
/* ------------------------------------------------------------------------ */

static HICON load_icon(int id, BOOL large)
{
    HICON icon = NULL;
    if (FAILED(LoadIconMetric(g_inst, MAKEINTRESOURCEW(id), large ? LIM_LARGE : LIM_SMALL, &icon)) ||
        icon == NULL) {
        int cx = GetSystemMetrics(large ? SM_CXICON : SM_CXSMICON);
        icon = (HICON)LoadImageW(g_inst, MAKEINTRESOURCEW(id), IMAGE_ICON, cx, cx, LR_DEFAULTCOLOR);
    }
    return icon;
}

static void load_icons(void)
{
    g_icon_app_small = load_icon(IDI_APP, FALSE);
    g_icon_app_large = load_icon(IDI_APP, TRUE);
    g_icon_on = load_icon(IDI_TRAY_ON, FALSE);
    g_icon_off = load_icon(IDI_TRAY_OFF, FALSE);
    if (g_icon_on == NULL)
        g_icon_on = g_icon_app_small;
    if (g_icon_off == NULL)
        g_icon_off = g_icon_app_small;
}

/* One line describing the connection; never contains the pairing code. */
static void status_text(wchar_t *buf, size_t cap)
{
    switch (g_status) {
    case KB_ST_CONNECTED:
        (void)StringCchPrintfW(buf, cap, L"Connected to %ls", g_address);
        break;
    case KB_ST_WAITING:
        (void)StringCchPrintfW(buf, cap, L"Waiting for your Mac (%ls)\x2026", g_address);
        break;
    case KB_ST_NOT_FOUND:
        (void)StringCchPrintfW(buf, cap, L"Can't find %ls on the network", g_address);
        break;
    case KB_ST_BAD_CODE:
        (void)StringCchCopyW(buf, cap, L"Pairing code doesn't match");
        break;
    case KB_ST_NONE:
    case KB_ST_CONNECTING:
    default:
        (void)StringCchPrintfW(buf, cap, L"Connecting to %ls\x2026", g_address);
        break;
    }
}

/* ------------------------------------------------------------------------ */
/* Tray icon                                                                */
/* ------------------------------------------------------------------------ */

static void tray_init(NOTIFYICONDATAW *nid)
{
    memset(nid, 0, sizeof(*nid));
    nid->cbSize = sizeof(*nid);
    nid->hWnd = g_hwnd;
    nid->uID = KB_TRAY_UID;
}

static void tray_fill_state(NOTIFYICONDATAW *nid)
{
    wchar_t status[128];
    status_text(status, ARRAYSIZE(status));
    nid->uFlags |= NIF_ICON | NIF_TIP | NIF_SHOWTIP;
    nid->hIcon = (g_status == KB_ST_CONNECTED) ? g_icon_on : g_icon_off;
    (void)StringCchPrintfW(nid->szTip, ARRAYSIZE(nid->szTip), L"KeyBridge\n%ls", status);
}

static BOOL tray_add(void)
{
    NOTIFYICONDATAW nid;

    tray_init(&nid);
    nid.uFlags = NIF_MESSAGE;
    nid.uCallbackMessage = WM_KB_TRAY;
    tray_fill_state(&nid);
    if (!Shell_NotifyIconW(NIM_ADD, &nid) && !Shell_NotifyIconW(NIM_MODIFY, &nid))
        return FALSE;
    nid.uVersion = NOTIFYICON_VERSION_4;
    (void)Shell_NotifyIconW(NIM_SETVERSION, &nid);
    g_tray_added = TRUE;
    return TRUE;
}

static void tray_update(void)
{
    NOTIFYICONDATAW nid;
    if (!g_tray_added)
        return;
    tray_init(&nid);
    tray_fill_state(&nid);
    (void)Shell_NotifyIconW(NIM_MODIFY, &nid);
}

static void tray_balloon(const wchar_t *title, const wchar_t *text, BOOL warning)
{
    NOTIFYICONDATAW nid;
    if (!g_tray_added)
        return;
    tray_init(&nid);
    nid.uFlags = NIF_INFO;
    (void)StringCchCopyW(nid.szInfoTitle, ARRAYSIZE(nid.szInfoTitle), title);
    (void)StringCchCopyW(nid.szInfo, ARRAYSIZE(nid.szInfo), text);
    if (warning) {
        nid.dwInfoFlags = NIIF_WARNING | NIIF_RESPECT_QUIET_TIME;
    } else {
        nid.dwInfoFlags = NIIF_USER | NIIF_LARGE_ICON | NIIF_RESPECT_QUIET_TIME;
        nid.hBalloonIcon = g_icon_app_large;
    }
    (void)Shell_NotifyIconW(NIM_MODIFY, &nid);
}

static void tray_remove(void)
{
    NOTIFYICONDATAW nid;
    if (!g_tray_added)
        return;
    tray_init(&nid);
    (void)Shell_NotifyIconW(NIM_DELETE, &nid);
    g_tray_added = FALSE;
}

/* Status from the worker. Balloons only on real state changes. */
static void on_status(kb_status st)
{
    kb_status prev = g_status;

    if (st == prev)
        return;
    g_status = st;
    tray_update();

    if (st == KB_ST_CONNECTED) {
        g_bad_code_notified = FALSE;
        tray_balloon(L"Connected to your Mac",
                     L"Switch your Mac to Windows mode to type on this PC.", FALSE);
    } else if (st == KB_ST_BAD_CODE) {
        if (!g_bad_code_notified) {
            g_bad_code_notified = TRUE;
            tray_balloon(L"Pairing code doesn't match",
                         L"Open KeyBridge Settings and enter the pairing code shown on your Mac.", TRUE);
        }
    } else if (prev == KB_ST_CONNECTED) {
        tray_balloon(L"Disconnected from your Mac", L"KeyBridge will reconnect automatically.", FALSE);
    }
}

/* ------------------------------------------------------------------------ */
/* Worker control                                                           */
/* ------------------------------------------------------------------------ */

static BOOL start_worker(const wchar_t *address, const uint8_t psk[KBP2_PSK_LEN])
{
    (void)StringCchCopyW(g_address, ARRAYSIZE(g_address), address);
    g_status = KB_ST_CONNECTING; /* quietly: a new connection, not a state change */
    g_bad_code_notified = FALSE;
    tray_update();
    return worker_start(g_hwnd, WM_KB_STATUS, g_address, psk);
}

static BOOL start_from_config(void)
{
    kb_config cfg;
    uint8_t psk[KBP2_PSK_LEN];
    BOOL ok = FALSE;

    if (!config_load(&cfg))
        return FALSE;
    if (kbp2_psk_from_code(cfg.code, psk))
        ok = start_worker(cfg.host, psk);
    SecureZeroMemory(psk, sizeof(psk));
    config_wipe(&cfg);
    return ok;
}

static void app_shutdown(void)
{
    if (g_quitting)
        return;
    g_quitting = TRUE;
    if (g_dialog != NULL)
        EndDialog(g_dialog, IDCANCEL);
    if (g_hwnd != NULL)
        KillTimer(g_hwnd, KB_TIMER_TRAY);
    worker_stop(3000); /* the worker releases every held key before exiting */
    tray_remove();
}

static void request_quit(void)
{
    if (g_dialog != NULL)
        EndDialog(g_dialog, IDCANCEL);
    PostMessageW(g_hwnd, WM_CLOSE, 0, 0);
}

/* ------------------------------------------------------------------------ */
/* Settings dialog                                                          */
/* ------------------------------------------------------------------------ */

static void settings_error(HWND dlg, int ctrl, const wchar_t *text)
{
    MessageBoxW(dlg, text, KB_APP_NAME, MB_OK | MB_ICONWARNING);
    SetFocus(GetDlgItem(dlg, ctrl));
    SendDlgItemMessageW(dlg, ctrl, EM_SETSEL, 0, -1);
}

static void settings_init(HWND dlg, BOOL first_run)
{
    kb_config cfg;
    wchar_t code[KB_CODE_DISPLAY_LEN + 1];
    BOOL autostart;

    if (g_icon_app_large != NULL)
        SendMessageW(dlg, WM_SETICON, ICON_BIG, (LPARAM)g_icon_app_large);
    if (g_icon_app_small != NULL)
        SendMessageW(dlg, WM_SETICON, ICON_SMALL, (LPARAM)g_icon_app_small);
    SendDlgItemMessageW(dlg, IDC_HOST, EM_LIMITTEXT, KB_HOST_MAX, 0);
    SendDlgItemMessageW(dlg, IDC_CODE, EM_LIMITTEXT, 64, 0);

    if (config_load(&cfg)) {
        SetDlgItemTextW(dlg, IDC_HOST, cfg.host);
        kb_format_code(cfg.code, code);
        SetDlgItemTextW(dlg, IDC_CODE, code);
        SecureZeroMemory(code, sizeof(code));
        config_wipe(&cfg);
    }

    autostart = first_run ? autostart_default() : autostart_is_enabled();
    CheckDlgButton(dlg, IDC_AUTOSTART, autostart ? BST_CHECKED : BST_UNCHECKED);
    if (first_run)
        SetWindowTextW(dlg, L"Set up KeyBridge");
    SetForegroundWindow(dlg);
}

static BOOL settings_apply(HWND dlg)
{
    wchar_t raw_host[KB_HOST_MAX + 2];
    wchar_t host[KB_HOST_MAX + 1];
    wchar_t parsed_host[KB_HOST_MAX + 1];
    wchar_t parsed_port[KB_PORT_MAX + 1];
    wchar_t raw_code[80];
    kb_config cfg;
    uint8_t psk[KBP2_PSK_LEN];
    size_t len;
    BOOL code_ok, started;

    memset(&cfg, 0, sizeof(cfg));
    GetDlgItemTextW(dlg, IDC_HOST, raw_host, (int)ARRAYSIZE(raw_host));
    len = kb_trim_copy(raw_host, host, ARRAYSIZE(host));
    if (len == 0 || len == (size_t)-1) {
        settings_error(dlg, IDC_HOST, L"Enter your Mac's address.\n\n" KB_WHERE_TO_FIND);
        return FALSE;
    }
    if (!kb_parse_address(host, parsed_host, ARRAYSIZE(parsed_host), parsed_port,
                          ARRAYSIZE(parsed_port), KBP2_PORT_DEFAULT)) {
        settings_error(dlg, IDC_HOST,
                       L"That address doesn't look right. Use the name or IP address shown on "
                       L"your Mac, for example Camerons-MacBook.local or 192.168.1.20.");
        return FALSE;
    }

    GetDlgItemTextW(dlg, IDC_CODE, raw_code, (int)ARRAYSIZE(raw_code));
    code_ok = kb_normalize_code(raw_code, cfg.code);
    SecureZeroMemory(raw_code, sizeof(raw_code));
    if (!code_ok) {
        settings_error(dlg, IDC_CODE,
                       L"That pairing code isn't valid. It has 20 letters and numbers, "
                       L"like ABCDE-FGHJK-MNPQR-STVWX.\n\n" KB_WHERE_TO_FIND);
        return FALSE;
    }

    (void)StringCchCopyW(cfg.host, ARRAYSIZE(cfg.host), host);
    if (!config_save(&cfg)) {
        config_wipe(&cfg);
        MessageBoxW(dlg, L"KeyBridge couldn't save your settings.", KB_APP_NAME, MB_OK | MB_ICONERROR);
        return FALSE;
    }

    if (!autostart_set(IsDlgButtonChecked(dlg, IDC_AUTOSTART) == BST_CHECKED))
        MessageBoxW(dlg, L"KeyBridge couldn't change the \"Start when I sign in\" setting.",
                    KB_APP_NAME, MB_OK | MB_ICONWARNING);

    started = kbp2_psk_from_code(cfg.code, psk) && start_worker(cfg.host, psk);
    SecureZeroMemory(psk, sizeof(psk));
    config_wipe(&cfg);
    if (!started) {
        MessageBoxW(dlg, L"KeyBridge couldn't start connecting.", KB_APP_NAME, MB_OK | MB_ICONERROR);
        return FALSE;
    }
    return TRUE;
}

static INT_PTR CALLBACK settings_proc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_INITDIALOG:
        g_dialog = dlg;
        settings_init(dlg, lp != 0);
        return TRUE;
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDOK:
            if (settings_apply(dlg))
                EndDialog(dlg, IDOK);
            return TRUE;
        case IDCANCEL:
            EndDialog(dlg, IDCANCEL);
            return TRUE;
        default:
            break;
        }
        break;
    case WM_DESTROY:
        SetDlgItemTextW(dlg, IDC_CODE, L"");
        if (g_dialog == dlg)
            g_dialog = NULL;
        break;
    default:
        break;
    }
    return FALSE;
}

static INT_PTR show_settings(BOOL first_run)
{
    if (g_dialog != NULL) {
        ShowWindow(g_dialog, SW_SHOWNORMAL);
        SetForegroundWindow(g_dialog);
        return IDCANCEL;
    }
    if (g_quitting)
        return IDCANCEL;
    return DialogBoxParamW(g_inst, MAKEINTRESOURCEW(IDD_SETTINGS), NULL, settings_proc,
                           (LPARAM)first_run);
}

/* ------------------------------------------------------------------------ */
/* Tray menu                                                                */
/* ------------------------------------------------------------------------ */

static void show_menu(int x, int y)
{
    HMENU menu = CreatePopupMenu();
    wchar_t status[160];
    UINT flags, cmd;

    if (menu == NULL)
        return;
    status_text(status, ARRAYSIZE(status));
    AppendMenuW(menu, MF_STRING | MF_GRAYED, IDM_STATUS, status);
    AppendMenuW(menu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(menu, MF_STRING, IDM_SETTINGS, L"Settings\x2026");
    AppendMenuW(menu, MF_STRING | (autostart_is_enabled() ? MF_CHECKED : MF_UNCHECKED),
                IDM_AUTOSTART, L"Start with Windows");
    AppendMenuW(menu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(menu, MF_STRING, IDM_QUIT, L"Quit");
    SetMenuDefaultItem(menu, IDM_SETTINGS, FALSE);

    /* The foreground dance makes the menu close when the user clicks away. */
    SetForegroundWindow(g_hwnd);
    flags = TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON | TPM_BOTTOMALIGN |
            (GetSystemMetrics(SM_MENUDROPALIGNMENT) ? TPM_RIGHTALIGN : TPM_LEFTALIGN);
    cmd = (UINT)TrackPopupMenuEx(menu, flags, x, y, g_hwnd, NULL);
    PostMessageW(g_hwnd, WM_NULL, 0, 0);
    DestroyMenu(menu);

    switch (cmd) {
    case IDM_SETTINGS:
        show_settings(FALSE);
        break;
    case IDM_AUTOSTART:
        if (!autostart_set(!autostart_is_enabled()))
            MessageBoxW(NULL, L"KeyBridge couldn't change the \"Start with Windows\" setting.",
                        KB_APP_NAME, MB_OK | MB_ICONWARNING);
        break;
    case IDM_QUIT:
        request_quit();
        break;
    default:
        break;
    }
}

/* ------------------------------------------------------------------------ */
/* Hidden window                                                            */
/* ------------------------------------------------------------------------ */

static LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    if (msg != 0 && msg == g_msg_taskbar_created) {
        /* Explorer restarted: the old icon is gone, add it again. */
        g_tray_added = FALSE;
        if (!g_quitting && !tray_add())
            SetTimer(hwnd, KB_TIMER_TRAY, KB_TRAY_RETRY_MS, NULL);
        return 0;
    }
    if (msg != 0 && msg == g_msg_show_settings) {
        /* A second launch of KeyBridge.exe asked us to open Settings. */
        if (!g_quitting)
            show_settings(FALSE);
        return 0;
    }

    switch (msg) {
    case WM_KB_TRAY:
        switch (LOWORD(lp)) {
        case WM_CONTEXTMENU:
            show_menu(KB_GET_X(wp), KB_GET_Y(wp));
            break;
        case WM_LBUTTONDBLCLK:
        case NIN_KEYSELECT:
            show_settings(FALSE);
            break;
        default:
            break;
        }
        return 0;

    case WM_KB_STATUS:
        if (wp == worker_generation() && !g_quitting)
            on_status((kb_status)lp);
        return 0;

    case WM_TIMER:
        if (wp == KB_TIMER_TRAY && (g_quitting || tray_add()))
            KillTimer(hwnd, KB_TIMER_TRAY);
        return 0;

    case WM_QUERYENDSESSION:
        return TRUE; /* sign-out, shutdown, or an installer's Restart Manager */

    case WM_ENDSESSION:
        if (wp) {
            app_shutdown();
            DestroyWindow(hwnd);
        }
        return 0;

    case WM_CLOSE:
        app_shutdown();
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        app_shutdown();
        g_hwnd = NULL;
        PostQuitMessage(0);
        return 0;

    default:
        break;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static BOOL create_window(void)
{
    WNDCLASSEXW wc;

    memset(&wc, 0, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = wnd_proc;
    wc.hInstance = g_inst;
    wc.hIcon = g_icon_app_large;
    wc.hIconSm = g_icon_app_small;
    wc.lpszClassName = KB_WINDOW_CLASS;
    if (!RegisterClassExW(&wc))
        return FALSE;

    /* A hidden top-level window rather than a message-only one: message-only
     * windows never receive the TaskbarCreated broadcast, and a second
     * instance (or the installer) finds this one with FindWindow. */
    g_hwnd = CreateWindowExW(WS_EX_TOOLWINDOW, KB_WINDOW_CLASS, KB_APP_NAME, WS_POPUP,
                             0, 0, 0, 0, NULL, NULL, g_inst, NULL);
    if (g_hwnd == NULL)
        return FALSE;

    g_msg_taskbar_created = RegisterWindowMessageW(L"TaskbarCreated");
    if (g_msg_taskbar_created != 0)
        ChangeWindowMessageFilterEx(g_hwnd, g_msg_taskbar_created, MSGFLT_ALLOW, NULL);
    if (g_msg_show_settings != 0)
        ChangeWindowMessageFilterEx(g_hwnd, g_msg_show_settings, MSGFLT_ALLOW, NULL);
    return TRUE;
}

/* Another KeyBridge is running: ask it to open Settings, then exit. */
static void notify_running_instance(void)
{
    int i;
    for (i = 0; i < 30; i++) {
        HWND other = FindWindowW(KB_WINDOW_CLASS, NULL);
        if (other != NULL) {
            DWORD pid = 0;
            GetWindowThreadProcessId(other, &pid);
            if (pid != 0)
                AllowSetForegroundWindow(pid);
            if (g_msg_show_settings != 0)
                PostMessageW(other, g_msg_show_settings, 0, 0);
            return;
        }
        Sleep(100); /* it may still be starting up */
    }
}

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE prev, PWSTR cmdline, int show)
{
    INITCOMMONCONTROLSEX icc;
    WSADATA wsa;
    HANDLE mutex;
    MSG msg;

    UNREFERENCED_PARAMETER(prev);
    UNREFERENCED_PARAMETER(cmdline);
    UNREFERENCED_PARAMETER(show);

    g_inst = inst;
    (void)HeapSetInformation(NULL, HeapEnableTerminationOnCorruption, NULL, 0);
    (void)SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);
    g_msg_show_settings = RegisterWindowMessageW(KB_MSG_SHOW_SETTINGS);

    /* Single instance. The handle stays open for the life of the process. */
    mutex = CreateMutexW(NULL, FALSE, KB_MUTEX_NAME);
    if (mutex != NULL && GetLastError() == ERROR_ALREADY_EXISTS) {
        notify_running_instance();
        CloseHandle(mutex);
        return 0;
    }

    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_STANDARD_CLASSES;
    (void)InitCommonControlsEx(&icc);

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0 || !kb_crypto_init()) {
        MessageBoxW(NULL, L"KeyBridge couldn't start networking or encryption on this PC.",
                    KB_APP_NAME, MB_OK | MB_ICONERROR);
        return 1;
    }

    load_icons();
    if (!create_window()) {
        MessageBoxW(NULL, L"KeyBridge couldn't start.", KB_APP_NAME, MB_OK | MB_ICONERROR);
        return 1;
    }

    /* First launch (or unreadable settings): ask for the Mac's address and
     * pairing code. Cancel quits. */
    if (!start_from_config()) {
        if (show_settings(TRUE) != IDOK || g_quitting) {
            if (g_hwnd != NULL)
                DestroyWindow(g_hwnd);
            return 0;
        }
    }

    if (!g_quitting && !tray_add())
        SetTimer(g_hwnd, KB_TIMER_TRAY, KB_TRAY_RETRY_MS, NULL);

    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    app_shutdown();
    /* No WSACleanup/kb_crypto_cleanup: if a worker is still inside a slow
     * name lookup it must not find its handles freed; process exit tidies up. */
    return 0;
}
