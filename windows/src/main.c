/*
 * KeyBridge - Windows tray app.
 *
 * Receives keystrokes from the KeyBridge Mac app over an authenticated,
 * encrypted KBP2 connection (docs/PROTOCOL.md) and types them on this PC.
 *
 * Threads: the UI thread owns the hidden window, the tray icon and the
 * dialogs; worker.c owns the session connection and injects keys; a
 * short-lived pairing thread runs pairing.c while the setup dialog is open;
 * DNS-SD callbacks (discovery.c) only queue events. Background threads never
 * touch UI objects: they post messages to the UI thread.
 */
#include "common.h"

#include <shellapi.h>
#include <commctrl.h>
#include <strsafe.h>

#include "resource.h"
#include "kbutil.h"
#include "crypto.h"
#include "kbp2.h"
#include "pairing.h"
#include "discovery.h"
#include "config.h"
#include "worker.h"

#ifdef KEYBRIDGE_SELFTEST
#error "main.c is the shipping app; the selftest build uses selftest.c instead"
#endif

#define KB_APP_NAME          L"KeyBridge"
#define KB_WINDOW_CLASS      L"KeyBridgeClientWnd"     /* installer.iss looks for this */
#define KB_MUTEX_NAME        L"Local\\KeyBridgeClient" /* installer.iss AppMutex */
#define KB_MSG_SHOW_SETTINGS L"KeyBridge.ShowSettings"

#define WM_KB_TRAY     (WM_APP + 1)  /* tray icon callback */
#define WM_KB_STATUS   (WM_APP + 2)  /* worker: wParam = generation, lParam = kb_status */
#define WM_KB_PAIR     (WM_APP + 3)  /* pairing thread -> setup dialog: wParam = job gen, lParam = event */
#define WM_KB_DISC     (WM_APP + 4)  /* discovery events queued -> setup dialog */

#define KB_PAIR_EV_SAS  1
#define KB_PAIR_EV_DONE 2

#define KB_TRAY_UID        1
#define KB_TIMER_TRAY      1   /* on the hidden window */
#define KB_TIMER_RESOLVE   2   /* on the setup dialog */
#define KB_TRAY_RETRY_MS   2000
#define KB_RESOLVE_WAIT_MS 6000

#define KB_MAX_MACS        32
#define KB_PLACEHOLDER     1000  /* list item data of the "Searching..." line */

#define IDM_STATUS     40001
#define IDM_PAIR       40002
#define IDM_FORGET     40003
#define IDM_AUTOSTART  40004
#define IDM_QUIT       40005

#ifndef NIF_SHOWTIP
#define NIF_SHOWTIP 0x00000080
#endif
#ifndef NIIF_LARGE_ICON
#define NIIF_LARGE_ICON 0x00000020
#endif
#ifndef NIIF_RESPECT_QUIET_TIME
#define NIIF_RESPECT_QUIET_TIME 0x00000080
#endif
#ifndef NIN_BALLOONUSERCLICK
#define NIN_BALLOONUSERCLICK (WM_USER + 5)
#endif
#ifndef ENDSESSION_CLOSEAPP
#define ENDSESSION_CLOSEAPP 0x00000001
#endif

#define KB_GET_X(wp) ((int)(short)LOWORD(wp))
#define KB_GET_Y(wp) ((int)(short)HIWORD(wp))

static HINSTANCE g_inst;
static HWND      g_hwnd;
static HWND      g_setup;      /* setup dialog, while open */
static HWND      g_compare;    /* compare dialog, while open */
static UINT      g_msg_taskbar_created;
static UINT      g_msg_show_settings;
static BOOL      g_tray_added;
static BOOL      g_quitting;
static BOOL      g_paired;     /* a pairing is stored and the worker was started */
static BOOL      g_not_paired_notified;
static BOOL      g_skip_connected_balloon;
static kb_status g_status = KB_ST_NONE;
static wchar_t   g_address[KB_HOST_MAX + 1];
static wchar_t   g_mac_name[KB_NAME_MAX + 1];
static HICON     g_icon_on;
static HICON     g_icon_off;
static HICON     g_icon_app_small;
static HICON     g_icon_app_large;

static INT_PTR show_setup(BOOL first_run);

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

static void set_dialog_icons(HWND dlg)
{
    if (g_icon_app_large != NULL)
        SendMessageW(dlg, WM_SETICON, ICON_BIG, (LPARAM)g_icon_app_large);
    if (g_icon_app_small != NULL)
        SendMessageW(dlg, WM_SETICON, ICON_SMALL, (LPARAM)g_icon_app_small);
}

/* The paired Mac as shown to the user: its name, else its address. */
static const wchar_t *mac_label(void)
{
    if (g_mac_name[0] != 0)
        return g_mac_name;
    if (g_address[0] != 0)
        return g_address;
    return L"your Mac";
}

/* One line describing the connection; never contains key material. */
static void status_text(wchar_t *buf, size_t cap)
{
    if (!g_paired) {
        (void)StringCchCopyW(buf, cap, L"Not paired with a Mac");
        return;
    }
    switch (g_status) {
    case KB_ST_CONNECTED:
        (void)StringCchPrintfW(buf, cap, L"Connected to %ls", mac_label());
        break;
    case KB_ST_WAITING:
        (void)StringCchPrintfW(buf, cap, L"Waiting for %ls\x2026", mac_label());
        break;
    case KB_ST_NOT_FOUND:
        (void)StringCchPrintfW(buf, cap, L"Can't find %ls on the network", mac_label());
        break;
    case KB_ST_NOT_PAIRED:
        (void)StringCchCopyW(buf, cap, L"Not paired with this Mac \x2014 pair again");
        break;
    case KB_ST_NONE:
    case KB_ST_CONNECTING:
    default:
        (void)StringCchPrintfW(buf, cap, L"Connecting to %ls\x2026", mac_label());
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
    nid->hIcon = (g_paired && g_status == KB_ST_CONNECTED) ? g_icon_on : g_icon_off;
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
        g_not_paired_notified = FALSE;
        if (g_skip_connected_balloon)
            g_skip_connected_balloon = FALSE; /* "Paired with ..." was just shown */
        else
            tray_balloon(L"Connected to your Mac",
                         L"Switch your Mac to Windows mode to type on this PC.", FALSE);
    } else if (st == KB_ST_NOT_PAIRED) {
        /* The worker has stopped retrying. One balloon until the user pairs
         * again or restarts KeyBridge. */
        g_skip_connected_balloon = FALSE;
        if (!g_not_paired_notified) {
            g_not_paired_notified = TRUE;
            tray_balloon(L"Not paired with this Mac \x2014 pair again",
                         L"Your Mac no longer recognizes this PC. Click here, or choose "
                         L"\x201CPair with a Different Mac\x2026\x201D in the KeyBridge menu.", TRUE);
        }
    } else if (prev == KB_ST_CONNECTED) {
        tray_balloon(L"Disconnected from your Mac", L"KeyBridge will reconnect automatically.", FALSE);
    }
}

/* ------------------------------------------------------------------------ */
/* Session worker control                                                   */
/* ------------------------------------------------------------------------ */

static BOOL start_session(const kb_config *cfg)
{
    (void)StringCchCopyW(g_address, ARRAYSIZE(g_address), cfg->host);
    (void)StringCchCopyW(g_mac_name, ARRAYSIZE(g_mac_name), cfg->mac_name);
    g_paired = TRUE;
    g_status = KB_ST_CONNECTING; /* quietly: a new connection, not a state change */
    g_not_paired_notified = FALSE;
    tray_update();
    if (worker_start(g_hwnd, WM_KB_STATUS, cfg->host, cfg->ltk))
        return TRUE;
    g_paired = FALSE;
    g_status = KB_ST_NONE;
    tray_update();
    return FALSE;
}

static BOOL start_from_config(void)
{
    kb_config cfg;
    BOOL ok = FALSE;

    if (config_load(&cfg))
        ok = start_session(&cfg);
    config_wipe(&cfg);
    return ok;
}

static void stop_session(void)
{
    worker_stop(3000); /* the worker releases every held key before exiting */
    g_paired = FALSE;
    g_status = KB_ST_NONE;
    g_address[0] = 0;
    g_mac_name[0] = 0;
    g_skip_connected_balloon = FALSE;
    tray_update();
}

static void forget_mac(void)
{
    wchar_t question[256];

    if (!g_paired)
        return;
    (void)StringCchPrintfW(question, ARRAYSIZE(question),
                           L"Forget %ls?\n\nKeyBridge will disconnect from it. To use this PC "
                           L"with a Mac again, you'll need to pair again.", mac_label());
    if (MessageBoxW(NULL, question, KB_APP_NAME,
                    MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2 | MB_SETFOREGROUND) != IDYES)
        return;
    if (!g_paired || g_quitting)
        return; /* something changed while the question was up */
    stop_session();
    if (!config_delete())
        MessageBoxW(NULL, L"KeyBridge couldn't delete its saved pairing.", KB_APP_NAME,
                    MB_OK | MB_ICONWARNING | MB_SETFOREGROUND);
}

static void app_shutdown(void)
{
    if (g_quitting)
        return;
    g_quitting = TRUE;
    if (g_compare != NULL)
        EndDialog(g_compare, IDCANCEL);
    if (g_setup != NULL)
        EndDialog(g_setup, IDCANCEL);
    if (g_hwnd != NULL)
        KillTimer(g_hwnd, KB_TIMER_TRAY);
    worker_stop(3000); /* the worker releases every held key before exiting */
    tray_remove();
}

static void request_quit(void)
{
    if (g_compare != NULL)
        EndDialog(g_compare, IDCANCEL);
    if (g_setup != NULL)
        EndDialog(g_setup, IDCANCEL);
    PostMessageW(g_hwnd, WM_CLOSE, 0, 0);
}

/* ------------------------------------------------------------------------ */
/* Pairing job (runs pairing.c on its own thread)                           */
/* ------------------------------------------------------------------------ */

/* Shared by the UI thread and the pairing thread; reference counted so
 * either can let go first. The thread writes the result fields and then
 * posts a message; the UI thread reads them only after that message. */
typedef struct {
    volatile LONG refs;
    HWND          notify;
    WPARAM        gen;
    HANDLE        stop;     /* manual-reset: cancel */
    HANDLE        confirm;  /* manual-reset: the user clicked Confirm */
    wchar_t       host[KB_HOST_MAX + 1];
    wchar_t       port[KB_PORT_MAX + 1];
    uint8_t       pc_name[KBPR_NAME_LEN];
    /* results */
    uint32_t      sas;
    wchar_t       mac_name[KB_NAME_MAX + 1];
    uint8_t       ltk[KBPR_LTK_LEN];
    kbp2_status   status;
} pair_job;

static WPARAM g_pair_gen; /* UI thread only; never reused, so stale messages are recognizable */

static void job_release(pair_job *j)
{
    if (InterlockedDecrement(&j->refs) != 0)
        return;
    if (j->stop != NULL)
        CloseHandle(j->stop);
    if (j->confirm != NULL)
        CloseHandle(j->confirm);
    SecureZeroMemory(j, sizeof(*j));
    HeapFree(GetProcessHeap(), 0, j);
}

/* Pairing thread: the number is ready. */
static void job_on_sas(void *ctx, uint32_t sas, const wchar_t *mac_name)
{
    pair_job *j = (pair_job *)ctx;
    j->sas = sas;
    (void)StringCchCopyW(j->mac_name, ARRAYSIZE(j->mac_name), mac_name);
    PostMessageW(j->notify, WM_KB_PAIR, j->gen, KB_PAIR_EV_SAS);
}

static DWORD WINAPI pair_thread(LPVOID param)
{
    pair_job *j = (pair_job *)param;
    wchar_t mac_name[KB_NAME_MAX + 1];
    kb_pair_params p;

    memset(&p, 0, sizeof(p));
    p.host = j->host;
    p.port = j->port;
    p.pc_name = j->pc_name;
    p.stop = j->stop;
    p.confirm = j->confirm;
    p.on_sas = job_on_sas;
    p.ctx = j;
    j->status = kb_pair_run(&p, j->ltk, mac_name);
    PostMessageW(j->notify, WM_KB_PAIR, j->gen, KB_PAIR_EV_DONE);
    job_release(j);
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Setup dialog                                                             */
/* ------------------------------------------------------------------------ */

typedef struct {
    BOOL           used;
    BOOL           resolved;
    wchar_t        instance[KB_DISC_INSTANCE_MAX + 1];
    wchar_t        label[KB_NAME_MAX + 1];
    wchar_t        host[KB_HOST_MAX + 1];
    unsigned short port;
} mac_entry;

/* One setup dialog at a time; UI thread only. */
static struct {
    BOOL      discovery;           /* the list is in use */
    mac_entry macs[KB_MAX_MACS];
    int       waiting_entry;       /* resolving this entry before pairing, or -1 */
    pair_job *job;                 /* pairing in progress (the UI's reference) */
    WPARAM    job_gen;
    BOOL      sas_shown;
    wchar_t   address[KB_HOST_MAX + 1]; /* stored on success (fits kb_config.host) */
    wchar_t   target[KB_HOST_MAX + 1];  /* shown while connecting */
} g_su;

static void set_status(HWND dlg, const wchar_t *text)
{
    SetDlgItemTextW(dlg, IDC_SETUP_STATUS, text);
}

static BOOL setup_busy(void)
{
    return g_su.job != NULL || g_su.waiting_entry >= 0;
}

static int selected_entry(HWND dlg)
{
    HWND list = GetDlgItem(dlg, IDC_MAC_LIST);
    LRESULT sel, data;

    if (!g_su.discovery)
        return -1;
    sel = SendMessageW(list, LB_GETCURSEL, 0, 0);
    if (sel == LB_ERR)
        return -1;
    data = SendMessageW(list, LB_GETITEMDATA, (WPARAM)sel, 0);
    if (data < 0 || data >= KB_MAX_MACS || !g_su.macs[data].used)
        return -1;
    return (int)data;
}

static void update_controls(HWND dlg)
{
    BOOL busy = setup_busy();
    BOOL can_pair = !busy && (selected_entry(dlg) >= 0 ||
                              GetWindowTextLengthW(GetDlgItem(dlg, IDC_HOST)) > 0);

    HWND focus;

    EnableWindow(GetDlgItem(dlg, IDC_MAC_LIST), !busy);
    EnableWindow(GetDlgItem(dlg, IDC_HOST), !busy);
    EnableWindow(GetDlgItem(dlg, IDC_AUTOSTART), !busy);
    EnableWindow(GetDlgItem(dlg, IDOK), can_pair);
    /* Never leave the keyboard focus on a control that was just disabled. */
    focus = GetFocus();
    if (busy && (focus == NULL || !IsWindowEnabled(focus)))
        SendMessageW(dlg, WM_NEXTDLGCTL, (WPARAM)GetDlgItem(dlg, IDCANCEL), TRUE);
}

static int list_find(HWND list, LPARAM data)
{
    int i, n = (int)SendMessageW(list, LB_GETCOUNT, 0, 0);
    for (i = 0; i < n; i++) {
        if (SendMessageW(list, LB_GETITEMDATA, (WPARAM)i, 0) == data)
            return i;
    }
    return -1;
}

/* "Searching..." while the list has no Macs in it. */
static void update_placeholder(HWND dlg)
{
    HWND list = GetDlgItem(dlg, IDC_MAC_LIST);
    int n = (int)SendMessageW(list, LB_GETCOUNT, 0, 0);
    int ph = list_find(list, KB_PLACEHOLDER);

    if (ph >= 0 && n > 1) {
        SendMessageW(list, LB_DELETESTRING, (WPARAM)ph, 0);
    } else if (ph < 0 && n == 0) {
        LRESULT i = SendMessageW(list, LB_ADDSTRING, 0, (LPARAM)L"Searching\x2026");
        if (i >= 0)
            SendMessageW(list, LB_SETITEMDATA, (WPARAM)i, KB_PLACEHOLDER);
    }
}

static int entry_find(const wchar_t *instance)
{
    int i;
    for (i = 0; i < KB_MAX_MACS; i++) {
        if (g_su.macs[i].used &&
            CompareStringOrdinal(g_su.macs[i].instance, -1, instance, -1, TRUE) == CSTR_EQUAL)
            return i;
    }
    return -1;
}

static int entry_add(HWND dlg, const wchar_t *instance)
{
    HWND list = GetDlgItem(dlg, IDC_MAC_LIST);
    mac_entry *e;
    LRESULT pos;
    int i;

    i = entry_find(instance);
    if (i >= 0)
        return i;
    for (i = 0; i < KB_MAX_MACS && g_su.macs[i].used; i++)
        ;
    if (i == KB_MAX_MACS)
        return -1;
    e = &g_su.macs[i];
    memset(e, 0, sizeof(*e));
    if (FAILED(StringCchCopyW(e->instance, ARRAYSIZE(e->instance), instance)))
        return -1;
    discovery_label(instance, e->label, ARRAYSIZE(e->label));
    if (e->label[0] == 0)
        (void)StringCchCopyNW(e->label, ARRAYSIZE(e->label), instance, KB_NAME_MAX);
    pos = SendMessageW(list, LB_ADDSTRING, 0, (LPARAM)e->label);
    if (pos < 0)
        return -1;
    SendMessageW(list, LB_SETITEMDATA, (WPARAM)pos, (LPARAM)i);
    e->used = TRUE;
    update_placeholder(dlg);
    return i;
}

static void entry_remove(HWND dlg, int i)
{
    HWND list = GetDlgItem(dlg, IDC_MAC_LIST);
    int pos = list_find(list, (LPARAM)i);

    if (pos >= 0)
        SendMessageW(list, LB_DELETESTRING, (WPARAM)pos, 0);
    memset(&g_su.macs[i], 0, sizeof(g_su.macs[i]));
    update_placeholder(dlg);
}

/* "host" or "host:port" ("[v6]:port") for an entry. */
static BOOL entry_address(const mac_entry *e, wchar_t *out, size_t cap)
{
    unsigned port = e->port != 0 ? e->port : 9876u;
    if (port == 9876u)
        return SUCCEEDED(StringCchCopyW(out, cap, e->host));
    if (wcschr(e->host, L':') != NULL)
        return SUCCEEDED(StringCchPrintfW(out, cap, L"[%ls]:%u", e->host, port));
    return SUCCEEDED(StringCchPrintfW(out, cap, L"%ls:%u", e->host, port));
}

/* Back to the idle Setup state with a message. */
static void pair_failed(HWND dlg, const wchar_t *detail)
{
    wchar_t text[256];

    if (g_su.waiting_entry >= 0) {
        KillTimer(dlg, KB_TIMER_RESOLVE);
        g_su.waiting_entry = -1;
    }
    (void)StringCchPrintfW(text, ARRAYSIZE(text), L"Pairing didn't complete.%ls%ls",
                           (detail != NULL && detail[0] != 0) ? L" " : L"",
                           detail != NULL ? detail : L"");
    set_status(dlg, text);
    update_controls(dlg);
}

/* Drop the UI's interest in the current pairing attempt (cancels it). */
static void pair_abandon(void)
{
    pair_job *j = g_su.job;
    if (j == NULL)
        return;
    g_su.job = NULL;
    g_su.sas_shown = FALSE;
    SetEvent(j->stop);
    job_release(j);
}

static void pair_start(HWND dlg, const wchar_t *address, const wchar_t *target)
{
    wchar_t text[KB_HOST_MAX + 64];
    pair_job *j;
    HANDLE th;

    j = (pair_job *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*j));
    if (j == NULL) {
        pair_failed(dlg, L"KeyBridge ran out of memory.");
        return;
    }
    if (!kb_parse_address(address, j->host, ARRAYSIZE(j->host), j->port, ARRAYSIZE(j->port),
                          KBP2_PORT_DEFAULT) ||
        FAILED(StringCchCopyW(g_su.address, ARRAYSIZE(g_su.address), address))) {
        HeapFree(GetProcessHeap(), 0, j);
        pair_failed(dlg, L"That address doesn't look right.");
        return;
    }
    j->stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    j->confirm = CreateEventW(NULL, TRUE, FALSE, NULL);
    kb_pc_name(j->pc_name);
    j->notify = dlg;
    j->gen = ++g_pair_gen;
    j->refs = 2; /* the UI's and the thread's */
    th = (j->stop != NULL && j->confirm != NULL) ? CreateThread(NULL, 0, pair_thread, j, 0, NULL) : NULL;
    if (th == NULL) {
        j->refs = 1;
        job_release(j);
        pair_failed(dlg, L"KeyBridge couldn't start pairing.");
        return;
    }
    CloseHandle(th); /* the reference count, not a join, ends the job */

    g_su.job = j;
    g_su.job_gen = j->gen;
    g_su.sas_shown = FALSE;
    (void)StringCchCopyW(g_su.target, ARRAYSIZE(g_su.target), target);
    (void)StringCchPrintfW(text, ARRAYSIZE(text), L"Connecting to %ls\x2026", target);
    set_status(dlg, text);
    update_controls(dlg);
}

static void pair_with_entry(HWND dlg, int i)
{
    wchar_t address[ARRAYSIZE(g_su.address)];
    if (!entry_address(&g_su.macs[i], address, ARRAYSIZE(address))) {
        pair_failed(dlg, L"That Mac's address is too long.");
        return;
    }
    pair_start(dlg, address, g_su.macs[i].label);
}

/* The Pair button (or a double-click in the list). */
static void do_pair(HWND dlg)
{
    wchar_t raw[KB_HOST_MAX + 16];
    wchar_t addr[KB_HOST_MAX + 16];
    wchar_t host[KB_HOST_MAX + 1];
    wchar_t port[KB_PORT_MAX + 1];
    wchar_t text[KB_NAME_MAX + 64];
    size_t len;
    int i;

    if (setup_busy())
        return;
    set_status(dlg, L"");

    i = selected_entry(dlg);
    if (i >= 0) {
        if (g_su.macs[i].resolved) {
            pair_with_entry(dlg, i);
            return;
        }
        /* Not looked up yet: resolve first, then pair. */
        if (!discovery_resolve(g_su.macs[i].instance)) {
            pair_failed(dlg, L"KeyBridge couldn't look up that Mac. Try again, or enter its "
                             L"address below.");
            return;
        }
        g_su.waiting_entry = i;
        SetTimer(dlg, KB_TIMER_RESOLVE, KB_RESOLVE_WAIT_MS, NULL);
        (void)StringCchPrintfW(text, ARRAYSIZE(text), L"Looking up %ls\x2026", g_su.macs[i].label);
        set_status(dlg, text);
        update_controls(dlg);
        return;
    }

    GetDlgItemTextW(dlg, IDC_HOST, raw, (int)ARRAYSIZE(raw));
    len = kb_trim_copy(raw, addr, ARRAYSIZE(addr));
    if (len == 0 || len == (size_t)-1 ||
        !kb_parse_address(addr, host, ARRAYSIZE(host), port, ARRAYSIZE(port), KBP2_PORT_DEFAULT)) {
        MessageBoxW(dlg,
                    L"That address doesn't look right. Use your Mac's name or IP address, for "
                    L"example Camerons-MacBook.local or 192.168.1.20.",
                    KB_APP_NAME, MB_OK | MB_ICONWARNING);
        SetFocus(GetDlgItem(dlg, IDC_HOST));
        SendDlgItemMessageW(dlg, IDC_HOST, EM_SETSEL, 0, -1);
        return;
    }
    pair_start(dlg, addr, host);
}

/* Pairing finished (any outcome). */
static void pair_finish(HWND dlg)
{
    pair_job *j = g_su.job;
    kbp2_status st = j->status;
    BOOL sas_shown = g_su.sas_shown;
    const wchar_t *detail = L"";
    wchar_t buf[256];

    if (st == KBP2_OK) {
        kb_config cfg;
        wchar_t title[96];
        BOOL saved, started;

        memset(&cfg, 0, sizeof(cfg));
        (void)StringCchCopyW(cfg.host, ARRAYSIZE(cfg.host), g_su.address);
        (void)StringCchCopyW(cfg.mac_name, ARRAYSIZE(cfg.mac_name), j->mac_name);
        memcpy(cfg.ltk, j->ltk, KB_LTK_LEN);
        pair_abandon(); /* done with the job (it is wiped when freed) */

        saved = config_save(&cfg);
        if (!saved) {
            config_wipe(&cfg);
            pair_failed(dlg, L"KeyBridge couldn't save the pairing on this PC.");
            return;
        }
        if (!autostart_set(IsDlgButtonChecked(dlg, IDC_AUTOSTART) == BST_CHECKED))
            MessageBoxW(dlg, L"KeyBridge couldn't change the \"Start when I sign in\" setting.",
                        KB_APP_NAME, MB_OK | MB_ICONWARNING);

        g_skip_connected_balloon = TRUE;
        started = start_session(&cfg); /* replaces any previous session */
        config_wipe(&cfg);
        if (!started) {
            g_skip_connected_balloon = FALSE;
            MessageBoxW(dlg, L"KeyBridge paired with your Mac but couldn't start connecting.",
                        KB_APP_NAME, MB_OK | MB_ICONERROR);
        }
        (void)StringCchPrintfW(title, ARRAYSIZE(title), L"Paired with %ls", mac_label());
        tray_balloon(title, L"Switch your Mac to Windows mode to type on this PC.", FALSE);
        EndDialog(dlg, IDOK);
        return;
    }

    pair_abandon();
    if (!sas_shown) {
        switch (st) {
        case KBP2_ERR_RESOLVE:
            (void)StringCchPrintfW(buf, ARRAYSIZE(buf), L"Can't find %ls on the network.", g_su.target);
            detail = buf;
            break;
        case KBP2_ERR_CONNECT:
            (void)StringCchPrintfW(buf, ARRAYSIZE(buf),
                                   L"Couldn't connect to %ls. Make sure KeyBridge is running on your Mac.",
                                   g_su.target);
            detail = buf;
            break;
        case KBP2_STOPPED:
            break;
        default:
            detail = L"On your Mac, click the KeyBridge menu bar icon \x2192 Pair a Windows PC\x2026, "
                     L"then try again.";
            break;
        }
    } else {
        switch (st) {
        case KBP2_ERR_TIMEOUT:
            detail = L"It took too long. Try again.";
            break;
        case KBP2_ERR_AUTH:
            detail = L"Your Mac's confirmation didn't match. Try again.";
            break;
        case KBP2_ERR_CLOSED:
        case KBP2_ERR_IO:
            detail = L"Your Mac cancelled, or the connection was lost.";
            break;
        default:
            break;
        }
    }
    pair_failed(dlg, detail);
}

static void on_disc_events(HWND dlg)
{
    kb_disc_event *ev;
    int i;

    /* A kb_disc_event is ~1 KB; keep it off the dialog's stack. */
    ev = (kb_disc_event *)HeapAlloc(GetProcessHeap(), 0, sizeof(*ev));
    if (ev == NULL)
        return;
    while (discovery_next(ev)) {
        if (!g_su.discovery)
            continue;
        switch (ev->kind) {
        case KB_DISC_ADDED:
            i = entry_add(dlg, ev->instance);
            if (i >= 0 && !g_su.macs[i].resolved)
                (void)discovery_resolve(ev->instance); /* eagerly, so Pair is instant */
            break;
        case KB_DISC_REMOVED:
            i = entry_find(ev->instance);
            if (i >= 0) {
                if (i == g_su.waiting_entry)
                    pair_failed(dlg, L"That Mac is no longer on the network.");
                entry_remove(dlg, i);
            }
            break;
        case KB_DISC_RESOLVED:
            i = entry_add(dlg, ev->instance);
            if (i >= 0 && ev->host[0] != 0) {
                (void)StringCchCopyW(g_su.macs[i].host, ARRAYSIZE(g_su.macs[i].host), ev->host);
                g_su.macs[i].port = ev->port;
                g_su.macs[i].resolved = TRUE;
                if (i == g_su.waiting_entry) {
                    KillTimer(dlg, KB_TIMER_RESOLVE);
                    g_su.waiting_entry = -1;
                    pair_with_entry(dlg, i);
                }
            }
            break;
        case KB_DISC_RESOLVE_FAILED:
            i = entry_find(ev->instance);
            if (i >= 0 && i == g_su.waiting_entry)
                pair_failed(dlg, L"KeyBridge couldn't look up that Mac. Try again, or enter its "
                                 L"address below.");
            break;
        default:
            break;
        }
    }
    HeapFree(GetProcessHeap(), 0, ev);
    update_controls(dlg);
}

static void move_control_up(HWND dlg, int id, int dy)
{
    HWND c = GetDlgItem(dlg, id);
    RECT r;
    if (c == NULL || !GetWindowRect(c, &r))
        return;
    MapWindowPoints(NULL, dlg, (POINT *)&r, 2);
    SetWindowPos(c, NULL, r.left, r.top - dy, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
}

/* No DNS-SD on this Windows: hide the list and close the gap. */
static void hide_discovery(HWND dlg)
{
    static const int below[] = { IDC_MANUAL_LABEL, IDC_HOST, IDC_HOST_HINT, IDC_AUTOSTART,
                                 IDC_SETUP_STATUS, IDOK, IDCANCEL };
    RECT a, b, w;
    int dy = 0;
    size_t k;

    if (GetWindowRect(GetDlgItem(dlg, IDC_LIST_LABEL), &a) &&
        GetWindowRect(GetDlgItem(dlg, IDC_MANUAL_LABEL), &b))
        dy = b.top - a.top;
    ShowWindow(GetDlgItem(dlg, IDC_LIST_LABEL), SW_HIDE);
    ShowWindow(GetDlgItem(dlg, IDC_MAC_LIST), SW_HIDE);
    SetDlgItemTextW(dlg, IDC_MANUAL_LABEL, L"&Enter your Mac's address:");
    if (dy > 0) {
        for (k = 0; k < ARRAYSIZE(below); k++)
            move_control_up(dlg, below[k], dy);
        if (GetWindowRect(dlg, &w))
            SetWindowPos(dlg, NULL, 0, 0, w.right - w.left, w.bottom - w.top - dy,
                         SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
    }
}

static void setup_init(HWND dlg, BOOL first_run)
{
    BOOL autostart;

    memset(&g_su, 0, sizeof(g_su));
    g_su.waiting_entry = -1;
    set_dialog_icons(dlg);
    SendDlgItemMessageW(dlg, IDC_HOST, EM_LIMITTEXT, KB_HOST_MAX, 0);

    autostart = first_run ? autostart_default() : autostart_is_enabled();
    CheckDlgButton(dlg, IDC_AUTOSTART, autostart ? BST_CHECKED : BST_UNCHECKED);

    g_su.discovery = discovery_available() && discovery_start(dlg, WM_KB_DISC, NULL);
    if (g_su.discovery)
        update_placeholder(dlg);
    else
        hide_discovery(dlg);

    if (g_paired && g_status == KB_ST_NOT_PAIRED)
        set_status(dlg, L"Your Mac no longer recognizes this PC. Pair again.");
    update_controls(dlg);
    SetForegroundWindow(dlg);
}

/* ------------------------------------------------------------------------ */
/* Compare dialog (modal, owned by the setup dialog)                        */
/* ------------------------------------------------------------------------ */

static HFONT g_font_number;
static HFONT g_font_title;

static HFONT derive_font(HWND dlg, int num, int den, LONG weight)
{
    LOGFONTW lf;
    HFONT base = (HFONT)SendMessageW(dlg, WM_GETFONT, 0, 0);
    if (base == NULL || GetObjectW(base, (int)sizeof(lf), &lf) == 0)
        return NULL;
    lf.lfHeight = MulDiv(lf.lfHeight, num, den);
    lf.lfWeight = weight;
    return CreateFontIndirectW(&lf);
}

static void compare_init(HWND dlg)
{
    wchar_t title[KB_NAME_MAX + 32];
    wchar_t number[KB_SAS_DISPLAY_LEN + 1];
    pair_job *j = g_su.job;

    g_compare = dlg;
    set_dialog_icons(dlg);
    g_font_title = derive_font(dlg, 1, 1, FW_SEMIBOLD);
    g_font_number = derive_font(dlg, 3, 1, FW_SEMIBOLD);
    if (g_font_title != NULL)
        SendDlgItemMessageW(dlg, IDC_CMP_TITLE, WM_SETFONT, (WPARAM)g_font_title, FALSE);
    if (g_font_number != NULL)
        SendDlgItemMessageW(dlg, IDC_CMP_NUMBER, WM_SETFONT, (WPARAM)g_font_number, FALSE);

    if (j->mac_name[0] != 0)
        (void)StringCchPrintfW(title, ARRAYSIZE(title), L"Pair with %ls?", j->mac_name);
    else
        (void)StringCchCopyW(title, ARRAYSIZE(title), L"Pair with this Mac?");
    SetDlgItemTextW(dlg, IDC_CMP_TITLE, title);
    kb_format_sas(j->sas, number);
    SetDlgItemTextW(dlg, IDC_CMP_NUMBER, number);
    SetDlgItemTextW(dlg, IDC_CMP_STATUS, L"");

    SetFocus(GetDlgItem(dlg, IDCANCEL));
    SetForegroundWindow(dlg);
}

static INT_PTR CALLBACK compare_proc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
    UNREFERENCED_PARAMETER(lp);

    switch (msg) {
    case WM_INITDIALOG:
        compare_init(dlg);
        return FALSE; /* focus was set explicitly */
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDC_CMP_CONFIRM:
            if (g_su.job != NULL) {
                SetEvent(g_su.job->confirm); /* the pairing thread sends PcConfirm */
                EnableWindow(GetDlgItem(dlg, IDC_CMP_CONFIRM), FALSE);
                SetDlgItemTextW(dlg, IDC_CMP_STATUS, L"Waiting for your Mac\x2026");
                SetFocus(GetDlgItem(dlg, IDCANCEL));
            }
            return TRUE;
        case IDCANCEL:
            EndDialog(dlg, IDCANCEL);
            return TRUE;
        case IDOK:
            return TRUE; /* Enter with no button focused: deliberately nothing */
        default:
            break;
        }
        break;
    case WM_DESTROY:
        if (g_compare == dlg)
            g_compare = NULL;
        if (g_font_title != NULL) {
            DeleteObject(g_font_title);
            g_font_title = NULL;
        }
        if (g_font_number != NULL) {
            DeleteObject(g_font_number);
            g_font_number = NULL;
        }
        break;
    default:
        break;
    }
    return FALSE;
}

static void on_pair_event(HWND dlg, WPARAM gen, LPARAM ev)
{
    INT_PTR r;

    if (g_su.job == NULL || gen != g_su.job_gen)
        return; /* from an attempt that was already abandoned */

    if (ev == KB_PAIR_EV_SAS) {
        if (g_compare != NULL || g_su.sas_shown)
            return;
        g_su.sas_shown = TRUE;
        set_status(dlg, L"Compare the numbers on both screens.");
        /* Nested modal loop. If the result arrives meanwhile, the DONE handler
         * below closes this dialog with IDABORT and handles the result. */
        r = DialogBoxParamW(g_inst, MAKEINTRESOURCEW(IDD_COMPARE), dlg, compare_proc, 0);
        if (r != IDABORT && g_su.job != NULL && g_su.job_gen == gen) {
            pair_abandon(); /* Cancel (or the dialog failed): the thread closes the connection */
            pair_failed(dlg, L"");
        }
    } else if (ev == KB_PAIR_EV_DONE) {
        if (g_compare != NULL)
            EndDialog(g_compare, IDABORT);
        pair_finish(dlg);
    }
}

static INT_PTR CALLBACK setup_proc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_INITDIALOG:
        g_setup = dlg;
        setup_init(dlg, lp != 0);
        return TRUE;

    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDC_MAC_LIST:
            if (HIWORD(wp) == LBN_SELCHANGE) {
                HWND list = GetDlgItem(dlg, IDC_MAC_LIST);
                LRESULT sel = SendMessageW(list, LB_GETCURSEL, 0, 0);
                if (sel != LB_ERR && SendMessageW(list, LB_GETITEMDATA, (WPARAM)sel, 0) == KB_PLACEHOLDER)
                    SendMessageW(list, LB_SETCURSEL, (WPARAM)-1, 0);
                else if (sel != LB_ERR)
                    SetDlgItemTextW(dlg, IDC_HOST, L""); /* one choice at a time */
                update_controls(dlg);
            } else if (HIWORD(wp) == LBN_DBLCLK) {
                if (selected_entry(dlg) >= 0)
                    do_pair(dlg);
            }
            return TRUE;
        case IDC_HOST:
            if (HIWORD(wp) == EN_CHANGE) {
                if (GetWindowTextLengthW(GetDlgItem(dlg, IDC_HOST)) > 0 && g_su.discovery)
                    SendDlgItemMessageW(dlg, IDC_MAC_LIST, LB_SETCURSEL, (WPARAM)-1, 0);
                update_controls(dlg);
            }
            return TRUE;
        case IDOK:
            if (IsWindowEnabled(GetDlgItem(dlg, IDOK)))
                do_pair(dlg);
            return TRUE;
        case IDCANCEL:
            if (setup_busy()) {
                /* First Cancel stops the attempt; the next one closes. */
                pair_abandon();
                pair_failed(dlg, L"");
            } else {
                EndDialog(dlg, IDCANCEL);
            }
            return TRUE;
        default:
            break;
        }
        break;

    case WM_CLOSE:
        EndDialog(dlg, IDCANCEL); /* the title-bar X always closes */
        return TRUE;

    case WM_KB_DISC:
        on_disc_events(dlg);
        return TRUE;

    case WM_KB_PAIR:
        on_pair_event(dlg, wp, lp);
        return TRUE;

    case WM_TIMER:
        if (wp == KB_TIMER_RESOLVE && g_su.waiting_entry >= 0)
            pair_failed(dlg, L"KeyBridge couldn't look up that Mac. Try again, or enter its "
                             L"address below.");
        return TRUE;

    case WM_DESTROY:
        KillTimer(dlg, KB_TIMER_RESOLVE);
        discovery_stop();
        pair_abandon();
        g_su.waiting_entry = -1;
        if (g_setup == dlg)
            g_setup = NULL;
        break;

    default:
        break;
    }
    return FALSE;
}

static INT_PTR show_setup(BOOL first_run)
{
    if (g_setup != NULL) {
        HWND front = g_compare != NULL ? g_compare : g_setup;
        ShowWindow(g_setup, SW_SHOWNORMAL);
        SetForegroundWindow(front);
        return IDCANCEL;
    }
    if (g_quitting)
        return IDCANCEL;
    return DialogBoxParamW(g_inst, MAKEINTRESOURCEW(IDD_SETUP), NULL, setup_proc, (LPARAM)first_run);
}

/* ------------------------------------------------------------------------ */
/* Tray menu                                                                */
/* ------------------------------------------------------------------------ */

/* Menu text treats '&' as a mnemonic marker; a Mac name may contain one. */
static void menu_escape(const wchar_t *in, wchar_t *out, size_t cap)
{
    size_t o = 0;
    if (cap == 0)
        return;
    for (; *in != 0 && o + 2 < cap; in++) {
        if (*in == L'&')
            out[o++] = L'&';
        out[o++] = *in;
    }
    out[o] = 0;
}

static void show_menu(int x, int y)
{
    HMENU menu = CreatePopupMenu();
    wchar_t status[160], escaped[320];
    UINT flags, cmd;

    if (menu == NULL)
        return;
    status_text(status, ARRAYSIZE(status));
    menu_escape(status, escaped, ARRAYSIZE(escaped));
    AppendMenuW(menu, MF_STRING | MF_GRAYED, IDM_STATUS, escaped);
    AppendMenuW(menu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(menu, MF_STRING, IDM_PAIR,
                g_paired ? L"Pair with a Different Mac\x2026" : L"Pair with a Mac\x2026");
    AppendMenuW(menu, MF_STRING | (g_paired ? 0u : MF_GRAYED), IDM_FORGET, L"Forget This Mac");
    AppendMenuW(menu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(menu, MF_STRING | (autostart_is_enabled() ? MF_CHECKED : MF_UNCHECKED),
                IDM_AUTOSTART, L"Start with Windows");
    AppendMenuW(menu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(menu, MF_STRING, IDM_QUIT, L"Quit");
    if (!g_paired || g_status == KB_ST_NOT_PAIRED)
        SetMenuDefaultItem(menu, IDM_PAIR, FALSE);

    /* The foreground dance makes the menu close when the user clicks away. */
    SetForegroundWindow(g_hwnd);
    flags = TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON | TPM_BOTTOMALIGN |
            (GetSystemMetrics(SM_MENUDROPALIGNMENT) ? TPM_RIGHTALIGN : TPM_LEFTALIGN);
    cmd = (UINT)TrackPopupMenuEx(menu, flags, x, y, g_hwnd, NULL);
    PostMessageW(g_hwnd, WM_NULL, 0, 0);
    DestroyMenu(menu);

    switch (cmd) {
    case IDM_PAIR:
        show_setup(FALSE);
        break;
    case IDM_FORGET:
        forget_mac();
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
        /* A second launch of KeyBridge.exe: show the pairing window. */
        if (!g_quitting)
            show_setup(FALSE);
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
            if (!g_paired || g_status == KB_ST_NOT_PAIRED)
                show_setup(FALSE);
            else
                show_menu(KB_GET_X(wp), KB_GET_Y(wp));
            break;
        case NIN_BALLOONUSERCLICK:
            if (g_paired && g_status == KB_ST_NOT_PAIRED)
                show_setup(FALSE);
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

/* Another KeyBridge is running: ask it to show its pairing window, then exit. */
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
    /* The icon goes up first, so the "Paired with ..." balloon has a home. */
    if (!tray_add())
        SetTimer(g_hwnd, KB_TIMER_TRAY, KB_TRAY_RETRY_MS, NULL);

    /* Not paired yet (first launch, a v1.1 config, or unreadable settings):
     * show the pairing window. Cancel quits. */
    if (!start_from_config()) {
        if (show_setup(TRUE) != IDOK || g_quitting) {
            if (g_hwnd != NULL)
                DestroyWindow(g_hwnd);
            return 0;
        }
    }

    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    app_shutdown();
    /* No WSACleanup/kb_crypto_cleanup: if a worker or pairing thread is still
     * inside a slow name lookup it must not find its handles freed; process
     * exit tidies up. */
    return 0;
}
