/*
 * KeyBridge – Windows client
 * Receives binary key-events from the Mac server and injects them via SendInput.
 *
 * Build (MinGW):  gcc -O2 -o keybridge.exe keybridge.c -lws2_32 -mwindows
 * Build (MSVC):   cl /O2 /W3 keybridge.c ws2_32.lib /link /SUBSYSTEM:WINDOWS
 *
 * Usage: keybridge.exe <mac-ip> [port]     (port default: 9876)
 *        Right-click the tray icon to quit.
 */

#define WIN32_LEAN_AND_MEAN
#define _WIN32_IE 0x0600
#include <windows.h>
#include <winsock2.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

/* ── Protocol ────────────────────────────────────────────────────────────── */
/* 4-byte frame sent by Mac:
 *   [0] flags  bit0=isDown, bit1=isExtended
 *   [1] vk low byte
 *   [2] vk high byte
 *   [3] 0x00 reserved
 */
#define FRAME_SZ 4
#define FLAG_DOWN     0x01
#define FLAG_EXTENDED 0x02

/* ── Tray icon ───────────────────────────────────────────────────────────── */
#define WM_TRAY  (WM_USER + 1)
#define IDM_QUIT 1001
#define TRAY_UID 1

static NOTIFYICONDATA g_nid;
static HWND           g_hwnd;

static void tray_update(const char *tip) {
    strncpy(g_nid.szTip, tip, sizeof(g_nid.szTip) - 1);
    Shell_NotifyIcon(NIM_MODIFY, &g_nid);
}

static LRESULT CALLBACK WndProc(HWND hw, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_TRAY && lp == WM_RBUTTONUP) {
        POINT pt; GetCursorPos(&pt);
        HMENU m = CreatePopupMenu();
        AppendMenu(m, MF_STRING, IDM_QUIT, "Quit KeyBridge");
        SetForegroundWindow(hw);
        TrackPopupMenu(m, TPM_BOTTOMALIGN, pt.x, pt.y, 0, hw, NULL);
        DestroyMenu(m);
    }
    if (msg == WM_COMMAND && LOWORD(wp) == IDM_QUIT)
        PostQuitMessage(0);
    if (msg == WM_DESTROY)
        PostQuitMessage(0);
    return DefWindowProc(hw, msg, wp, lp);
}

static HWND create_tray_window(void) {
    WNDCLASS wc = {0};
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = GetModuleHandle(NULL);
    wc.lpszClassName = "KeyBridgeTray";
    RegisterClass(&wc);

    HWND hw = CreateWindow(wc.lpszClassName, "KeyBridge",
                           0, 0, 0, 0, 0, HWND_MESSAGE, NULL, wc.hInstance, NULL);

    memset(&g_nid, 0, sizeof(g_nid));
    g_nid.cbSize           = sizeof(g_nid);
    g_nid.hWnd             = hw;
    g_nid.uID              = TRAY_UID;
    g_nid.uFlags           = NIF_ICON | NIF_TIP | NIF_MESSAGE;
    g_nid.uCallbackMessage = WM_TRAY;
    g_nid.hIcon            = LoadIcon(NULL, IDI_APPLICATION);
    strncpy(g_nid.szTip, "KeyBridge – connecting…", sizeof(g_nid.szTip) - 1);
    Shell_NotifyIcon(NIM_ADD, &g_nid);
    return hw;
}

/* ── Key injection ───────────────────────────────────────────────────────── */
static void inject_key(WORD vk, BOOL extended, BOOL key_down) {
    INPUT inp = {0};
    inp.type           = INPUT_KEYBOARD;
    inp.ki.wVk         = vk;
    inp.ki.dwFlags     = key_down ? 0 : KEYEVENTF_KEYUP;
    if (extended) inp.ki.dwFlags |= KEYEVENTF_EXTENDEDKEY;
    SendInput(1, &inp, sizeof(INPUT));
}

/* ── Network thread ──────────────────────────────────────────────────────── */
typedef struct { char ip[64]; int port; } ConnArgs;

static DWORD WINAPI net_thread(LPVOID param) {
    ConnArgs *a = (ConnArgs *)param;
    char tip[128];

    for (;;) {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) { Sleep(2000); continue; }

        /* TCP_NODELAY – the single biggest latency win */
        int one = 1;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof(one));

        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons((u_short)a->port);
        addr.sin_addr.s_addr = inet_addr(a->ip);

        snprintf(tip, sizeof(tip), "KeyBridge – connecting to %s…", a->ip);
        tray_update(tip);

        if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
            closesocket(s);
            Sleep(2000);
            continue;
        }

        snprintf(tip, sizeof(tip), "KeyBridge – connected to %s", a->ip);
        tray_update(tip);

        char buf[FRAME_SZ * 64];  /* batch-read multiple frames at once */
        int leftover = 0;

        for (;;) {
            int n = recv(s, buf + leftover, (int)(sizeof(buf) - leftover), 0);
            if (n <= 0) break;
            int total = leftover + n;
            int offset = 0;
            while (offset + FRAME_SZ <= total) {
                unsigned char *f = (unsigned char *)(buf + offset);
                WORD  vk       = (WORD)f[1] | ((WORD)f[2] << 8);
                BOOL  down     = (f[0] & FLAG_DOWN)     != 0;
                BOOL  extended = (f[0] & FLAG_EXTENDED) != 0;
                if (vk) inject_key(vk, extended, down);
                offset += FRAME_SZ;
            }
            leftover = total - offset;
            if (leftover > 0) memmove(buf, buf + offset, leftover);
        }

        closesocket(s);
        snprintf(tip, sizeof(tip), "KeyBridge – disconnected, retrying…");
        tray_update(tip);
        Sleep(2000);
    }
    return 0;
}

/* ── Entry point ─────────────────────────────────────────────────────────── */
int WINAPI WinMain(HINSTANCE hi, HINSTANCE hp, LPSTR cmd, int show) {
    /* Parse command line: keybridge.exe <ip> [port] */
    int argc;
    LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argc < 2) {
        MessageBox(NULL,
            "Usage: keybridge.exe <mac-ip-address> [port]\n\n"
            "Example: keybridge.exe 192.168.1.10\n\n"
            "Start this on your Windows PC, then start KeyBridge on your Mac.",
            "KeyBridge", MB_OK | MB_ICONINFORMATION);
        return 1;
    }

    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    static ConnArgs ca;
    WideCharToMultiByte(CP_ACP, 0, argv[1], -1, ca.ip, sizeof(ca.ip), NULL, NULL);
    ca.port = (argc >= 3) ? _wtoi(argv[2]) : 9876;
    LocalFree(argv);

    g_hwnd = create_tray_window();
    CreateThread(NULL, 0, net_thread, &ca, 0, NULL);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    Shell_NotifyIcon(NIM_DELETE, &g_nid);
    WSACleanup();
    return 0;
}
