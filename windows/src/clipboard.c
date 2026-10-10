/*
 * KeyBridge - shared clipboard, Windows side (see clipboard.h and
 * docs/PROTOCOL.md section 5a).
 *
 * Threads: the window and everything marked "UI thread" run on the thread
 * that called clipboard_init. The worker thread only touches the state
 * guarded by g_lock (a static SRWLOCK: nothing to initialize or destroy, so
 * a worker that outlives clipboard_shutdown is still safe).
 */
#include "clipboard.h"
#include "config.h"   /* prefs_share_clipboard */
#include "crypto.h"   /* kb_sha256 */
#include "kbclip.h"

#include <stdlib.h>
#include <wchar.h>

#define KB_CLIP_CLASS         L"KeyBridgeClipboardWatcher"
#define WM_KB_CLIP_APPLY      (WM_APP + 1)  /* private to this window class */
#define KB_CLIP_READ_TRIES    5             /* OpenClipboard attempts when reading */
#define KB_CLIP_WRITE_TRIES   10            /* ... and when setting received text */
#define KB_CLIP_RETRY_MS      15

/* ---- Shared with the worker: guarded by g_lock -------------------------- */
static SRWLOCK  g_lock = SRWLOCK_INIT;
static HWND     g_hwnd;              /* NULL before init / after shutdown */
static LONG     g_session_seq;       /* last session id handed out */
static LONG     g_session;           /* current session id; 0 = none */
static BOOL     g_can_send;          /* the peer's CAPS had bit0 */
static uint8_t *g_out;               /* outgoing text waiting for the worker */
static size_t   g_out_len;
static uint8_t *g_in;                /* received text waiting for the UI thread */
static size_t   g_in_len;
static LONG     g_in_session;
static uint8_t  g_last_sha[KB_SHA256_LEN]; /* last text sent or received this session */
static BOOL     g_have_last;

/* ---- UI thread only ----------------------------------------------------- */
static HANDLE   g_wake;              /* auto-reset; set when g_out is filled */
static HWND     g_window;
static BOOL     g_listening;
static UINT     g_fmt_exclude;       /* ExcludeClipboardContentFromMonitorProcessing */
static UINT     g_fmt_history;       /* CanIncludeInClipboardHistory */
static UINT     g_fmt_cloud;         /* CanUploadToCloudClipboard */
static DWORD    g_own_seq;           /* GetClipboardSequenceNumber after our own set */
static BOOL     g_setting;           /* inside our own set: ignore the notification */

static BOOL open_clipboard_retry(HWND hwnd, int tries)
{
    int i;
    for (i = 0; i < tries; i++) {
        if (OpenClipboard(hwnd))
            return TRUE;
        Sleep(KB_CLIP_RETRY_MS); /* another program has it open; it is quick */
    }
    return FALSE;
}

/* Clipboard open. TRUE if fmt is present holding DWORD 0 ("don't share"), or
 * present but unreadable (assume the source meant to exclude it). */
static BOOL dword_format_is_zero(UINT fmt)
{
    HANDLE h;
    const void *p;
    SIZE_T size;
    DWORD v = 0;

    if (!IsClipboardFormatAvailable(fmt))
        return FALSE;
    h = GetClipboardData(fmt);
    if (h == NULL)
        return TRUE;
    size = GlobalSize(h);
    p = GlobalLock(h);
    if (p == NULL)
        return TRUE;
    if (size >= sizeof(v))
        memcpy(&v, p, sizeof(v));
    (void)GlobalUnlock(h);
    return v == 0;
}

/* Clipboard open. FALSE if the source marked the content as not to be
 * shared (password managers do this). */
static BOOL content_shareable(void)
{
    if (IsClipboardFormatAvailable(g_fmt_exclude))
        return FALSE;
    return !dword_format_is_zero(g_fmt_history) && !dword_format_is_zero(g_fmt_cloud);
}

/* Clipboard open. CF_UNICODETEXT as UTF-8 (malloc'd), 1..KBCLIP_TEXT_MAX
 * bytes. Lone surrogates become U+FFFD, so the result is valid UTF-8. */
static BOOL read_text_utf8(uint8_t **out, size_t *out_len)
{
    HANDLE h;
    const wchar_t *w;
    SIZE_T size;
    size_t wlen;
    BOOL ok = FALSE;

    *out = NULL;
    *out_len = 0;
    h = GetClipboardData(CF_UNICODETEXT);
    if (h == NULL)
        return FALSE;
    size = GlobalSize(h);
    w = (const wchar_t *)GlobalLock(h);
    if (w == NULL)
        return FALSE;
    /* Never trust the terminator: stay inside the allocation. */
    wlen = wcsnlen(w, size / sizeof(wchar_t));
    /* Every UTF-16 unit is at least one UTF-8 byte, so this bounds the work. */
    if (wlen > 0 && wlen <= KBCLIP_TEXT_MAX) {
        int n = WideCharToMultiByte(CP_UTF8, 0, w, (int)wlen, NULL, 0, NULL, NULL);
        if (n > 0 && (size_t)n <= KBCLIP_TEXT_MAX) {
            uint8_t *buf = (uint8_t *)malloc((size_t)n);
            if (buf != NULL) {
                if (WideCharToMultiByte(CP_UTF8, 0, w, (int)wlen, (LPSTR)buf, n, NULL, NULL) == n) {
                    *out = buf;
                    *out_len = (size_t)n;
                    ok = TRUE;
                } else {
                    kbclip_free(buf, (size_t)n);
                }
            }
        }
    }
    (void)GlobalUnlock(h);
    return ok;
}

/* WM_CLIPBOARDUPDATE: queue the new text for the worker if it should be shared. */
static void on_clipboard_update(HWND hwnd)
{
    uint8_t sha[KB_SHA256_LEN];
    uint8_t *text = NULL;
    size_t len = 0;
    LONG session;
    BOOL active, queued = FALSE;

    if (g_setting)
        return; /* our own SetClipboardData */
    if (g_own_seq != 0 && GetClipboardSequenceNumber() == g_own_seq)
        return; /* still the text we set from the Mac */

    AcquireSRWLockShared(&g_lock);
    session = g_session;
    active = session != 0 && g_can_send;
    ReleaseSRWLockShared(&g_lock);
    /* Not connected, or the Mac can't take it: don't even read the clipboard.
     * Changes made while disconnected are never sent later. */
    if (!active || !prefs_share_clipboard())
        return;
    if (!IsClipboardFormatAvailable(CF_UNICODETEXT))
        return;

    if (!open_clipboard_retry(hwnd, KB_CLIP_READ_TRIES))
        return;
    if (content_shareable())
        (void)read_text_utf8(&text, &len);
    CloseClipboard();
    if (text == NULL)
        return;

    if (kb_sha256(text, (ULONG)len, NULL, 0, sha)) {
        AcquireSRWLockExclusive(&g_lock);
        if (g_session == session && g_can_send &&
            !(g_have_last && memcmp(sha, g_last_sha, sizeof(sha)) == 0)) {
            kbclip_free(g_out, g_out_len); /* newer text replaces unsent text */
            g_out = text;
            g_out_len = len;
            text = NULL;
            memcpy(g_last_sha, sha, sizeof(sha));
            g_have_last = TRUE;
            queued = TRUE;
        }
        ReleaseSRWLockExclusive(&g_lock);
    }
    kbclip_free(text, len);
    SecureZeroMemory(sha, sizeof(sha));
    if (queued && g_wake != NULL)
        SetEvent(g_wake);
}

static void global_wipe_free(HGLOBAL h)
{
    void *p = GlobalLock(h);
    if (p != NULL) {
        SecureZeroMemory(p, GlobalSize(h));
        (void)GlobalUnlock(h);
    }
    (void)GlobalFree(h);
}

/* WM_KB_CLIP_APPLY: set the text the worker received as CF_UNICODETEXT. */
static void apply_incoming(HWND hwnd)
{
    uint8_t sha[KB_SHA256_LEN];
    uint8_t *text;
    size_t len;
    LONG session;
    HGLOBAL h = NULL;
    wchar_t *w;
    int wlen;

    AcquireSRWLockExclusive(&g_lock);
    text = g_in;
    len = g_in_len;
    session = g_in_session;
    g_in = NULL;
    g_in_len = 0;
    ReleaseSRWLockExclusive(&g_lock);
    if (text == NULL)
        return;
    if (len == 0 || len > KBCLIP_TEXT_MAX || !prefs_share_clipboard())
        goto done;

    wlen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (LPCCH)text, (int)len, NULL, 0);
    if (wlen <= 0)
        goto done;
    h = GlobalAlloc(GMEM_MOVEABLE, ((SIZE_T)wlen + 1) * sizeof(wchar_t));
    if (h == NULL)
        goto done;
    w = (wchar_t *)GlobalLock(h);
    if (w == NULL)
        goto done;
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (LPCCH)text, (int)len, w, wlen) != wlen) {
        (void)GlobalUnlock(h);
        goto done;
    }
    w[wlen] = 0;
    (void)GlobalUnlock(h);

    /* Remember it before setting it: the change notification may arrive
     * while CloseClipboard runs, and copying the same text later must not
     * send it back either. */
    if (kb_sha256(text, (ULONG)len, NULL, 0, sha)) {
        AcquireSRWLockExclusive(&g_lock);
        if (g_session == session) {
            memcpy(g_last_sha, sha, sizeof(sha));
            g_have_last = TRUE;
        }
        ReleaseSRWLockExclusive(&g_lock);
        SecureZeroMemory(sha, sizeof(sha));
    }

    g_setting = TRUE;
    if (open_clipboard_retry(hwnd, KB_CLIP_WRITE_TRIES)) {
        if (EmptyClipboard() && SetClipboardData(CF_UNICODETEXT, h) != NULL)
            h = NULL; /* the system owns it now */
        CloseClipboard();
        if (h == NULL)
            g_own_seq = GetClipboardSequenceNumber();
    }
    g_setting = FALSE;

done:
    if (h != NULL)
        global_wipe_free(h);
    kbclip_free(text, len);
}

static LRESULT CALLBACK clip_wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CLIPBOARDUPDATE:
        on_clipboard_update(hwnd);
        return 0;
    case WM_KB_CLIP_APPLY:
        apply_incoming(hwnd);
        return 0;
    default:
        break;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

BOOL clipboard_init(HINSTANCE inst)
{
    WNDCLASSEXW wc;
    HWND hwnd;

    if (g_window != NULL)
        return TRUE;
    if (g_wake == NULL) {
        g_wake = CreateEventW(NULL, FALSE, FALSE, NULL);
        if (g_wake == NULL)
            return FALSE;
    }

    memset(&wc, 0, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = clip_wnd_proc;
    wc.hInstance = inst;
    wc.lpszClassName = KB_CLIP_CLASS;
    if (!RegisterClassExW(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
        goto fail;
    hwnd = CreateWindowExW(0, KB_CLIP_CLASS, L"", 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, inst, NULL);
    if (hwnd == NULL)
        goto fail;

    g_fmt_exclude = RegisterClipboardFormatW(L"ExcludeClipboardContentFromMonitorProcessing");
    g_fmt_history = RegisterClipboardFormatW(L"CanIncludeInClipboardHistory");
    g_fmt_cloud = RegisterClipboardFormatW(L"CanUploadToCloudClipboard");
    /* Without the privacy formats we could not honor them: never send then.
     * Receiving still works. */
    g_listening = g_fmt_exclude != 0 && g_fmt_history != 0 && g_fmt_cloud != 0 &&
                  AddClipboardFormatListener(hwnd);
    g_window = hwnd;

    AcquireSRWLockExclusive(&g_lock);
    g_hwnd = hwnd;
    ReleaseSRWLockExclusive(&g_lock);
    return TRUE;

fail:
    CloseHandle(g_wake);
    g_wake = NULL;
    return FALSE;
}

void clipboard_shutdown(void)
{
    uint8_t *out, *in;
    size_t out_len, in_len;

    AcquireSRWLockExclusive(&g_lock);
    g_hwnd = NULL;
    g_session = 0;
    g_can_send = FALSE;
    out = g_out;
    out_len = g_out_len;
    in = g_in;
    in_len = g_in_len;
    g_out = NULL;
    g_out_len = 0;
    g_in = NULL;
    g_in_len = 0;
    g_have_last = FALSE;
    SecureZeroMemory(g_last_sha, sizeof(g_last_sha));
    ReleaseSRWLockExclusive(&g_lock);
    kbclip_free(out, out_len);
    kbclip_free(in, in_len);

    if (g_window != NULL) {
        if (g_listening)
            (void)RemoveClipboardFormatListener(g_window);
        DestroyWindow(g_window); /* drops any queued WM_KB_CLIP_APPLY */
        g_window = NULL;
    }
    g_listening = FALSE;
    if (g_wake != NULL) {
        CloseHandle(g_wake); /* a running worker holds its own duplicate */
        g_wake = NULL;
    }
}

HANDLE clipboard_wake_event(void)
{
    return g_wake;
}

/* ---- Worker thread ------------------------------------------------------ */

BOOL clipboard_available(void)
{
    BOOL ok;
    AcquireSRWLockShared(&g_lock);
    ok = g_hwnd != NULL;
    ReleaseSRWLockShared(&g_lock);
    return ok;
}

LONG clipboard_session_begin(void)
{
    uint8_t *out;
    size_t out_len;
    LONG id;

    AcquireSRWLockExclusive(&g_lock);
    id = (g_session_seq < MAXLONG) ? g_session_seq + 1 : 1;
    g_session_seq = id;
    g_session = id;
    g_can_send = FALSE; /* until the peer's CAPS says it can receive */
    out = g_out;
    out_len = g_out_len;
    g_out = NULL;
    g_out_len = 0;
    g_have_last = FALSE;
    SecureZeroMemory(g_last_sha, sizeof(g_last_sha));
    ReleaseSRWLockExclusive(&g_lock);
    kbclip_free(out, out_len);
    return id;
}

void clipboard_session_peer_caps(LONG session, BOOL can_receive)
{
    AcquireSRWLockExclusive(&g_lock);
    if (g_session == session)
        g_can_send = can_receive;
    ReleaseSRWLockExclusive(&g_lock);
}

void clipboard_session_end(LONG session)
{
    uint8_t *out = NULL;
    size_t out_len = 0;

    AcquireSRWLockExclusive(&g_lock);
    if (g_session == session) {
        g_session = 0;
        g_can_send = FALSE;
        out = g_out;
        out_len = g_out_len;
        g_out = NULL;
        g_out_len = 0;
        g_have_last = FALSE;
        SecureZeroMemory(g_last_sha, sizeof(g_last_sha));
    }
    ReleaseSRWLockExclusive(&g_lock);
    kbclip_free(out, out_len);
}

BOOL clipboard_take_outgoing(LONG session, uint8_t **text, size_t *len)
{
    BOOL ok = FALSE;

    *text = NULL;
    *len = 0;
    AcquireSRWLockExclusive(&g_lock);
    if (g_session == session && g_out != NULL) {
        *text = g_out;
        *len = g_out_len;
        g_out = NULL;
        g_out_len = 0;
        ok = TRUE;
    }
    ReleaseSRWLockExclusive(&g_lock);
    return ok;
}

void clipboard_deliver_incoming(LONG session, uint8_t *text, size_t len)
{
    uint8_t *old = NULL;
    size_t old_len = 0;
    HWND hwnd;
    BOOL stored = FALSE;

    AcquireSRWLockExclusive(&g_lock);
    hwnd = g_hwnd;
    if (hwnd != NULL && text != NULL && len != 0) {
        old = g_in; /* not applied yet: the newer text wins */
        old_len = g_in_len;
        g_in = text;
        g_in_len = len;
        g_in_session = session;
        stored = TRUE;
    }
    ReleaseSRWLockExclusive(&g_lock);
    kbclip_free(old, old_len);
    if (!stored) {
        kbclip_free(text, len);
        return;
    }
    /* If this fails (window gone, queue full), the text stays in the slot
     * until the next delivery or clipboard_shutdown frees it. */
    (void)PostMessageW(hwnd, WM_KB_CLIP_APPLY, 0, 0);
}
