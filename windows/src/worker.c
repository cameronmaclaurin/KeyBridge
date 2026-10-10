/*
 * KeyBridge - connection worker thread (see worker.h).
 *
 * Keys are injected directly from this thread as records arrive: no hop
 * through the UI thread, so the added latency is one SendInput call.
 */
#include "worker.h"
#include "inject.h"

#define KB_CONNECT_TIMEOUT_MS 3000 /* per resolved address */
#define KB_BAD_CODE_RETRY_MS  10000

typedef struct {
    HWND      notify;
    UINT      msg;
    WPARAM    generation;
    HANDLE    stop;                       /* this thread's own handle to the stop event */
    wchar_t   host[KB_HOST_MAX + 1];
    wchar_t   port[KB_PORT_MAX + 1];
    uint8_t   psk[KBP2_PSK_LEN];
    kb_keys   keys;
    kb_status last;
} worker_ctx;

static HANDLE g_thread;      /* UI thread's handle to the current worker */
static HANDLE g_stop;        /* UI thread's handle to its stop event */
static WPARAM g_generation;  /* touched by the UI thread only */

static void post_status(worker_ctx *w, kb_status st)
{
    if (st == w->last)
        return;
    w->last = st;
    PostMessageW(w->notify, w->msg, w->generation, (LPARAM)st);
}

/* Authenticated session: runs until the connection fails or stop is signaled. */
static kbp2_status run_session(worker_ctx *w, kbp2_conn *c, kbp2_session *s)
{
    static const uint8_t pong[KBP2_PLAINTEXT_LEN] = { KBP2_PONG, 0, 0, 0 };
    uint8_t pt[KBP2_PLAINTEXT_LEN];

    for (;;) {
        /* Liveness: no record for 6 s -> give up on this connection. */
        kbp2_status st = kbp2_recv_record(c, s, pt, KBP2_LIVENESS_MS);
        if (st != KBP2_OK)
            return st;

        switch (pt[0]) {
        case KBP2_KEY: {
            unsigned vk = (unsigned)pt[2] | ((unsigned)pt[3] << 8);
            if (vk >= 1 && vk <= 254)
                inject_key(&w->keys, vk, (pt[1] & KBP2_FLAG_EXTENDED) != 0,
                           (pt[1] & KBP2_FLAG_DOWN) != 0);
            break;
        }
        case KBP2_PING:
            st = kbp2_send_record(c, s, pong);
            if (st != KBP2_OK)
                return st;
            break;
        case KBP2_RELEASE_ALL:
            inject_release_all(&w->keys);
            break;
        default:
            break; /* unknown types are ignored (forward compatibility) */
        }
    }
}

static DWORD WINAPI worker_main(LPVOID param)
{
    static const DWORD backoff_ms[] = { 1000, 2000, 4000, 8000, 10000 };
    worker_ctx *w = (worker_ctx *)param;
    unsigned attempt = 0;

    post_status(w, KB_ST_CONNECTING);

    for (;;) {
        kbp2_conn conn;
        kbp2_session session;
        kbp2_status st;
        DWORD delay;

        if (WaitForSingleObject(w->stop, 0) == WAIT_OBJECT_0)
            break;

        kbp2_conn_init(&conn, w->stop);
        st = kbp2_connect(&conn, w->host, w->port, KB_CONNECT_TIMEOUT_MS);
        if (st == KBP2_OK) {
            st = kbp2_client_handshake(&conn, w->psk, &session);
            if (st == KBP2_OK) {
                attempt = 0; /* backoff resets after a successful handshake */
                post_status(w, KB_ST_CONNECTED);
                st = run_session(w, &conn, &session);
                inject_release_all(&w->keys); /* never leave keys stuck down */
                kbp2_session_free(&session);
                if (st != KBP2_STOPPED)
                    post_status(w, KB_ST_WAITING);
            }
        }
        kbp2_conn_close(&conn);
        if (st == KBP2_STOPPED)
            break;

        if (st == KBP2_ERR_AUTH) {
            post_status(w, KB_ST_BAD_CODE);
            delay = KB_BAD_CODE_RETRY_MS; /* "no faster than every 10 s" */
        } else {
            if (st == KBP2_ERR_RESOLVE)
                post_status(w, KB_ST_NOT_FOUND);
            else if (w->last != KB_ST_WAITING)
                post_status(w, KB_ST_WAITING);
            delay = backoff_ms[attempt < ARRAYSIZE(backoff_ms) ? attempt : ARRAYSIZE(backoff_ms) - 1];
        }
        if (attempt < ARRAYSIZE(backoff_ms))
            attempt++;

        if (WaitForSingleObject(w->stop, delay) == WAIT_OBJECT_0)
            break;
    }

    inject_release_all(&w->keys);
    SecureZeroMemory(w->psk, sizeof(w->psk));
    CloseHandle(w->stop);
    HeapFree(GetProcessHeap(), 0, w);
    return 0;
}

BOOL worker_start(HWND notify, UINT msg, const wchar_t *address, const uint8_t psk[KBP2_PSK_LEN])
{
    worker_ctx *w;
    HANDLE ev = NULL, dup = NULL, th = NULL;

    worker_stop(0);

    w = (worker_ctx *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*w));
    if (w == NULL)
        return FALSE;
    if (!kb_parse_address(address, w->host, ARRAYSIZE(w->host), w->port, ARRAYSIZE(w->port),
                          KBP2_PORT_DEFAULT))
        goto fail;

    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (ev == NULL)
        goto fail;
    /* The worker gets its own handle so either side can close theirs freely. */
    if (!DuplicateHandle(GetCurrentProcess(), ev, GetCurrentProcess(), &dup, 0, FALSE,
                         DUPLICATE_SAME_ACCESS))
        goto fail;

    memcpy(w->psk, psk, KBP2_PSK_LEN);
    w->notify = notify;
    w->msg = msg;
    w->stop = dup;
    w->last = KB_ST_NONE;
    w->generation = ++g_generation;

    th = CreateThread(NULL, 0, worker_main, w, 0, NULL);
    if (th == NULL)
        goto fail;
    SetThreadPriority(th, THREAD_PRIORITY_ABOVE_NORMAL); /* keystrokes are latency-sensitive */

    g_thread = th;
    g_stop = ev;
    return TRUE;

fail:
    if (dup != NULL)
        CloseHandle(dup);
    if (ev != NULL)
        CloseHandle(ev);
    SecureZeroMemory(w, sizeof(*w));
    HeapFree(GetProcessHeap(), 0, w);
    g_generation++;
    return FALSE;
}

void worker_stop(DWORD wait_ms)
{
    if (g_thread == NULL)
        return;
    SetEvent(g_stop);
    CloseHandle(g_stop);
    g_stop = NULL;
    if (wait_ms != 0)
        WaitForSingleObject(g_thread, wait_ms);
    CloseHandle(g_thread);
    g_thread = NULL;
    g_generation++; /* anything still queued from the old worker is now stale */
}

WPARAM worker_generation(void)
{
    return g_generation;
}
