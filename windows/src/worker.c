/*
 * KeyBridge - connection worker thread (see worker.h).
 *
 * Keys are injected directly from this thread as records arrive: no hop
 * through the UI thread, so the added latency is one SendInput call. The
 * socket is driven by the non-blocking kbp2_io pump, so an outgoing
 * clipboard transfer never holds up incoming keystrokes.
 */
#include "worker.h"
#include "inject.h"
#include "clipboard.h"
#include "config.h" /* prefs_share_clipboard */

#define KB_CONNECT_TIMEOUT_MS 3000 /* per resolved address */

typedef struct {
    HWND      notify;
    UINT      msg;
    WPARAM    generation;
    HANDLE    stop;                       /* this thread's own handle to the stop event */
    HANDLE    clip_wake;                  /* own duplicate of clipboard_wake_event(); may be NULL */
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

/* Per-session buffers, on the heap (the record pump is about 50 KB). */
typedef struct {
    kbp2_io io;
    uint8_t chunk[KBCLIP_CHUNK_MAX];
} session_bufs;

/* The outgoing clipboard transfer in flight (section 5a: one per direction). */
typedef struct {
    uint8_t *text;   /* NULL when idle; malloc'd, freed with kbclip_free */
    size_t   len;
    size_t   off;    /* bytes already queued */
    uint16_t id;
} clip_tx;

static void tx_drop(clip_tx *tx)
{
    kbclip_free(tx->text, tx->len);
    tx->text = NULL;
    tx->len = 0;
    tx->off = 0;
}

/* Authenticated session: runs until the connection fails or stop is signaled.
 * This thread is the only writer to the socket, so records always go out in
 * seq order; clipboard text arrives from the UI thread through
 * clipboard_take_outgoing when w->clip_wake is set. */
static kbp2_status run_session(worker_ctx *w, kbp2_conn *c, kbp2_session *s)
{
    static const uint8_t pong[KBP2_PLAINTEXT_LEN] = { KBP2_PONG, 0, 0, 0 };
    uint8_t caps[KBP2_PLAINTEXT_LEN];
    session_bufs *b;
    kbp2_io *io;
    kbclip_rx rx;
    clip_tx tx;
    uint16_t next_id = 0;     /* transfer_id: per direction, from 0 */
    BOOL receive;             /* what our CAPS advertised */
    BOOL peer_caps_seen = FALSE, peer_receives = FALSE;
    LONG clip;
    kbp2_status st;

    b = (session_bufs *)HeapAlloc(GetProcessHeap(), 0, sizeof(*b));
    if (b == NULL)
        return KBP2_ERR_IO;
    io = &b->io;
    kbp2_io_init(io, c, s);
    kbclip_rx_init(&rx);
    memset(&tx, 0, sizeof(tx));

    /* Clears anything copied before now: the existing clipboard is never
     * pushed when a session starts. */
    clip = clipboard_session_begin();
    receive = w->clip_wake != NULL && clipboard_available() && prefs_share_clipboard();

    /* Section 5a: CAPS is the first record after ClientFinished. */
    caps[0] = KBP2_CAPS;
    caps[1] = receive ? KBP2_CAPS_CLIPBOARD : 0;
    caps[2] = 0;
    caps[3] = 0;
    st = kbp2_io_queue_record(io, caps);

    while (st == KBP2_OK) {
        kbp2_event ev;

        /* Next chunk only once the previous one is on its way, so a PONG
         * never waits behind more than one chunk. */
        if (tx.text != NULL && kbp2_io_send_idle(io)) {
            size_t n = kbclip_make_chunk(b->chunk, tx.id, tx.text, tx.len, &tx.off);
            if (n != 0) {
                st = kbp2_io_queue_chunk(io, b->chunk, n);
                SecureZeroMemory(b->chunk, n);
            }
            if (n == 0 || tx.off >= tx.len)
                tx_drop(&tx);
            if (st != KBP2_OK)
                break;
        }

        /* Liveness (section 6) is inside: no valid record or chunk for 6 s
         * -> KBP2_ERR_TIMEOUT. */
        st = kbp2_io_next(io, w->clip_wake, tx.text != NULL, &ev);
        if (st == KBP2_WOKEN) {
            uint8_t *text;
            size_t len;
            st = KBP2_OK;
            if (clipboard_take_outgoing(clip, &text, &len)) {
                if (peer_receives && len >= 1 && len <= KBCLIP_TEXT_MAX) {
                    tx_drop(&tx); /* starting a new transfer abandons the old one */
                    tx.text = text;
                    tx.len = len;
                    tx.off = 0;
                    tx.id = next_id;
                    next_id = (uint16_t)(next_id + 1u);
                } else {
                    kbclip_free(text, len);
                }
            }
            continue;
        }
        if (st != KBP2_OK)
            break;

        if (ev.type == KBP2_EV_CHUNK) {
            uint8_t *text;
            size_t len;
            /* Sharing off: we advertised bit0 = 0 and ignore DATA (it was
             * still decrypted, so the record stream stays in sync). */
            if (receive && kbclip_rx_chunk(&rx, ev.data, ev.len, &text, &len))
                clipboard_deliver_incoming(clip, text, len); /* takes ownership */
            continue;
        }
        if (ev.type != KBP2_EV_RECORD)
            continue; /* KBP2_EV_SENT: queue the next chunk */

        switch (ev.data[0]) {
        case KBP2_KEY: {
            unsigned vk = (unsigned)ev.data[2] | ((unsigned)ev.data[3] << 8);
            if (vk >= 1 && vk <= 254)
                inject_key(&w->keys, vk, (ev.data[1] & KBP2_FLAG_EXTENDED) != 0,
                           (ev.data[1] & KBP2_FLAG_DOWN) != 0);
            break;
        }
        case KBP2_PING:
            st = kbp2_io_queue_record(io, pong);
            break;
        case KBP2_RELEASE_ALL:
            inject_release_all(&w->keys);
            break;
        case KBP2_CAPS:
            if (!peer_caps_seen) { /* exactly one per session; ignore repeats */
                peer_caps_seen = TRUE;
                peer_receives = (ev.data[1] & KBP2_CAPS_CLIPBOARD) != 0;
                clipboard_session_peer_caps(clip, peer_receives);
            }
            break;
        default:
            break; /* unknown types are ignored (forward compatibility) */
        }
    }

    clipboard_session_end(clip);
    tx_drop(&tx);
    kbclip_rx_free(&rx);
    kbp2_io_wipe(io);
    HeapFree(GetProcessHeap(), 0, b);
    return st;
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
            /* server_finished mismatch: this Mac does not have our key (it
             * forgot us or paired with another PC). Stop retrying until the
             * user pairs again or restarts the app (section 6). */
            post_status(w, KB_ST_NOT_PAIRED);
            break;
        }
        if (st == KBP2_ERR_RESOLVE)
            post_status(w, KB_ST_NOT_FOUND);
        else if (w->last != KB_ST_WAITING)
            post_status(w, KB_ST_WAITING);
        delay = backoff_ms[attempt < ARRAYSIZE(backoff_ms) ? attempt : ARRAYSIZE(backoff_ms) - 1];
        if (attempt < ARRAYSIZE(backoff_ms))
            attempt++;

        if (WaitForSingleObject(w->stop, delay) == WAIT_OBJECT_0)
            break;
    }

    inject_release_all(&w->keys);
    SecureZeroMemory(w->psk, sizeof(w->psk));
    if (w->clip_wake != NULL)
        CloseHandle(w->clip_wake);
    CloseHandle(w->stop);
    HeapFree(GetProcessHeap(), 0, w);
    return 0;
}

BOOL worker_start(HWND notify, UINT msg, const wchar_t *address, const uint8_t psk[KBP2_PSK_LEN])
{
    worker_ctx *w;
    HANDLE ev = NULL, dup = NULL, th = NULL, clip;

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

    /* Clipboard sharing is optional: without the event the worker simply
     * never sends clipboard text and advertises CAPS bit0 = 0. */
    clip = clipboard_wake_event();
    if (clip != NULL &&
        !DuplicateHandle(GetCurrentProcess(), clip, GetCurrentProcess(), &w->clip_wake, 0, FALSE,
                         DUPLICATE_SAME_ACCESS))
        w->clip_wake = NULL;

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
    if (w->clip_wake != NULL)
        CloseHandle(w->clip_wake);
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
