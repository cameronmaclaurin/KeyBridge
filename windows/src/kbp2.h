/*
 * KeyBridge - KBP2 client: TCP connection, handshake and record layer,
 * exactly as specified in docs/PROTOCOL.md. Shared by the app and the
 * selftest build so both run the same code.
 */
#ifndef KB_KBP2_H
#define KB_KBP2_H

#include "common.h"
#include "kbutil.h"
#include "kbclip.h"

#define KBP2_PORT_DEFAULT      L"9876"
#define KBP2_MAGIC             "KBR2"
#define KBP2_MAGIC_LEN         4
#define KBP2_PUB_LEN           65
#define KBP2_NONCE_LEN         32
#define KBP2_FINISHED_LEN      32
#define KBP2_CLIENT_HELLO_LEN  101  /* magic || client_pub || client_nonce */
#define KBP2_SERVER_HELLO_LEN  133  /* magic || server_pub || server_nonce || server_finished */
#define KBP2_SH_PREFIX_LEN     101
#define KBP2_PLAINTEXT_LEN     4
#define KBP2_RECORD_LEN        20   /* ciphertext(4) || tag(16) */
#define KBP2_PSK_LEN           32   /* = the ltk from pairing (section 2) */

#define KBP2_HANDSHAKE_MS      5000 /* section 4 */
#define KBP2_LIVENESS_MS       6000 /* section 6 */
#define KBP2_SEND_MS           5000
#define KBP2_DRAIN_MS          1000 /* graceful close, section 5 */

/* Record types (section 5). */
#define KBP2_KEY               0x01
#define KBP2_PING              0x02
#define KBP2_PONG              0x03
#define KBP2_RELEASE_ALL       0x04
#define KBP2_DATA              0x05 /* b1 b2 b3 = sealed chunk length N (24-bit BE); section 5a */
#define KBP2_CAPS              0x06 /* b1 = capability bits; section 5a */
#define KBP2_FLAG_DOWN         0x01
#define KBP2_FLAG_EXTENDED     0x02
#define KBP2_CAPS_CLIPBOARD    0x01 /* CAPS b1 bit0: "I can receive clipboard text" */

#define KBP2_TAG_LEN           16
/* Largest thing ever written in one piece: a DATA header and its sealed chunk
 * (they are never split, section 5a). */
#define KBP2_FRAME_MAX         (KBP2_RECORD_LEN + KBCLIP_CHUNK_MAX + KBP2_TAG_LEN)
/* Send queue: one frame plus room for small records (PONG, CAPS) behind it. */
#define KBP2_OUT_CAP           (KBP2_FRAME_MAX + 64 * KBP2_RECORD_LEN)

typedef enum {
    KBP2_OK = 0,
    KBP2_STOPPED,        /* the caller's stop event was signaled */
    KBP2_WOKEN,          /* kbp2_read_exact_ex: the wake event was signaled first */
    KBP2_ERR_RESOLVE,    /* host name did not resolve */
    KBP2_ERR_CONNECT,    /* no address accepted the connection */
    KBP2_ERR_IO,         /* socket error */
    KBP2_ERR_CLOSED,     /* peer closed the connection */
    KBP2_ERR_TIMEOUT,    /* nothing arrived in time */
    KBP2_ERR_PROTOCOL,   /* bad magic, invalid public key, or unexpected data */
    KBP2_ERR_AUTH,       /* server_finished mismatch (not paired with this Mac), or a
                            pairing commit/confirm mismatch */
    KBP2_ERR_RECORD,     /* record failed authentication (tampered/replayed/reordered) */
    KBP2_ERR_CRYPTO      /* CNG failure */
} kbp2_status;

typedef struct {
    SOCKET   sock;
    WSAEVENT event;
    HANDLE   stop;   /* optional manual-reset event that aborts any wait; may be NULL */
} kbp2_conn;

typedef struct {
    BCRYPT_KEY_HANDLE send_key;  /* k_c2s */
    BCRYPT_KEY_HANDLE recv_key;  /* k_s2c */
    uint64_t send_seq;
    uint64_t recv_seq;
} kbp2_session;

/* Expand(prk, info) = HMAC-SHA256(key = prk, data = label || extra || 0x01)
 * (section 3). extra may be NULL/0. */
BOOL kbp2_expand(const uint8_t prk[32], const char *label, ULONG label_len,
                 const uint8_t *extra, ULONG extra_len, uint8_t out[32]);

void        kbp2_conn_init(kbp2_conn *c, HANDLE stop);
/* Resolve host (AF_UNSPEC, so "Name.local", IPv4 and IPv6 all work) and try
 * each address in turn, each with its own timeout. Sets TCP_NODELAY. */
kbp2_status kbp2_connect(kbp2_conn *c, const wchar_t *host, const wchar_t *port,
                         DWORD per_address_timeout_ms);
/* Graceful close (section 5): shutdown(SD_SEND), discard input until EOF or
 * KBP2_DRAIN_MS, then closesocket. Safe on a closed/never-opened conn. */
void        kbp2_conn_close(kbp2_conn *c);

/* Exact-length I/O with a hard deadline (GetTickCount64 time); the conn's
 * stop event aborts either with KBP2_STOPPED. A clean EOF before the first
 * byte is KBP2_ERR_CLOSED, mid-message it is KBP2_ERR_IO. */
kbp2_status kbp2_read_exact(kbp2_conn *c, uint8_t *buf, size_t len, ULONGLONG deadline);
kbp2_status kbp2_write_all(kbp2_conn *c, const uint8_t *buf, size_t len, ULONGLONG deadline);
/* Like kbp2_read_exact, but resumable: *got bytes are already in buf, and it
 * returns KBP2_WOKEN (keeping *got) if wake (optional event) is signaled while
 * no data is available. Call again with the same buf/got to continue. */
kbp2_status kbp2_read_exact_ex(kbp2_conn *c, uint8_t *buf, size_t len, size_t *got,
                               ULONGLONG deadline, HANDLE wake);

/* Client handshake (section 4). On KBP2_OK the session is authenticated and
 * owns two key handles (release with kbp2_session_free). */
kbp2_status kbp2_client_handshake(kbp2_conn *c, const uint8_t psk[KBP2_PSK_LEN], kbp2_session *s);

kbp2_status kbp2_send_record(kbp2_conn *c, kbp2_session *s, const uint8_t pt[KBP2_PLAINTEXT_LEN]);
/* Waits up to timeout_ms for one complete record. */
kbp2_status kbp2_recv_record(kbp2_conn *c, kbp2_session *s, uint8_t pt[KBP2_PLAINTEXT_LEN],
                             DWORD timeout_ms);
void        kbp2_session_free(kbp2_session *s);

/* ------------------------------------------------------------------------ */
/* Session I/O with clipboard data (sections 5, 5a, 6)                      */
/* ------------------------------------------------------------------------ */
/*
 * A non-blocking record pump for an authenticated session: sends are queued
 * (sealed in seq order at queue time) and written as the socket accepts them,
 * while received records are decoded as soon as they are complete, so a
 * large outgoing clipboard transfer never delays incoming keystrokes. One
 * thread owns a kbp2_io; it is the only writer to the socket. Do not mix with
 * kbp2_send_record / kbp2_recv_record on the same session.
 *
 * Liveness (section 6): kbp2_io_next fails with KBP2_ERR_TIMEOUT if no valid
 * record or chunk arrives for KBP2_LIVENESS_MS, or if queued output makes no
 * progress for KBP2_SEND_MS.
 *
 * The struct is about 50 KB: allocate it on the heap (or statically).
 */
typedef enum {
    KBP2_EV_RECORD = 1,  /* data = 4-byte record plaintext (never a DATA header) */
    KBP2_EV_CHUNK,       /* data = decrypted chunk plaintext, len = N (5..16388) */
    KBP2_EV_SENT         /* only with want_sent: the send queue is empty */
} kbp2_event_type;

typedef struct {
    kbp2_event_type type;
    const uint8_t  *data; /* points into the kbp2_io; valid until the next call */
    size_t          len;
} kbp2_event;

typedef struct {
    kbp2_conn    *conn;
    kbp2_session *sess;
    ULONGLONG     live_deadline;
    ULONGLONG     send_deadline;
    size_t        in_need;   /* KBP2_RECORD_LEN, or N + 16 while reading a chunk */
    size_t        in_got;
    BOOL          in_chunk;
    size_t        out_pos;
    size_t        out_len;
    uint8_t       in[KBCLIP_CHUNK_MAX + KBP2_TAG_LEN];
    uint8_t       pt[KBCLIP_CHUNK_MAX];
    uint8_t       out[KBP2_OUT_CAP];
} kbp2_io;

void        kbp2_io_init(kbp2_io *io, kbp2_conn *c, kbp2_session *s);
/* Wipe buffered plaintext/ciphertext. Does not touch the conn or session. */
void        kbp2_io_wipe(kbp2_io *io);
/* Seal one 4-byte record with the next seq and queue it (then try to send). */
kbp2_status kbp2_io_queue_record(kbp2_io *io, const uint8_t pt[KBP2_PLAINTEXT_LEN]);
/* TRUE when everything queued has been handed to the socket. Queue the next
 * chunk only then, so small records never wait behind more than one chunk. */
BOOL        kbp2_io_send_idle(const kbp2_io *io);
/* Queue a DATA header (seq) and its sealed chunk (seq + 1) back to back.
 * chunk_len must be KBCLIP_CHUNK_MIN..KBCLIP_CHUNK_MAX. */
kbp2_status kbp2_io_queue_chunk(kbp2_io *io, const uint8_t *chunk, size_t chunk_len);
/* Send what the socket accepts and wait for the next event: a record or a
 * chunk (KBP2_OK), the wake event (KBP2_WOKEN; optional), KBP2_EV_SENT when
 * want_sent and the queue is empty, the conn's stop event (KBP2_STOPPED), or
 * an error. A clean close on a record boundary is KBP2_ERR_CLOSED. A DATA
 * header with N outside 5..16388 is KBP2_ERR_PROTOCOL; a record or chunk that
 * fails authentication is KBP2_ERR_RECORD. Data that has already arrived is
 * always returned before the wake event and before KBP2_EV_SENT. */
kbp2_status kbp2_io_next(kbp2_io *io, HANDLE wake, BOOL want_sent, kbp2_event *ev);

const char *kbp2_status_text(kbp2_status st);

#endif
