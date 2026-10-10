/*
 * KeyBridge - KBP2 client: TCP connection, handshake and record layer,
 * exactly as specified in docs/PROTOCOL.md. Shared by the app and the
 * selftest build so both run the same code.
 */
#ifndef KB_KBP2_H
#define KB_KBP2_H

#include "common.h"
#include "kbutil.h"

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
#define KBP2_FLAG_DOWN         0x01
#define KBP2_FLAG_EXTENDED     0x02

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

const char *kbp2_status_text(kbp2_status st);

#endif
