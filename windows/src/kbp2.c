/*
 * KeyBridge - KBP2 client (see kbp2.h and docs/PROTOCOL.md).
 *
 * Sockets are non-blocking with WSAEventSelect, so every wait can also be
 * woken by the caller's stop event and every read has a hard deadline.
 */
#include "kbp2.h"
#include "crypto.h"

#ifndef WSA_FLAG_NO_HANDLE_INHERIT
#define WSA_FLAG_NO_HANDLE_INHERIT 0x80
#endif

/* Labels (ASCII, no terminator on the wire). */
static const char kLabelServerFinished[] = "KBR2 server finished";
static const char kLabelClientFinished[] = "KBR2 client finished";
static const char kLabelTrafficS2C[]     = "KBR2 traffic s2c";
static const char kLabelTrafficC2S[]     = "KBR2 traffic c2s";
#define LABEL(s) (s), ((ULONG)(sizeof(s) - 1))

/* ------------------------------------------------------------------------ */
/* Key schedule helpers (section 3)                                         */
/* ------------------------------------------------------------------------ */

/* Expand(prk, info) = HMAC-SHA256(prk, info || 0x01) with info = label || extra. */
BOOL kbp2_expand(const uint8_t prk[KB_SHA256_LEN], const char *label, ULONG label_len,
                        const uint8_t *extra, ULONG extra_len, uint8_t out[KB_SHA256_LEN])
{
    static const uint8_t one = 0x01;
    return kb_hmac_sha256(prk, KB_SHA256_LEN, label, label_len, extra, extra_len, &one, 1, out);
}

/* ------------------------------------------------------------------------ */
/* Socket plumbing                                                          */
/* ------------------------------------------------------------------------ */

static BOOL stop_signaled(const kbp2_conn *c)
{
    return c->stop != NULL && WaitForSingleObject(c->stop, 0) == WAIT_OBJECT_0;
}

static kbp2_status error_status(int wsa_error)
{
    switch (wsa_error) {
    case WSAECONNRESET:
    case WSAECONNABORTED:
    case WSAENETRESET:
    case WSAESHUTDOWN:
        return KBP2_ERR_CLOSED;
    default:
        return KBP2_ERR_IO;
    }
}

/* Wait for socket activity, the stop event (if honor_stop), the optional wake
 * event, or the deadline. Resets the socket's event via WSAEnumNetworkEvents.
 * Returns KBP2_WOKEN if wake was signaled. */
static kbp2_status conn_wait(kbp2_conn *c, ULONGLONG deadline, BOOL honor_stop, HANDLE wake,
                             WSANETWORKEVENTS *ne)
{
    HANDLE handles[3];
    DWORD count = 0, ms, r, wake_index = MAXDWORD;
    BOOL with_stop = honor_stop && c->stop != NULL;
    ULONGLONG now = GetTickCount64();

    memset(ne, 0, sizeof(*ne));
    if (now >= deadline)
        return KBP2_ERR_TIMEOUT;
    ms = (deadline - now > 0x7FFFFFFFull) ? 0x7FFFFFFFul : (DWORD)(deadline - now);

    if (with_stop)
        handles[count++] = c->stop; /* first, so it wins when several are signaled */
    if (wake != NULL) {
        wake_index = count;
        handles[count++] = wake;
    }
    handles[count++] = c->event;

    r = WaitForMultipleObjects(count, handles, FALSE, ms);
    if (r == WAIT_TIMEOUT)
        return KBP2_ERR_TIMEOUT;
    if (r >= WAIT_OBJECT_0 + count)
        return KBP2_ERR_IO;
    if (with_stop && r == WAIT_OBJECT_0)
        return KBP2_STOPPED;
    if (r - WAIT_OBJECT_0 == wake_index)
        return KBP2_WOKEN;
    if (WSAEnumNetworkEvents(c->sock, c->event, ne) == SOCKET_ERROR)
        return KBP2_ERR_IO;
    return KBP2_OK;
}

kbp2_status kbp2_read_exact_ex(kbp2_conn *c, uint8_t *buf, size_t len, size_t *got,
                               ULONGLONG deadline, HANDLE wake)
{
    while (*got < len) {
        WSANETWORKEVENTS ne;
        kbp2_status st;
        int r, err;

        if (stop_signaled(c))
            return KBP2_STOPPED;
        if (c->sock == INVALID_SOCKET)
            return KBP2_ERR_IO;
        r = recv(c->sock, (char *)buf + *got, (int)(len - *got), 0);
        if (r > 0) {
            *got += (size_t)r;
            continue;
        }
        /* A close on a message boundary is a clean close; a close in the
         * middle of a message is a truncated message, i.e. an error. */
        if (r == 0)
            return *got == 0 ? KBP2_ERR_CLOSED : KBP2_ERR_IO;
        err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK) {
            st = error_status(err);
            return (st == KBP2_ERR_CLOSED && *got != 0) ? KBP2_ERR_IO : st;
        }
        /* Data already received always wins over the wake event. */
        st = conn_wait(c, deadline, TRUE, wake, &ne);
        if (st != KBP2_OK)
            return st;
    }
    return KBP2_OK;
}

kbp2_status kbp2_read_exact(kbp2_conn *c, uint8_t *buf, size_t len, ULONGLONG deadline)
{
    size_t got = 0;
    return kbp2_read_exact_ex(c, buf, len, &got, deadline, NULL);
}

kbp2_status kbp2_write_all(kbp2_conn *c, const uint8_t *buf, size_t len, ULONGLONG deadline)
{
    size_t sent = 0;

    while (sent < len) {
        WSANETWORKEVENTS ne;
        kbp2_status st;
        int r, err;

        if (stop_signaled(c))
            return KBP2_STOPPED;
        if (c->sock == INVALID_SOCKET)
            return KBP2_ERR_IO;
        r = send(c->sock, (const char *)buf + sent, (int)(len - sent), 0);
        if (r > 0) {
            sent += (size_t)r;
            continue;
        }
        err = (r == 0) ? WSAECONNRESET : WSAGetLastError();
        if (err != WSAEWOULDBLOCK)
            return error_status(err);
        st = conn_wait(c, deadline, TRUE, NULL, &ne); /* FD_WRITE re-arms after WSAEWOULDBLOCK */
        if (st != KBP2_OK)
            return st;
    }
    return KBP2_OK;
}

static void abort_socket(kbp2_conn *c)
{
    if (c->sock != INVALID_SOCKET) {
        closesocket(c->sock);
        c->sock = INVALID_SOCKET;
    }
}

void kbp2_conn_init(kbp2_conn *c, HANDLE stop)
{
    c->sock = INVALID_SOCKET;
    c->event = WSA_INVALID_EVENT;
    c->stop = stop;
}

kbp2_status kbp2_connect(kbp2_conn *c, const wchar_t *host, const wchar_t *port,
                         DWORD per_address_timeout_ms)
{
    ADDRINFOW hints;
    ADDRINFOW *res = NULL;
    ADDRINFOW *ai;
    kbp2_status result = KBP2_ERR_CONNECT;

    abort_socket(c);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;      /* IPv4, IPv6, and mDNS "Name.local" */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (GetAddrInfoW(host, port, &hints, &res) != 0 || res == NULL) {
        if (res != NULL)
            FreeAddrInfoW(res);
        return stop_signaled(c) ? KBP2_STOPPED : KBP2_ERR_RESOLVE;
    }

    if (c->event == WSA_INVALID_EVENT) {
        c->event = WSACreateEvent();
        if (c->event == WSA_INVALID_EVENT) {
            FreeAddrInfoW(res);
            return KBP2_ERR_IO;
        }
    }

    for (ai = res; ai != NULL; ai = ai->ai_next) {
        SOCKET s;
        int one = 1;
        ULONGLONG deadline;
        kbp2_status st = KBP2_ERR_CONNECT;

        if (stop_signaled(c)) {
            result = KBP2_STOPPED;
            break;
        }
        if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
            continue;

        s = WSASocketW(ai->ai_family, ai->ai_socktype, ai->ai_protocol, NULL, 0,
                       WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
        if (s == INVALID_SOCKET)
            continue;
        /* Latency: never coalesce our tiny writes. */
        (void)setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, (int)sizeof(one));

        WSAResetEvent(c->event);
        if (WSAEventSelect(s, c->event, FD_CONNECT | FD_READ | FD_WRITE | FD_CLOSE) == SOCKET_ERROR) {
            closesocket(s);
            continue;
        }
        c->sock = s; /* now non-blocking */

        if (connect(s, ai->ai_addr, (int)ai->ai_addrlen) == 0) {
            result = KBP2_OK;
            break;
        }
        if (WSAGetLastError() != WSAEWOULDBLOCK) {
            abort_socket(c);
            continue;
        }

        deadline = GetTickCount64() + per_address_timeout_ms;
        for (;;) {
            WSANETWORKEVENTS ne;
            st = conn_wait(c, deadline, TRUE, NULL, &ne);
            if (st != KBP2_OK)
                break;
            if (ne.lNetworkEvents & FD_CONNECT) {
                st = (ne.iErrorCode[FD_CONNECT_BIT] == 0) ? KBP2_OK : KBP2_ERR_CONNECT;
                break;
            }
        }
        if (st == KBP2_OK) {
            result = KBP2_OK;
            break;
        }
        abort_socket(c);
        if (st == KBP2_STOPPED) {
            result = KBP2_STOPPED;
            break;
        }
    }

    FreeAddrInfoW(res);
    if (result != KBP2_OK)
        abort_socket(c);
    return result;
}

void kbp2_conn_close(kbp2_conn *c)
{
    if (c->sock != INVALID_SOCKET) {
        /* Section 5 graceful close: FIN first, then discard whatever the peer
         * still sends until EOF or 1 s, so closesocket never has unread data
         * (which would turn it into an RST). A stop request cuts the drain
         * short: when quitting, nothing in flight matters any more. */
        if (shutdown(c->sock, SD_SEND) == 0) {
            ULONGLONG deadline = GetTickCount64() + KBP2_DRAIN_MS;
            char junk[256];
            for (;;) {
                WSANETWORKEVENTS ne;
                int r;
                if (GetTickCount64() >= deadline)
                    break;
                r = recv(c->sock, junk, (int)sizeof(junk), 0);
                if (r > 0)
                    continue;
                if (r == 0 || WSAGetLastError() != WSAEWOULDBLOCK)
                    break;
                if (conn_wait(c, deadline, TRUE, NULL, &ne) != KBP2_OK)
                    break;
            }
            SecureZeroMemory(junk, sizeof(junk));
        }
        closesocket(c->sock);
        c->sock = INVALID_SOCKET;
    }
    if (c->event != WSA_INVALID_EVENT) {
        WSACloseEvent(c->event);
        c->event = WSA_INVALID_EVENT;
    }
}

/* ------------------------------------------------------------------------ */
/* Handshake (section 4, client steps)                                      */
/* ------------------------------------------------------------------------ */

kbp2_status kbp2_client_handshake(kbp2_conn *c, const uint8_t psk[KBP2_PSK_LEN], kbp2_session *s)
{
    uint8_t ch[KBP2_CLIENT_HELLO_LEN];
    uint8_t sh[KBP2_SERVER_HELLO_LEN];
    uint8_t ecdh[KB_ECDH_LEN];
    uint8_t prk[KB_SHA256_LEN];
    uint8_t th1[KB_SHA256_LEN];
    uint8_t th2[KB_SHA256_LEN];
    uint8_t finished_key[KB_SHA256_LEN];
    uint8_t server_finished[KBP2_FINISHED_LEN];
    uint8_t client_finished[KBP2_FINISHED_LEN];
    uint8_t k_s2c[KB_AES_KEY_LEN];
    uint8_t k_c2s[KB_AES_KEY_LEN];
    const uint8_t *server_pub = sh + KBP2_MAGIC_LEN;
    const uint8_t *received_finished = sh + KBP2_SH_PREFIX_LEN;
    BCRYPT_KEY_HANDLE priv = NULL;
    ULONGLONG deadline = GetTickCount64() + KBP2_HANDSHAKE_MS;
    kbp2_status st;

    memset(s, 0, sizeof(*s));

    /* 1. Ephemeral key pair and client_nonce; send ClientHello (101 bytes). */
    memcpy(ch, KBP2_MAGIC, KBP2_MAGIC_LEN);
    if (!kb_ecdh_generate(&priv, ch + KBP2_MAGIC_LEN) ||
        !kb_random(ch + KBP2_MAGIC_LEN + KBP2_PUB_LEN, KBP2_NONCE_LEN)) {
        st = KBP2_ERR_CRYPTO;
        goto done;
    }
    st = kbp2_write_all(c, ch, sizeof(ch), deadline);
    if (st != KBP2_OK)
        goto done;

    /* 2. Read exactly 133 bytes within the 5 s window; check magic and key. */
    st = kbp2_read_exact(c, sh, sizeof(sh), deadline);
    if (st != KBP2_OK)
        goto done;
    if (memcmp(sh, KBP2_MAGIC, KBP2_MAGIC_LEN) != 0 || !kb_p256_point_valid(server_pub)) {
        st = KBP2_ERR_PROTOCOL;
        goto done;
    }

    /* ecdh = ECDH(own private, server_pub); prk = Extract(psk, ecdh). */
    if (!kb_ecdh_derive(priv, server_pub, ecdh)) {
        st = KBP2_ERR_PROTOCOL;
        goto done;
    }
    kb_key_destroy(&priv); /* ephemeral: used exactly once */
    if (!kb_hmac_sha256(psk, KBP2_PSK_LEN, ecdh, KB_ECDH_LEN, NULL, 0, NULL, 0, prk)) {
        st = KBP2_ERR_CRYPTO;
        goto done;
    }

    /* TH1 = SHA-256(ClientHello || SH_prefix), TH2 = SHA-256(ClientHello || ServerHello). */
    if (!kb_sha256(ch, (ULONG)sizeof(ch), sh, KBP2_SH_PREFIX_LEN, th1) ||
        !kb_sha256(ch, (ULONG)sizeof(ch), sh, KBP2_SERVER_HELLO_LEN, th2)) {
        st = KBP2_ERR_CRYPTO;
        goto done;
    }

    /* server_finished = HMAC(Expand(prk, "KBR2 server finished"), TH1), compared in constant time. */
    if (!kbp2_expand(prk, LABEL(kLabelServerFinished), NULL, 0, finished_key) ||
        !kb_hmac_sha256(finished_key, KB_SHA256_LEN, th1, KB_SHA256_LEN, NULL, 0, NULL, 0,
                        server_finished)) {
        st = KBP2_ERR_CRYPTO;
        goto done;
    }
    if (!kb_ct_equal(server_finished, received_finished, KBP2_FINISHED_LEN)) {
        /* 3. Not paired with this Mac (different ltk): close without sending
         *    ClientFinished. */
        st = KBP2_ERR_AUTH;
        goto done;
    }

    /* client_finished = HMAC(Expand(prk, "KBR2 client finished"), TH2). */
    if (!kbp2_expand(prk, LABEL(kLabelClientFinished), NULL, 0, finished_key) ||
        !kb_hmac_sha256(finished_key, KB_SHA256_LEN, th2, KB_SHA256_LEN, NULL, 0, NULL, 0,
                        client_finished)) {
        st = KBP2_ERR_CRYPTO;
        goto done;
    }

    /* k_s2c = Expand(prk, "KBR2 traffic s2c" || TH2); k_c2s = Expand(prk, "KBR2 traffic c2s" || TH2). */
    if (!kbp2_expand(prk, LABEL(kLabelTrafficS2C), th2, KB_SHA256_LEN, k_s2c) ||
        !kbp2_expand(prk, LABEL(kLabelTrafficC2S), th2, KB_SHA256_LEN, k_c2s) ||
        !kb_gcm_key(&s->recv_key, k_s2c) ||
        !kb_gcm_key(&s->send_key, k_c2s)) {
        st = KBP2_ERR_CRYPTO;
        goto done;
    }

    /* 4. Send ClientFinished (32 bytes); the session is authenticated. */
    st = kbp2_write_all(c, client_finished, sizeof(client_finished), deadline);
    if (st != KBP2_OK)
        goto done;
    s->send_seq = 0;
    s->recv_seq = 0;

done:
    kb_key_destroy(&priv);
    SecureZeroMemory(ecdh, sizeof(ecdh));
    SecureZeroMemory(prk, sizeof(prk));
    SecureZeroMemory(finished_key, sizeof(finished_key));
    SecureZeroMemory(server_finished, sizeof(server_finished));
    SecureZeroMemory(client_finished, sizeof(client_finished));
    SecureZeroMemory(k_s2c, sizeof(k_s2c));
    SecureZeroMemory(k_c2s, sizeof(k_c2s));
    if (st != KBP2_OK)
        kbp2_session_free(s);
    return st;
}

/* ------------------------------------------------------------------------ */
/* Records (section 5)                                                      */
/* ------------------------------------------------------------------------ */

kbp2_status kbp2_send_record(kbp2_conn *c, kbp2_session *s, const uint8_t pt[KBP2_PLAINTEXT_LEN])
{
    uint8_t record[KBP2_RECORD_LEN];
    uint8_t nonce[KB_NONCE_LEN];

    if (s->send_key == NULL || s->send_seq == UINT64_MAX)
        return KBP2_ERR_CRYPTO;
    kb_record_nonce(s->send_seq, nonce);
    if (!kb_gcm_seal(s->send_key, nonce, pt, KBP2_PLAINTEXT_LEN, record, record + KBP2_PLAINTEXT_LEN))
        return KBP2_ERR_CRYPTO;
    s->send_seq++;
    return kbp2_write_all(c, record, sizeof(record), GetTickCount64() + KBP2_SEND_MS);
}

kbp2_status kbp2_recv_record(kbp2_conn *c, kbp2_session *s, uint8_t pt[KBP2_PLAINTEXT_LEN],
                             DWORD timeout_ms)
{
    uint8_t record[KBP2_RECORD_LEN];
    uint8_t nonce[KB_NONCE_LEN];
    kbp2_status st;

    memset(pt, 0, KBP2_PLAINTEXT_LEN);
    if (s->recv_key == NULL || s->recv_seq == UINT64_MAX)
        return KBP2_ERR_CRYPTO;
    st = kbp2_read_exact(c, record, sizeof(record), GetTickCount64() + timeout_ms);
    if (st != KBP2_OK)
        return st;
    kb_record_nonce(s->recv_seq, nonce);
    if (!kb_gcm_open(s->recv_key, nonce, record, KBP2_PLAINTEXT_LEN, record + KBP2_PLAINTEXT_LEN, pt))
        return KBP2_ERR_RECORD; /* caller must close the connection immediately */
    s->recv_seq++;
    return KBP2_OK;
}

/* ------------------------------------------------------------------------ */
/* Session I/O pump (sections 5, 5a, 6)                                     */
/* ------------------------------------------------------------------------ */

void kbp2_io_init(kbp2_io *io, kbp2_conn *c, kbp2_session *s)
{
    io->conn = c;
    io->sess = s;
    io->live_deadline = GetTickCount64() + KBP2_LIVENESS_MS;
    io->send_deadline = 0;
    io->in_need = KBP2_RECORD_LEN;
    io->in_got = 0;
    io->in_chunk = FALSE;
    io->out_pos = 0;
    io->out_len = 0;
}

void kbp2_io_wipe(kbp2_io *io)
{
    SecureZeroMemory(io->in, sizeof(io->in));
    SecureZeroMemory(io->pt, sizeof(io->pt));
    SecureZeroMemory(io->out, sizeof(io->out));
    io->in_got = 0;
    io->out_pos = 0;
    io->out_len = 0;
}

BOOL kbp2_io_send_idle(const kbp2_io *io)
{
    return io->out_pos >= io->out_len;
}

/* Hand queued bytes to the socket until it would block. */
static kbp2_status io_flush(kbp2_io *io)
{
    kbp2_conn *c = io->conn;

    while (io->out_pos < io->out_len) {
        int r, err;
        size_t n = io->out_len - io->out_pos;

        if (c->sock == INVALID_SOCKET)
            return KBP2_ERR_IO;
        r = send(c->sock, (const char *)io->out + io->out_pos, (int)n, 0);
        if (r > 0) {
            io->out_pos += (size_t)r;
            io->send_deadline = GetTickCount64() + KBP2_SEND_MS; /* progress */
            continue;
        }
        err = (r == 0) ? WSAECONNRESET : WSAGetLastError();
        if (err == WSAEWOULDBLOCK)
            break; /* FD_WRITE re-arms and wakes conn_wait */
        return error_status(err);
    }
    if (io->out_pos >= io->out_len) {
        io->out_pos = 0;
        io->out_len = 0;
    }
    return KBP2_OK;
}

/* Make room for need more bytes at the end of the send queue. */
static BOOL io_reserve(kbp2_io *io, size_t need)
{
    if (io->out_pos >= io->out_len) {
        io->out_pos = 0;
        io->out_len = 0;
    }
    if (sizeof(io->out) - io->out_len >= need)
        return TRUE;
    if (io->out_pos != 0) {
        memmove(io->out, io->out + io->out_pos, io->out_len - io->out_pos);
        io->out_len -= io->out_pos;
        io->out_pos = 0;
    }
    return sizeof(io->out) - io->out_len >= need;
}

/* Seal len bytes of pt with the next send seq into dst (len ciphertext bytes
 * followed by the 16-byte tag). */
static kbp2_status io_seal(kbp2_io *io, const uint8_t *pt, size_t len, uint8_t *dst)
{
    uint8_t nonce[KB_NONCE_LEN];
    kbp2_session *s = io->sess;

    if (s->send_key == NULL || s->send_seq == UINT64_MAX)
        return KBP2_ERR_CRYPTO;
    kb_record_nonce(s->send_seq, nonce);
    if (!kb_gcm_seal(s->send_key, nonce, pt, (ULONG)len, dst, dst + len))
        return KBP2_ERR_CRYPTO;
    s->send_seq++;
    return KBP2_OK;
}

static void io_mark_queued(kbp2_io *io, BOOL was_idle)
{
    if (was_idle)
        io->send_deadline = GetTickCount64() + KBP2_SEND_MS;
}

kbp2_status kbp2_io_queue_record(kbp2_io *io, const uint8_t pt[KBP2_PLAINTEXT_LEN])
{
    BOOL was_idle = kbp2_io_send_idle(io);
    kbp2_status st;

    /* Full means the peer stopped reading long ago (the queue holds a chunk
     * and 64 records); the connection is no use. */
    if (!io_reserve(io, KBP2_RECORD_LEN))
        return KBP2_ERR_TIMEOUT;
    st = io_seal(io, pt, KBP2_PLAINTEXT_LEN, io->out + io->out_len);
    if (st != KBP2_OK)
        return st;
    io->out_len += KBP2_RECORD_LEN;
    io_mark_queued(io, was_idle);
    return io_flush(io); /* small records go out at once */
}

kbp2_status kbp2_io_queue_chunk(kbp2_io *io, const uint8_t *chunk, size_t chunk_len)
{
    uint8_t hdr[KBP2_PLAINTEXT_LEN];
    BOOL was_idle = kbp2_io_send_idle(io);
    kbp2_status st;
    uint8_t *dst;

    if (chunk_len < KBCLIP_CHUNK_MIN || chunk_len > KBCLIP_CHUNK_MAX)
        return KBP2_ERR_PROTOCOL;
    if (io->sess->send_seq >= UINT64_MAX - 1)
        return KBP2_ERR_CRYPTO; /* header and chunk need two seqs */
    if (!io_reserve(io, KBP2_RECORD_LEN + chunk_len + KBP2_TAG_LEN))
        return KBP2_ERR_TIMEOUT;

    hdr[0] = KBP2_DATA;
    hdr[1] = (uint8_t)((chunk_len >> 16) & 0xFF);
    hdr[2] = (uint8_t)((chunk_len >> 8) & 0xFF);
    hdr[3] = (uint8_t)(chunk_len & 0xFF);
    dst = io->out + io->out_len;
    st = io_seal(io, hdr, sizeof(hdr), dst);                       /* seq     */
    if (st == KBP2_OK)
        st = io_seal(io, chunk, chunk_len, dst + KBP2_RECORD_LEN); /* seq + 1 */
    if (st != KBP2_OK) {
        SecureZeroMemory(dst, KBP2_RECORD_LEN + chunk_len + KBP2_TAG_LEN);
        return st;
    }
    io->out_len += KBP2_RECORD_LEN + chunk_len + KBP2_TAG_LEN;
    io_mark_queued(io, was_idle);
    return io_flush(io);
}

/* Read what is available. *have is set when a record or chunk is complete;
 * *progress when a DATA header was consumed (so the chunk should be read at
 * once). Returns KBP2_OK if the socket simply has nothing more right now. */
static kbp2_status io_read(kbp2_io *io, kbp2_event *ev, BOOL *have, BOOL *progress)
{
    kbp2_conn *c = io->conn;
    kbp2_session *s = io->sess;
    uint8_t nonce[KB_NONCE_LEN];
    size_t ct_len;

    *have = FALSE;
    *progress = FALSE;
    while (io->in_got < io->in_need) {
        int r, err;
        kbp2_status st;
        BOOL mid = io->in_got != 0 || io->in_chunk; /* inside a header+chunk pair */

        if (c->sock == INVALID_SOCKET)
            return KBP2_ERR_IO;
        r = recv(c->sock, (char *)io->in + io->in_got, (int)(io->in_need - io->in_got), 0);
        if (r > 0) {
            io->in_got += (size_t)r;
            continue;
        }
        /* A close on a record boundary is clean; anywhere else (including
         * between a DATA header and its chunk) is a truncated message. */
        if (r == 0)
            return mid ? KBP2_ERR_IO : KBP2_ERR_CLOSED;
        err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK)
            return KBP2_OK;
        st = error_status(err);
        return (st == KBP2_ERR_CLOSED && mid) ? KBP2_ERR_IO : st;
    }

    if (s->recv_key == NULL || s->recv_seq == UINT64_MAX)
        return KBP2_ERR_CRYPTO;
    ct_len = io->in_need - KBP2_TAG_LEN;
    kb_record_nonce(s->recv_seq, nonce);
    if (!kb_gcm_open(s->recv_key, nonce, io->in, (ULONG)ct_len, io->in + ct_len, io->pt))
        return KBP2_ERR_RECORD; /* caller must close the connection immediately */
    s->recv_seq++;
    io->live_deadline = GetTickCount64() + KBP2_LIVENESS_MS; /* any valid record or chunk */
    io->in_got = 0;

    if (io->in_chunk) {
        io->in_chunk = FALSE;
        io->in_need = KBP2_RECORD_LEN;
        ev->type = KBP2_EV_CHUNK;
        ev->data = io->pt;
        ev->len = ct_len;
        *have = TRUE;
        return KBP2_OK;
    }
    if (io->pt[0] == KBP2_DATA) {
        size_t n = ((size_t)io->pt[1] << 16) | ((size_t)io->pt[2] << 8) | (size_t)io->pt[3];
        if (n < KBCLIP_CHUNK_MIN || n > KBCLIP_CHUNK_MAX)
            return KBP2_ERR_PROTOCOL; /* a bad chunk length closes the connection */
        io->in_chunk = TRUE;
        io->in_need = n + KBP2_TAG_LEN;
        *progress = TRUE;
        return KBP2_OK;
    }
    ev->type = KBP2_EV_RECORD;
    ev->data = io->pt;
    ev->len = KBP2_PLAINTEXT_LEN;
    *have = TRUE;
    return KBP2_OK;
}

kbp2_status kbp2_io_next(kbp2_io *io, HANDLE wake, BOOL want_sent, kbp2_event *ev)
{
    kbp2_conn *c = io->conn;

    ev->type = KBP2_EV_SENT;
    ev->data = NULL;
    ev->len = 0;
    for (;;) {
        WSANETWORKEVENTS ne;
        ULONGLONG now, deadline;
        BOOL have, progress, sending;
        kbp2_status st;

        if (stop_signaled(c))
            return KBP2_STOPPED;
        /* Incoming first: keystrokes never wait behind our own output. */
        st = io_read(io, ev, &have, &progress);
        if (st != KBP2_OK || have)
            return st;
        if (progress)
            continue; /* DATA header consumed: its chunk is probably here already */
        st = io_flush(io);
        if (st != KBP2_OK)
            return st;
        sending = !kbp2_io_send_idle(io);
        if (want_sent && !sending) {
            ev->type = KBP2_EV_SENT;
            return KBP2_OK;
        }

        now = GetTickCount64();
        if (now >= io->live_deadline)
            return KBP2_ERR_TIMEOUT;          /* section 6: nothing valid for 6 s */
        if (sending && now >= io->send_deadline)
            return KBP2_ERR_TIMEOUT;          /* the peer stopped reading */
        deadline = io->live_deadline;
        if (sending && io->send_deadline < deadline)
            deadline = io->send_deadline;

        st = conn_wait(c, deadline, TRUE, wake, &ne);
        if (st == KBP2_ERR_TIMEOUT)
            continue; /* the checks above report which deadline passed */
        if (st != KBP2_OK)
            return st; /* KBP2_STOPPED, KBP2_WOKEN or KBP2_ERR_IO */
    }
}

void kbp2_session_free(kbp2_session *s)
{
    kb_key_destroy(&s->send_key);
    kb_key_destroy(&s->recv_key);
    s->send_seq = 0;
    s->recv_seq = 0;
}

const char *kbp2_status_text(kbp2_status st)
{
    switch (st) {
    case KBP2_OK:           return "ok";
    case KBP2_STOPPED:      return "stopped";
    case KBP2_WOKEN:        return "woken";
    case KBP2_ERR_RESOLVE:  return "could not resolve host name";
    case KBP2_ERR_CONNECT:  return "could not connect";
    case KBP2_ERR_IO:       return "socket error";
    case KBP2_ERR_CLOSED:   return "connection closed by peer";
    case KBP2_ERR_TIMEOUT:  return "timed out";
    case KBP2_ERR_PROTOCOL: return "protocol error (bad magic, invalid public key or unexpected data)";
    case KBP2_ERR_AUTH:     return "authentication failed (finished, commit or confirm value mismatch)";
    case KBP2_ERR_RECORD:   return "record failed authentication";
    case KBP2_ERR_CRYPTO:   return "cryptography error";
    }
    return "unknown error";
}
