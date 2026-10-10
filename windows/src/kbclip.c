/*
 * KeyBridge - clipboard transfer helpers (see kbclip.h, docs/PROTOCOL.md 5a).
 */
#include "kbclip.h"

#include <stdlib.h>
#include <string.h>

/* A wipe the compiler may not optimize away. */
static void wipe(uint8_t *p, size_t len)
{
    volatile uint8_t *v = p;
    while (len-- > 0)
        *v++ = 0;
}

void kbclip_free(uint8_t *p, size_t len)
{
    if (p == NULL)
        return;
    wipe(p, len);
    free(p);
}

int kbclip_utf8_valid(const uint8_t *s, size_t len)
{
    size_t i = 0;

    while (i < len) {
        uint8_t c = s[i];
        size_t need, k;
        uint8_t lo = 0x80, hi = 0xBF; /* allowed range of the second byte */

        if (c < 0x80) {
            i++;
            continue;
        }
        if (c >= 0xC2 && c <= 0xDF) {
            need = 1;
        } else if (c >= 0xE0 && c <= 0xEF) {
            need = 2;
            if (c == 0xE0)
                lo = 0xA0;      /* no overlong 3-byte forms */
            else if (c == 0xED)
                hi = 0x9F;      /* no UTF-16 surrogates U+D800..U+DFFF */
        } else if (c >= 0xF0 && c <= 0xF4) {
            need = 3;
            if (c == 0xF0)
                lo = 0x90;      /* no overlong 4-byte forms */
            else if (c == 0xF4)
                hi = 0x8F;      /* nothing above U+10FFFF */
        } else {
            return 0;           /* 0x80..0xC1 (continuation/overlong) or 0xF5..0xFF */
        }
        if (len - i - 1 < need)
            return 0;           /* truncated sequence */
        if (s[i + 1] < lo || s[i + 1] > hi)
            return 0;
        for (k = 2; k <= need; k++) {
            if ((s[i + k] & 0xC0) != 0x80)
                return 0;
        }
        i += need + 1;
    }
    return 1;
}

size_t kbclip_make_chunk(uint8_t out[KBCLIP_CHUNK_MAX], uint16_t transfer_id,
                         const uint8_t *text, size_t len, size_t *off)
{
    size_t start = *off, n;
    uint8_t flags = 0;

    if (len == 0 || len > KBCLIP_TEXT_MAX || start >= len)
        return 0;
    n = len - start;
    if (n > KBCLIP_PAYLOAD_MAX)
        n = KBCLIP_PAYLOAD_MAX;
    if (start == 0)
        flags |= KBCLIP_FLAG_FIRST;
    if (start + n == len)
        flags |= KBCLIP_FLAG_LAST;

    out[0] = KBCLIP_KIND_TEXT;
    out[1] = flags;
    out[2] = (uint8_t)(transfer_id >> 8);
    out[3] = (uint8_t)(transfer_id & 0xFF);
    memcpy(out + KBCLIP_HDR_LEN, text + start, n);
    *off = start + n;
    return KBCLIP_HDR_LEN + n;
}

void kbclip_rx_init(kbclip_rx *rx)
{
    rx->buf = NULL;
    rx->len = 0;
    rx->cap = 0;
    rx->id = 0;
    rx->state = KBCLIP_RX_IDLE;
}

/* Drop the buffer (wiped) and go to the given state. */
static void rx_drop(kbclip_rx *rx, int state)
{
    kbclip_free(rx->buf, rx->cap);
    rx->buf = NULL;
    rx->len = 0;
    rx->cap = 0;
    rx->state = state;
}

void kbclip_rx_free(kbclip_rx *rx)
{
    rx_drop(rx, KBCLIP_RX_IDLE);
}

/* Make room for need bytes in total (need <= KBCLIP_TEXT_MAX). */
static int rx_reserve(kbclip_rx *rx, size_t need)
{
    size_t cap;
    uint8_t *nb;

    if (need <= rx->cap)
        return 1;
    cap = rx->cap < KBCLIP_PAYLOAD_MAX ? KBCLIP_PAYLOAD_MAX : rx->cap;
    while (cap < need)
        cap *= 2;
    if (cap > KBCLIP_TEXT_MAX)
        cap = KBCLIP_TEXT_MAX;
    /* Not realloc: the old block is wiped before it is released. */
    nb = (uint8_t *)malloc(cap);
    if (nb == NULL)
        return 0;
    if (rx->len != 0)
        memcpy(nb, rx->buf, rx->len);
    kbclip_free(rx->buf, rx->cap);
    rx->buf = nb;
    rx->cap = cap;
    return 1;
}

int kbclip_rx_chunk(kbclip_rx *rx, const uint8_t *chunk, size_t n,
                    uint8_t **text, size_t *text_len)
{
    uint8_t flags;
    uint16_t id;
    size_t plen;

    *text = NULL;
    *text_len = 0;
    if (n < KBCLIP_CHUNK_MIN || n > KBCLIP_CHUNK_MAX)
        return 0;
    if (chunk[0] != KBCLIP_KIND_TEXT)
        return 0; /* unknown kind: already decrypted by the caller; discard */
    flags = chunk[1];
    id = (uint16_t)(((unsigned)chunk[2] << 8) | (unsigned)chunk[3]);
    plen = n - KBCLIP_HDR_LEN;

    if (flags & KBCLIP_FLAG_FIRST) {
        /* A new transfer abandons any unfinished one. */
        rx_drop(rx, KBCLIP_RX_COLLECTING);
        rx->id = id;
    } else if (rx->state != KBCLIP_RX_COLLECTING || id != rx->id) {
        return 0; /* no matching transfer (or it is being discarded) */
    }

    if (plen > KBCLIP_TEXT_MAX - rx->len) {
        rx_drop(rx, KBCLIP_RX_DISCARDING); /* over 1 MiB: ignore until the next "first" */
        return 0;
    }
    if (!rx_reserve(rx, rx->len + plen)) {
        rx_drop(rx, KBCLIP_RX_DISCARDING);
        return 0;
    }
    memcpy(rx->buf + rx->len, chunk + KBCLIP_HDR_LEN, plen);
    rx->len += plen;

    if (!(flags & KBCLIP_FLAG_LAST))
        return 0;

    if (!kbclip_utf8_valid(rx->buf, rx->len)) {
        rx_drop(rx, KBCLIP_RX_IDLE);
        return 0;
    }
    /* Hand the buffer over. Wipe the unused tail so kbclip_free(text, len)
     * leaves nothing behind. */
    if (rx->cap > rx->len)
        wipe(rx->buf + rx->len, rx->cap - rx->len);
    *text = rx->buf;
    *text_len = rx->len;
    rx->buf = NULL;
    rx->len = 0;
    rx->cap = 0;
    rx->state = KBCLIP_RX_IDLE;
    return 1;
}
