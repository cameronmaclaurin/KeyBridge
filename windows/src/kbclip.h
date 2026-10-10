/*
 * KeyBridge - clipboard transfer helpers for docs/PROTOCOL.md section 5a:
 * chunk building, chunk reassembly and UTF-8 validation. Pure C with no
 * Windows dependencies (so they can be unit-tested on any platform); shared
 * by the app (worker.c) and the selftest build.
 *
 * Chunk plaintext = kind(1) || flags(1) || transfer_id(2, big-endian) || payload.
 */
#ifndef KB_KBCLIP_H
#define KB_KBCLIP_H

#include <stddef.h>
#include <stdint.h>

#define KBCLIP_KIND_TEXT     0x01      /* clipboard text, UTF-8, no BOM, no terminator */
#define KBCLIP_FLAG_FIRST    0x01
#define KBCLIP_FLAG_LAST     0x02
#define KBCLIP_HDR_LEN       4         /* kind || flags || transfer_id */
#define KBCLIP_PAYLOAD_MAX   16384     /* per chunk */
#define KBCLIP_CHUNK_MIN     (KBCLIP_HDR_LEN + 1)                   /* 5 */
#define KBCLIP_CHUNK_MAX     (KBCLIP_HDR_LEN + KBCLIP_PAYLOAD_MAX)  /* 16388 */
#define KBCLIP_TEXT_MAX      1048576u  /* total UTF-8 bytes per transfer */

/* 1 if s[0..len) is well-formed UTF-8 (no overlong forms, no surrogates,
 * nothing above U+10FFFF). An empty string is valid. */
int kbclip_utf8_valid(const uint8_t *s, size_t len);

/* Build the next chunk of a text transfer into out. *off is how many bytes of
 * text have been sent already; it is advanced past this chunk's payload.
 * Returns the chunk plaintext length (KBCLIP_CHUNK_MIN..KBCLIP_CHUNK_MAX), or
 * 0 if there is nothing left to send (or len is 0 or over KBCLIP_TEXT_MAX). */
size_t kbclip_make_chunk(uint8_t out[KBCLIP_CHUNK_MAX], uint16_t transfer_id,
                         const uint8_t *text, size_t len, size_t *off);

/* Receive-side reassembly state for one direction. Zero-initialized (or
 * kbclip_rx_init) is the idle state. */
typedef struct {
    uint8_t *buf;      /* malloc'd; NULL when idle */
    size_t   len;
    size_t   cap;
    uint16_t id;       /* transfer_id of the buffer being collected */
    int      state;    /* KBCLIP_RX_IDLE / _COLLECTING / _DISCARDING */
} kbclip_rx;

#define KBCLIP_RX_IDLE        0
#define KBCLIP_RX_COLLECTING  1
#define KBCLIP_RX_DISCARDING  2  /* over the limit: ignore chunks until the next "first" */

void kbclip_rx_init(kbclip_rx *rx);
/* Wipes and frees any partial transfer. */
void kbclip_rx_free(kbclip_rx *rx);

/* Feed one decrypted chunk plaintext (n bytes). Returns 1 when it completes a
 * valid clipboard-text transfer: *text then owns a malloc'd buffer of
 * *text_len (>= 1) bytes, which the caller releases with kbclip_free.
 * Otherwise returns 0 (chunk absorbed, or discarded per section 5a: unknown
 * kind, transfer_id mismatch, over 1 MiB, invalid UTF-8, malformed). */
int kbclip_rx_chunk(kbclip_rx *rx, const uint8_t *chunk, size_t n,
                    uint8_t **text, size_t *text_len);

/* Wipe len bytes at p, then free(p). NULL is fine. */
void kbclip_free(uint8_t *p, size_t len);

#endif
