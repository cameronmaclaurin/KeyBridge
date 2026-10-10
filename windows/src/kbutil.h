/*
 * KeyBridge - pure C helpers with no Windows dependencies (so they can be
 * unit-tested on any platform): constant-time compare, record nonces, P-256
 * point validation, address parsing, pairing display helpers.
 */
#ifndef KB_KBUTIL_H
#define KB_KBUTIL_H

#include <stddef.h>
#include <stdint.h>
#include <wchar.h>

#define KB_HOST_MAX        255  /* max characters accepted for the Mac address field */
#define KB_PORT_MAX        5    /* "65535" */
#define KB_NONCE_LEN       12
#define KB_NAME_MAX        64   /* display-name characters kept (64 UTF-8 bytes on the wire) */
#define KB_SAS_DISPLAY_LEN 7    /* "482 913" */

/* 1 if the n bytes at a and b are equal. Runs in time independent of the data. */
int kb_ct_equal(const void *a, const void *b, size_t n);

/* nonce = 0x00000000 || seq (uint64 big-endian). */
void kb_record_nonce(uint64_t seq, uint8_t nonce[KB_NONCE_LEN]);

/* 1 if pub is 0x04 || X || Y with X, Y < p and (X, Y) on NIST P-256. */
int kb_p256_point_valid(const uint8_t pub[65]);

/* Parse the Mac address field: "host", "host:port", "[v6addr]", "[v6addr]:port"
 * or a bare IPv6 address (two or more colons, no port). Leading/trailing
 * whitespace is ignored. On success writes host and port (default_port if none
 * was given) and returns 1. */
int kb_parse_address(const wchar_t *in,
                     wchar_t *host, size_t host_cap,
                     wchar_t *port, size_t port_cap,
                     const wchar_t *default_port);

/* Copy in to out without leading/trailing whitespace. Returns the length. */
size_t kb_trim_copy(const wchar_t *in, wchar_t *out, size_t out_cap);

/* sas = uint32_be(h[0..4]) mod 1000000, where h = SHA-256("KBPR sas" || TH). */
uint32_t kb_sas_from_hash(const uint8_t h[32]);

/* "482 913": six digits with leading zeros, a space after the third. */
void kb_format_sas(uint32_t sas, wchar_t out[KB_SAS_DISPLAY_LEN + 1]);

/* Length of the longest prefix of the UTF-8 string s (len bytes) that is at
 * most max bytes and does not split a character. */
size_t kb_utf8_prefix_len(const char *s, size_t len, size_t max);

/* Copy a peer-supplied display name (already decoded to UTF-16, in_len units,
 * stopping early at a NUL) without control or invisible formatting
 * characters, trimmed. Returns the output length. */
size_t kb_sanitize_name(const wchar_t *in, size_t in_len, wchar_t *out, size_t out_cap);

#endif
