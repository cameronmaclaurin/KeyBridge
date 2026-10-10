/*
 * KeyBridge - pure C helpers with no Windows dependencies (so they can be
 * unit-tested on any platform): pairing-code normalization, constant-time
 * compare, record nonces, P-256 point validation, address parsing.
 */
#ifndef KB_KBUTIL_H
#define KB_KBUTIL_H

#include <stddef.h>
#include <stdint.h>
#include <wchar.h>

#define KB_CODE_LEN        20   /* normalized pairing code length (docs/PROTOCOL.md section 2) */
#define KB_CODE_DISPLAY_LEN 23  /* "ABCDE-FGHJK-MNPQR-STVWX" */
#define KB_HOST_MAX        255  /* max characters accepted for the Mac address field */
#define KB_PORT_MAX        5    /* "65535" */
#define KB_NONCE_LEN       12

/* Normalize user input per spec section 2. On success writes 20 symbols plus a
 * NUL terminator to out and returns 1; returns 0 (and wipes out) if invalid. */
int kb_normalize_code(const wchar_t *in, char out[KB_CODE_LEN + 1]);

/* "ABCDE-FGHJK-MNPQR-STVWX" form of a normalized code. */
void kb_format_code(const char code[KB_CODE_LEN], wchar_t out[KB_CODE_DISPLAY_LEN + 1]);

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

#endif
