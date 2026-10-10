/*
 * KeyBridge - update manifest helpers (docs/UPDATES.md). Pure C with no
 * Windows dependencies, so they can be unit-tested on any platform. The app
 * (update.c) and the selftest use exactly these functions.
 *
 * None of these check the signature: update.c verifies it first and only
 * then calls kb_upd_parse_manifest (spec section 2).
 */
#ifndef KB_UPDATE_MANIFEST_H
#define KB_UPDATE_MANIFEST_H

#include <stddef.h>
#include <stdint.h>

#define KB_UPD_META_MAX     16384      /* manifest and signature: "Reject responses larger than 16 KB" */
#define KB_UPD_VERSION_MAX  32         /* characters in "MAJOR.MINOR.PATCH" */
#define KB_UPD_URL_MAX      1024       /* characters in a URL */
#define KB_UPD_SHA256_HEX   64
#define KB_UPD_SIZE_MAX     200000000u
#define KB_UPD_SIG_LEN      64         /* raw r || s */
#define KB_UPD_PUBKEY_LEN   65         /* 0x04 || X || Y */

#define KB_UPD_HEADER       "keybridge-update-manifest 1"
/* Every download URL (mac-url, windows-url) must start with this. */
#define KB_UPD_URL_PREFIX   "https://github.com/cameronmaclaurin/KeyBridge/releases/download/"
/* notes-url points at the release page (".../releases/tag/vX.Y.Z"), so it
 * cannot carry the download prefix; it must stay inside the repo's releases. */
#define KB_UPD_NOTES_PREFIX "https://github.com/cameronmaclaurin/KeyBridge/releases/"

typedef struct {
    char     version[KB_UPD_VERSION_MAX + 1];
    char     notes_url[KB_UPD_URL_MAX + 1];
    char     mac_url[KB_UPD_URL_MAX + 1];
    char     mac_sha256[KB_UPD_SHA256_HEX + 1];
    uint32_t mac_size;
    char     windows_url[KB_UPD_URL_MAX + 1];
    char     windows_sha256[KB_UPD_SHA256_HEX + 1];
    uint32_t windows_size;
} kb_update_manifest;

/* Strict parse of the (already signature-checked) manifest bytes. Returns 1
 * and fills *m if valid; returns 0 and zeroes *m otherwise. */
int kb_upd_parse_manifest(const uint8_t *buf, size_t len, kb_update_manifest *m);

/* 1 if s[0..len) is MAJOR.MINOR.PATCH: decimal, no leading zeros except a
 * lone "0", at most KB_UPD_VERSION_MAX characters. */
int kb_upd_version_valid(const char *s, size_t len);

/* Numeric per-component comparison of two valid NUL-terminated versions:
 * <0 if a < b, 0 if equal, >0 if a > b. No component size limit. */
int kb_upd_version_compare(const char *a, const char *b);

/* Decode update-manifest.sig: exactly 88 base64 characters (64 bytes),
 * optionally followed by one "\n". Returns 1 on success. */
int kb_upd_decode_sig(const uint8_t *in, size_t len, uint8_t out[KB_UPD_SIG_LEN]);

/* Exactly 2*outlen hex characters (either case) -> bytes. Returns 1 on success. */
int kb_upd_hex_decode(const char *hex, size_t hexlen, uint8_t *out, size_t outlen);

/* Lowercase hex of n bytes into out (2n characters plus a NUL). */
void kb_upd_hex_encode(const uint8_t *in, size_t n, char *out);

#endif
