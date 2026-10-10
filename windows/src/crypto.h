/*
 * KeyBridge - thin wrappers over Windows CNG (bcrypt.dll) for the KBP2
 * primitives: SHA-256, HMAC-SHA256, P-256 ECDH, AES-256-GCM, system RNG.
 * All functions return TRUE on success. Secrets passed in are not retained.
 */
#ifndef KB_CRYPTO_H
#define KB_CRYPTO_H

#include "common.h"

#define KB_SHA256_LEN   32
#define KB_P256_PUB_LEN 65   /* 0x04 || X(32) || Y(32) */
#define KB_ECDH_LEN     32   /* big-endian X coordinate of the shared point */
#define KB_AES_KEY_LEN  32
#define KB_GCM_TAG_LEN  16

/* Open the algorithm providers once per process. Safe to call more than once. */
BOOL kb_crypto_init(void);
void kb_crypto_cleanup(void);

/* Fill buf from the OS CSPRNG. */
BOOL kb_random(void *buf, ULONG len);

/* SHA-256(a || b). Either part may be empty. */
BOOL kb_sha256(const void *a, ULONG alen, const void *b, ULONG blen,
               uint8_t out[KB_SHA256_LEN]);

/* HMAC-SHA256(key, a || b || c). Any part may be empty. */
BOOL kb_hmac_sha256(const void *key, ULONG keylen,
                    const void *a, ULONG alen,
                    const void *b, ULONG blen,
                    const void *c, ULONG clen,
                    uint8_t out[KB_SHA256_LEN]);

/* Fresh ephemeral P-256 key pair. *priv must later go to kb_key_destroy. */
BOOL kb_ecdh_generate(BCRYPT_KEY_HANDLE *priv, uint8_t pub[KB_P256_PUB_LEN]);

/* ecdh = big-endian X coordinate of priv * peer_pub. Rejects anything that is
 * not a valid uncompressed P-256 point. */
BOOL kb_ecdh_derive(BCRYPT_KEY_HANDLE priv, const uint8_t peer_pub[KB_P256_PUB_LEN],
                    uint8_t ecdh[KB_ECDH_LEN]);

/* AES-256-GCM key object from 32 raw bytes. */
BOOL kb_gcm_key(BCRYPT_KEY_HANDLE *key, const uint8_t raw[KB_AES_KEY_LEN]);

/* AES-256-GCM, 12-byte nonce, empty AAD, 16-byte tag. len may be small (4). */
BOOL kb_gcm_seal(BCRYPT_KEY_HANDLE key, const uint8_t nonce[12],
                 const uint8_t *pt, ULONG len, uint8_t *ct, uint8_t tag[KB_GCM_TAG_LEN]);
/* Returns FALSE if the tag does not verify; pt is zeroed in that case. */
BOOL kb_gcm_open(BCRYPT_KEY_HANDLE key, const uint8_t nonce[12],
                 const uint8_t *ct, ULONG len, const uint8_t tag[KB_GCM_TAG_LEN], uint8_t *pt);

void kb_key_destroy(BCRYPT_KEY_HANDLE *key);

#endif
