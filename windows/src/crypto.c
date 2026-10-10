/*
 * KeyBridge - CNG wrappers (see crypto.h).
 */
#include "crypto.h"
#include "kbutil.h"

/* Older/third-party SDK headers may lack these. Values are from the Windows SDK. */
#ifndef BCRYPT_KDF_RAW_SECRET
#define BCRYPT_KDF_RAW_SECRET L"TRUNCATE"
#endif
#ifndef BCRYPT_ECDH_PUBLIC_P256_MAGIC
#define BCRYPT_ECDH_PUBLIC_P256_MAGIC 0x314B4345 /* "ECK1" */
#endif
#ifndef BCRYPT_USE_SYSTEM_PREFERRED_RNG
#define BCRYPT_USE_SYSTEM_PREFERRED_RNG 0x00000002
#endif
#ifndef BCRYPT_SUCCESS
#define BCRYPT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

/* Algorithm handles are opened once and shared; CNG algorithm handles may be
 * used from several threads at once. */
static BCRYPT_ALG_HANDLE g_alg_sha256;
static BCRYPT_ALG_HANDLE g_alg_hmac;
static BCRYPT_ALG_HANDLE g_alg_ecdh;
static BCRYPT_ALG_HANDLE g_alg_aes_gcm;

static void close_alg(BCRYPT_ALG_HANDLE *h)
{
    if (*h != NULL) {
        BCryptCloseAlgorithmProvider(*h, 0);
        *h = NULL;
    }
}

void kb_crypto_cleanup(void)
{
    close_alg(&g_alg_sha256);
    close_alg(&g_alg_hmac);
    close_alg(&g_alg_ecdh);
    close_alg(&g_alg_aes_gcm);
}

BOOL kb_crypto_init(void)
{
    if (g_alg_sha256 != NULL && g_alg_hmac != NULL && g_alg_ecdh != NULL && g_alg_aes_gcm != NULL)
        return TRUE;
    kb_crypto_cleanup();

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&g_alg_sha256, BCRYPT_SHA256_ALGORITHM, NULL, 0)))
        goto fail;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&g_alg_hmac, BCRYPT_SHA256_ALGORITHM, NULL,
                                                    BCRYPT_ALG_HANDLE_HMAC_FLAG)))
        goto fail;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&g_alg_ecdh, BCRYPT_ECDH_P256_ALGORITHM, NULL, 0)))
        goto fail;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&g_alg_aes_gcm, BCRYPT_AES_ALGORITHM, NULL, 0)))
        goto fail;
    if (!BCRYPT_SUCCESS(BCryptSetProperty(g_alg_aes_gcm, BCRYPT_CHAINING_MODE,
                                          (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                                          (ULONG)sizeof(BCRYPT_CHAIN_MODE_GCM), 0)))
        goto fail;
    return TRUE;

fail:
    kb_crypto_cleanup();
    return FALSE;
}

BOOL kb_random(void *buf, ULONG len)
{
    return BCRYPT_SUCCESS(BCryptGenRandom(NULL, (PUCHAR)buf, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG));
}

static BOOL hash_part(BCRYPT_HASH_HANDLE h, const void *p, ULONG n)
{
    if (n == 0)
        return TRUE;
    return BCRYPT_SUCCESS(BCryptHashData(h, (PUCHAR)p, n, 0));
}

BOOL kb_sha256(const void *a, ULONG alen, const void *b, ULONG blen, uint8_t out[KB_SHA256_LEN])
{
    BCRYPT_HASH_HANDLE h = NULL;
    BOOL ok = FALSE;

    if (!BCRYPT_SUCCESS(BCryptCreateHash(g_alg_sha256, &h, NULL, 0, NULL, 0, 0)))
        return FALSE;
    if (hash_part(h, a, alen) && hash_part(h, b, blen) &&
        BCRYPT_SUCCESS(BCryptFinishHash(h, out, KB_SHA256_LEN, 0)))
        ok = TRUE;
    BCryptDestroyHash(h);
    return ok;
}

BOOL kb_hmac_sha256(const void *key, ULONG keylen,
                    const void *a, ULONG alen,
                    const void *b, ULONG blen,
                    const void *c, ULONG clen,
                    uint8_t out[KB_SHA256_LEN])
{
    BCRYPT_HASH_HANDLE h = NULL;
    BOOL ok = FALSE;

    if (!BCRYPT_SUCCESS(BCryptCreateHash(g_alg_hmac, &h, NULL, 0, (PUCHAR)key, keylen, 0)))
        return FALSE;
    if (hash_part(h, a, alen) && hash_part(h, b, blen) && hash_part(h, c, clen) &&
        BCRYPT_SUCCESS(BCryptFinishHash(h, out, KB_SHA256_LEN, 0)))
        ok = TRUE;
    BCryptDestroyHash(h);
    return ok;
}

BOOL kb_ecdh_generate(BCRYPT_KEY_HANDLE *priv, uint8_t pub[KB_P256_PUB_LEN])
{
    BCRYPT_KEY_HANDLE key = NULL;
    BCRYPT_ECCKEY_BLOB hdr;
    uint8_t blob[sizeof(BCRYPT_ECCKEY_BLOB) + 2 * 32];
    ULONG cb = 0;

    *priv = NULL;
    if (!BCRYPT_SUCCESS(BCryptGenerateKeyPair(g_alg_ecdh, &key, 256, 0)))
        return FALSE;
    if (!BCRYPT_SUCCESS(BCryptFinalizeKeyPair(key, 0)))
        goto fail;

    /* BCRYPT_ECCPUBLIC_BLOB = BCRYPT_ECCKEY_BLOB header || X || Y (big-endian). */
    if (!BCRYPT_SUCCESS(BCryptExportKey(key, NULL, BCRYPT_ECCPUBLIC_BLOB, blob,
                                        (ULONG)sizeof(blob), &cb, 0)))
        goto fail;
    memcpy(&hdr, blob, sizeof(hdr));
    if (cb != sizeof(blob) || hdr.cbKey != 32)
        goto fail;

    pub[0] = 0x04;
    memcpy(pub + 1, blob + sizeof(hdr), 2 * 32);
    if (!kb_p256_point_valid(pub)) /* self-check of the encoding */
        goto fail;
    *priv = key;
    return TRUE;

fail:
    BCryptDestroyKey(key);
    SecureZeroMemory(pub, KB_P256_PUB_LEN);
    return FALSE;
}

BOOL kb_ecdh_derive(BCRYPT_KEY_HANDLE priv, const uint8_t peer_pub[KB_P256_PUB_LEN],
                    uint8_t ecdh[KB_ECDH_LEN])
{
    BCRYPT_ECCKEY_BLOB hdr;
    uint8_t blob[sizeof(BCRYPT_ECCKEY_BLOB) + 2 * 32];
    uint8_t raw[KB_ECDH_LEN];
    BCRYPT_KEY_HANDLE peer = NULL;
    BCRYPT_SECRET_HANDLE secret = NULL;
    ULONG cb = 0;
    BOOL ok = FALSE;
    int i;

    SecureZeroMemory(ecdh, KB_ECDH_LEN);
    if (priv == NULL)
        return FALSE;

    /* Prefix 0x04, coordinates < p, point on the curve. CNG validates on
     * import too; this check does not depend on that. */
    if (!kb_p256_point_valid(peer_pub))
        return FALSE;

    hdr.dwMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
    hdr.cbKey = 32;
    memcpy(blob, &hdr, sizeof(hdr));
    memcpy(blob + sizeof(hdr), peer_pub + 1, 2 * 32);

    if (!BCRYPT_SUCCESS(BCryptImportKeyPair(g_alg_ecdh, NULL, BCRYPT_ECCPUBLIC_BLOB, &peer,
                                            blob, (ULONG)sizeof(blob), 0)))
        goto done;
    if (!BCRYPT_SUCCESS(BCryptSecretAgreement(priv, peer, &secret, 0)))
        goto done;
    if (!BCRYPT_SUCCESS(BCryptDeriveKey(secret, BCRYPT_KDF_RAW_SECRET, NULL, raw,
                                        (ULONG)sizeof(raw), &cb, 0)))
        goto done;
    if (cb != KB_ECDH_LEN)
        goto done;

    /* BCRYPT_KDF_RAW_SECRET returns the shared X coordinate LITTLE-endian.
     * KBP2 uses the big-endian X coordinate (like every other ECDH API). */
    for (i = 0; i < KB_ECDH_LEN; i++)
        ecdh[i] = raw[KB_ECDH_LEN - 1 - i];
    ok = TRUE;

done:
    SecureZeroMemory(raw, sizeof(raw));
    if (secret != NULL)
        BCryptDestroySecret(secret);
    if (peer != NULL)
        BCryptDestroyKey(peer);
    if (!ok)
        SecureZeroMemory(ecdh, KB_ECDH_LEN);
    return ok;
}

BOOL kb_gcm_key(BCRYPT_KEY_HANDLE *key, const uint8_t raw[KB_AES_KEY_LEN])
{
    *key = NULL;
    return BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(g_alg_aes_gcm, key, NULL, 0,
                                                     (PUCHAR)raw, KB_AES_KEY_LEN, 0));
}

BOOL kb_gcm_seal(BCRYPT_KEY_HANDLE key, const uint8_t nonce[12],
                 const uint8_t *pt, ULONG len, uint8_t *ct, uint8_t tag[KB_GCM_TAG_LEN])
{
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    uint8_t n[12];
    ULONG cb = 0;

    memcpy(n, nonce, sizeof(n));
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = n;
    info.cbNonce = (ULONG)sizeof(n);
    info.pbAuthData = NULL; /* empty AAD */
    info.cbAuthData = 0;
    info.pbTag = tag;
    info.cbTag = KB_GCM_TAG_LEN;

    if (!BCRYPT_SUCCESS(BCryptEncrypt(key, (PUCHAR)pt, len, &info, NULL, 0, ct, len, &cb, 0)))
        return FALSE;
    return cb == len;
}

BOOL kb_gcm_open(BCRYPT_KEY_HANDLE key, const uint8_t nonce[12],
                 const uint8_t *ct, ULONG len, const uint8_t tag[KB_GCM_TAG_LEN], uint8_t *pt)
{
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    uint8_t n[12];
    uint8_t t[KB_GCM_TAG_LEN];
    ULONG cb = 0;
    NTSTATUS st;

    memcpy(n, nonce, sizeof(n));
    memcpy(t, tag, sizeof(t));
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = n;
    info.cbNonce = (ULONG)sizeof(n);
    info.pbAuthData = NULL;
    info.cbAuthData = 0;
    info.pbTag = t;
    info.cbTag = KB_GCM_TAG_LEN;

    /* Fails with STATUS_AUTH_TAG_MISMATCH if the record was tampered with,
     * replayed, reordered, or sealed with another key. */
    st = BCryptDecrypt(key, (PUCHAR)ct, len, &info, NULL, 0, pt, len, &cb, 0);
    if (!BCRYPT_SUCCESS(st) || cb != len) {
        SecureZeroMemory(pt, len);
        return FALSE;
    }
    return TRUE;
}

void kb_key_destroy(BCRYPT_KEY_HANDLE *key)
{
    if (*key != NULL) {
        BCryptDestroyKey(*key);
        *key = NULL;
    }
}
