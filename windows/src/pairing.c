/*
 * KeyBridge - pairing initiator (see pairing.h and docs/PROTOCOL.md section 2).
 */
#include "pairing.h"
#include "crypto.h"

/* Labels (ASCII, no terminator on the wire). */
static const char kLabelCommit[]     = "KBPR commit";
static const char kLabelSas[]        = "KBPR sas";
static const char kLabelLtk[]        = "KBPR long-term key";
static const char kLabelPcConfirm[]  = "KBPR pc confirm";
static const char kLabelMacConfirm[] = "KBPR mac confirm";
#define LABEL(s) (s), ((ULONG)(sizeof(s) - 1))

#define KBPR_MAGIC_LEN 4
/* PairHello || PairCommit || pc_nonce || mac_nonce, the input to TH. */
#define KBPR_TH_INPUT_LEN (KBPR_HELLO_LEN + KBPR_COMMIT_LEN + 2 * KBPR_NONCE_LEN)

/* ------------------------------------------------------------------------ */
/* Display names (section 2.2)                                              */
/* ------------------------------------------------------------------------ */

void kb_pair_encode_name(const wchar_t *name, uint8_t out[KBPR_NAME_LEN])
{
    /* 64 UTF-16 units always cover at least 64 UTF-8 bytes (or the whole
     * string), and convert to at most 3 bytes each. */
    char buf[KB_NAME_MAX * 3 + 1];
    size_t n = 0, m;
    int len;

    memset(out, 0, KBPR_NAME_LEN);
    if (name == NULL)
        return;
    while (n < KB_NAME_MAX && name[n] != 0)
        n++;
    /* Never cut between the two halves of a surrogate pair. */
    if (n == KB_NAME_MAX && (unsigned)name[n - 1] >= 0xD800u && (unsigned)name[n - 1] <= 0xDBFFu)
        n--;
    if (n == 0)
        return;
    len = WideCharToMultiByte(CP_UTF8, 0, name, (int)n, buf, (int)sizeof(buf), NULL, NULL);
    if (len <= 0)
        return;
    m = kb_utf8_prefix_len(buf, (size_t)len, KBPR_NAME_LEN);
    memcpy(out, buf, m);
}

void kb_pc_name(uint8_t out[KBPR_NAME_LEN])
{
    wchar_t name[256];
    DWORD cch = (DWORD)ARRAYSIZE(name);

    if (GetComputerNameExW(ComputerNamePhysicalDnsHostname, name, &cch) && cch > 0) {
        name[ARRAYSIZE(name) - 1] = 0;
        kb_pair_encode_name(name, out);
        if (out[0] != 0)
            return;
    }
    kb_pair_encode_name(L"Windows PC", out);
}

void kb_pair_decode_name(const uint8_t name[KBPR_NAME_LEN], wchar_t out[KB_NAME_MAX + 1])
{
    /* Each byte becomes at most one UTF-16 unit (invalid bytes -> U+FFFD). */
    wchar_t wide[KBPR_NAME_LEN];
    size_t n = 0;
    int w;

    out[0] = 0;
    while (n < KBPR_NAME_LEN && name[n] != 0)
        n++;
    if (n == 0)
        return;
    /* Flags 0 (no MB_ERR_INVALID_CHARS): lenient decoding. */
    w = MultiByteToWideChar(CP_UTF8, 0, (const char *)name, (int)n, wide, (int)ARRAYSIZE(wide));
    if (w <= 0)
        return;
    (void)kb_sanitize_name(wide, (size_t)w, out, KB_NAME_MAX + 1);
    SecureZeroMemory(wide, sizeof(wide));
}

/* ------------------------------------------------------------------------ */
/* Initiator (sections 2.2 - 2.4)                                           */
/* ------------------------------------------------------------------------ */

kbp2_status kb_pair_run(const kb_pair_params *p, uint8_t ltk[KBPR_LTK_LEN],
                        wchar_t mac_name[KB_NAME_MAX + 1])
{
    uint8_t th_input[KBPR_TH_INPUT_LEN];
    uint8_t *const hello      = th_input;                       /* PairHello  (133) */
    uint8_t *const commit_msg = hello + KBPR_HELLO_LEN;         /* PairCommit (165) */
    uint8_t *const pc_nonce   = commit_msg + KBPR_COMMIT_LEN;   /* PcNonce    (32)  */
    uint8_t *const mac_nonce  = pc_nonce + KBPR_NONCE_LEN;      /* MacNonce   (32)  */
    const uint8_t *const pc_pub       = hello + KBPR_MAGIC_LEN;
    const uint8_t *const mac_pub      = commit_msg + KBPR_MAGIC_LEN;
    const uint8_t *const mac_name_raw = mac_pub + KB_P256_PUB_LEN;
    const uint8_t *const commit_rx    = mac_name_raw + KBPR_NAME_LEN;
    uint8_t commit[KB_SHA256_LEN];
    uint8_t th[KB_SHA256_LEN];
    uint8_t sas_hash[KB_SHA256_LEN];
    uint8_t ecdh[KB_ECDH_LEN];
    uint8_t prk[KB_SHA256_LEN];
    uint8_t key[KB_SHA256_LEN];
    uint8_t ltk_tmp[KBPR_LTK_LEN];
    uint8_t pc_confirm[KBPR_CONFIRM_LEN];
    uint8_t mac_confirm[KBPR_CONFIRM_LEN];
    uint8_t mac_confirm_rx[KBPR_CONFIRM_LEN];
    uint8_t extra = 0;
    BCRYPT_KEY_HANDLE priv = NULL;
    kbp2_conn conn;
    kbp2_status st;
    ULONGLONG deadline = 0, confirm_deadline = 0;
    BOOL sent_pc = FALSE, have_mac = FALSE;
    size_t got = 0;

    SecureZeroMemory(ltk, KBPR_LTK_LEN);
    mac_name[0] = 0;
    kbp2_conn_init(&conn, p->stop);

    /* Fresh key pair and nonce for this attempt (2.2). */
    memcpy(hello, KBPR_MAGIC, KBPR_MAGIC_LEN);
    if (!kb_ecdh_generate(&priv, hello + KBPR_MAGIC_LEN) || !kb_random(pc_nonce, KBPR_NONCE_LEN)) {
        st = KBP2_ERR_CRYPTO;
        goto done;
    }
    memcpy(hello + KBPR_MAGIC_LEN + KB_P256_PUB_LEN, p->pc_name, KBPR_NAME_LEN);

    st = kbp2_connect(&conn, p->host, p->port, KBPR_CONNECT_MS);
    if (st != KBP2_OK)
        goto done;
    /* PairHello through MacNonce: 10 s from connecting. */
    deadline = GetTickCount64() + KBPR_EXCHANGE_MS;

    /* PairHello (133) -> */
    st = kbp2_write_all(&conn, hello, KBPR_HELLO_LEN, deadline);
    if (st != KBP2_OK)
        goto done;

    /* <- PairCommit (165): magic, valid point. */
    st = kbp2_read_exact(&conn, commit_msg, KBPR_COMMIT_LEN, deadline);
    if (st != KBP2_OK)
        goto done;
    if (memcmp(commit_msg, KBPR_MAGIC, KBPR_MAGIC_LEN) != 0 || !kb_p256_point_valid(mac_pub)) {
        st = KBP2_ERR_PROTOCOL;
        goto done;
    }
    kb_pair_decode_name(mac_name_raw, mac_name);
    if (!kb_ecdh_derive(priv, mac_pub, ecdh)) {
        st = KBP2_ERR_PROTOCOL;
        goto done;
    }
    kb_key_destroy(&priv); /* used exactly once */

    /* PcNonce (32) -> only now that the whole PairCommit has been received
     * and parsed: revealing pc_nonce earlier would let a man-in-the-middle
     * search for matching numbers (2.2). Then <- MacNonce (32). */
    st = kbp2_write_all(&conn, pc_nonce, KBPR_NONCE_LEN, deadline);
    if (st != KBP2_OK)
        goto done;
    st = kbp2_read_exact(&conn, mac_nonce, KBPR_NONCE_LEN, deadline);
    if (st != KBP2_OK)
        goto done;
    /* The 120 s confirmation phase counts from receiving MacNonce (2.4). */
    confirm_deadline = GetTickCount64() + KBPR_CONFIRM_MS;

    /* commit = HMAC-SHA256(key = mac_nonce, "KBPR commit" || mac_pub || pc_pub),
     * compared in constant time. */
    if (!kb_hmac_sha256(mac_nonce, KBPR_NONCE_LEN, LABEL(kLabelCommit),
                        mac_pub, KB_P256_PUB_LEN, pc_pub, KB_P256_PUB_LEN, commit)) {
        st = KBP2_ERR_CRYPTO;
        goto done;
    }
    if (!kb_ct_equal(commit, commit_rx, KB_SHA256_LEN)) {
        st = KBP2_ERR_AUTH;
        goto done;
    }

    /* Derivations (2.3):
     *   TH          = SHA-256(PairHello || PairCommit || pc_nonce || mac_nonce)
     *   sas         = uint32_be(SHA-256("KBPR sas" || TH)[0..4]) mod 1000000
     *   prk         = Extract(salt = TH, ikm = ecdh) = HMAC(key = TH, ecdh)
     *   ltk         = Expand(prk, "KBPR long-term key")
     *   pc_confirm  = HMAC(key = Expand(prk, "KBPR pc confirm"),  TH)
     *   mac_confirm = HMAC(key = Expand(prk, "KBPR mac confirm"), TH) */
    if (!kb_sha256(th_input, (ULONG)sizeof(th_input), NULL, 0, th) ||
        !kb_sha256(LABEL(kLabelSas), th, KB_SHA256_LEN, sas_hash) ||
        !kb_hmac_sha256(th, KB_SHA256_LEN, ecdh, KB_ECDH_LEN, NULL, 0, NULL, 0, prk) ||
        !kbp2_expand(prk, LABEL(kLabelLtk), NULL, 0, ltk_tmp) ||
        !kbp2_expand(prk, LABEL(kLabelPcConfirm), NULL, 0, key) ||
        !kb_hmac_sha256(key, KB_SHA256_LEN, th, KB_SHA256_LEN, NULL, 0, NULL, 0, pc_confirm) ||
        !kbp2_expand(prk, LABEL(kLabelMacConfirm), NULL, 0, key) ||
        !kb_hmac_sha256(key, KB_SHA256_LEN, th, KB_SHA256_LEN, NULL, 0, NULL, 0, mac_confirm)) {
        st = KBP2_ERR_CRYPTO;
        goto done;
    }

    if (p->on_sas != NULL)
        p->on_sas(p->ctx, kb_sas_from_hash(sas_hash), mac_name);

    /* Confirmation phase (120 s). PcConfirm goes out when the local user
     * confirms; MacConfirm may arrive before or after that. Success needs
     * both: our own Confirm and a verified MacConfirm (2.4). */
    deadline = confirm_deadline;
    for (;;) {
        if (!sent_pc && p->confirm != NULL && WaitForSingleObject(p->confirm, 0) == WAIT_OBJECT_0) {
            st = kbp2_write_all(&conn, pc_confirm, KBPR_CONFIRM_LEN, deadline);
            if (st != KBP2_OK)
                goto done;
            sent_pc = TRUE;
        }
        if (sent_pc && have_mac)
            break;

        if (!have_mac) {
            /* Wait for MacConfirm; until we have confirmed, the confirm event
             * also wakes us (partial input is kept in got). */
            st = kbp2_read_exact_ex(&conn, mac_confirm_rx, KBPR_CONFIRM_LEN, &got, deadline,
                                    sent_pc ? NULL : p->confirm);
            if (st == KBP2_WOKEN)
                continue;
            if (st != KBP2_OK)
                goto done;
            if (!kb_ct_equal(mac_confirm_rx, mac_confirm, KBPR_CONFIRM_LEN)) {
                st = KBP2_ERR_AUTH;
                goto done;
            }
            have_mac = TRUE;
        } else {
            /* Verified MacConfirm in hand; waiting only for our own user. The
             * Mac sends nothing more: EOF means it gave up, data is a
             * protocol error. */
            size_t one = 0;
            st = kbp2_read_exact_ex(&conn, &extra, 1, &one, deadline, p->confirm);
            if (st == KBP2_WOKEN)
                continue;
            if (st == KBP2_OK)
                st = KBP2_ERR_PROTOCOL;
            goto done;
        }
    }

    memcpy(ltk, ltk_tmp, KBPR_LTK_LEN);
    st = KBP2_OK;

done:
    kb_key_destroy(&priv);
    /* Graceful close (section 5) in every case, even after a cancel, so the
     * peer sees a FIN rather than an RST. Bounded by KBP2_DRAIN_MS. */
    conn.stop = NULL;
    kbp2_conn_close(&conn);

    SecureZeroMemory(th_input, sizeof(th_input));
    SecureZeroMemory(commit, sizeof(commit));
    SecureZeroMemory(th, sizeof(th));
    SecureZeroMemory(sas_hash, sizeof(sas_hash));
    SecureZeroMemory(ecdh, sizeof(ecdh));
    SecureZeroMemory(prk, sizeof(prk));
    SecureZeroMemory(key, sizeof(key));
    SecureZeroMemory(ltk_tmp, sizeof(ltk_tmp));
    SecureZeroMemory(pc_confirm, sizeof(pc_confirm));
    SecureZeroMemory(mac_confirm, sizeof(mac_confirm));
    SecureZeroMemory(mac_confirm_rx, sizeof(mac_confirm_rx));
    if (st != KBP2_OK)
        SecureZeroMemory(ltk, KBPR_LTK_LEN);
    return st;
}
