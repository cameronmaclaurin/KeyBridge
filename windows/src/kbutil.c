/*
 * KeyBridge - pure C helpers (no Windows headers; see kbutil.h).
 */
#include "kbutil.h"

#include <string.h>

/* ------------------------------------------------------------------------ */
/* Pairing code (docs/PROTOCOL.md section 2)                                */
/* ------------------------------------------------------------------------ */

static const char kb_alphabet[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

static int kb_in_alphabet(wchar_t c)
{
    size_t i;
    for (i = 0; i < sizeof(kb_alphabet) - 1; i++) {
        if ((wchar_t)(unsigned char)kb_alphabet[i] == c)
            return 1;
    }
    return 0;
}

/* The characters Python's str.isspace() accepts (the reference implementation
 * uses it), so both sides agree on what "all whitespace" means. */
static int kb_is_space(wchar_t c)
{
    unsigned long u = (unsigned long)c;
    if (u == 0x20 || (u >= 0x09 && u <= 0x0D) || (u >= 0x1C && u <= 0x1F))
        return 1;
    if (u == 0x85 || u == 0xA0 || u == 0x1680)
        return 1;
    if (u >= 0x2000 && u <= 0x200A)
        return 1;
    if (u == 0x2028 || u == 0x2029 || u == 0x202F || u == 0x205F || u == 0x3000)
        return 1;
    return 0;
}

static void kb_wipe(void *p, size_t n)
{
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--)
        *v++ = 0;
}

int kb_normalize_code(const wchar_t *in, char out[KB_CODE_LEN + 1])
{
    size_t n = 0;

    if (in == NULL)
        goto invalid;

    for (; *in != 0; in++) {
        wchar_t c = *in;

        /* 2. Remove '-' and all whitespace. */
        if (c == L'-' || kb_is_space(c))
            continue;

        /* 1. Uppercase. Only ASCII letters can end up valid; U+0131 and
         *    U+017F are the two non-ASCII letters whose uppercase is ASCII. */
        if (c >= L'a' && c <= L'z')
            c = (wchar_t)(c - (L'a' - L'A'));
        else if ((unsigned long)c == 0x0131)
            c = L'I';
        else if ((unsigned long)c == 0x017F)
            c = L'S';

        /* 3. O -> 0, I -> 1, L -> 1. */
        if (c == L'O')
            c = L'0';
        else if (c == L'I' || c == L'L')
            c = L'1';

        /* 4. Exactly 20 symbols from the alphabet. */
        if (!kb_in_alphabet(c) || n >= KB_CODE_LEN)
            goto invalid;
        out[n++] = (char)c;
    }

    if (n != KB_CODE_LEN)
        goto invalid;
    out[KB_CODE_LEN] = 0;
    return 1;

invalid:
    kb_wipe(out, KB_CODE_LEN + 1);
    return 0;
}

void kb_format_code(const char code[KB_CODE_LEN], wchar_t out[KB_CODE_DISPLAY_LEN + 1])
{
    size_t i, o = 0;
    for (i = 0; i < KB_CODE_LEN; i++) {
        if (i != 0 && i % 5 == 0)
            out[o++] = L'-';
        out[o++] = (wchar_t)(unsigned char)code[i];
    }
    out[o] = 0;
}

/* ------------------------------------------------------------------------ */
/* Constant-time compare, record nonce                                      */
/* ------------------------------------------------------------------------ */

int kb_ct_equal(const void *a, const void *b, size_t n)
{
    const volatile unsigned char *x = (const volatile unsigned char *)a;
    const volatile unsigned char *y = (const volatile unsigned char *)b;
    volatile unsigned char acc = 0;
    size_t i;

    for (i = 0; i < n; i++)
        acc = (unsigned char)(acc | (unsigned char)(x[i] ^ y[i]));
    return acc == 0;
}

void kb_record_nonce(uint64_t seq, uint8_t nonce[KB_NONCE_LEN])
{
    int i;
    nonce[0] = nonce[1] = nonce[2] = nonce[3] = 0;
    for (i = 0; i < 8; i++)
        nonce[4 + i] = (uint8_t)(seq >> (56 - 8 * i));
}

/* ------------------------------------------------------------------------ */
/* P-256 point validation: y^2 == x^3 - 3x + b (mod p), x < p, y < p.       */
/* Public data only, so plain (non-constant-time) arithmetic is fine. The   */
/* modular multiply is double-and-add: slow-ish but tiny and obviously      */
/* correct, and it runs once per handshake.                                 */
/* ------------------------------------------------------------------------ */

typedef struct {
    uint32_t v[8]; /* little-endian 32-bit limbs */
} kb_u256;

static const kb_u256 kb_p256_p = { {
    0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000001u, 0xFFFFFFFFu
} };

static const kb_u256 kb_p256_b = { {
    0x27D2604Bu, 0x3BCE3C3Eu, 0xCC53B0F6u, 0x651D06B0u,
    0x769886BCu, 0xB3EBBD55u, 0xAA3A93E7u, 0x5AC635D8u
} };

static void u256_load_be(kb_u256 *r, const uint8_t *b)
{
    int i;
    for (i = 0; i < 8; i++) {
        const uint8_t *q = b + (7 - i) * 4;
        r->v[i] = ((uint32_t)q[0] << 24) | ((uint32_t)q[1] << 16) |
                  ((uint32_t)q[2] << 8) | (uint32_t)q[3];
    }
}

static int u256_cmp(const kb_u256 *a, const kb_u256 *b)
{
    int i;
    for (i = 7; i >= 0; i--) {
        if (a->v[i] > b->v[i])
            return 1;
        if (a->v[i] < b->v[i])
            return -1;
    }
    return 0;
}

static uint32_t u256_add(kb_u256 *r, const kb_u256 *a, const kb_u256 *b)
{
    uint64_t c = 0;
    int i;
    for (i = 0; i < 8; i++) {
        c += (uint64_t)a->v[i] + (uint64_t)b->v[i];
        r->v[i] = (uint32_t)c;
        c >>= 32;
    }
    return (uint32_t)c;
}

static uint32_t u256_sub(kb_u256 *r, const kb_u256 *a, const kb_u256 *b)
{
    uint64_t borrow = 0;
    int i;
    for (i = 0; i < 8; i++) {
        uint64_t d = (uint64_t)a->v[i] - (uint64_t)b->v[i] - borrow;
        r->v[i] = (uint32_t)d;
        borrow = d >> 63;
    }
    return (uint32_t)borrow;
}

/* r = a + b mod p, for a, b < p. */
static void u256_addmod(kb_u256 *r, const kb_u256 *a, const kb_u256 *b)
{
    kb_u256 t;
    uint32_t carry = u256_add(&t, a, b);
    if (carry != 0 || u256_cmp(&t, &kb_p256_p) >= 0)
        (void)u256_sub(&t, &t, &kb_p256_p);
    *r = t;
}

/* r = a - b mod p, for a, b < p. */
static void u256_submod(kb_u256 *r, const kb_u256 *a, const kb_u256 *b)
{
    kb_u256 t;
    if (u256_sub(&t, a, b) != 0)
        (void)u256_add(&t, &t, &kb_p256_p);
    *r = t;
}

/* r = a * b mod p, for a, b < p. */
static void u256_mulmod(kb_u256 *r, const kb_u256 *a, const kb_u256 *b)
{
    kb_u256 acc;
    int bit;
    memset(&acc, 0, sizeof(acc));
    for (bit = 255; bit >= 0; bit--) {
        u256_addmod(&acc, &acc, &acc);
        if ((b->v[bit / 32] >> (bit % 32)) & 1u)
            u256_addmod(&acc, &acc, a);
    }
    *r = acc;
}

int kb_p256_point_valid(const uint8_t pub[65])
{
    static const kb_u256 three = { { 3u, 0, 0, 0, 0, 0, 0, 0 } };
    kb_u256 x, y, lhs, rhs, t;

    if (pub[0] != 0x04)
        return 0;
    u256_load_be(&x, pub + 1);
    u256_load_be(&y, pub + 33);
    if (u256_cmp(&x, &kb_p256_p) >= 0 || u256_cmp(&y, &kb_p256_p) >= 0)
        return 0;

    u256_mulmod(&lhs, &y, &y);         /* y^2          */
    u256_mulmod(&t, &x, &x);           /* x^2          */
    u256_submod(&t, &t, &three);       /* x^2 - 3      */
    u256_mulmod(&t, &t, &x);           /* x^3 - 3x     */
    u256_addmod(&rhs, &t, &kb_p256_b); /* x^3 - 3x + b */
    return u256_cmp(&lhs, &rhs) == 0;
}

/* ------------------------------------------------------------------------ */
/* Address parsing                                                          */
/* ------------------------------------------------------------------------ */

static int kb_is_trim_space(wchar_t c)
{
    return kb_is_space(c) || (unsigned long)c == 0x200B || (unsigned long)c == 0xFEFF;
}

size_t kb_trim_copy(const wchar_t *in, wchar_t *out, size_t out_cap)
{
    size_t start = 0, end, len;

    if (out_cap == 0)
        return (size_t)-1;
    out[0] = 0;
    if (in == NULL)
        return 0;
    end = wcslen(in);
    while (start < end && kb_is_trim_space(in[start]))
        start++;
    while (end > start && kb_is_trim_space(in[end - 1]))
        end--;
    len = end - start;
    if (len >= out_cap)
        return (size_t)-1;
    memcpy(out, in + start, len * sizeof(wchar_t));
    out[len] = 0;
    return len;
}

int kb_parse_address(const wchar_t *in,
                     wchar_t *host, size_t host_cap,
                     wchar_t *port, size_t port_cap,
                     const wchar_t *default_port)
{
    wchar_t buf[KB_HOST_MAX + 1 + 2 + 1 + KB_PORT_MAX + 1]; /* [host]:port */
    const wchar_t *h = buf;
    const wchar_t *p = NULL;
    size_t len, hlen, plen, i;

    if (host_cap == 0 || port_cap == 0)
        return 0;
    host[0] = 0;
    port[0] = 0;

    len = kb_trim_copy(in, buf, sizeof(buf) / sizeof(buf[0]));
    if (len == 0 || len == (size_t)-1)
        return 0;

    if (buf[0] == L'[') {
        const wchar_t *close = wcschr(buf, L']');
        if (close == NULL)
            return 0;
        h = buf + 1;
        hlen = (size_t)(close - h);
        if (close[1] == L':')
            p = close + 2;
        else if (close[1] != 0)
            return 0;
    } else {
        const wchar_t *colon = wcschr(buf, L':');
        if (colon != NULL && wcschr(colon + 1, L':') == NULL) {
            hlen = (size_t)(colon - buf); /* host:port */
            p = colon + 1;
        } else {
            hlen = len;                   /* hostname, IPv4, or bare IPv6 */
        }
    }

    if (hlen == 0 || hlen > KB_HOST_MAX || hlen >= host_cap)
        return 0;
    for (i = 0; i < hlen; i++) {
        unsigned long c = (unsigned long)h[i];
        if (c <= 0x20 || c == 0x7F || c == L'/' || c == L'\\' || c == L'[' || c == L']')
            return 0;
    }

    if (p != NULL) {
        unsigned long value = 0;
        plen = wcslen(p);
        if (plen == 0 || plen > KB_PORT_MAX)
            return 0;
        for (i = 0; i < plen; i++) {
            if (p[i] < L'0' || p[i] > L'9')
                return 0;
            value = value * 10 + (unsigned long)(p[i] - L'0');
        }
        if (value == 0 || value > 65535)
            return 0;
    } else {
        p = default_port;
        plen = wcslen(p);
    }
    if (plen >= port_cap)
        return 0;

    memcpy(host, h, hlen * sizeof(wchar_t));
    host[hlen] = 0;
    memcpy(port, p, plen * sizeof(wchar_t));
    port[plen] = 0;
    return 1;
}
