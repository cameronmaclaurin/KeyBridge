/*
 * KeyBridge - update manifest helpers (see update_manifest.h, docs/UPDATES.md).
 */
#include "update_manifest.h"

#include <string.h>

/* Bits for the nine required keys ("all nine keys must be present exactly once"). */
enum {
    K_HEADER = 1u << 0,
    K_VERSION = 1u << 1,
    K_NOTES_URL = 1u << 2,
    K_MAC_URL = 1u << 3,
    K_MAC_SHA = 1u << 4,
    K_MAC_SIZE = 1u << 5,
    K_WIN_URL = 1u << 6,
    K_WIN_SHA = 1u << 7,
    K_WIN_SIZE = 1u << 8,
    K_ALL = (1u << 9) - 1u
};

static int key_is(const uint8_t *key, size_t len, const char *name)
{
    size_t n = strlen(name);
    return len == n && memcmp(key, name, n) == 0;
}

static unsigned key_bit(const uint8_t *key, size_t len)
{
    if (key_is(key, len, "keybridge-update-manifest"))
        return K_HEADER;
    if (key_is(key, len, "version"))
        return K_VERSION;
    if (key_is(key, len, "notes-url"))
        return K_NOTES_URL;
    if (key_is(key, len, "mac-url"))
        return K_MAC_URL;
    if (key_is(key, len, "mac-sha256"))
        return K_MAC_SHA;
    if (key_is(key, len, "mac-size"))
        return K_MAC_SIZE;
    if (key_is(key, len, "windows-url"))
        return K_WIN_URL;
    if (key_is(key, len, "windows-sha256"))
        return K_WIN_SHA;
    if (key_is(key, len, "windows-size"))
        return K_WIN_SIZE;
    return 0; /* unknown keys are ignored */
}

static int is_digit(uint8_t c)
{
    return c >= '0' && c <= '9';
}

/* Characters allowed in a URI (RFC 3986): unreserved, reserved and '%'. */
static int is_url_char(uint8_t c)
{
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || is_digit(c))
        return 1;
    return c != 0 && strchr("-._~:/?#[]@!$&'()*+,;=%", (int)c) != NULL;
}

static int copy_url(const uint8_t *v, size_t len, const char *prefix, char out[KB_UPD_URL_MAX + 1])
{
    size_t plen = strlen(prefix), i;

    if (len <= plen || len > KB_UPD_URL_MAX || memcmp(v, prefix, plen) != 0)
        return 0;
    for (i = 0; i < len; i++) {
        if (!is_url_char(v[i]))
            return 0; /* also rejects whitespace and control characters */
        if (v[i] == '.' && i + 1 < len && v[i + 1] == '.')
            return 0; /* no ".." anywhere */
    }
    memcpy(out, v, len);
    out[len] = 0;
    return 1;
}

static int copy_sha256(const uint8_t *v, size_t len, char out[KB_UPD_SHA256_HEX + 1])
{
    size_t i;

    if (len != KB_UPD_SHA256_HEX)
        return 0;
    for (i = 0; i < len; i++) {
        if (!is_digit(v[i]) && !(v[i] >= 'a' && v[i] <= 'f'))
            return 0;
    }
    memcpy(out, v, len);
    out[len] = 0;
    return 1;
}

/* Decimal 1..KB_UPD_SIZE_MAX, no sign, no leading zeros. */
static int parse_size(const uint8_t *v, size_t len, uint32_t *out)
{
    uint32_t n = 0;
    size_t i;

    if (len == 0 || len > 9 || v[0] == '0')
        return 0;
    for (i = 0; i < len; i++) {
        if (!is_digit(v[i]))
            return 0;
        n = n * 10u + (uint32_t)(v[i] - '0'); /* at most 999,999,999: no overflow */
    }
    if (n < 1u || n > KB_UPD_SIZE_MAX)
        return 0;
    *out = n;
    return 1;
}

int kb_upd_version_valid(const char *s, size_t len)
{
    size_t i = 0;
    int part;

    if (len == 0 || len > KB_UPD_VERSION_MAX)
        return 0;
    for (part = 0; part < 3; part++) {
        size_t start = i;
        while (i < len && is_digit((uint8_t)s[i]))
            i++;
        if (i == start)
            return 0;
        if (s[start] == '0' && i - start > 1)
            return 0; /* leading zero */
        if (part < 2) {
            if (i >= len || s[i] != '.')
                return 0;
            i++;
        }
    }
    return i == len;
}

int kb_upd_version_compare(const char *a, const char *b)
{
    int part;

    for (part = 0; part < 3; part++) {
        size_t la = 0, lb = 0;
        int c;

        while (is_digit((uint8_t)a[la]))
            la++;
        while (is_digit((uint8_t)b[lb]))
            lb++;
        /* No leading zeros, so a longer digit string is a bigger number. */
        if (la != lb)
            return la < lb ? -1 : 1;
        c = memcmp(a, b, la);
        if (c != 0)
            return c < 0 ? -1 : 1;
        a += la;
        b += lb;
        if (*a == '.')
            a++;
        if (*b == '.')
            b++;
    }
    return 0;
}

int kb_upd_parse_manifest(const uint8_t *buf, size_t len, kb_update_manifest *m)
{
    size_t pos = 0, i;
    unsigned seen = 0;
    int first = 1;

    memset(m, 0, sizeof(*m));
    if (buf == NULL || len == 0 || len > KB_UPD_META_MAX)
        return 0;
    /* LF line endings only: no CR, NUL, other control characters or DEL. */
    for (i = 0; i < len; i++) {
        if ((buf[i] < 0x20 && buf[i] != '\n') || buf[i] == 0x7F)
            return 0;
    }

    while (pos < len) {
        const uint8_t *line = buf + pos;
        const uint8_t *eol = (const uint8_t *)memchr(line, '\n', len - pos);
        size_t line_len = eol != NULL ? (size_t)(eol - line) : len - pos;
        const uint8_t *sp, *v;
        size_t key_len, vlen;
        unsigned bit;
        int ok = 0;

        pos += line_len + (eol != NULL ? 1u : 0u);

        if (first) {
            if (!key_is(line, line_len, KB_UPD_HEADER))
                return 0;
            seen = K_HEADER;
            first = 0;
            continue;
        }

        sp = (const uint8_t *)memchr(line, ' ', line_len);
        if (sp == NULL || sp == line)
            goto bad; /* every line is "key value" */
        key_len = (size_t)(sp - line);
        v = sp + 1;
        vlen = line_len - key_len - 1;

        bit = key_bit(line, key_len);
        if (bit == 0)
            continue;
        if ((seen & bit) != 0)
            goto bad; /* duplicate (including a second header line) */
        seen |= bit;

        switch (bit) {
        case K_VERSION:
            ok = kb_upd_version_valid((const char *)v, vlen);
            if (ok) {
                memcpy(m->version, v, vlen);
                m->version[vlen] = 0;
            }
            break;
        case K_NOTES_URL:
            ok = copy_url(v, vlen, KB_UPD_NOTES_PREFIX, m->notes_url);
            break;
        case K_MAC_URL:
            ok = copy_url(v, vlen, KB_UPD_URL_PREFIX, m->mac_url);
            break;
        case K_MAC_SHA:
            ok = copy_sha256(v, vlen, m->mac_sha256);
            break;
        case K_MAC_SIZE:
            ok = parse_size(v, vlen, &m->mac_size);
            break;
        case K_WIN_URL:
            ok = copy_url(v, vlen, KB_UPD_URL_PREFIX, m->windows_url);
            break;
        case K_WIN_SHA:
            ok = copy_sha256(v, vlen, m->windows_sha256);
            break;
        case K_WIN_SIZE:
            ok = parse_size(v, vlen, &m->windows_size);
            break;
        default:
            break;
        }
        if (!ok)
            goto bad;
    }

    if (seen == K_ALL)
        return 1;
bad:
    memset(m, 0, sizeof(*m));
    return 0;
}

static int b64_value(uint8_t c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1;
}

int kb_upd_decode_sig(const uint8_t *in, size_t len, uint8_t out[KB_UPD_SIG_LEN])
{
    /* 64 bytes = 21 full 3-byte groups (84 chars) + 1 byte ("xy=="): 88 chars. */
    int v[88];
    size_t i, o = 0;

    if (in == NULL)
        return 0;
    if (len > 0 && in[len - 1] == '\n')
        len--; /* one trailing LF is allowed */
    if (len != 88 || in[86] != '=' || in[87] != '=')
        return 0;
    for (i = 0; i < 86; i++) {
        v[i] = b64_value(in[i]);
        if (v[i] < 0)
            return 0;
    }
    for (i = 0; i < 84; i += 4) {
        out[o++] = (uint8_t)((v[i] << 2) | (v[i + 1] >> 4));
        out[o++] = (uint8_t)(((v[i + 1] & 0x0F) << 4) | (v[i + 2] >> 2));
        out[o++] = (uint8_t)(((v[i + 2] & 0x03) << 6) | v[i + 3]);
    }
    out[o] = (uint8_t)((v[84] << 2) | (v[85] >> 4));
    return 1;
}

static int hex_digit(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

int kb_upd_hex_decode(const char *hex, size_t hexlen, uint8_t *out, size_t outlen)
{
    size_t i;

    if (hex == NULL || hexlen != 2 * outlen)
        return 0;
    for (i = 0; i < outlen; i++) {
        int hi = hex_digit(hex[2 * i]), lo = hex_digit(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            memset(out, 0, outlen);
            return 0;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 1;
}

void kb_upd_hex_encode(const uint8_t *in, size_t n, char *out)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < n; i++) {
        out[2 * i] = digits[in[i] >> 4];
        out[2 * i + 1] = digits[in[i] & 0x0F];
    }
    out[2 * n] = 0;
}
