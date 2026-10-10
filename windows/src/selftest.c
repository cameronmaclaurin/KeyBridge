/*
 * KeyBridge - conformance selftest (docs/PROTOCOL.md Appendix A.2, A.4, A.5;
 * docs/UPDATES.md section 6).
 *
 * Built only by "build.bat <version> selftest" as KeyBridge-selftest.exe.
 * Uses the same KBP2 handshake/record code (kbp2.c), pairing code
 * (pairing.c) and discovery code (discovery.c) as the app, but never
 * injects keys. Shipping builds never compile this file.
 *
 *   --selftest-client      --host H --port P --psk <64 hex>             (A.2)
 *       0 server closed after a good session, 1 failure after HANDSHAKE OK
 *       (or could not connect), 2 handshake failed.
 *   --selftest-pair-client --host H --port P --name NAME [--confirm yes|no] (A.4)
 *       0 PAIRED or CANCELLED, 2 PAIR FAILED.
 *   --selftest-discover    [--timeout <seconds, default 5>]             (A.5)
 *       0 done browsing, 3 DNS-SD APIs not available, 1 browse failed.
 *   --selftest-verify-update <manifest-file> <sig-file> --current X.Y.Z [--pubkey <130 hex>]
 *       (UPDATES.md 6) one line: "UPDATE <version> <windows-url> <sha256> <size>"
 *       or "CURRENT" (exit 0), or "INVALID" (exit 2). Uses update.c's
 *       kb_upd_evaluate, exactly as the app does.
 *   64 bad command line, in every mode.
 */
#ifndef KEYBRIDGE_SELFTEST
#error "selftest.c is only built with /DKEYBRIDGE_SELFTEST (build.bat <version> selftest)"
#endif

#include "common.h"

#include <stdio.h>
#include <io.h>
#include <fcntl.h>

#include "kbutil.h"
#include "crypto.h"
#include "kbp2.h"
#include "pairing.h"
#include "discovery.h"
#include "update.h"

#define EXIT_OK          0
#define EXIT_ERROR       1
#define EXIT_HANDSHAKE   2
#define EXIT_PAIR_FAILED 2
#define EXIT_NO_DNSSD    3
#define EXIT_INVALID     2
#define EXIT_USAGE       64

#define DISCOVER_DEFAULT_S 5
#define DISCOVER_MAX_S     3600
#define DISCOVER_MAX_FOUND 64

/* Transcript lines go to stdout, one per event, flushed immediately. */
static void out_line(const char *line)
{
    fputs(line, stdout);
    fputc('\n', stdout);
    fflush(stdout);
}

static int usage(void)
{
    fputs("usage: KeyBridge-selftest.exe --selftest-client --host <H> --port <P> --psk <64 hex chars>\n"
          "       KeyBridge-selftest.exe --selftest-pair-client --host <H> --port <P> --name <NAME>"
          " [--confirm yes|no]\n"
          "       KeyBridge-selftest.exe --selftest-discover [--timeout <seconds>]\n"
          "       KeyBridge-selftest.exe --selftest-verify-update <manifest-file> <sig-file>"
          " --current <X.Y.Z> [--pubkey <130 hex chars>]\n",
          stderr);
    return EXIT_USAGE;
}

static int parse_uint(const wchar_t *p, unsigned long min, unsigned long max, unsigned long *out)
{
    unsigned long v = 0;
    size_t i, n = wcslen(p);
    if (n == 0 || n > 9)
        return 0;
    for (i = 0; i < n; i++) {
        if (p[i] < L'0' || p[i] > L'9')
            return 0;
        v = v * 10 + (unsigned long)(p[i] - L'0');
    }
    if (v < min || v > max)
        return 0;
    *out = v;
    return 1;
}

static int valid_port(const wchar_t *p)
{
    unsigned long v;
    return wcslen(p) <= 5 && parse_uint(p, 1, 65535, &v);
}

static int hex_value(wchar_t c)
{
    if (c >= L'0' && c <= L'9')
        return (int)(c - L'0');
    if (c >= L'a' && c <= L'f')
        return (int)(c - L'a') + 10;
    if (c >= L'A' && c <= L'F')
        return (int)(c - L'A') + 10;
    return -1;
}

/* Exactly 64 hex characters, case-insensitive. */
static int parse_psk(const wchar_t *s, uint8_t psk[KBP2_PSK_LEN])
{
    size_t i;
    if (wcslen(s) != 2 * KBP2_PSK_LEN)
        return 0;
    for (i = 0; i < KBP2_PSK_LEN; i++) {
        int hi = hex_value(s[2 * i]), lo = hex_value(s[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            SecureZeroMemory(psk, KBP2_PSK_LEN);
            return 0;
        }
        psk[i] = (uint8_t)((hi << 4) | lo);
    }
    return 1;
}

/* UTF-16 -> UTF-8 for stdout. */
static void to_utf8(const wchar_t *in, char *out, int cap)
{
    int n = WideCharToMultiByte(CP_UTF8, 0, in, -1, out, cap, NULL, NULL);
    if (n <= 0)
        out[0] = 0;
}

static BOOL net_init(void)
{
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return FALSE;
    if (!kb_crypto_init()) {
        WSACleanup();
        return FALSE;
    }
    return TRUE;
}

static void net_cleanup(void)
{
    kb_crypto_cleanup();
    WSACleanup();
}

/* ------------------------------------------------------------------------ */
/* A.2 session client                                                       */
/* ------------------------------------------------------------------------ */

/* After HANDSHAKE OK: print every event until the server closes. */
static int run_session(kbp2_conn *c, kbp2_session *s)
{
    static const uint8_t pong[KBP2_PLAINTEXT_LEN] = { KBP2_PONG, 0, 0, 0 };
    uint8_t pt[KBP2_PLAINTEXT_LEN];
    char line[64];

    for (;;) {
        kbp2_status st = kbp2_recv_record(c, s, pt, KBP2_LIVENESS_MS);
        if (st == KBP2_ERR_CLOSED) {
            out_line("CLOSED");
            return EXIT_OK;
        }
        if (st != KBP2_OK) {
            fprintf(stderr, "error: %s\n", kbp2_status_text(st));
            return EXIT_ERROR;
        }

        switch (pt[0]) {
        case KBP2_KEY: {
            unsigned vk = (unsigned)pt[2] | ((unsigned)pt[3] << 8);
            if (vk >= 1 && vk <= 254) { /* others are ignored and not printed */
                (void)snprintf(line, sizeof(line), "KEY down=%u ext=%u vk=0x%04X",
                               (unsigned)(pt[1] & KBP2_FLAG_DOWN),
                               (unsigned)((pt[1] & KBP2_FLAG_EXTENDED) >> 1), vk);
                out_line(line);
            }
            break;
        }
        case KBP2_PING:
            out_line("PING");
            st = kbp2_send_record(c, s, pong);
            if (st != KBP2_OK) {
                fprintf(stderr, "error: could not send PONG: %s\n", kbp2_status_text(st));
                return EXIT_ERROR;
            }
            break;
        case KBP2_RELEASE_ALL:
            out_line("RELEASE_ALL");
            break;
        default:
            break; /* unknown types are ignored */
        }
    }
}

static int run_client(const wchar_t *host, const wchar_t *port, uint8_t psk[KBP2_PSK_LEN])
{
    kbp2_conn conn;
    kbp2_session session;
    kbp2_status st;
    int rc;

    if (!net_init()) {
        fputs("error: could not initialize Winsock/CNG\n", stderr);
        SecureZeroMemory(psk, KBP2_PSK_LEN);
        return EXIT_ERROR;
    }

    kbp2_conn_init(&conn, NULL);
    st = kbp2_connect(&conn, host, port, KBP2_HANDSHAKE_MS);
    if (st != KBP2_OK) {
        fprintf(stderr, "error: connect failed: %s\n", kbp2_status_text(st));
        kbp2_conn_close(&conn);
        SecureZeroMemory(psk, KBP2_PSK_LEN);
        net_cleanup();
        return EXIT_ERROR;
    }

    st = kbp2_client_handshake(&conn, psk, &session);
    SecureZeroMemory(psk, KBP2_PSK_LEN);
    if (st != KBP2_OK) {
        fprintf(stderr, "handshake failed: %s\n", kbp2_status_text(st));
        out_line("HANDSHAKE FAILED");
        kbp2_conn_close(&conn);
        net_cleanup();
        return EXIT_HANDSHAKE;
    }
    out_line("HANDSHAKE OK");

    rc = run_session(&conn, &session);
    kbp2_session_free(&session);
    kbp2_conn_close(&conn);
    net_cleanup();
    return rc;
}

/* ------------------------------------------------------------------------ */
/* A.4 pairing initiator                                                    */
/* ------------------------------------------------------------------------ */

typedef struct {
    BOOL   confirm_yes;
    BOOL   sas_shown;
    HANDLE stop;
    HANDLE confirm;
} pair_ctx;

static void pair_on_sas(void *ctx, uint32_t sas, const wchar_t *mac_name)
{
    pair_ctx *pc = (pair_ctx *)ctx;
    char line[32];

    UNREFERENCED_PARAMETER(mac_name);
    (void)snprintf(line, sizeof(line), "SAS %06u", (unsigned)sas);
    out_line(line);
    pc->sas_shown = TRUE;
    /* The "user" answers at once: --confirm yes sends PcConfirm, no cancels. */
    SetEvent(pc->confirm_yes ? pc->confirm : pc->stop);
}

static int run_pair_client(const wchar_t *host, const wchar_t *port, const wchar_t *name,
                           BOOL confirm_yes)
{
    static const char hex[] = "0123456789abcdef";
    uint8_t pc_name[KBPR_NAME_LEN];
    uint8_t ltk[KBPR_LTK_LEN];
    wchar_t mac_name[KB_NAME_MAX + 1];
    char line[8 + 2 * KBPR_LTK_LEN + 1];
    kb_pair_params params;
    pair_ctx ctx;
    kbp2_status st;
    int rc, i;

    memset(&ctx, 0, sizeof(ctx));
    ctx.confirm_yes = confirm_yes;
    ctx.stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    ctx.confirm = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (ctx.stop == NULL || ctx.confirm == NULL || !net_init()) {
        fputs("error: could not initialize Winsock/CNG\n", stderr);
        out_line("PAIR FAILED");
        if (ctx.stop != NULL)
            CloseHandle(ctx.stop);
        if (ctx.confirm != NULL)
            CloseHandle(ctx.confirm);
        return EXIT_PAIR_FAILED;
    }

    kb_pair_encode_name(name, pc_name);
    memset(&params, 0, sizeof(params));
    params.host = host;
    params.port = port;
    params.pc_name = pc_name;
    params.stop = ctx.stop;
    params.confirm = ctx.confirm;
    params.on_sas = pair_on_sas;
    params.ctx = &ctx;

    st = kb_pair_run(&params, ltk, mac_name);
    if (st == KBP2_OK) {
        memcpy(line, "PAIRED ", 7);
        for (i = 0; i < KBPR_LTK_LEN; i++) {
            line[7 + 2 * i] = hex[ltk[i] >> 4];
            line[8 + 2 * i] = hex[ltk[i] & 0x0F];
        }
        line[7 + 2 * KBPR_LTK_LEN] = 0;
        out_line(line);
        rc = EXIT_OK;
    } else if (st == KBP2_STOPPED && !confirm_yes && ctx.sas_shown) {
        out_line("CANCELLED");
        rc = EXIT_OK;
    } else {
        fprintf(stderr, "pairing failed: %s\n", kbp2_status_text(st));
        out_line("PAIR FAILED");
        rc = EXIT_PAIR_FAILED;
    }

    SecureZeroMemory(ltk, sizeof(ltk));
    SecureZeroMemory(line, sizeof(line));
    CloseHandle(ctx.stop);
    CloseHandle(ctx.confirm);
    net_cleanup();
    return rc;
}

/* ------------------------------------------------------------------------ */
/* A.5 discovery                                                            */
/* ------------------------------------------------------------------------ */

typedef struct {
    wchar_t instance[KB_DISC_INSTANCE_MAX + 1];
    BOOL    printed;
    int     resolve_tries;
} found_entry;

static found_entry *find_entry(found_entry *list, int *count, const wchar_t *instance, BOOL add)
{
    int i;
    for (i = 0; i < *count; i++) {
        if (_wcsicmp(list[i].instance, instance) == 0)
            return &list[i];
    }
    if (!add || *count >= DISCOVER_MAX_FOUND)
        return NULL;
    memset(&list[*count], 0, sizeof(list[*count]));
    for (i = 0; i < KB_DISC_INSTANCE_MAX && instance[i] != 0; i++)
        list[*count].instance[i] = instance[i];
    list[*count].instance[i] = 0;
    return &list[(*count)++];
}

static void print_found(const kb_disc_event *ev)
{
    wchar_t label[KB_DISC_INSTANCE_MAX + 1];
    char name8[4 * (KB_DISC_INSTANCE_MAX + 1)];
    char host8[4 * (KB_HOST_MAX + 1)];
    char line[sizeof(name8) + sizeof(host8) + 64];

    discovery_label(ev->instance, label, ARRAYSIZE(label));
    to_utf8(label[0] != 0 ? label : ev->instance, name8, (int)sizeof(name8));
    to_utf8(ev->host, host8, (int)sizeof(host8));
    (void)snprintf(line, sizeof(line), "FOUND name=%s host=%s port=%u", name8, host8,
                   (unsigned)ev->port);
    out_line(line);
}

static int run_discover(unsigned long timeout_s)
{
    static found_entry found[DISCOVER_MAX_FOUND];
    static kb_disc_event ev;
    int count = 0;
    HANDLE wake;
    ULONGLONG deadline;

    if (!discovery_available()) {
        fputs("error: the DNS-SD APIs (DnsServiceBrowse) are not available on this Windows\n",
              stderr);
        return EXIT_NO_DNSSD;
    }
    wake = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (wake == NULL || !discovery_start(NULL, 0, wake)) {
        fputs("error: could not start browsing for _keybridge._tcp.local\n", stderr);
        if (wake != NULL)
            CloseHandle(wake);
        return EXIT_ERROR;
    }

    deadline = GetTickCount64() + (ULONGLONG)timeout_s * 1000u;
    for (;;) {
        ULONGLONG now = GetTickCount64();
        found_entry *e;

        while (discovery_next(&ev)) {
            switch (ev.kind) {
            case KB_DISC_ADDED:
                e = find_entry(found, &count, ev.instance, TRUE);
                if (e != NULL && !e->printed && e->resolve_tries == 0) {
                    e->resolve_tries = 1;
                    (void)discovery_resolve(ev.instance);
                }
                break;
            case KB_DISC_RESOLVED:
                e = find_entry(found, &count, ev.instance, TRUE);
                if (e != NULL && !e->printed) {
                    e->printed = TRUE;
                    print_found(&ev);
                }
                break;
            case KB_DISC_RESOLVE_FAILED:
                e = find_entry(found, &count, ev.instance, FALSE);
                if (e != NULL && !e->printed && e->resolve_tries < 3) {
                    e->resolve_tries++;
                    (void)discovery_resolve(ev.instance);
                }
                break;
            case KB_DISC_REMOVED:
            default:
                break;
            }
        }
        if (now >= deadline)
            break;
        (void)WaitForSingleObject(wake, (DWORD)(deadline - now));
    }

    discovery_stop();
    CloseHandle(wake);
    return EXIT_OK;
}

/* ------------------------------------------------------------------------ */
/* UPDATES.md section 6: manifest verification                              */
/* ------------------------------------------------------------------------ */

/* Read at most cap bytes. 1 = ok, 0 = larger than cap, -1 = can't read. */
static int read_small_file(const wchar_t *path, uint8_t *buf, DWORD cap, size_t *len)
{
    HANDLE f;
    DWORD got = 0, n;
    int rc = 1;

    *len = 0;
    f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE)
        return -1;
    for (;;) {
        BYTE extra;
        if (got == cap) {
            /* Full: one more byte means the file is too large. */
            n = 0;
            if (!ReadFile(f, &extra, 1, &n, NULL))
                rc = -1;
            else if (n != 0)
                rc = 0;
            break;
        }
        n = 0;
        if (!ReadFile(f, buf + got, cap - got, &n, NULL)) {
            rc = -1;
            break;
        }
        if (n == 0)
            break;
        got += n;
    }
    CloseHandle(f);
    *len = got;
    return rc;
}

static int run_verify_update(const wchar_t *manifest_path, const wchar_t *sig_path,
                             const char *current, const uint8_t *pubkey)
{
    static uint8_t manifest[KB_UPD_META_MAX];
    static uint8_t sig[KB_UPD_META_MAX];
    static kb_update_manifest m;
    static char line[32 + KB_UPD_VERSION_MAX + KB_UPD_URL_MAX + KB_UPD_SHA256_HEX];
    size_t mlen = 0, slen = 0;
    int mrc, src;

    mrc = read_small_file(manifest_path, manifest, (DWORD)sizeof(manifest), &mlen);
    src = read_small_file(sig_path, sig, (DWORD)sizeof(sig), &slen);
    if (mrc < 0 || src < 0)
        fputs("error: could not read the manifest or signature file\n", stderr);
    else if (mrc == 0 || src == 0)
        fputs("error: manifest or signature is larger than 16 KB\n", stderr);

    if (mrc == 1 && src == 1) {
        switch (kb_upd_evaluate(manifest, mlen, sig, slen, pubkey, current, &m)) {
        case KB_UPD_V_NEWER:
            (void)snprintf(line, sizeof(line), "UPDATE %s %s %s %lu", m.version, m.windows_url,
                           m.windows_sha256, (unsigned long)m.windows_size);
            out_line(line);
            return EXIT_OK;
        case KB_UPD_V_CURRENT:
            out_line("CURRENT");
            return EXIT_OK;
        case KB_UPD_V_INVALID:
        default:
            break;
        }
    }
    out_line("INVALID");
    return EXIT_INVALID;
}

/* ASCII-only copy of a command-line argument. */
static int narrow_arg(const wchar_t *in, char *out, size_t cap)
{
    size_t i;
    for (i = 0; in[i] != 0; i++) {
        if (i + 1 >= cap || in[i] >= 0x80)
            return 0;
        out[i] = (char)in[i];
    }
    out[i] = 0;
    return 1;
}

/* ------------------------------------------------------------------------ */
/* Command line                                                             */
/* ------------------------------------------------------------------------ */

enum { MODE_NONE, MODE_CLIENT, MODE_PAIR_CLIENT, MODE_DISCOVER, MODE_VERIFY_UPDATE };

int wmain(int argc, wchar_t **argv)
{
    const wchar_t *host = NULL, *port = NULL, *psk_arg = NULL, *name = NULL;
    const wchar_t *confirm = NULL, *timeout = NULL;
    const wchar_t *current = NULL, *pubkey_arg = NULL, *manifest_path = NULL, *sig_path = NULL;
    char current8[KB_UPD_VERSION_MAX + 1], pubkey8[2 * KB_UPD_PUBKEY_LEN + 1];
    uint8_t pubkey[KB_UPD_PUBKEY_LEN];
    uint8_t psk[KBP2_PSK_LEN];
    unsigned long timeout_s = DISCOVER_DEFAULT_S;
    int mode = MODE_NONE, i;

    (void)_setmode(_fileno(stdout), _O_BINARY); /* "\n" line endings, not "\r\n" */

    for (i = 1; i < argc; i++) {
        const wchar_t *a = argv[i];
        int new_mode = MODE_NONE;
        const wchar_t **slot = NULL;

        if (wcscmp(a, L"--selftest-client") == 0)
            new_mode = MODE_CLIENT;
        else if (wcscmp(a, L"--selftest-pair-client") == 0)
            new_mode = MODE_PAIR_CLIENT;
        else if (wcscmp(a, L"--selftest-discover") == 0)
            new_mode = MODE_DISCOVER;
        else if (wcscmp(a, L"--selftest-verify-update") == 0)
            new_mode = MODE_VERIFY_UPDATE;
        else if (wcscmp(a, L"--current") == 0)
            slot = &current;
        else if (wcscmp(a, L"--pubkey") == 0)
            slot = &pubkey_arg;
        else if (wcscmp(a, L"--host") == 0)
            slot = &host;
        else if (wcscmp(a, L"--port") == 0)
            slot = &port;
        else if (wcscmp(a, L"--psk") == 0)
            slot = &psk_arg;
        else if (wcscmp(a, L"--name") == 0)
            slot = &name;
        else if (wcscmp(a, L"--confirm") == 0)
            slot = &confirm;
        else if (wcscmp(a, L"--timeout") == 0)
            slot = &timeout;
        else
            return usage();

        if (new_mode != MODE_NONE) {
            if (mode != MODE_NONE)
                return usage();
            mode = new_mode;
            if (mode == MODE_VERIFY_UPDATE) { /* two positional file names follow */
                if (i + 2 >= argc)
                    return usage();
                manifest_path = argv[++i];
                sig_path = argv[++i];
            }
        } else {
            if (*slot != NULL || i + 1 >= argc)
                return usage();
            *slot = argv[++i];
        }
    }

    if (mode != MODE_VERIFY_UPDATE && (current != NULL || pubkey_arg != NULL))
        return usage();

    switch (mode) {
    case MODE_VERIFY_UPDATE:
        if (current == NULL || host != NULL || port != NULL || psk_arg != NULL || name != NULL ||
            confirm != NULL || timeout != NULL)
            return usage();
        if (!narrow_arg(current, current8, sizeof(current8)) ||
            !kb_upd_version_valid(current8, strlen(current8))) {
            fputs("error: --current must be MAJOR.MINOR.PATCH\n", stderr);
            return EXIT_USAGE;
        }
        if (pubkey_arg != NULL &&
            (!narrow_arg(pubkey_arg, pubkey8, sizeof(pubkey8)) ||
             !kb_upd_hex_decode(pubkey8, strlen(pubkey8), pubkey, sizeof(pubkey)) ||
             !kb_p256_point_valid(pubkey))) {
            fputs("error: --pubkey must be 130 hex characters (an uncompressed P-256 point)\n", stderr);
            return EXIT_USAGE;
        }
        return run_verify_update(manifest_path, sig_path, current8,
                                 pubkey_arg != NULL ? pubkey : NULL);

    case MODE_CLIENT:
        if (host == NULL || port == NULL || psk_arg == NULL || name != NULL || confirm != NULL ||
            timeout != NULL || !valid_port(port))
            return usage();
        if (!parse_psk(psk_arg, psk)) {
            fputs("error: --psk must be 64 hex characters\n", stderr);
            return EXIT_USAGE;
        }
        return run_client(host, port, psk);

    case MODE_PAIR_CLIENT:
        if (host == NULL || port == NULL || name == NULL || psk_arg != NULL || timeout != NULL ||
            !valid_port(port))
            return usage();
        if (confirm != NULL && wcscmp(confirm, L"yes") != 0 && wcscmp(confirm, L"no") != 0)
            return usage();
        return run_pair_client(host, port, name, confirm == NULL || wcscmp(confirm, L"yes") == 0);

    case MODE_DISCOVER:
        if (host != NULL || port != NULL || psk_arg != NULL || name != NULL || confirm != NULL)
            return usage();
        if (timeout != NULL && !parse_uint(timeout, 1, DISCOVER_MAX_S, &timeout_s))
            return usage();
        return run_discover(timeout_s);

    default:
        return usage();
    }
}
