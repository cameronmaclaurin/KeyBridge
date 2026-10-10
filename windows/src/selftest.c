/*
 * KeyBridge - conformance selftest client (docs/PROTOCOL.md Appendix A.2).
 *
 * Built only by "build.bat <version> selftest" as KeyBridge-selftest.exe.
 * Uses the same KBP2 handshake and record code as the app (kbp2.c), but
 * never injects keys. Shipping builds never compile this file.
 *
 * Exit codes: 0 server closed the connection after a good session,
 *             1 failure after HANDSHAKE OK, or could not connect at all,
 *             2 handshake failed, 64 bad command line.
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

#define EXIT_OK          0
#define EXIT_ERROR       1
#define EXIT_HANDSHAKE   2
#define EXIT_USAGE       64

/* Transcript lines go to stdout, one per event, flushed immediately. */
static void out_line(const char *line)
{
    fputs(line, stdout);
    fputc('\n', stdout);
    fflush(stdout);
}

static int usage(void)
{
    fputs("usage: KeyBridge-selftest.exe --selftest-client --host <H> --port <P> --code <CODE>\n",
          stderr);
    return EXIT_USAGE;
}

static int valid_port(const wchar_t *p)
{
    unsigned long v = 0;
    size_t i, n = wcslen(p);
    if (n == 0 || n > 5)
        return 0;
    for (i = 0; i < n; i++) {
        if (p[i] < L'0' || p[i] > L'9')
            return 0;
        v = v * 10 + (unsigned long)(p[i] - L'0');
    }
    return v >= 1 && v <= 65535;
}

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

int wmain(int argc, wchar_t **argv)
{
    const wchar_t *host = NULL, *port = NULL, *code_arg = NULL;
    BOOL client_mode = FALSE;
    char code[KB_CODE_LEN + 1];
    uint8_t psk[KBP2_PSK_LEN];
    WSADATA wsa;
    kbp2_conn conn;
    kbp2_session session;
    kbp2_status st;
    int i, rc;

    (void)_setmode(_fileno(stdout), _O_BINARY); /* "\n" line endings, not "\r\n" */

    for (i = 1; i < argc; i++) {
        if (wcscmp(argv[i], L"--selftest-client") == 0)
            client_mode = TRUE;
        else if (wcscmp(argv[i], L"--host") == 0 && i + 1 < argc)
            host = argv[++i];
        else if (wcscmp(argv[i], L"--port") == 0 && i + 1 < argc)
            port = argv[++i];
        else if (wcscmp(argv[i], L"--code") == 0 && i + 1 < argc)
            code_arg = argv[++i];
        else
            return usage();
    }
    if (!client_mode || host == NULL || port == NULL || code_arg == NULL || !valid_port(port))
        return usage();
    if (!kb_normalize_code(code_arg, code)) {
        fputs("error: invalid pairing code\n", stderr);
        return EXIT_USAGE;
    }

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0 || !kb_crypto_init() ||
        !kbp2_psk_from_code(code, psk)) {
        fputs("error: could not initialize Winsock/CNG\n", stderr);
        return EXIT_ERROR;
    }
    SecureZeroMemory(code, sizeof(code));

    kbp2_conn_init(&conn, NULL);
    st = kbp2_connect(&conn, host, port, KBP2_HANDSHAKE_MS);
    if (st != KBP2_OK) {
        fprintf(stderr, "error: connect failed: %s\n", kbp2_status_text(st));
        kbp2_conn_close(&conn);
        SecureZeroMemory(psk, sizeof(psk));
        return EXIT_ERROR;
    }

    st = kbp2_client_handshake(&conn, psk, &session);
    SecureZeroMemory(psk, sizeof(psk));
    if (st != KBP2_OK) {
        fprintf(stderr, "handshake failed: %s\n", kbp2_status_text(st));
        out_line("HANDSHAKE FAILED");
        kbp2_conn_close(&conn);
        return EXIT_HANDSHAKE;
    }
    out_line("HANDSHAKE OK");

    rc = run_session(&conn, &session);
    kbp2_session_free(&session);
    kbp2_conn_close(&conn);
    kb_crypto_cleanup();
    WSACleanup();
    return rc;
}
