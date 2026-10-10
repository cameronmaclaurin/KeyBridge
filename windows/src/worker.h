/*
 * KeyBridge - background connection worker: connect, handshake, inject keys,
 * answer PINGs, reconnect with backoff. Status changes are posted to the UI
 * window as msg(wParam = generation, lParam = kb_status).
 *
 * It also carries the shared clipboard (docs/PROTOCOL.md 5a): it sends CAPS
 * first in every session, sends text that clipboard.c hands it (only if the
 * Mac's CAPS had bit0), and passes received text back to clipboard.c. It is
 * the only thread that writes to the socket. clipboard_init must run before
 * the first worker_start.
 */
#ifndef KB_WORKER_H
#define KB_WORKER_H

#include "common.h"
#include "kbp2.h"

typedef enum {
    KB_ST_NONE = 0,
    KB_ST_CONNECTING,   /* first attempt, or re-attempt after a session ended */
    KB_ST_CONNECTED,    /* authenticated session */
    KB_ST_WAITING,      /* Mac not reachable / not answering; retrying */
    KB_ST_NOT_FOUND,    /* address did not resolve; retrying */
    KB_ST_NOT_PAIRED    /* server_finished mismatch: the Mac no longer has our key.
                           The worker has stopped; it does not retry. */
} kb_status;

/* Stops any running worker and starts a new one. address is the stored Mac
 * address ("host" or "host:port"); psk (the ltk from pairing) is copied.
 * UI thread only. */
BOOL   worker_start(HWND notify, UINT msg, const wchar_t *address, const uint8_t psk[KBP2_PSK_LEN]);
/* Signals the worker to stop (it releases held keys on its way out) and waits
 * up to wait_ms for it. Later status messages from it are ignored because the
 * generation changes. UI thread only. */
void   worker_stop(DWORD wait_ms);
/* Generation of the current worker; compare with a status message's wParam. */
WPARAM worker_generation(void);

#endif
