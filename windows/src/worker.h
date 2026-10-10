/*
 * KeyBridge - background connection worker: connect, handshake, inject keys,
 * answer PINGs, reconnect with backoff. Status changes are posted to the UI
 * window as msg(wParam = generation, lParam = kb_status).
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
    KB_ST_BAD_CODE      /* server_finished mismatch; retrying every 10 s */
} kb_status;

/* Stops any running worker and starts a new one. address is the Mac address
 * field ("host" or "host:port"); psk is copied. UI thread only. */
BOOL   worker_start(HWND notify, UINT msg, const wchar_t *address, const uint8_t psk[KBP2_PSK_LEN]);
/* Signals the worker to stop (it releases held keys on its way out) and waits
 * up to wait_ms for it. Later status messages from it are ignored because the
 * generation changes. UI thread only. */
void   worker_stop(DWORD wait_ms);
/* Generation of the current worker; compare with a status message's wParam. */
WPARAM worker_generation(void);

#endif
