/*
 * KeyBridge - pairing initiator: Bluetooth-style numeric comparison
 * (docs/PROTOCOL.md section 2). The PC connects, both sides show the same
 * 6-digit number, both users confirm, and both sides end up with the same
 * 32-byte long-term key (ltk) that becomes the session psk.
 *
 * Shared by the app (run on a background thread) and the selftest build, so
 * both run the same code. No UI calls are made from here.
 */
#ifndef KB_PAIRING_H
#define KB_PAIRING_H

#include "common.h"
#include "kbutil.h"
#include "kbp2.h"

#define KBPR_MAGIC          "KBPR"
#define KBPR_NAME_LEN       64    /* UTF-8, NUL-padded */
#define KBPR_HELLO_LEN      133   /* "KBPR" || pc_pub(65) || pc_name(64) */
#define KBPR_COMMIT_LEN     165   /* "KBPR" || mac_pub(65) || mac_name(64) || commit(32) */
#define KBPR_NONCE_LEN      32
#define KBPR_CONFIRM_LEN    32
#define KBPR_LTK_LEN        32

#define KBPR_CONNECT_MS     5000    /* per resolved address */
#define KBPR_EXCHANGE_MS    10000   /* PairHello .. MacNonce, from connecting (2.4) */
#define KBPR_CONFIRM_MS     120000  /* confirmation phase (2.4) */

/* Called on the pairing thread once the commitment has verified, i.e. when
 * the number should be shown. mac_name is sanitized for display (may be ""). */
typedef void (*kb_pair_sas_fn)(void *ctx, uint32_t sas, const wchar_t *mac_name);

typedef struct {
    const wchar_t *host;                  /* host name or address, no port */
    const wchar_t *port;                  /* decimal */
    const uint8_t *pc_name;               /* KBPR_NAME_LEN bytes (kb_pc_name) */
    HANDLE         stop;                  /* manual-reset: cancel; may be NULL */
    HANDLE         confirm;               /* manual-reset: the local user clicked Confirm */
    kb_pair_sas_fn on_sas;
    void          *ctx;
} kb_pair_params;

/* Runs the whole initiator side, including connecting and the graceful close.
 *   KBP2_OK       paired: ltk and mac_name are filled in. Store ltk now.
 *   KBP2_STOPPED  cancelled through p->stop.
 *   anything else failed (timeout, peer closed, commit/confirm mismatch, ...).
 * On any result other than KBP2_OK, ltk is zeroed. mac_name (KB_NAME_MAX + 1
 * characters) is filled in as soon as PairCommit arrives. */
kbp2_status kb_pair_run(const kb_pair_params *p, uint8_t ltk[KBPR_LTK_LEN],
                        wchar_t mac_name[KB_NAME_MAX + 1]);

/* name (UTF-16, e.g. from the command line or GetComputerNameExW) as UTF-8,
 * truncated at a character boundary to at most 64 bytes, NUL-padded. */
void kb_pair_encode_name(const wchar_t *name, uint8_t out[KBPR_NAME_LEN]);

/* This PC's display name: GetComputerNameExW(ComputerNamePhysicalDnsHostname),
 * encoded as above. Falls back to "Windows PC". */
void kb_pc_name(uint8_t out[KBPR_NAME_LEN]);

/* A received 64-byte name for display: bytes up to the first NUL, decoded as
 * UTF-8 leniently (invalid sequences become U+FFFD), control and invisible
 * formatting characters removed, trimmed. */
void kb_pair_decode_name(const uint8_t name[KBPR_NAME_LEN], wchar_t out[KB_NAME_MAX + 1]);

#endif
