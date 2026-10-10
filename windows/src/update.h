/*
 * KeyBridge - secure auto-update (docs/UPDATES.md).
 *
 *   kb_upd_evaluate     signature check + strict parse + version compare.
 *                       Shared by the app and the selftest
 *                       (its verify-update hook), so both run the same code.
 *   kb_upd_check_start  fetch manifest + signature on a worker thread.
 *   kb_upd_download_start
 *                       download the Windows installer on a worker thread to a
 *                       fresh per-user temp directory and verify size + SHA-256.
 *   kb_upd_launch_installer
 *                       run the verified installer silently (installed copy).
 *
 * Jobs are reference counted: the worker thread and the UI each hold one
 * reference. The thread fills in the result, publishes it with
 * kb_upd_job_result (interlocked), then posts msg(wParam 0, lParam job id) to
 * the notify window. The UI may poll instead. Releasing the UI's reference
 * cancels a running job; a downloaded installer that was never launched is
 * deleted when the job is freed.
 */
#ifndef KB_UPDATE_H
#define KB_UPDATE_H

#include "common.h"
#include "update_manifest.h"

/* The signing public key (uncompressed P-256 point, hex). Must equal
 * tools/update_pubkey.txt exactly; CI checks this. */
extern const char kb_update_pubkey_hex[];

typedef enum {
    KB_UPD_V_INVALID = 0,  /* bad signature, bad format or a bad URL */
    KB_UPD_V_NEWER,        /* valid and newer than current */
    KB_UPD_V_CURRENT       /* valid but not newer */
} kb_upd_verdict;

/* Verifies sig (contents of update-manifest.sig) over the exact manifest
 * bytes with pubkey (65 bytes; NULL = the embedded key), then parses the
 * manifest and compares its version with current (a valid X.Y.Z). *out is
 * filled for NEWER and CURRENT and zeroed for INVALID. */
kb_upd_verdict kb_upd_evaluate(const uint8_t *manifest, size_t manifest_len,
                               const uint8_t *sig, size_t sig_len,
                               const uint8_t *pubkey, const char *current,
                               kb_update_manifest *out);

typedef enum {
    KB_UPD_RUNNING = 0,
    KB_UPD_NEWER,           /* check: an update is available (kb_upd_job_manifest) */
    KB_UPD_CURRENT,         /* check: up to date */
    KB_UPD_DOWNLOADED,      /* download: the installer is verified and ready */
    KB_UPD_ERR_NETWORK,     /* couldn't connect, TLS failure, timeout (detail = Win32 error) */
    KB_UPD_ERR_HTTP,        /* HTTP status other than 200 (detail = status) */
    KB_UPD_ERR_TOO_LARGE,   /* manifest or signature over 16 KB */
    KB_UPD_ERR_INVALID,     /* bad signature, bad format or a bad URL */
    KB_UPD_ERR_DAMAGED,     /* download: wrong size or SHA-256 ("damaged or tampered with") */
    KB_UPD_ERR_FILE,        /* couldn't write the temporary file (detail = Win32 error) */
    KB_UPD_ERR_CANCELLED,
    KB_UPD_ERR_INTERNAL
} kb_upd_result;

typedef struct kb_upd_job kb_upd_job;

/* Start a check. current is the running version (X.Y.Z). NULL on failure. */
kb_upd_job *kb_upd_check_start(HWND notify, UINT msg, const char *current);
/* Start downloading m->windows_url. NULL on failure. */
kb_upd_job *kb_upd_download_start(HWND notify, UINT msg, const kb_update_manifest *m,
                                  const char *current);

LONG kb_upd_job_id(const kb_upd_job *j);
/* KB_UPD_RUNNING until the job has finished; after that, everything the
 * thread wrote is visible to the caller. */
kb_upd_result kb_upd_job_result(kb_upd_job *j);
DWORD kb_upd_job_detail(const kb_upd_job *j);
/* Bytes downloaded so far and the expected total. */
void kb_upd_job_progress(kb_upd_job *j, ULONGLONG *done, ULONGLONG *total);
/* The verified manifest (check: NEWER or CURRENT; download: its input). */
const kb_update_manifest *kb_upd_job_manifest(const kb_upd_job *j);
/* Download result DOWNLOADED only: run the installer with
 * /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /RELAUNCH. The caller must then
 * quit. UI thread. On failure returns FALSE with a Win32 error in *err. */
BOOL kb_upd_launch_installer(kb_upd_job *j, DWORD *err);
/* Drop the UI's reference (cancels the job if it is still running). */
void kb_upd_job_release(kb_upd_job *j);

/* TRUE if this exe runs from the per-user install directory (so the
 * installer can replace it); FALSE for a portable copy. */
BOOL kb_upd_is_installed_copy(void);

#endif
