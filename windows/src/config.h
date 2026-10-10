/*
 * KeyBridge - settings storage.
 *   %APPDATA%\KeyBridge\config.bin : Mac address, Mac display name and the
 *                                   32-byte long-term key from pairing,
 *                                   encrypted with DPAPI (current user).
 *   HKCU\...\CurrentVersion\Run    : "KeyBridge" = "<quoted exe path>".
 *   HKCU\Software\KeyBridge         : StartAtSignIn (installer), AutoUpdate,
 *                                   SkippedVersion, LastUpdateCheck.
 */
#ifndef KB_CONFIG_H
#define KB_CONFIG_H

#include "common.h"
#include "kbutil.h"

#define KB_LTK_LEN 32

typedef struct {
    wchar_t host[KB_HOST_MAX + 1];     /* host name or address; may include ":port" */
    wchar_t mac_name[KB_NAME_MAX + 1]; /* for display; may be empty */
    uint8_t ltk[KB_LTK_LEN];           /* session psk; never logged */
} kb_config;

/* FALSE if there is no config yet or it cannot be decrypted/parsed. A v1.1
 * config (typed pairing code) is not accepted: the user pairs again. */
BOOL config_load(kb_config *cfg);
BOOL config_save(const kb_config *cfg);
/* Forget the pairing: delete config.bin. TRUE if it is gone. */
BOOL config_delete(void);
void config_wipe(kb_config *cfg);

BOOL autostart_is_enabled(void);
BOOL autostart_set(BOOL enable);
/* First-run default for "Start KeyBridge when I sign in": the installer's
 * choice if it recorded one, otherwise TRUE. */
BOOL autostart_default(void);

/* "Automatically Check for Updates": AutoUpdate DWORD, default on. */
BOOL prefs_auto_update(void);
BOOL prefs_set_auto_update(BOOL enable);
/* "Skip This Version": SkippedVersion string (an X.Y.Z version). */
BOOL prefs_is_skipped_version(const char *version);
BOOL prefs_set_skipped_version(const char *version);
/* When the last update check succeeded: LastUpdateCheck QWORD, seconds since
 * 1970 (UTC); 0 if never. */
ULONGLONG prefs_last_update_check(void);
BOOL prefs_set_last_update_check(ULONGLONG unix_seconds);

#endif
