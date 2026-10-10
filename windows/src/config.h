/*
 * KeyBridge - settings storage.
 *   %APPDATA%\KeyBridge\config.bin : Mac address, Mac display name and the
 *                                   32-byte long-term key from pairing,
 *                                   encrypted with DPAPI (current user).
 *   HKCU\...\CurrentVersion\Run    : "KeyBridge" = "<quoted exe path>".
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

#endif
