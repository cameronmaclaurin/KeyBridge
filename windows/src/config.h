/*
 * KeyBridge - settings storage.
 *   %APPDATA%\KeyBridge\config.bin : Mac address + normalized pairing code,
 *                                   encrypted with DPAPI (current user).
 *   HKCU\...\CurrentVersion\Run    : "KeyBridge" = "<quoted exe path>".
 */
#ifndef KB_CONFIG_H
#define KB_CONFIG_H

#include "common.h"
#include "kbutil.h"

typedef struct {
    wchar_t host[KB_HOST_MAX + 1];   /* as typed (trimmed); may include ":port" */
    char    code[KB_CODE_LEN + 1];   /* normalized pairing code */
} kb_config;

/* FALSE if there is no config yet or it cannot be decrypted/parsed. */
BOOL config_load(kb_config *cfg);
BOOL config_save(const kb_config *cfg);
void config_wipe(kb_config *cfg);

BOOL autostart_is_enabled(void);
BOOL autostart_set(BOOL enable);
/* First-run default for "Start KeyBridge when I sign in": the installer's
 * choice if it recorded one, otherwise TRUE. */
BOOL autostart_default(void);

#endif
