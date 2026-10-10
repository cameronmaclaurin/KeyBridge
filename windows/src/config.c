/*
 * KeyBridge - settings storage (see config.h).
 *
 * config.bin = CryptProtectData(plain), plain =
 *     "KBC1" || host_chars (uint16 LE) || host (UTF-16LE) || code (20 ASCII)
 */
#include "config.h"

#include <wincrypt.h>
#include <shlobj.h>
#include <strsafe.h>

#define KB_RUN_KEY        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
#define KB_APPROVED_KEY   L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run"
#define KB_RUN_VALUE      L"KeyBridge"
#define KB_APP_KEY        L"Software\\KeyBridge"
#define KB_PREF_AUTOSTART L"StartAtSignIn"
#define KB_CONFIG_FILE    L"config.bin"
#define KB_CONFIG_TMP     L"config.bin.tmp"
#define KB_CONFIG_MAX     65536

static const BYTE kMagic[4] = { 'K', 'B', 'C', '1' };
static const char kEntropy[] = "KeyBridge config v1";

#define PLAIN_MAX (4 + 2 + KB_HOST_MAX * 2 + KB_CODE_LEN)

void config_wipe(kb_config *cfg)
{
    SecureZeroMemory(cfg, sizeof(*cfg));
}

static BOOL config_path(wchar_t path[MAX_PATH], const wchar_t *file, BOOL create_dir)
{
    wchar_t dir[MAX_PATH];

    if (FAILED(SHGetFolderPathW(NULL, CSIDL_APPDATA | CSIDL_FLAG_CREATE, NULL,
                                SHGFP_TYPE_CURRENT, dir)))
        return FALSE;
    if (FAILED(StringCchCatW(dir, MAX_PATH, L"\\KeyBridge")))
        return FALSE;
    if (create_dir && !CreateDirectoryW(dir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
        return FALSE;
    if (FAILED(StringCchCopyW(path, MAX_PATH, dir)) ||
        FAILED(StringCchCatW(path, MAX_PATH, L"\\")) ||
        FAILED(StringCchCatW(path, MAX_PATH, file)))
        return FALSE;
    return TRUE;
}

static void entropy_blob(DATA_BLOB *b)
{
    b->pbData = (BYTE *)kEntropy;
    b->cbData = (DWORD)(sizeof(kEntropy) - 1);
}

static BOOL parse_plain(const BYTE *p, DWORD n, kb_config *cfg)
{
    wchar_t wcode[KB_CODE_LEN + 1];
    char code[KB_CODE_LEN + 1];
    DWORD hlen, i;
    const BYTE *cp;
    BOOL ok = FALSE;

    if (n < 6 || memcmp(p, kMagic, sizeof(kMagic)) != 0)
        return FALSE;
    hlen = (DWORD)p[4] | ((DWORD)p[5] << 8);
    if (hlen == 0 || hlen > KB_HOST_MAX || n != 6 + hlen * 2 + KB_CODE_LEN)
        return FALSE;

    for (i = 0; i < hlen; i++)
        cfg->host[i] = (wchar_t)((DWORD)p[6 + 2 * i] | ((DWORD)p[7 + 2 * i] << 8));
    cfg->host[hlen] = 0;
    if (wcslen(cfg->host) != hlen)
        return FALSE;

    cp = p + 6 + hlen * 2;
    for (i = 0; i < KB_CODE_LEN; i++)
        wcode[i] = (wchar_t)cp[i];
    wcode[KB_CODE_LEN] = 0;
    /* Stored codes are already normalized; anything else is corrupt. */
    if (kb_normalize_code(wcode, code) && memcmp(code, cp, KB_CODE_LEN) == 0) {
        memcpy(cfg->code, code, sizeof(cfg->code));
        ok = TRUE;
    }
    SecureZeroMemory(wcode, sizeof(wcode));
    SecureZeroMemory(code, sizeof(code));
    return ok;
}

BOOL config_load(kb_config *cfg)
{
    wchar_t path[MAX_PATH];
    HANDLE f;
    LARGE_INTEGER size;
    BYTE *buf = NULL;
    DWORD got = 0;
    DATA_BLOB in, out, ent;
    BOOL ok = FALSE;

    config_wipe(cfg);
    out.pbData = NULL;
    out.cbData = 0;
    if (!config_path(path, KB_CONFIG_FILE, FALSE))
        return FALSE;
    f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE)
        return FALSE;

    if (!GetFileSizeEx(f, &size) || size.QuadPart <= 0 || size.QuadPart > KB_CONFIG_MAX)
        goto done;
    buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)size.QuadPart);
    if (buf == NULL)
        goto done;
    if (!ReadFile(f, buf, (DWORD)size.QuadPart, &got, NULL) || got != (DWORD)size.QuadPart)
        goto done;

    in.pbData = buf;
    in.cbData = got;
    entropy_blob(&ent);
    if (!CryptUnprotectData(&in, NULL, &ent, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &out))
        goto done;
    ok = parse_plain(out.pbData, out.cbData, cfg);

done:
    if (out.pbData != NULL) {
        SecureZeroMemory(out.pbData, out.cbData);
        LocalFree(out.pbData);
    }
    if (buf != NULL)
        HeapFree(GetProcessHeap(), 0, buf);
    CloseHandle(f);
    if (!ok)
        config_wipe(cfg);
    return ok;
}

BOOL config_save(const kb_config *cfg)
{
    BYTE plain[PLAIN_MAX];
    wchar_t path[MAX_PATH], tmp[MAX_PATH];
    DATA_BLOB in, out, ent;
    size_t hlen = wcslen(cfg->host);
    size_t i;
    DWORD n, written = 0;
    HANDLE f;
    BOOL ok = FALSE;

    out.pbData = NULL;
    out.cbData = 0;
    if (hlen == 0 || hlen > KB_HOST_MAX || strlen(cfg->code) != KB_CODE_LEN)
        return FALSE;

    memcpy(plain, kMagic, sizeof(kMagic));
    plain[4] = (BYTE)(hlen & 0xFF);
    plain[5] = (BYTE)((hlen >> 8) & 0xFF);
    for (i = 0; i < hlen; i++) {
        plain[6 + 2 * i] = (BYTE)(cfg->host[i] & 0xFF);
        plain[7 + 2 * i] = (BYTE)((cfg->host[i] >> 8) & 0xFF);
    }
    memcpy(plain + 6 + hlen * 2, cfg->code, KB_CODE_LEN);
    n = (DWORD)(6 + hlen * 2 + KB_CODE_LEN);

    in.pbData = plain;
    in.cbData = n;
    entropy_blob(&ent);
    if (!CryptProtectData(&in, L"KeyBridge settings", &ent, NULL, NULL,
                          CRYPTPROTECT_UI_FORBIDDEN, &out))
        goto done;
    if (!config_path(path, KB_CONFIG_FILE, TRUE) || !config_path(tmp, KB_CONFIG_TMP, TRUE))
        goto done;

    /* Write a temp file and rename it over the old one, so a crash never
     * leaves a half-written config. */
    f = CreateFileW(tmp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE)
        goto done;
    ok = WriteFile(f, out.pbData, out.cbData, &written, NULL) && written == out.cbData &&
         FlushFileBuffers(f);
    CloseHandle(f);
    if (ok)
        ok = MoveFileExW(tmp, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
    if (!ok)
        DeleteFileW(tmp);

done:
    SecureZeroMemory(plain, sizeof(plain));
    if (out.pbData != NULL)
        LocalFree(out.pbData);
    return ok;
}

/* ------------------------------------------------------------------------ */
/* Start with Windows                                                       */
/* ------------------------------------------------------------------------ */

/* Task Manager's Startup tab disables a Run entry by writing a binary value
 * under StartupApproved\Run whose first byte is odd. */
static BOOL disabled_in_task_manager(void)
{
    BYTE data[16];
    DWORD cb = sizeof(data);
    if (RegGetValueW(HKEY_CURRENT_USER, KB_APPROVED_KEY, KB_RUN_VALUE, RRF_RT_REG_BINARY,
                     NULL, data, &cb) != ERROR_SUCCESS || cb == 0)
        return FALSE;
    return (data[0] & 1) != 0;
}

BOOL autostart_is_enabled(void)
{
    DWORD cb = 0;
    if (RegGetValueW(HKEY_CURRENT_USER, KB_RUN_KEY, KB_RUN_VALUE, RRF_RT_ANY,
                     NULL, NULL, &cb) != ERROR_SUCCESS)
        return FALSE;
    return !disabled_in_task_manager();
}

BOOL autostart_set(BOOL enable)
{
    LSTATUS r;

    /* Clear any Task Manager override so our setting is what takes effect. */
    (void)RegDeleteKeyValueW(HKEY_CURRENT_USER, KB_APPROVED_KEY, KB_RUN_VALUE);

    if (enable) {
        wchar_t exe[1024];
        wchar_t value[1024 + 3];
        HKEY key = NULL;
        DWORD n = GetModuleFileNameW(NULL, exe, (DWORD)ARRAYSIZE(exe));

        if (n == 0 || n >= ARRAYSIZE(exe))
            return FALSE;
        if (FAILED(StringCchCopyW(value, ARRAYSIZE(value), L"\"")) ||
            FAILED(StringCchCatW(value, ARRAYSIZE(value), exe)) ||
            FAILED(StringCchCatW(value, ARRAYSIZE(value), L"\"")))
            return FALSE;
        r = RegCreateKeyExW(HKEY_CURRENT_USER, KB_RUN_KEY, 0, NULL, 0, KEY_SET_VALUE, NULL, &key, NULL);
        if (r != ERROR_SUCCESS)
            return FALSE;
        r = RegSetValueExW(key, KB_RUN_VALUE, 0, REG_SZ, (const BYTE *)value,
                           (DWORD)((wcslen(value) + 1) * sizeof(wchar_t)));
        RegCloseKey(key);
        return r == ERROR_SUCCESS;
    }

    r = RegDeleteKeyValueW(HKEY_CURRENT_USER, KB_RUN_KEY, KB_RUN_VALUE);
    return r == ERROR_SUCCESS || r == ERROR_FILE_NOT_FOUND;
}

BOOL autostart_default(void)
{
    DWORD v = 1, cb = sizeof(v);
    if (RegGetValueW(HKEY_CURRENT_USER, KB_APP_KEY, KB_PREF_AUTOSTART, RRF_RT_REG_DWORD,
                     NULL, &v, &cb) == ERROR_SUCCESS)
        return v != 0;
    return TRUE;
}
