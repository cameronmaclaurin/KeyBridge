/*
 * KeyBridge - settings storage (see config.h).
 *
 * config.bin = CryptProtectData(plain, entropy "KeyBridge config v2"), plain =
 *     "KBC2" || host_chars (uint16 LE) || host (UTF-16LE)
 *            || name_chars (uint16 LE) || mac_name (UTF-16LE) || ltk (32)
 *
 * v1.1 wrote "KBC1" (a typed pairing code) with entropy "KeyBridge config
 * v1"; that no longer decrypts or parses, so a v1.1 user simply pairs again.
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
#define KB_PREF_AUTO_UPDATE L"AutoUpdate"
#define KB_PREF_SHARE_CLIPBOARD L"ShareClipboard"
#define KB_PREF_SKIPPED   L"SkippedVersion"
#define KB_PREF_LAST_CHECK L"LastUpdateCheck"
#define KB_VERSION_CHARS  32
#define KB_CONFIG_FILE    L"config.bin"
#define KB_CONFIG_TMP     L"config.bin.tmp"
#define KB_CONFIG_MAX     65536

static const BYTE kMagic[4] = { 'K', 'B', 'C', '2' };
static const char kEntropy[] = "KeyBridge config v2";

#define PLAIN_MAX (4 + 2 + KB_HOST_MAX * 2 + 2 + KB_NAME_MAX * 2 + KB_LTK_LEN)

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

/* Read a uint16-LE length-prefixed UTF-16LE string at p[*off]. */
static BOOL read_string(const BYTE *p, DWORD n, DWORD *off, wchar_t *out, DWORD max_chars,
                        BOOL allow_empty)
{
    DWORD len, i;

    if (n - *off < 2)
        return FALSE;
    len = (DWORD)p[*off] | ((DWORD)p[*off + 1] << 8);
    *off += 2;
    if ((len == 0 && !allow_empty) || len > max_chars || n - *off < len * 2)
        return FALSE;
    for (i = 0; i < len; i++)
        out[i] = (wchar_t)((DWORD)p[*off + 2 * i] | ((DWORD)p[*off + 2 * i + 1] << 8));
    out[len] = 0;
    *off += len * 2;
    return wcslen(out) == len; /* no embedded NULs */
}

static void write_string(BYTE *p, DWORD *off, const wchar_t *s, size_t len)
{
    size_t i;
    p[(*off)++] = (BYTE)(len & 0xFF);
    p[(*off)++] = (BYTE)((len >> 8) & 0xFF);
    for (i = 0; i < len; i++) {
        p[(*off)++] = (BYTE)(s[i] & 0xFF);
        p[(*off)++] = (BYTE)((s[i] >> 8) & 0xFF);
    }
}

static BOOL parse_plain(const BYTE *p, DWORD n, kb_config *cfg)
{
    DWORD off = 4;

    if (n < 4 || memcmp(p, kMagic, sizeof(kMagic)) != 0)
        return FALSE;
    if (!read_string(p, n, &off, cfg->host, KB_HOST_MAX, FALSE) ||
        !read_string(p, n, &off, cfg->mac_name, KB_NAME_MAX, TRUE))
        return FALSE;
    if (n - off != KB_LTK_LEN)
        return FALSE;
    memcpy(cfg->ltk, p + off, KB_LTK_LEN);
    return TRUE;
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
    size_t nlen = wcslen(cfg->mac_name);
    DWORD n = 0, written = 0;
    HANDLE f;
    BOOL ok = FALSE;

    out.pbData = NULL;
    out.cbData = 0;
    if (hlen == 0 || hlen > KB_HOST_MAX || nlen > KB_NAME_MAX)
        return FALSE;

    memcpy(plain, kMagic, sizeof(kMagic));
    n = (DWORD)sizeof(kMagic);
    write_string(plain, &n, cfg->host, hlen);
    write_string(plain, &n, cfg->mac_name, nlen);
    memcpy(plain + n, cfg->ltk, KB_LTK_LEN);
    n += KB_LTK_LEN;

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

BOOL config_delete(void)
{
    wchar_t path[MAX_PATH], tmp[MAX_PATH];

    if (!config_path(path, KB_CONFIG_FILE, FALSE))
        return FALSE;
    if (config_path(tmp, KB_CONFIG_TMP, FALSE))
        (void)DeleteFileW(tmp);
    if (!DeleteFileW(path)) {
        DWORD err = GetLastError();
        return err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND;
    }
    return TRUE;
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

/* ------------------------------------------------------------------------ */
/* Update preferences (HKCU\Software\KeyBridge)                             */
/* ------------------------------------------------------------------------ */

static BOOL pref_set(const wchar_t *name, DWORD type, const void *data, DWORD cb)
{
    HKEY key = NULL;
    LSTATUS r = RegCreateKeyExW(HKEY_CURRENT_USER, KB_APP_KEY, 0, NULL, 0, KEY_SET_VALUE, NULL,
                                &key, NULL);
    if (r != ERROR_SUCCESS)
        return FALSE;
    r = RegSetValueExW(key, name, 0, type, (const BYTE *)data, cb);
    RegCloseKey(key);
    return r == ERROR_SUCCESS;
}

BOOL prefs_auto_update(void)
{
    DWORD v = 1, cb = sizeof(v);
    if (RegGetValueW(HKEY_CURRENT_USER, KB_APP_KEY, KB_PREF_AUTO_UPDATE, RRF_RT_REG_DWORD,
                     NULL, &v, &cb) == ERROR_SUCCESS)
        return v != 0;
    return TRUE;
}

BOOL prefs_set_auto_update(BOOL enable)
{
    DWORD v = enable ? 1u : 0u;
    return pref_set(KB_PREF_AUTO_UPDATE, REG_DWORD, &v, (DWORD)sizeof(v));
}

BOOL prefs_share_clipboard(void)
{
    DWORD v = 1, cb = sizeof(v);
    if (RegGetValueW(HKEY_CURRENT_USER, KB_APP_KEY, KB_PREF_SHARE_CLIPBOARD, RRF_RT_REG_DWORD,
                     NULL, &v, &cb) == ERROR_SUCCESS)
        return v != 0;
    return TRUE;
}

BOOL prefs_set_share_clipboard(BOOL enable)
{
    DWORD v = enable ? 1u : 0u;
    return pref_set(KB_PREF_SHARE_CLIPBOARD, REG_DWORD, &v, (DWORD)sizeof(v));
}

/* An ASCII version string as UTF-16. FALSE if it is empty or too long. */
static BOOL version_to_wide(const char *version, wchar_t out[KB_VERSION_CHARS + 1])
{
    size_t i;
    for (i = 0; version[i] != 0; i++) {
        if (i >= KB_VERSION_CHARS || (unsigned char)version[i] >= 0x80)
            return FALSE;
        out[i] = (wchar_t)version[i];
    }
    out[i] = 0;
    return i > 0;
}

BOOL prefs_is_skipped_version(const char *version)
{
    wchar_t want[KB_VERSION_CHARS + 1], have[KB_VERSION_CHARS + 1];
    DWORD cb = sizeof(have);

    if (!version_to_wide(version, want))
        return FALSE;
    if (RegGetValueW(HKEY_CURRENT_USER, KB_APP_KEY, KB_PREF_SKIPPED, RRF_RT_REG_SZ, NULL,
                     have, &cb) != ERROR_SUCCESS)
        return FALSE;
    return wcscmp(want, have) == 0;
}

BOOL prefs_set_skipped_version(const char *version)
{
    wchar_t v[KB_VERSION_CHARS + 1];
    if (!version_to_wide(version, v))
        return FALSE;
    return pref_set(KB_PREF_SKIPPED, REG_SZ, v, (DWORD)((wcslen(v) + 1) * sizeof(wchar_t)));
}

ULONGLONG prefs_last_update_check(void)
{
    ULONGLONG v = 0;
    DWORD cb = sizeof(v);
    if (RegGetValueW(HKEY_CURRENT_USER, KB_APP_KEY, KB_PREF_LAST_CHECK, RRF_RT_REG_QWORD,
                     NULL, &v, &cb) != ERROR_SUCCESS)
        return 0;
    return v;
}

BOOL prefs_set_last_update_check(ULONGLONG unix_seconds)
{
    return pref_set(KB_PREF_LAST_CHECK, REG_QWORD, &unix_seconds, (DWORD)sizeof(unix_seconds));
}
