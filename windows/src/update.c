/*
 * KeyBridge - secure auto-update (see update.h and docs/UPDATES.md).
 *
 * Trust: the ECDSA P-256 signature over update-manifest.txt is the root of
 * trust (HTTPS alone is not enough). The installer is accepted only if its
 * size and SHA-256 match the signed manifest. It is verified a second time
 * through a read handle that denies writers, and that handle stays open until
 * the installer has been started, so the file that runs is the file that was
 * checked.
 */
#include "update.h"
#include "kbutil.h"
#include "crypto.h"

#include <limits.h>
#include <winhttp.h>
#include <shlobj.h>
#include <strsafe.h>

/* Older or third-party SDK headers may lack these. Values are from the Windows SDK. */
#ifndef BCRYPT_SUCCESS
#define BCRYPT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#ifndef BCRYPT_ECDSA_P256_ALGORITHM
#define BCRYPT_ECDSA_P256_ALGORITHM L"ECDSA_P256"
#endif
#ifndef BCRYPT_ECDSA_PUBLIC_P256_MAGIC
#define BCRYPT_ECDSA_PUBLIC_P256_MAGIC 0x31534345 /* "ECS1" */
#endif
#ifndef WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY
#define WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY 4
#endif
#ifndef ERROR_INVALID_STATE
#define ERROR_INVALID_STATE 5023L
#endif

/* tools/update_pubkey.txt, verbatim (CI checks that they are equal). */
const char kb_update_pubkey_hex[] =
    "04290216611bac006bab98e63c0a3fa68f3c6bb49293fd65cec42c7b323f2caea9cbe542a9b238561284afe444746c091ab8cfc37aa50a01c40cf3477968d8df33";

#define KB_UPD_MANIFEST_URL L"https://github.com/cameronmaclaurin/KeyBridge/releases/latest/download/update-manifest.txt"
#define KB_UPD_SIG_URL      L"https://github.com/cameronmaclaurin/KeyBridge/releases/latest/download/update-manifest.sig"
#define KB_UPD_DIR_PREFIX   L"KeyBridge-update-"
#define KB_UPD_FILE_NAME    L"KeyBridge-Windows-Setup.exe"
#define KB_UPD_SETUP_ARGS   L" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /RELAUNCH"
/* Inno Setup's uninstall key for AppId {2E6550FF-...} (installer.iss). */
#define KB_UPD_INNO_KEY     L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{2E6550FF-4C8C-4A49-A08B-636892AB8489}_is1"
#define KB_UPD_CHUNK        65536u

#define KB_TIMEOUT_RESOLVE_MS 15000
#define KB_TIMEOUT_CONNECT_MS 15000
#define KB_TIMEOUT_SEND_MS    30000
#define KB_TIMEOUT_RECEIVE_MS 30000

/* http_get's "the body was received in full" (not a final job result). */
#define HTTP_DONE KB_UPD_RUNNING

enum { JOB_CHECK = 1, JOB_DOWNLOAD = 2 };

struct kb_upd_job {
    volatile LONG      refs;
    volatile LONG      cancel;
    volatile LONG      result;  /* kb_upd_result; written last by the thread */
    volatile LONG64    done;    /* download progress, bytes */
    LONG               id;
    int                kind;
    HWND               notify;
    UINT               msg;
    DWORD              detail;
    BOOL               launched;
    HANDLE             lock;    /* read handle denying writers to the verified installer */
    char               current[KB_UPD_VERSION_MAX + 1];
    wchar_t            agent[48];
    wchar_t            dir[MAX_PATH];
    wchar_t            path[MAX_PATH];
    kb_update_manifest manifest;
    uint8_t            manifest_buf[KB_UPD_META_MAX];
    uint8_t            sig_buf[KB_UPD_META_MAX];
};

static volatile LONG g_next_job_id;

/* ------------------------------------------------------------------------ */
/* SHA-256 and signature verification (CNG)                                 */
/* ------------------------------------------------------------------------ */

typedef struct {
    BCRYPT_ALG_HANDLE  alg;
    BCRYPT_HASH_HANDLE hash;
} sha_ctx;

static void sha_end(sha_ctx *c)
{
    if (c->hash != NULL) {
        BCryptDestroyHash(c->hash);
        c->hash = NULL;
    }
    if (c->alg != NULL) {
        BCryptCloseAlgorithmProvider(c->alg, 0);
        c->alg = NULL;
    }
}

static BOOL sha_begin(sha_ctx *c)
{
    c->alg = NULL;
    c->hash = NULL;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&c->alg, BCRYPT_SHA256_ALGORITHM, NULL, 0))) {
        c->alg = NULL;
        return FALSE;
    }
    if (!BCRYPT_SUCCESS(BCryptCreateHash(c->alg, &c->hash, NULL, 0, NULL, 0, 0))) {
        c->hash = NULL;
        sha_end(c);
        return FALSE;
    }
    return TRUE;
}

static BOOL sha_add(sha_ctx *c, const void *p, ULONG n)
{
    return n == 0 || BCRYPT_SUCCESS(BCryptHashData(c->hash, (PUCHAR)p, n, 0));
}

static BOOL sha_finish(sha_ctx *c, uint8_t out[KB_SHA256_LEN])
{
    return BCRYPT_SUCCESS(BCryptFinishHash(c->hash, out, KB_SHA256_LEN, 0));
}

/* ECDSA P-256 / SHA-256 over msg; sig is raw r || s (what CNG expects). */
static BOOL ecdsa_p256_verify(const uint8_t *msg, size_t len, const uint8_t sig[KB_UPD_SIG_LEN],
                              const uint8_t pub[KB_UPD_PUBKEY_LEN])
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    BCRYPT_ECCKEY_BLOB hdr;
    uint8_t blob[sizeof(BCRYPT_ECCKEY_BLOB) + 64];
    uint8_t hash[KB_SHA256_LEN];
    sha_ctx sc;
    BOOL ok;

    if (len > KB_UPD_META_MAX || !kb_p256_point_valid(pub))
        return FALSE;
    if (!sha_begin(&sc))
        return FALSE;
    ok = sha_add(&sc, msg, (ULONG)len) && sha_finish(&sc, hash);
    sha_end(&sc);
    if (!ok)
        return FALSE;

    /* BCRYPT_ECCPUBLIC_BLOB = header || X || Y (big-endian). */
    hdr.dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
    hdr.cbKey = 32;
    memcpy(blob, &hdr, sizeof(hdr));
    memcpy(blob + sizeof(hdr), pub + 1, 64);

    ok = FALSE;
    if (BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0))) {
        if (BCRYPT_SUCCESS(BCryptImportKeyPair(alg, NULL, BCRYPT_ECCPUBLIC_BLOB, &key, blob,
                                               (ULONG)sizeof(blob), 0))) {
            ok = BCryptVerifySignature(key, NULL, hash, (ULONG)sizeof(hash), (PUCHAR)sig,
                                       KB_UPD_SIG_LEN, 0) == 0; /* STATUS_SUCCESS only */
            BCryptDestroyKey(key);
        }
        BCryptCloseAlgorithmProvider(alg, 0);
    }
    SecureZeroMemory(blob, sizeof(blob));
    return ok;
}

kb_upd_verdict kb_upd_evaluate(const uint8_t *manifest, size_t manifest_len,
                               const uint8_t *sig, size_t sig_len,
                               const uint8_t *pubkey, const char *current,
                               kb_update_manifest *out)
{
    uint8_t embedded[KB_UPD_PUBKEY_LEN];
    uint8_t raw_sig[KB_UPD_SIG_LEN];

    memset(out, 0, sizeof(*out));
    if (manifest == NULL || sig == NULL || current == NULL)
        return KB_UPD_V_INVALID;
    if (manifest_len == 0 || manifest_len > KB_UPD_META_MAX || sig_len > KB_UPD_META_MAX)
        return KB_UPD_V_INVALID;
    if (!kb_upd_version_valid(current, strlen(current)))
        return KB_UPD_V_INVALID;
    if (pubkey == NULL) {
        if (!kb_upd_hex_decode(kb_update_pubkey_hex, strlen(kb_update_pubkey_hex), embedded,
                               sizeof(embedded)))
            return KB_UPD_V_INVALID;
        pubkey = embedded;
    }

    /* The signature first; nothing in the manifest is looked at before it verifies. */
    if (!kb_upd_decode_sig(sig, sig_len, raw_sig) ||
        !ecdsa_p256_verify(manifest, manifest_len, raw_sig, pubkey))
        return KB_UPD_V_INVALID;
    if (!kb_upd_parse_manifest(manifest, manifest_len, out))
        return KB_UPD_V_INVALID;
    return kb_upd_version_compare(out->version, current) > 0 ? KB_UPD_V_NEWER : KB_UPD_V_CURRENT;
}

/* ------------------------------------------------------------------------ */
/* Jobs                                                                     */
/* ------------------------------------------------------------------------ */

static BOOL job_cancelled(kb_upd_job *j)
{
    return InterlockedCompareExchange(&j->cancel, 0, 0) != 0;
}

/* Close the lock handle and delete the downloaded installer and its directory. */
static void discard_files(kb_upd_job *j)
{
    if (j->lock != INVALID_HANDLE_VALUE) {
        CloseHandle(j->lock);
        j->lock = INVALID_HANDLE_VALUE;
    }
    if (j->path[0] != 0) {
        (void)DeleteFileW(j->path);
        j->path[0] = 0;
    }
    if (j->dir[0] != 0) {
        (void)RemoveDirectoryW(j->dir);
        j->dir[0] = 0;
    }
}

static void job_release(kb_upd_job *j)
{
    if (InterlockedDecrement(&j->refs) != 0)
        return;
    if (j->launched) {
        /* The installer is running from it: leave the file; the next check
         * (cleanup_stale) removes it. */
        if (j->lock != INVALID_HANDLE_VALUE)
            CloseHandle(j->lock);
    } else {
        discard_files(j);
    }
    HeapFree(GetProcessHeap(), 0, j);
}

/* Worker thread: publish the result, tell the UI, drop the thread's reference. */
static void job_finish(kb_upd_job *j, kb_upd_result r)
{
    HWND notify = j->notify;
    UINT msg = j->msg;
    LONG id = j->id;

    InterlockedExchange(&j->result, (LONG)r);
    if (notify != NULL)
        (void)PostMessageW(notify, msg, 0, (LPARAM)id);
    job_release(j);
}

static kb_upd_job *job_new(int kind, HWND notify, UINT msg, const char *current)
{
    kb_upd_job *j;
    size_t n, i;

    if (current == NULL)
        return NULL;
    n = strlen(current);
    if (!kb_upd_version_valid(current, n))
        return NULL;
    j = (kb_upd_job *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*j));
    if (j == NULL)
        return NULL;
    j->refs = 2; /* the UI's and the thread's */
    j->id = InterlockedIncrement(&g_next_job_id);
    j->kind = kind;
    j->notify = notify;
    j->msg = msg;
    j->lock = INVALID_HANDLE_VALUE;
    memcpy(j->current, current, n + 1);
    /* User-Agent "KeyBridge/X.Y.Z" (the version is plain ASCII). */
    (void)StringCchCopyW(j->agent, ARRAYSIZE(j->agent), L"KeyBridge/");
    for (i = wcslen(j->agent); *current != 0 && i + 1 < ARRAYSIZE(j->agent); current++)
        j->agent[i++] = (wchar_t)(unsigned char)*current;
    j->agent[i] = 0;
    return j;
}

static kb_upd_job *job_start(kb_upd_job *j, LPTHREAD_START_ROUTINE fn)
{
    HANDLE th = CreateThread(NULL, 0, fn, j, 0, NULL);
    if (th == NULL) {
        j->refs = 1;
        job_release(j);
        return NULL;
    }
    CloseHandle(th); /* the reference count, not a join, ends the job */
    return j;
}

LONG kb_upd_job_id(const kb_upd_job *j)
{
    return j->id;
}

kb_upd_result kb_upd_job_result(kb_upd_job *j)
{
    return (kb_upd_result)InterlockedCompareExchange(&j->result, 0, 0);
}

DWORD kb_upd_job_detail(const kb_upd_job *j)
{
    return j->detail;
}

void kb_upd_job_progress(kb_upd_job *j, ULONGLONG *done, ULONGLONG *total)
{
    *done = (ULONGLONG)InterlockedCompareExchange64(&j->done, 0, 0);
    *total = j->kind == JOB_DOWNLOAD ? (ULONGLONG)j->manifest.windows_size : 0u;
}

const kb_update_manifest *kb_upd_job_manifest(const kb_upd_job *j)
{
    return &j->manifest;
}

void kb_upd_job_release(kb_upd_job *j)
{
    if (j == NULL)
        return;
    InterlockedExchange(&j->cancel, 1);
    job_release(j);
}

/* ------------------------------------------------------------------------ */
/* HTTPS (WinHTTP, synchronous, on the job's thread)                        */
/* ------------------------------------------------------------------------ */

typedef BOOL (*sink_fn)(void *ctx, const uint8_t *p, DWORD n);

typedef struct {
    uint8_t *buf;
    size_t   len;
    size_t   cap;
} mem_sink;

static BOOL mem_write(void *ctx, const uint8_t *p, DWORD n)
{
    mem_sink *m = (mem_sink *)ctx;
    if (n > m->cap - m->len)
        return FALSE;
    memcpy(m->buf + m->len, p, n);
    m->len += n;
    return TRUE;
}

typedef struct {
    HANDLE      file;
    sha_ctx    *sha;
    kb_upd_job *job;
    ULONGLONG   total;
} file_sink;

static BOOL file_write(void *ctx, const uint8_t *p, DWORD n)
{
    file_sink *fs = (file_sink *)ctx;
    DWORD written = 0;

    if (!WriteFile(fs->file, p, n, &written, NULL) || written != n)
        return FALSE;
    if (!sha_add(fs->sha, p, n)) {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }
    fs->total += n;
    InterlockedExchange64(&fs->job->done, (LONG64)fs->total);
    return TRUE;
}

/* Default redirect policy (never HTTPS -> HTTP) and certificate validation;
 * the system proxy settings. */
static HINTERNET open_session(const kb_upd_job *j)
{
    HINTERNET s = WinHttpOpen(j->agent, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME,
                              WINHTTP_NO_PROXY_BYPASS, 0);
    if (s == NULL)
        return NULL;
    (void)WinHttpSetTimeouts(s, KB_TIMEOUT_RESOLVE_MS, KB_TIMEOUT_CONNECT_MS, KB_TIMEOUT_SEND_MS,
                             KB_TIMEOUT_RECEIVE_MS);
    return s;
}

/* GET url and stream the body (at most limit bytes) into sink. Returns
 * HTTP_DONE when the whole body arrived, too_large if it is bigger than
 * limit, or another error result (j->detail says more). */
static kb_upd_result http_get(kb_upd_job *j, HINTERNET session, const wchar_t *url,
                              ULONGLONG limit, kb_upd_result too_large,
                              sink_fn sink, void *ctx, uint8_t *buf, DWORD buf_len)
{
    URL_COMPONENTS uc;
    wchar_t host[256];
    wchar_t path[KB_UPD_URL_MAX + 1];
    wchar_t extra[KB_UPD_URL_MAX + 1];
    wchar_t object[2 * KB_UPD_URL_MAX + 2];
    HINTERNET conn = NULL, req = NULL;
    DWORD status = 0, clen = 0, cb, n;
    ULONGLONG total = 0;
    kb_upd_result r = KB_UPD_ERR_NETWORK;

    memset(&uc, 0, sizeof(uc));
    uc.dwStructSize = (DWORD)sizeof(uc);
    uc.lpszHostName = host;
    uc.dwHostNameLength = (DWORD)ARRAYSIZE(host);
    uc.lpszUrlPath = path;
    uc.dwUrlPathLength = (DWORD)ARRAYSIZE(path);
    uc.lpszExtraInfo = extra;
    uc.dwExtraInfoLength = (DWORD)ARRAYSIZE(extra);
    if (!WinHttpCrackUrl(url, 0, 0, &uc) || uc.nScheme != INTERNET_SCHEME_HTTPS || host[0] == 0 ||
        FAILED(StringCchCopyW(object, ARRAYSIZE(object), path)) ||
        FAILED(StringCchCatW(object, ARRAYSIZE(object), extra))) {
        j->detail = ERROR_INVALID_PARAMETER;
        return KB_UPD_ERR_INTERNAL;
    }

    conn = WinHttpConnect(session, host, uc.nPort, 0);
    if (conn == NULL)
        goto net_fail;
    req = WinHttpOpenRequest(conn, L"GET", object, NULL, WINHTTP_NO_REFERER,
                             WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (req == NULL)
        goto net_fail;
    if (!WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(req, NULL))
        goto net_fail;

    cb = (DWORD)sizeof(status);
    if (!WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &status, &cb, WINHTTP_NO_HEADER_INDEX))
        goto net_fail;
    if (status != 200) {
        j->detail = status;
        r = KB_UPD_ERR_HTTP;
        goto done;
    }
    /* Refuse early if the server announces too much; the loop below is what
     * actually enforces the limit. */
    cb = (DWORD)sizeof(clen);
    if (WinHttpQueryHeaders(req, WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &clen, &cb, WINHTTP_NO_HEADER_INDEX) &&
        clen > limit) {
        r = too_large;
        goto done;
    }

    for (;;) {
        if (job_cancelled(j)) {
            r = KB_UPD_ERR_CANCELLED;
            goto done;
        }
        n = 0;
        if (!WinHttpReadData(req, buf, buf_len, &n))
            goto net_fail;
        if (n == 0)
            break;
        if (n > buf_len || (ULONGLONG)n > limit - total) {
            r = too_large;
            goto done;
        }
        if (!sink(ctx, buf, n)) {
            j->detail = GetLastError();
            r = KB_UPD_ERR_FILE;
            goto done;
        }
        total += n;
    }
    r = HTTP_DONE;
    goto done;

net_fail:
    j->detail = GetLastError();
    r = KB_UPD_ERR_NETWORK;
done:
    if (req != NULL)
        WinHttpCloseHandle(req);
    if (conn != NULL)
        WinHttpCloseHandle(conn);
    return r;
}

/* ------------------------------------------------------------------------ */
/* Temporary files                                                          */
/* ------------------------------------------------------------------------ */

/* The PID in "<pid>-<random>", or 0. */
static DWORD dir_pid(const wchar_t *s)
{
    ULONGLONG v = 0;
    int digits = 0;

    for (; *s >= L'0' && *s <= L'9'; s++) {
        if (++digits > 10)
            return 0;
        v = v * 10u + (ULONGLONG)(*s - L'0');
    }
    if (digits == 0 || *s != L'-' || v > 0xFFFFFFFFu)
        return 0;
    return (DWORD)v;
}

/* Remove installers left behind by earlier runs (after a successful update
 * the installer cannot delete itself). Only our own file name inside our own
 * "KeyBridge-update-<pid>-<random>" directories is touched; directories of
 * this process and reparse points are skipped. */
static void cleanup_stale(void)
{
    wchar_t tmp[MAX_PATH + 1], pattern[MAX_PATH], dir[MAX_PATH], file[MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE h;
    size_t plen = wcslen(KB_UPD_DIR_PREFIX);
    DWORD n = GetTempPathW((DWORD)ARRAYSIZE(tmp), tmp);

    if (n == 0 || n >= ARRAYSIZE(tmp))
        return;
    if (FAILED(StringCchPrintfW(pattern, ARRAYSIZE(pattern), L"%ls%ls*", tmp, KB_UPD_DIR_PREFIX)))
        return;
    h = FindFirstFileExW(pattern, FindExInfoBasic, &fd, FindExSearchLimitToDirectories, NULL, 0);
    if (h == INVALID_HANDLE_VALUE)
        return;
    do {
        if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
            (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            continue;
        /* The pattern can also match short (8.3) names: check the real name. */
        if (wcslen(fd.cFileName) <= plen ||
            CompareStringOrdinal(fd.cFileName, (int)plen, KB_UPD_DIR_PREFIX, (int)plen, TRUE) != CSTR_EQUAL)
            continue;
        if (dir_pid(fd.cFileName + plen) == GetCurrentProcessId())
            continue;
        if (FAILED(StringCchPrintfW(dir, ARRAYSIZE(dir), L"%ls%ls", tmp, fd.cFileName)) ||
            FAILED(StringCchPrintfW(file, ARRAYSIZE(file), L"%ls\\%ls", dir, KB_UPD_FILE_NAME)))
            continue;
        (void)DeleteFileW(file);
        (void)RemoveDirectoryW(dir); /* fails, harmlessly, if anything else is in it */
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

/* A new, uniquely named directory in the user's temp directory. */
static BOOL make_temp_dir(kb_upd_job *j)
{
    wchar_t tmp[MAX_PATH + 1];
    DWORD n = GetTempPathW((DWORD)ARRAYSIZE(tmp), tmp);
    int attempt;

    if (n == 0 || n >= ARRAYSIZE(tmp))
        return FALSE;
    for (attempt = 0; attempt < 8; attempt++) {
        ULONGLONG rnd = 0;
        if (!kb_random(&rnd, (ULONG)sizeof(rnd)))
            return FALSE;
        if (FAILED(StringCchPrintfW(j->dir, ARRAYSIZE(j->dir), L"%ls%ls%lu-%016llx", tmp,
                                    KB_UPD_DIR_PREFIX, GetCurrentProcessId(), rnd))) {
            j->dir[0] = 0;
            SetLastError(ERROR_BUFFER_OVERFLOW);
            return FALSE;
        }
        if (CreateDirectoryW(j->dir, NULL)) {
            if (FAILED(StringCchPrintfW(j->path, ARRAYSIZE(j->path), L"%ls\\%ls", j->dir,
                                        KB_UPD_FILE_NAME))) {
                (void)RemoveDirectoryW(j->dir);
                j->dir[0] = 0;
                j->path[0] = 0;
                SetLastError(ERROR_BUFFER_OVERFLOW);
                return FALSE;
            }
            return TRUE;
        }
        if (GetLastError() != ERROR_ALREADY_EXISTS) {
            j->dir[0] = 0;
            return FALSE;
        }
    }
    j->dir[0] = 0;
    return FALSE;
}

/* SHA-256 and length of a whole file, read from the start. */
static BOOL hash_file(HANDLE f, uint8_t *buf, DWORD buf_len, uint8_t out[KB_SHA256_LEN],
                      ULONGLONG *size)
{
    LARGE_INTEGER zero;
    sha_ctx sc;
    DWORD n;
    BOOL ok = FALSE;

    *size = 0;
    zero.QuadPart = 0;
    if (!SetFilePointerEx(f, zero, NULL, FILE_BEGIN) || !sha_begin(&sc))
        return FALSE;
    for (;;) {
        n = 0;
        if (!ReadFile(f, buf, buf_len, &n, NULL))
            break;
        if (n == 0) {
            ok = sha_finish(&sc, out);
            break;
        }
        if (!sha_add(&sc, buf, n))
            break;
        *size += n;
    }
    sha_end(&sc);
    return ok;
}

static BOOL utf8_to_wide(const char *s, wchar_t *out, size_t cap)
{
    return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, out, (int)cap) > 0;
}

/* ------------------------------------------------------------------------ */
/* Worker threads                                                           */
/* ------------------------------------------------------------------------ */

static DWORD WINAPI check_thread(LPVOID param)
{
    kb_upd_job *j = (kb_upd_job *)param;
    kb_upd_result r = KB_UPD_ERR_INTERNAL;
    HINTERNET session = NULL;
    uint8_t *chunk;
    mem_sink ms, ss;

    ms.buf = j->manifest_buf;
    ms.len = 0;
    ms.cap = sizeof(j->manifest_buf);
    ss.buf = j->sig_buf;
    ss.len = 0;
    ss.cap = sizeof(j->sig_buf);
    cleanup_stale();
    chunk = (uint8_t *)HeapAlloc(GetProcessHeap(), 0, KB_UPD_CHUNK);
    if (chunk == NULL)
        goto done;
    session = open_session(j);
    if (session == NULL) {
        j->detail = GetLastError();
        r = KB_UPD_ERR_NETWORK;
        goto done;
    }

    r = http_get(j, session, KB_UPD_MANIFEST_URL, KB_UPD_META_MAX, KB_UPD_ERR_TOO_LARGE,
                 mem_write, &ms, chunk, KB_UPD_CHUNK);
    if (r == HTTP_DONE)
        r = http_get(j, session, KB_UPD_SIG_URL, KB_UPD_META_MAX, KB_UPD_ERR_TOO_LARGE,
                     mem_write, &ss, chunk, KB_UPD_CHUNK);
    if (r == HTTP_DONE) {
        switch (kb_upd_evaluate(ms.buf, ms.len, ss.buf, ss.len, NULL, j->current, &j->manifest)) {
        case KB_UPD_V_NEWER:
            r = KB_UPD_NEWER;
            break;
        case KB_UPD_V_CURRENT:
            r = KB_UPD_CURRENT;
            break;
        case KB_UPD_V_INVALID:
        default:
            r = KB_UPD_ERR_INVALID;
            break;
        }
    }

done:
    if (session != NULL)
        WinHttpCloseHandle(session);
    if (chunk != NULL)
        HeapFree(GetProcessHeap(), 0, chunk);
    if (r != KB_UPD_NEWER && r != KB_UPD_CURRENT && job_cancelled(j))
        r = KB_UPD_ERR_CANCELLED;
    job_finish(j, r);
    return 0;
}

static DWORD WINAPI download_thread(LPVOID param)
{
    kb_upd_job *j = (kb_upd_job *)param;
    kb_upd_result r = KB_UPD_ERR_INTERNAL;
    HANDLE f = INVALID_HANDLE_VALUE;
    HINTERNET session = NULL;
    uint8_t *chunk = NULL;
    uint8_t expected[KB_SHA256_LEN], digest[KB_SHA256_LEN];
    wchar_t url[KB_UPD_URL_MAX + 1];
    ULONGLONG size = 0;
    file_sink fs;
    sha_ctx sha;

    memset(&sha, 0, sizeof(sha));
    memset(&fs, 0, sizeof(fs));
    cleanup_stale();
    if (!kb_upd_hex_decode(j->manifest.windows_sha256, KB_UPD_SHA256_HEX, expected, sizeof(expected)) ||
        !utf8_to_wide(j->manifest.windows_url, url, ARRAYSIZE(url)))
        goto done;
    chunk = (uint8_t *)HeapAlloc(GetProcessHeap(), 0, KB_UPD_CHUNK);
    if (chunk == NULL || !sha_begin(&sha))
        goto done;

    if (!make_temp_dir(j)) {
        j->detail = GetLastError();
        r = KB_UPD_ERR_FILE;
        goto done;
    }
    f = CreateFileW(j->path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        j->detail = GetLastError();
        r = KB_UPD_ERR_FILE;
        goto done;
    }
    session = open_session(j);
    if (session == NULL) {
        j->detail = GetLastError();
        r = KB_UPD_ERR_NETWORK;
        goto done;
    }

    fs.file = f;
    fs.sha = &sha;
    fs.job = j;
    fs.total = 0;
    /* Anything larger than windows-size is rejected while it streams in. */
    r = http_get(j, session, url, j->manifest.windows_size, KB_UPD_ERR_DAMAGED, file_write, &fs,
                 chunk, KB_UPD_CHUNK);
    if (r != HTTP_DONE)
        goto done;
    if (!CloseHandle(f)) {
        f = INVALID_HANDLE_VALUE;
        j->detail = GetLastError();
        r = KB_UPD_ERR_FILE;
        goto done;
    }
    f = INVALID_HANDLE_VALUE;
    if (fs.total != j->manifest.windows_size || !sha_finish(&sha, digest) ||
        !kb_ct_equal(digest, expected, sizeof(digest))) {
        r = KB_UPD_ERR_DAMAGED;
        goto done;
    }

    /* Reopen read-only, denying writers and deleters until the installer has
     * been started, and check the bytes that will actually run once more. */
    j->lock = CreateFileW(j->path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                          FILE_ATTRIBUTE_NORMAL, NULL);
    if (j->lock == INVALID_HANDLE_VALUE) {
        j->detail = GetLastError();
        r = KB_UPD_ERR_FILE;
        goto done;
    }
    if (!hash_file(j->lock, chunk, KB_UPD_CHUNK, digest, &size) ||
        size != j->manifest.windows_size || !kb_ct_equal(digest, expected, sizeof(digest))) {
        r = KB_UPD_ERR_DAMAGED;
        goto done;
    }
    r = KB_UPD_DOWNLOADED;

done:
    if (f != INVALID_HANDLE_VALUE)
        CloseHandle(f);
    if (session != NULL)
        WinHttpCloseHandle(session);
    sha_end(&sha);
    if (chunk != NULL)
        HeapFree(GetProcessHeap(), 0, chunk);
    if (r != KB_UPD_DOWNLOADED) {
        if (job_cancelled(j))
            r = KB_UPD_ERR_CANCELLED;
        discard_files(j); /* never leave a bad or partial installer behind */
    }
    job_finish(j, r);
    return 0;
}

kb_upd_job *kb_upd_check_start(HWND notify, UINT msg, const char *current)
{
    kb_upd_job *j = job_new(JOB_CHECK, notify, msg, current);
    if (j == NULL)
        return NULL;
    return job_start(j, check_thread);
}

kb_upd_job *kb_upd_download_start(HWND notify, UINT msg, const kb_update_manifest *m,
                                  const char *current)
{
    kb_upd_job *j;

    if (m == NULL || m->windows_url[0] == 0 || m->windows_size == 0 ||
        m->windows_size > KB_UPD_SIZE_MAX || strlen(m->windows_sha256) != KB_UPD_SHA256_HEX)
        return NULL;
    j = job_new(JOB_DOWNLOAD, notify, msg, current);
    if (j == NULL)
        return NULL;
    j->manifest = *m;
    return job_start(j, download_thread);
}

/* ------------------------------------------------------------------------ */
/* Installing                                                               */
/* ------------------------------------------------------------------------ */

BOOL kb_upd_launch_installer(kb_upd_job *j, DWORD *err)
{
    wchar_t cmd[MAX_PATH + 64];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    BOOL ok;

    *err = ERROR_INVALID_STATE;
    if (j == NULL || j->kind != JOB_DOWNLOAD || kb_upd_job_result(j) != KB_UPD_DOWNLOADED ||
        j->launched || j->lock == INVALID_HANDLE_VALUE || j->path[0] == 0)
        return FALSE;
    /* The full path, quoted, then the silent-update switches. */
    if (FAILED(StringCchPrintfW(cmd, ARRAYSIZE(cmd), L"\"%ls\"%ls", j->path, KB_UPD_SETUP_ARGS))) {
        *err = ERROR_BUFFER_OVERFLOW;
        return FALSE;
    }
    memset(&si, 0, sizeof(si));
    si.cb = (DWORD)sizeof(si);
    memset(&pi, 0, sizeof(pi));
    ok = CreateProcessW(j->path, cmd, NULL, NULL, FALSE, 0, NULL, j->dir, &si, &pi);
    if (!ok && GetLastError() == ERROR_SHARING_VIOLATION) {
        /* Should not happen (the lock handle shares reads, which is all that
         * starting a process needs), but never let the lock block an update. */
        CloseHandle(j->lock);
        j->lock = INVALID_HANDLE_VALUE;
        ok = CreateProcessW(j->path, cmd, NULL, NULL, FALSE, 0, NULL, j->dir, &si, &pi);
    }
    if (!ok) {
        *err = GetLastError();
        return FALSE;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    j->launched = TRUE;
    *err = 0;
    return TRUE;
}

/* exe's directory (with a trailing backslash) equals dir, ignoring case. */
static BOOL exe_in_dir(const wchar_t *exe, const wchar_t *dir)
{
    size_t dlen = wcslen(dir), elen = wcslen(exe);

    if (dlen < 4 || dir[dlen - 1] != L'\\' || elen <= dlen || dlen > (size_t)INT_MAX)
        return FALSE;
    if (CompareStringOrdinal(exe, (int)dlen, dir, (int)dlen, TRUE) != CSTR_EQUAL)
        return FALSE;
    return wcschr(exe + dlen, L'\\') == NULL;
}

BOOL kb_upd_is_installed_copy(void)
{
    wchar_t exe[1024];
    wchar_t dir[1024];
    DWORD n, cb;

    n = GetModuleFileNameW(NULL, exe, (DWORD)ARRAYSIZE(exe));
    if (n == 0 || n >= ARRAYSIZE(exe))
        return FALSE;

    /* The installer's default: %LOCALAPPDATA%\Programs\KeyBridge\ */
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, SHGFP_TYPE_CURRENT, dir)) &&
        SUCCEEDED(StringCchCatW(dir, ARRAYSIZE(dir), L"\\Programs\\KeyBridge\\")) &&
        exe_in_dir(exe, dir))
        return TRUE;

    /* Or wherever the per-user installer put it (first installs may choose
     * the folder); the silent update reuses that folder. */
    cb = (DWORD)(sizeof(dir) - 2 * sizeof(wchar_t));
    if (RegGetValueW(HKEY_CURRENT_USER, KB_UPD_INNO_KEY, L"InstallLocation", RRF_RT_REG_SZ, NULL,
                     dir, &cb) == ERROR_SUCCESS) {
        size_t len = wcslen(dir);
        if (len > 0 && dir[len - 1] != L'\\')
            (void)StringCchCatW(dir, ARRAYSIZE(dir), L"\\");
        if (exe_in_dir(exe, dir))
            return TRUE;
    }
    return FALSE;
}
