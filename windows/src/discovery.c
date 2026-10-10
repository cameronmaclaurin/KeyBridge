/*
 * KeyBridge - DNS-SD discovery of Macs running KeyBridge (see discovery.h).
 */
#include "discovery.h"

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4201) /* nameless struct/union inside the SDK header */
#endif
#include <windns.h>
#ifdef _MSC_VER
#pragma warning(pop)
#endif

#ifndef DNS_REQUEST_PENDING
#define DNS_REQUEST_PENDING 9506L
#endif
#ifndef DNS_QUERY_REQUEST_VERSION1
#define DNS_QUERY_REQUEST_VERSION1 0x1
#endif

/* ------------------------------------------------------------------------ */
/* DNS-SD API (windns.h, dnsapi.dll), loaded at run time                     */
/*                                                                          */
/* The structures are declared here under our own names, with exactly the  */
/* layout of the Windows SDK's DNS_SERVICE_CANCEL, DNS_SERVICE_INSTANCE,    */
/* DNS_SERVICE_BROWSE_REQUEST and DNS_SERVICE_RESOLVE_REQUEST, so the build */
/* does not depend on which SDK (or NTDDI_VERSION guard) declares them and  */
/* nothing links against the DNS-SD exports.                                */
/* ------------------------------------------------------------------------ */

typedef struct {
    PVOID reserved;
} kb_dns_service_cancel;

typedef struct {
    LPWSTR pszInstanceName;
    LPWSTR pszHostName;
    void  *ip4Address;          /* IP4_ADDRESS * */
    void  *ip6Address;          /* IP6_ADDRESS * */
    WORD   wPort;
    WORD   wPriority;
    WORD   wWeight;
    DWORD  dwPropertyCount;
    PWSTR *keys;
    PWSTR *values;
    DWORD  dwInterfaceIndex;
} kb_dns_service_instance;

typedef VOID (WINAPI *kb_dns_browse_callback)(DWORD Status, PVOID pQueryContext,
                                              PDNS_RECORDW pDnsRecord);
typedef VOID (WINAPI *kb_dns_resolve_complete)(DWORD Status, PVOID pQueryContext,
                                               kb_dns_service_instance *pInstance);

typedef struct {
    ULONG                  Version;          /* DNS_QUERY_REQUEST_VERSION1 */
    ULONG                  InterfaceIndex;   /* 0 = all interfaces */
    PCWSTR                 QueryName;
    kb_dns_browse_callback pBrowseCallback;  /* SDK: union { pBrowseCallback; pBrowseCallbackV2; } */
    PVOID                  pQueryContext;
} kb_dns_browse_request;

typedef struct {
    ULONG                   Version;
    ULONG                   InterfaceIndex;
    PWSTR                   QueryName;
    kb_dns_resolve_complete pResolveCompletionCallback;
    PVOID                   pQueryContext;
} kb_dns_resolve_request;

typedef DNS_STATUS (WINAPI *fn_DnsServiceBrowse)(kb_dns_browse_request *, kb_dns_service_cancel *);
typedef DNS_STATUS (WINAPI *fn_DnsServiceCancel)(kb_dns_service_cancel *);
typedef DNS_STATUS (WINAPI *fn_DnsServiceResolve)(kb_dns_resolve_request *, kb_dns_service_cancel *);
typedef VOID (WINAPI *fn_DnsServiceFreeInstance)(kb_dns_service_instance *);
typedef VOID (WINAPI *fn_DnsFree)(PVOID, DNS_FREE_TYPE);

static BOOL                      g_load_tried;
static BOOL                      g_api_ok;
static fn_DnsServiceBrowse       p_DnsServiceBrowse;
static fn_DnsServiceCancel       p_DnsServiceBrowseCancel;
static fn_DnsServiceResolve      p_DnsServiceResolve;
static fn_DnsServiceCancel       p_DnsServiceResolveCancel;
static fn_DnsServiceFreeInstance p_DnsServiceFreeInstance;
static fn_DnsFree                p_DnsFree;

static BOOL load_api(void)
{
    HMODULE m;

    if (g_load_tried)
        return g_api_ok;
    g_load_tried = TRUE;

    /* System32 only. The module stays loaded for the life of the process:
     * a callback may still be running after a cancel. */
    m = LoadLibraryExW(L"dnsapi.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (m == NULL)
        return FALSE;
    p_DnsServiceBrowse        = (fn_DnsServiceBrowse)GetProcAddress(m, "DnsServiceBrowse");
    p_DnsServiceBrowseCancel  = (fn_DnsServiceCancel)GetProcAddress(m, "DnsServiceBrowseCancel");
    p_DnsServiceResolve       = (fn_DnsServiceResolve)GetProcAddress(m, "DnsServiceResolve");
    p_DnsServiceResolveCancel = (fn_DnsServiceCancel)GetProcAddress(m, "DnsServiceResolveCancel");
    p_DnsServiceFreeInstance  = (fn_DnsServiceFreeInstance)GetProcAddress(m, "DnsServiceFreeInstance");
    p_DnsFree                 = (fn_DnsFree)GetProcAddress(m, "DnsFree");
    g_api_ok = p_DnsServiceBrowse != NULL && p_DnsServiceBrowseCancel != NULL &&
               p_DnsServiceResolve != NULL && p_DnsServiceResolveCancel != NULL &&
               p_DnsServiceFreeInstance != NULL && p_DnsFree != NULL;
    return g_api_ok;
}

BOOL discovery_available(void)
{
    return load_api();
}

/* ------------------------------------------------------------------------ */
/* State                                                                    */
/* ------------------------------------------------------------------------ */

#define KB_DISC_QUEUE 64
#define KB_DISC_SLOTS 8
#define KB_CTX_BROWSE 0xFFu

/* Shared with the callbacks; guarded by g_lock. */
static SRWLOCK       g_lock = SRWLOCK_INIT;
static ULONG         g_session;   /* changes on every start and stop */
static BOOL          g_active;
static HWND          g_hwnd;
static UINT          g_msg;
static HANDLE        g_event;
static BOOL          g_posted;    /* a notification message is outstanding */
static kb_disc_event g_queue[KB_DISC_QUEUE];
static unsigned      g_head;
static unsigned      g_count;

/* Owner thread only, except slot.busy (cleared by callbacks under g_lock)
 * and slot.name (read by callbacks under g_lock). Requests, names and cancel
 * handles live in static storage, so nothing the API may still look at after
 * a cancel is ever freed. */
static kb_dns_browse_request g_browse_req;
static kb_dns_service_cancel g_browse_cancel;
static BOOL                  g_browsing;
static struct {
    BOOL                   busy;
    kb_dns_resolve_request req;
    kb_dns_service_cancel  cancel;
    wchar_t                name[KB_DISC_INSTANCE_MAX + 1];
} g_slots[KB_DISC_SLOTS];

/* Callback context: session (low 24 bits) and slot (or KB_CTX_BROWSE). */
static PVOID make_ctx(ULONG session, unsigned slot)
{
    return (PVOID)(ULONG_PTR)(((ULONG_PTR)(session & 0xFFFFFFu) << 8) | (ULONG_PTR)(slot & 0xFFu));
}

static BOOL ctx_current_locked(PVOID ctx)
{
    return g_active && ((((ULONG_PTR)ctx) >> 8) & 0xFFFFFFu) == (ULONG_PTR)(g_session & 0xFFFFFFu);
}

static wchar_t ascii_lower(wchar_t c)
{
    return (c >= L'A' && c <= L'Z') ? (wchar_t)(c + (L'a' - L'A')) : c;
}

static BOOL equal_ci(const wchar_t *a, const wchar_t *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        if (ascii_lower(a[i]) != ascii_lower(b[i]))
            return FALSE;
    }
    return TRUE;
}

static const wchar_t kSuffix[] = L"." KB_DISC_SERVICE; /* "._keybridge._tcp.local" */
#define KB_SUFFIX_LEN (ARRAYSIZE(kSuffix) - 1)

/* Length of name without one trailing dot. */
static size_t name_len(const wchar_t *name)
{
    size_t n = wcslen(name);
    if (n > 0 && name[n - 1] == L'.')
        n--;
    return n;
}

/* "<something>._keybridge._tcp.local[.]" that fits an event. */
static BOOL is_our_instance(const wchar_t *name)
{
    size_t n;
    if (name == NULL)
        return FALSE;
    n = name_len(name);
    return n > KB_SUFFIX_LEN && n <= KB_DISC_INSTANCE_MAX &&
           equal_ci(name + n - KB_SUFFIX_LEN, kSuffix, KB_SUFFIX_LEN);
}

/* Copy without a trailing dot. FALSE if empty or too long. */
static BOOL copy_name(wchar_t *dst, size_t cap, const wchar_t *src)
{
    size_t n;
    dst[0] = 0;
    if (src == NULL)
        return FALSE;
    n = name_len(src);
    if (n == 0 || n >= cap)
        return FALSE;
    memcpy(dst, src, n * sizeof(wchar_t));
    dst[n] = 0;
    return TRUE;
}

static kb_disc_event *push_locked(kb_disc_kind kind, const wchar_t *instance)
{
    kb_disc_event *ev;
    if (g_count == KB_DISC_QUEUE)
        return NULL; /* the owner is not keeping up; drop */
    ev = &g_queue[(g_head + g_count) % KB_DISC_QUEUE];
    memset(ev, 0, sizeof(*ev));
    if (!copy_name(ev->instance, ARRAYSIZE(ev->instance), instance))
        return NULL;
    ev->kind = kind;
    g_count++;
    return ev;
}

static void notify_locked(void)
{
    if (g_event != NULL)
        SetEvent(g_event);
    if (g_hwnd != NULL && !g_posted && PostMessageW(g_hwnd, g_msg, 0, 0))
        g_posted = TRUE;
}

/* ------------------------------------------------------------------------ */
/* Callbacks (system thread pool)                                           */
/* ------------------------------------------------------------------------ */

static VOID WINAPI on_browse(DWORD status, PVOID ctx, PDNS_RECORDW records)
{
    PDNS_RECORDW r;
    BOOL queued = FALSE;

    AcquireSRWLockExclusive(&g_lock);
    if (status == ERROR_SUCCESS && ctx_current_locked(ctx)) {
        for (r = records; r != NULL; r = r->pNext) {
            if (r->wType == DNS_TYPE_PTR && is_our_instance(r->Data.PTR.pNameHost)) {
                /* TTL 0 is a "goodbye": the service went away. */
                if (push_locked(r->dwTtl == 0 ? KB_DISC_REMOVED : KB_DISC_ADDED,
                                r->Data.PTR.pNameHost) != NULL)
                    queued = TRUE;
            } else if (r->wType == DNS_TYPE_SRV && r->dwTtl != 0 && is_our_instance(r->pName)) {
                /* Often included with the PTR: saves a separate resolve. */
                wchar_t host[KB_HOST_MAX + 1];
                if (copy_name(host, ARRAYSIZE(host), r->Data.SRV.pNameTarget)) {
                    kb_disc_event *ev = push_locked(KB_DISC_RESOLVED, r->pName);
                    if (ev != NULL) {
                        memcpy(ev->host, host, sizeof(host));
                        ev->port = r->Data.SRV.wPort;
                        queued = TRUE;
                    }
                }
            }
        }
        if (queued)
            notify_locked();
    }
    ReleaseSRWLockExclusive(&g_lock);

    if (records != NULL)
        p_DnsFree(records, DnsFreeRecordList); /* the callback owns the list */
}

static VOID WINAPI on_resolve(DWORD status, PVOID ctx, kb_dns_service_instance *inst)
{
    unsigned slot = (unsigned)((ULONG_PTR)ctx & 0xFFu);

    AcquireSRWLockExclusive(&g_lock);
    if (slot < KB_DISC_SLOTS && ctx_current_locked(ctx) && g_slots[slot].busy) {
        wchar_t host[KB_HOST_MAX + 1];
        BOOL ok = status == ERROR_SUCCESS && inst != NULL &&
                  copy_name(host, ARRAYSIZE(host), inst->pszHostName);
        kb_disc_event *ev;

        g_slots[slot].busy = FALSE;
        /* Report under the name we asked for, so the owner can match it. */
        ev = push_locked(ok ? KB_DISC_RESOLVED : KB_DISC_RESOLVE_FAILED, g_slots[slot].name);
        if (ev != NULL) {
            if (ok) {
                memcpy(ev->host, host, sizeof(host));
                ev->port = inst->wPort;
            }
            notify_locked();
        }
    }
    ReleaseSRWLockExclusive(&g_lock);

    if (inst != NULL)
        p_DnsServiceFreeInstance(inst); /* the callback owns the instance */
}

/* ------------------------------------------------------------------------ */
/* Owner-thread API                                                         */
/* ------------------------------------------------------------------------ */

void discovery_stop(void)
{
    BOOL busy[KB_DISC_SLOTS];
    unsigned i;

    AcquireSRWLockExclusive(&g_lock);
    g_session++; /* callbacks still in flight now see a stale context */
    g_active = FALSE;
    g_hwnd = NULL;
    g_event = NULL;
    g_posted = FALSE;
    g_head = 0;
    g_count = 0;
    for (i = 0; i < KB_DISC_SLOTS; i++) {
        busy[i] = g_slots[i].busy;
        g_slots[i].busy = FALSE;
    }
    ReleaseSRWLockExclusive(&g_lock);

    /* Cancel outside the lock: a cancel may wait for, or run, a callback. */
    if (g_browsing) {
        g_browsing = FALSE;
        (void)p_DnsServiceBrowseCancel(&g_browse_cancel);
    }
    for (i = 0; i < KB_DISC_SLOTS; i++) {
        if (busy[i])
            (void)p_DnsServiceResolveCancel(&g_slots[i].cancel);
    }
}

BOOL discovery_start(HWND hwnd, UINT msg, HANDLE event)
{
    ULONG session;

    if (!load_api())
        return FALSE;
    discovery_stop();

    AcquireSRWLockExclusive(&g_lock);
    session = ++g_session;
    g_active = TRUE;
    g_hwnd = hwnd;
    g_msg = msg;
    g_event = event;
    g_posted = FALSE;
    g_head = 0;
    g_count = 0;
    ReleaseSRWLockExclusive(&g_lock);

    memset(&g_browse_req, 0, sizeof(g_browse_req));
    g_browse_req.Version = DNS_QUERY_REQUEST_VERSION1;
    g_browse_req.InterfaceIndex = 0;
    g_browse_req.QueryName = KB_DISC_SERVICE;
    g_browse_req.pBrowseCallback = on_browse;
    g_browse_req.pQueryContext = make_ctx(session, KB_CTX_BROWSE);
    memset(&g_browse_cancel, 0, sizeof(g_browse_cancel));

    if (p_DnsServiceBrowse(&g_browse_req, &g_browse_cancel) != DNS_REQUEST_PENDING) {
        discovery_stop();
        return FALSE;
    }
    g_browsing = TRUE;
    return TRUE;
}

BOOL discovery_resolve(const wchar_t *instance)
{
    unsigned i, slot = KB_DISC_SLOTS;
    BOOL already = FALSE;
    ULONG session;
    size_t len;

    if (!g_api_ok || instance == NULL)
        return FALSE;
    len = name_len(instance);
    if (len == 0 || len > KB_DISC_INSTANCE_MAX)
        return FALSE;

    AcquireSRWLockExclusive(&g_lock);
    session = g_session;
    if (g_active) {
        for (i = 0; i < KB_DISC_SLOTS; i++) {
            if (g_slots[i].busy) {
                if (name_len(g_slots[i].name) == len && equal_ci(g_slots[i].name, instance, len))
                    already = TRUE; /* that lookup's answer will do */
            } else if (slot == KB_DISC_SLOTS) {
                slot = i;
            }
        }
        if (!already && slot < KB_DISC_SLOTS) {
            memcpy(g_slots[slot].name, instance, len * sizeof(wchar_t));
            g_slots[slot].name[len] = 0;
            g_slots[slot].busy = TRUE;
        }
    }
    ReleaseSRWLockExclusive(&g_lock);

    if (already)
        return TRUE;
    if (slot == KB_DISC_SLOTS)
        return FALSE;

    memset(&g_slots[slot].req, 0, sizeof(g_slots[slot].req));
    g_slots[slot].req.Version = DNS_QUERY_REQUEST_VERSION1;
    g_slots[slot].req.InterfaceIndex = 0;
    g_slots[slot].req.QueryName = g_slots[slot].name;
    g_slots[slot].req.pResolveCompletionCallback = on_resolve;
    g_slots[slot].req.pQueryContext = make_ctx(session, slot);
    memset(&g_slots[slot].cancel, 0, sizeof(g_slots[slot].cancel));

    if (p_DnsServiceResolve(&g_slots[slot].req, &g_slots[slot].cancel) != DNS_REQUEST_PENDING) {
        AcquireSRWLockExclusive(&g_lock);
        if (g_session == session)
            g_slots[slot].busy = FALSE;
        ReleaseSRWLockExclusive(&g_lock);
        return FALSE;
    }
    return TRUE;
}

BOOL discovery_next(kb_disc_event *ev)
{
    BOOL ok = FALSE;

    AcquireSRWLockExclusive(&g_lock);
    if (g_count > 0) {
        *ev = g_queue[g_head];
        g_head = (g_head + 1) % KB_DISC_QUEUE;
        g_count--;
        ok = TRUE;
    } else {
        g_posted = FALSE; /* drained: the next event posts a new notification */
    }
    ReleaseSRWLockExclusive(&g_lock);
    return ok;
}

/* ------------------------------------------------------------------------ */
/* Display name                                                             */
/* ------------------------------------------------------------------------ */

static int escape_value(const wchar_t *s, size_t i, size_t len)
{
    int v;
    /* "\ddd": a backslash and three decimal digits, value 0..255. */
    if (i + 3 >= len || s[i] != L'\\')
        return -1;
    if (s[i + 1] < L'0' || s[i + 1] > L'9' || s[i + 2] < L'0' || s[i + 2] > L'9' ||
        s[i + 3] < L'0' || s[i + 3] > L'9')
        return -1;
    v = (int)(s[i + 1] - L'0') * 100 + (int)(s[i + 2] - L'0') * 10 + (int)(s[i + 3] - L'0');
    return v <= 255 ? v : -1;
}

void discovery_label(const wchar_t *instance, wchar_t *out, size_t cap)
{
    wchar_t tmp[KB_DISC_INSTANCE_MAX + 1];
    char bytes[KB_DISC_INSTANCE_MAX + 1];
    size_t len, i = 0, n = 0;

    if (cap == 0)
        return;
    out[0] = 0;
    if (instance == NULL)
        return;
    len = name_len(instance);
    if (len > KB_SUFFIX_LEN && equal_ci(instance + len - KB_SUFFIX_LEN, kSuffix, KB_SUFFIX_LEN))
        len -= KB_SUFFIX_LEN;
    if (len > KB_DISC_INSTANCE_MAX)
        len = KB_DISC_INSTANCE_MAX;

    while (i < len && n + 1 < ARRAYSIZE(tmp)) {
        if (escape_value(instance, i, len) >= 0) {
            /* A run of \ddd escapes is a UTF-8 byte sequence. */
            size_t nb = 0;
            int v, w;
            while (nb < sizeof(bytes) && (v = escape_value(instance, i, len)) >= 0) {
                bytes[nb++] = (char)(unsigned char)v;
                i += 4;
            }
            w = MultiByteToWideChar(CP_UTF8, 0, bytes, (int)nb, tmp + n,
                                    (int)(ARRAYSIZE(tmp) - 1 - n));
            if (w > 0)
                n += (size_t)w;
        } else if (instance[i] == L'\\' && i + 1 < len) {
            tmp[n++] = instance[i + 1]; /* "\." -> ".", "\\" -> "\" */
            i += 2;
        } else {
            tmp[n++] = instance[i++];
        }
    }
    tmp[n] = 0;
    (void)kb_sanitize_name(tmp, n, out, cap);
}
