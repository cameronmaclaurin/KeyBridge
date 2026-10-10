/*
 * KeyBridge - find Macs running KeyBridge on the local network
 * (docs/PROTOCOL.md section 1a): DNS-SD browse of _keybridge._tcp.local with
 * DnsServiceBrowse / DnsServiceResolve. dnsapi.dll is loaded at run time, so
 * on Windows builds without these APIs discovery_available() is FALSE and
 * the app offers manual entry only. Discovery is not trusted; it only saves
 * typing an address.
 *
 * DNS-SD callbacks arrive on system thread-pool threads. They only queue
 * events; the owner is notified (a posted message and/or a signaled event)
 * and drains the queue with discovery_next() on its own thread.
 * discovery_start/stop/resolve must all be called from one thread.
 */
#ifndef KB_DISCOVERY_H
#define KB_DISCOVERY_H

#include "common.h"
#include "kbutil.h"

#define KB_DISC_SERVICE       L"_keybridge._tcp.local"
#define KB_DISC_INSTANCE_MAX  255   /* full DNS name of an instance */

typedef enum {
    KB_DISC_ADDED = 1,      /* instance appeared (PTR record) */
    KB_DISC_REMOVED,        /* instance went away (PTR record with TTL 0) */
    KB_DISC_RESOLVED,       /* host and port known (SRV record or DnsServiceResolve) */
    KB_DISC_RESOLVE_FAILED  /* DnsServiceResolve failed for this instance */
} kb_disc_kind;

typedef struct {
    kb_disc_kind   kind;
    wchar_t        instance[KB_DISC_INSTANCE_MAX + 1]; /* "<name>._keybridge._tcp.local" */
    wchar_t        host[KB_HOST_MAX + 1];              /* RESOLVED: "Name.local", no trailing dot */
    unsigned short port;                               /* RESOLVED */
} kb_disc_event;

/* TRUE if dnsapi.dll exports the DNS-SD functions (Windows 10 1903+). */
BOOL discovery_available(void);

/* Start browsing. Whenever new events are queued, posts msg to hwnd (once
 * until the queue has been drained) and/or sets event; either may be NULL.
 * Stops any earlier browse first. */
BOOL discovery_start(HWND hwnd, UINT msg, HANDLE event);

/* Cancel the browse and any resolves, and drop queued events. Safe to call
 * when not started. After it returns no further notifications are sent. */
void discovery_stop(void);

/* Ask for the host and port of an instance; the answer arrives as a
 * KB_DISC_RESOLVED or KB_DISC_RESOLVE_FAILED event. FALSE if it could not be
 * started (not browsing, too many lookups in flight, or an API error). */
BOOL discovery_resolve(const wchar_t *instance);

/* Pop the next queued event. FALSE when the queue is empty. */
BOOL discovery_next(kb_disc_event *ev);

/* The user-visible name of an instance: the full name without the
 * "._keybridge._tcp.local" suffix, with DNS escapes (\. \\ \ddd) decoded and
 * unprintable characters removed. */
void discovery_label(const wchar_t *instance, wchar_t *out, size_t cap);

#endif
