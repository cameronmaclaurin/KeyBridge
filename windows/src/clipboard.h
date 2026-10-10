/*
 * KeyBridge - shared clipboard, Windows side (docs/PROTOCOL.md section 5a,
 * "Clipboard behavior"). Plain text only, both directions.
 *
 * A message-only window on the UI thread watches the clipboard with
 * AddClipboardFormatListener. While a session is up and the Mac said it can
 * receive clipboard text (CAPS bit0) and "Share clipboard" is on, each change
 * is read as CF_UNICODETEXT, converted to UTF-8 and left in a one-slot
 * outgoing buffer; the wake event tells the connection worker, which is the
 * only thread that writes to the socket. Text received by the worker goes
 * the other way through a one-slot incoming buffer and a posted message, and
 * the window sets it as CF_UNICODETEXT.
 *
 * Contents are never logged. Text buffers handed across are malloc'd and
 * released with kbclip_free (which wipes them).
 */
#ifndef KB_CLIPBOARD_H
#define KB_CLIPBOARD_H

#include "common.h"

/* UI thread. Call once at startup, before the first worker_start, from the
 * thread that runs the message loop. FALSE if the window could not be created
 * (the app then works without clipboard sharing). */
BOOL   clipboard_init(HINSTANCE inst);
/* UI thread, at exit (after worker_stop). Safe to call more than once, and
 * safe even if a worker is somehow still running. */
void   clipboard_shutdown(void);

/* UI thread: the auto-reset event that is set when outgoing text is waiting.
 * worker_start duplicates it for its thread. NULL if clipboard_init failed. */
HANDLE clipboard_wake_event(void);

/* ---- Worker thread ------------------------------------------------------ */

/* TRUE if received text can be applied (the window exists). */
BOOL   clipboard_available(void);
/* A session was authenticated. Clears pending text and the dedupe hash, so
 * the clipboard that existed before the session is never pushed. Returns the
 * session's id (nonzero) for the calls below. */
LONG   clipboard_session_begin(void);
/* The peer's CAPS arrived; can_receive = its bit0. Only then are local
 * clipboard changes picked up for this session. */
void   clipboard_session_peer_caps(LONG session, BOOL can_receive);
/* The session ended. Ignored if a newer session has begun since. */
void   clipboard_session_end(LONG session);
/* Take the waiting outgoing text, if any (1..1 MiB of UTF-8). The caller
 * owns *text and frees it with kbclip_free(*text, *len). */
BOOL   clipboard_take_outgoing(LONG session, uint8_t **text, size_t *len);
/* A complete, valid UTF-8 transfer arrived. Takes ownership of text (always:
 * it is freed here if it cannot be delivered) and asks the UI thread to set
 * it on the clipboard. */
void   clipboard_deliver_incoming(LONG session, uint8_t *text, size_t len);

#endif
