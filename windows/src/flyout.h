/*
 * KeyBridge - the tray flyout: a Windows 11 style panel that opens above the
 * notification area. flyout.cpp is the only C++ translation unit (no STL, no
 * exceptions, no RTTI); this header is its C API.
 *
 * The flyout knows nothing about the protocol, pairing, discovery, updates or
 * settings storage. main.c describes what to show in a fly_state and the
 * flyout reports what the user asked for through one callback. UI thread
 * only.
 */
#ifndef KB_FLYOUT_H
#define KB_FLYOUT_H

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FLY_NAME_MAX 64  /* == KB_NAME_MAX */
#define FLY_ADDR_MAX 255 /* == KB_HOST_MAX */
#define FLY_MSG_MAX  256
#define FLY_MAX_MACS 8

typedef enum {
    FLY_CONN_UNPAIRED,
    FLY_CONN_CONNECTING,
    FLY_CONN_CONNECTED,
    FLY_CONN_WAITING,
    FLY_CONN_NOT_FOUND,
    FLY_CONN_NOT_PAIRED
} fly_conn;

typedef enum {
    FLY_PAIR_IDLE,
    FLY_PAIR_BUSY,     /* connecting to (or looking up) the chosen Mac */
    FLY_PAIR_COMPARE,  /* the number is on screen */
    FLY_PAIR_WAIT_MAC, /* confirmed here; waiting for the Mac */
    FLY_PAIR_SUCCESS
} fly_pair;

typedef enum {
    FLY_UPD_NONE,
    FLY_UPD_CHECKING,
    FLY_UPD_AVAILABLE,
    FLY_UPD_DOWNLOADING,
    FLY_UPD_INSTALLING,
    FLY_UPD_FAILED
} fly_upd;

typedef enum {
    FLY_SEV_NONE,
    FLY_SEV_INFO,
    FLY_SEV_SUCCESS,
    FLY_SEV_CAUTION,
    FLY_SEV_CRITICAL
} fly_sev;

typedef enum { FLY_PAGE_HOME, FLY_PAGE_PAIR, FLY_PAGE_SETTINGS } fly_page;

typedef struct {
    int     id;                       /* echoed in FLY_ACT_PAIR_MAC */
    wchar_t name[FLY_NAME_MAX + 1];
    wchar_t detail[FLY_ADDR_MAX + 1]; /* "Name.local", or "" while unresolved */
} fly_mac;

typedef struct {
    wchar_t  version[32];                /* "1.6.0" */
    fly_conn conn;
    wchar_t  mac_name[FLY_NAME_MAX + 1]; /* paired Mac: name, else address */
    int      latency_ms;                 /* < 0: not shown */
    BOOL     autostart, clipboard, autoupdate;
    BOOL     discovery_available, searching, search_empty;
    int      nmacs;
    fly_mac  macs[FLY_MAX_MACS];
    fly_pair pair;
    int      pair_mac_id;                /* row being paired, -1 = manual address */
    wchar_t  pair_name[FLY_NAME_MAX + 1];
    uint32_t sas;
    fly_upd  upd;
    wchar_t  upd_version[32];
    BOOL     upd_installable;            /* FALSE: portable copy -> "Download" */
    int      upd_permille;               /* -1 = size unknown */
    wchar_t  upd_status[FLY_MSG_MAX];    /* "Last checked today at 9:41" */
    wchar_t  upd_error[FLY_MSG_MAX];
    fly_sev  notice_sev;                 /* FLY_SEV_NONE = no notice */
    wchar_t  notice_title[FLY_MSG_MAX], notice_text[FLY_MSG_MAX];
} fly_state;

typedef enum {
    FLY_ACT_SHOWN = 1,
    FLY_ACT_HIDDEN,
    FLY_ACT_DISCOVERY,    /* arg 1: the Mac list is on screen; 0: it isn't */
    FLY_ACT_PAIR_MAC,     /* arg = fly_mac.id */
    FLY_ACT_PAIR_ADDRESS, /* text = raw text-field contents */
    FLY_ACT_CANCEL_PAIR,
    FLY_ACT_CONFIRM,
    FLY_ACT_SEARCH_AGAIN,
    FLY_ACT_RECONNECT,
    FLY_ACT_SET_AUTOSTART, /* arg 0/1 */
    FLY_ACT_SET_CLIPBOARD, /* arg 0/1 */
    FLY_ACT_SET_AUTOUPDATE, /* arg 0/1 */
    FLY_ACT_CHECK_UPDATE,
    FLY_ACT_INSTALL_UPDATE,
    FLY_ACT_SKIP_UPDATE,
    FLY_ACT_CANCEL_UPDATE,
    FLY_ACT_WHATS_NEW,
    FLY_ACT_FORGET,        /* after the inline confirmation */
    FLY_ACT_NOTICE_CLOSED,
    FLY_ACT_QUIT
} fly_action;

typedef void (*fly_action_fn)(void *ctx, fly_action a, int arg, const wchar_t *text);

#define FLY_INIT_STICKY       0x1u /* preview: no light dismiss, Esc never hides */
#define FLY_SHOW_KEYBOARD     0x1u /* focus ring + initial focus on the primary control */
#define FLY_SHOW_PROGRAMMATIC 0x2u /* not a tray click */

/* owner/tray_uid identify the notification icon the flyout opens above. */
BOOL flyout_init(HINSTANCE inst, HWND owner, UINT tray_uid, fly_action_fn fn, void *ctx,
                 unsigned flags);
/* Copied. Relayout and repaint if visible. */
void flyout_set_state(const fly_state *s);
/* anchor {-1,-1} = the cursor. FALSE if the flyout can't be shown on this PC
 * (Direct2D/DirectWrite missing); the caller should fall back to its menu. */
BOOL flyout_show(POINT anchor, fly_page page, unsigned show_flags);
/* Tray left click: hide if open, else show the home page. Same return value. */
BOOL flyout_toggle(POINT anchor, unsigned show_flags);
void flyout_hide(void);
BOOL flyout_visible(void);
/* Destroys the windows and releases Direct2D. */
void flyout_shutdown(void);

#ifdef KEYBRIDGE_UI_PREVIEW
/* preview.c (UI preview build only): if the command line asks for a preview,
 * runs it with fake state and returns TRUE with the exit code. */
BOOL kb_preview_main(HINSTANCE inst, int *exit_code);
#endif

#ifdef __cplusplus
}
#endif

#endif
