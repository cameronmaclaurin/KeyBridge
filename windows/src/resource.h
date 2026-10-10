/* KeyBridge - resource IDs (shared by keybridge.rc and the C sources). */
#ifndef KB_RESOURCE_H
#define KB_RESOURCE_H

#define IDI_APP         1     /* first icon: what Explorer shows for KeyBridge.exe */
#define IDI_TRAY_ON     2
#define IDI_TRAY_OFF    3

#define IDD_SETUP       101   /* "Pair with your Mac" */
#define IDD_COMPARE     102   /* compare the 6-digit number */
#define IDD_SETTINGS    103   /* tray menu > Settings... */

/* Dialog header, shared by every dialog: the app icon (owner-drawn, see
 * ui.h), a title and a line of secondary text. */
#define IDC_HDR_ICON     900
#define IDC_HDR_TITLE    901
#define IDC_HDR_SUBTITLE 902

/* Setup dialog. The Pair button is IDOK. IDC_HELP_TEXT is its header's
 * second line. */
#define IDC_HELP_TEXT   1000
#define IDC_LIST_LABEL  1001
#define IDC_MAC_LIST    1002
#define IDC_MANUAL_LABEL 1003
#define IDC_HOST        1004
#define IDC_HOST_HINT   1005
#define IDC_AUTOSTART   1006
#define IDC_SETUP_STATUS 1007

/* Compare dialog. Confirm is deliberately not IDOK, so Enter never confirms
 * by accident. IDC_CMP_TITLE and IDC_CMP_HINT are its header. */
#define IDC_CMP_TITLE   1100
#define IDC_CMP_HINT    1101
#define IDC_CMP_NUMBER  1102
#define IDC_CMP_STATUS  1103
#define IDC_CMP_CONFIRM 1104

/* Settings dialog. Close is IDCANCEL. */
#define IDC_SET_SEC_GENERAL 1200
#define IDC_SET_AUTOSTART   1201
#define IDC_SET_CLIPBOARD   1202
#define IDC_SET_CLIP_HELP   1203
#define IDC_SET_SEP1        1204
#define IDC_SET_SEC_UPDATES 1205
#define IDC_SET_AUTOUPDATE  1206
#define IDC_SET_VERSION     1207
#define IDC_SET_CHECKNOW    1208
#define IDC_SET_SEP2        1209
#define IDC_SET_SEC_MAC     1210
#define IDC_SET_MAC_NAME    1211
#define IDC_SET_MAC_DOT     1212
#define IDC_SET_MAC_STATUS  1213
#define IDC_SET_PAIR        1214
#define IDC_SET_FORGET      1215

#ifndef IDC_STATIC
#define IDC_STATIC      (-1)
#endif

#endif
