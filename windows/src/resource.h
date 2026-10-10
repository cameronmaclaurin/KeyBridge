/* KeyBridge - resource IDs (shared by keybridge.rc and the C sources). */
#ifndef KB_RESOURCE_H
#define KB_RESOURCE_H

#define IDI_APP         1     /* first icon: what Explorer shows for KeyBridge.exe */
#define IDI_TRAY_ON     2
#define IDI_TRAY_OFF    3

#define IDD_SETUP       101   /* "Pair with your Mac" */
#define IDD_COMPARE     102   /* compare the 6-digit number */

/* Setup dialog. The Pair button is IDOK. */
#define IDC_HELP_TEXT   1000
#define IDC_LIST_LABEL  1001
#define IDC_MAC_LIST    1002
#define IDC_MANUAL_LABEL 1003
#define IDC_HOST        1004
#define IDC_HOST_HINT   1005
#define IDC_AUTOSTART   1006
#define IDC_SETUP_STATUS 1007

/* Compare dialog. Confirm is deliberately not IDOK, so Enter never confirms
 * by accident. */
#define IDC_CMP_TITLE   1100
#define IDC_CMP_HINT    1101
#define IDC_CMP_NUMBER  1102
#define IDC_CMP_STATUS  1103
#define IDC_CMP_CONFIRM 1104

#ifndef IDC_STATIC
#define IDC_STATIC      (-1)
#endif

#endif
