/* KeyBridge - resource IDs (shared by keybridge.rc and the C sources). */
#ifndef KB_RESOURCE_H
#define KB_RESOURCE_H

#define IDI_APP         1     /* first icon: what Explorer shows for KeyBridge.exe */
#define IDI_TRAY_ON     2
#define IDI_TRAY_OFF    3

#define IDD_SETTINGS    101

#define IDC_INTRO       1000
#define IDC_HOST        1001
#define IDC_CODE        1002
#define IDC_AUTOSTART   1003
#define IDC_HOST_HINT   1004
#define IDC_CODE_HINT   1005

#ifndef IDC_STATIC
#define IDC_STATIC      (-1)
#endif

#endif
