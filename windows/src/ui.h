/*
 * KeyBridge - dialog look and feel for Windows 10 and 11.
 *
 * Included by main.c only (everything here is static); it is not a separate
 * translation unit and build.bat does not compile it on its own.
 *
 * The dialogs use the Task Dialog layout, so they match the update prompt:
 * a white content area that starts with a header (the app icon, a semibold
 * title and a line of secondary text) and a light-gray command area along
 * the bottom for the buttons. Every color comes from the system or is
 * replaced by a system color in High Contrast. Classic controls are not
 * dark-themed (Windows has no supported way to do that); only the title bar
 * follows the system app theme, through DWMWA_USE_IMMERSIVE_DARK_MODE.
 *
 * Fonts: the templates use Segoe UI 9 pt. On Windows 11, Segoe UI Variable
 * replaces it at the same size. Fonts and the header icon are created for
 * the dialog's DPI and created again after WM_DPICHANGED (PerMonitorV2).
 *
 * Each dialog keeps a ui_state, calls ui_init in WM_INITDIALOG, passes every
 * message to ui_dialog_message first, and calls ui_free in WM_DESTROY.
 */
#ifndef KB_UI_H
#define KB_UI_H

#include "common.h"

#include <commctrl.h>
#include <strsafe.h>

#include "resource.h"

/* Posted to a dialog once DefDlgProc has rescaled it for a new DPI. */
#define WM_KB_UI_DPI (WM_APP + 32)

/* dwmapi.h's DWMWA_USE_IMMERSIVE_DARK_MODE (Windows 10 20H1 and later). */
#define KB_DWMWA_USE_IMMERSIVE_DARK_MODE 20

typedef enum {
    UI_BODY = 0,
    UI_STRONG,     /* semibold body text: section labels */
    UI_TITLE,      /* header title */
    UI_BIG,        /* the 6-digit number (owner-drawn) */
    UI_SECONDARY,  /* hints and the header's second line */
    UI_SEPARATOR,  /* owner-drawn 1 px line */
    UI_ICON,       /* owner-drawn header icon */
    UI_DOT         /* the colored connection dot in Settings */
} ui_role;

typedef struct {
    UINT  dpi;
    HFONT body;    /* Segoe UI Variable Text, or NULL to keep the template's Segoe UI */
    HFONT strong;
    HFONT title;
    HFONT big;     /* only for a dialog with IDC_CMP_NUMBER */
    HICON icon;    /* only for a dialog with IDC_HDR_ICON */
    int   icon_px;
} ui_state;

/* Defined in main.c: the connection dot's color (not High Contrast). */
static COLORREF ui_dot_color(void);

static ui_role ui_role_of(int id)
{
    switch (id) {
    case IDC_HDR_ICON:
        return UI_ICON;
    case IDC_HDR_TITLE:
    case IDC_CMP_TITLE:
        return UI_TITLE;
    case IDC_CMP_NUMBER:
        return UI_BIG;
    case IDC_HDR_SUBTITLE:
    case IDC_HELP_TEXT:
    case IDC_HOST_HINT:
    case IDC_CMP_HINT:
    case IDC_SET_CLIP_HELP:
    case IDC_SET_MAC_STATUS:
        return UI_SECONDARY;
    case IDC_SET_SEC_GENERAL:
    case IDC_SET_SEC_UPDATES:
    case IDC_SET_SEC_MAC:
        return UI_STRONG;
    case IDC_SET_SEP1:
    case IDC_SET_SEP2:
        return UI_SEPARATOR;
    case IDC_SET_MAC_DOT:
        return UI_DOT;
    default:
        return UI_BODY;
    }
}

/* ------------------------------------------------------------------------ */
/* System state                                                             */
/* ------------------------------------------------------------------------ */

typedef UINT (WINAPI *ui_fn_GetDpiForWindow)(HWND);
typedef HRESULT (WINAPI *ui_fn_DwmSetWindowAttribute)(HWND, DWORD, LPCVOID, DWORD);

/* GetDpiForWindow is Windows 10 1607+; looked up at run time. */
static UINT ui_dpi(HWND hwnd)
{
    static ui_fn_GetDpiForWindow fn;
    static BOOL looked;
    UINT dpi = 0;

    if (!looked) {
        HMODULE user32 = GetModuleHandleW(L"user32.dll");
        if (user32 != NULL)
            fn = (ui_fn_GetDpiForWindow)GetProcAddress(user32, "GetDpiForWindow");
        looked = TRUE;
    }
    if (fn != NULL && hwnd != NULL)
        dpi = fn(hwnd);
    if (dpi == 0) {
        HDC dc = GetDC(NULL);
        if (dc != NULL) {
            dpi = (UINT)GetDeviceCaps(dc, LOGPIXELSY);
            ReleaseDC(NULL, dc);
        }
    }
    return dpi != 0 ? dpi : 96u;
}

static int ui_px(const ui_state *st, int px96)
{
    int px = MulDiv(px96, (int)st->dpi, 96);
    return px > 0 ? px : 1;
}

static BOOL ui_high_contrast(void)
{
    HIGHCONTRASTW hc;
    memset(&hc, 0, sizeof(hc));
    hc.cbSize = (UINT)sizeof(hc);
    return SystemParametersInfoW(SPI_GETHIGHCONTRAST, (UINT)sizeof(hc), &hc, 0) &&
           (hc.dwFlags & HCF_HIGHCONTRASTON) != 0;
}

/* Settings > Personalization > Colors > "Choose your default app mode". */
static BOOL ui_apps_use_dark_theme(void)
{
    DWORD light = 1, cb = (DWORD)sizeof(light);

    if (ui_high_contrast())
        return FALSE; /* High Contrast themes color the title bar themselves */
    if (RegGetValueW(HKEY_CURRENT_USER,
                     L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
                     L"AppsUseLightTheme", RRF_RT_REG_DWORD, NULL, &light, &cb) != ERROR_SUCCESS)
        return FALSE;
    return light == 0;
}

/* Dark or light title bar to match the system app theme. Older Windows
 * versions reject the attribute, which leaves the usual title bar. */
static void ui_title_bar(HWND hwnd, BOOL redraw)
{
    static ui_fn_DwmSetWindowAttribute fn;
    static BOOL looked;
    BOOL dark;

    if (!looked) {
        HMODULE dwm = LoadLibraryExW(L"dwmapi.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (dwm != NULL) /* stays loaded for the life of the process */
            fn = (ui_fn_DwmSetWindowAttribute)GetProcAddress(dwm, "DwmSetWindowAttribute");
        looked = TRUE;
    }
    if (fn == NULL || hwnd == NULL)
        return;
    dark = ui_apps_use_dark_theme();
    if (FAILED(fn(hwnd, KB_DWMWA_USE_IMMERSIVE_DARK_MODE, &dark, (DWORD)sizeof(dark))))
        return;
    if (redraw) /* Windows 10 repaints the frame only when asked */
        SetWindowPos(hwnd, NULL, 0, 0, 0, 0,
                     SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
}

/* ------------------------------------------------------------------------ */
/* Colors                                                                   */
/* ------------------------------------------------------------------------ */

static void ui_fill(HDC dc, const RECT *r, COLORREF color)
{
    COLORREF old = SetDCBrushColor(dc, color);
    FillRect(dc, r, (HBRUSH)GetStockObject(DC_BRUSH));
    if (old != CLR_INVALID)
        SetDCBrushColor(dc, old);
}

static COLORREF ui_line_color(void)
{
    return ui_high_contrast() ? GetSysColor(COLOR_WINDOWTEXT) : RGB(0xDF, 0xDF, 0xDF);
}

static COLORREF ui_text_color(ui_role role)
{
    if (ui_high_contrast())
        return GetSysColor(COLOR_WINDOWTEXT);
    switch (role) {
    case UI_SECONDARY:
        return RGB(0x5F, 0x5F, 0x5F); /* 6.4:1 on white */
    case UI_DOT:
        return ui_dot_color();
    default:
        return GetSysColor(COLOR_WINDOWTEXT);
    }
}

/* The command area starts half a button height above the Cancel/Close
 * button (7 DLU for a 14 DLU button), wherever the dialog has moved it. */
static int ui_footer_top(HWND dlg)
{
    HWND cancel = GetDlgItem(dlg, IDCANCEL);
    RECT rc, b;

    GetClientRect(dlg, &rc);
    if (cancel == NULL || !GetWindowRect(cancel, &b))
        return rc.bottom;
    MapWindowPoints(NULL, dlg, (POINT *)&b, 2);
    return b.top - (b.bottom - b.top) / 2;
}

static void ui_paint_background(const ui_state *st, HWND dlg, HDC dc)
{
    RECT rc, r;
    int top = ui_footer_top(dlg);

    GetClientRect(dlg, &rc);
    r = rc;
    r.bottom = top;
    FillRect(dc, &r, GetSysColorBrush(COLOR_WINDOW));
    if (top < rc.bottom) {
        r = rc;
        r.top = top;
        FillRect(dc, &r, GetSysColorBrush(COLOR_BTNFACE));
        r.bottom = r.top + ui_px(st, 1);
        ui_fill(dc, &r, ui_line_color());
    }
}

static INT_PTR ui_ctlcolor(HWND dlg, HDC dc, HWND ctl)
{
    RECT r;
    int bg = COLOR_WINDOW;

    if (GetWindowRect(ctl, &r)) {
        MapWindowPoints(NULL, dlg, (POINT *)&r, 2);
        if (r.top >= ui_footer_top(dlg))
            bg = COLOR_BTNFACE;
    }
    if (IsWindowEnabled(ctl))
        SetTextColor(dc, ui_text_color(ui_role_of(GetDlgCtrlID(ctl))));
    else
        SetTextColor(dc, GetSysColor(COLOR_GRAYTEXT));
    SetBkMode(dc, OPAQUE);
    SetBkColor(dc, GetSysColor(bg));
    return (INT_PTR)GetSysColorBrush(bg);
}

/* ------------------------------------------------------------------------ */
/* Fonts and the header icon                                                */
/* ------------------------------------------------------------------------ */

static int CALLBACK ui_font_found(const LOGFONTW *lf, const TEXTMETRICW *tm, DWORD type, LPARAM lp)
{
    UNREFERENCED_PARAMETER(lf);
    UNREFERENCED_PARAMETER(tm);
    UNREFERENCED_PARAMETER(type);
    *(BOOL *)lp = TRUE;
    return 0; /* one match is enough */
}

static BOOL ui_face_exists(const wchar_t *face)
{
    LOGFONTW lf;
    BOOL found = FALSE;
    HDC dc;

    memset(&lf, 0, sizeof(lf));
    lf.lfCharSet = DEFAULT_CHARSET;
    if (FAILED(StringCchCopyW(lf.lfFaceName, ARRAYSIZE(lf.lfFaceName), face)))
        return FALSE;
    dc = GetDC(NULL);
    if (dc == NULL)
        return FALSE;
    (void)EnumFontFamiliesExW(dc, &lf, ui_font_found, (LPARAM)&found, 0);
    ReleaseDC(NULL, dc);
    return found;
}

/* Segoe UI Variable ships with Windows 11. */
static BOOL ui_have_variable_font(void)
{
    static int have = -1;
    if (have < 0)
        have = (ui_face_exists(L"Segoe UI Variable Text") &&
                ui_face_exists(L"Segoe UI Variable Display")) ? 1 : 0;
    return have == 1;
}

static HFONT ui_font(const wchar_t *face, int tenths_pt, LONG weight, UINT dpi)
{
    LOGFONTW lf;

    memset(&lf, 0, sizeof(lf));
    lf.lfHeight = -MulDiv(tenths_pt, (int)dpi, 720);
    lf.lfWeight = weight;
    lf.lfCharSet = DEFAULT_CHARSET;
    lf.lfOutPrecision = OUT_DEFAULT_PRECIS;
    lf.lfClipPrecision = CLIP_DEFAULT_PRECIS;
    lf.lfQuality = DEFAULT_QUALITY; /* follows the user's ClearType setting */
    lf.lfPitchAndFamily = DEFAULT_PITCH | FF_SWISS;
    if (FAILED(StringCchCopyW(lf.lfFaceName, ARRAYSIZE(lf.lfFaceName), face)))
        return NULL;
    return CreateFontIndirectW(&lf);
}

static void ui_free(ui_state *st)
{
    if (st->body != NULL)
        DeleteObject(st->body);
    if (st->strong != NULL)
        DeleteObject(st->strong);
    if (st->title != NULL)
        DeleteObject(st->title);
    if (st->big != NULL)
        DeleteObject(st->big);
    if (st->icon != NULL)
        DestroyIcon(st->icon);
    memset(st, 0, sizeof(*st));
}

static BOOL CALLBACK ui_set_font(HWND child, LPARAM lp)
{
    const ui_state *st = (const ui_state *)lp;
    HFONT font;

    switch (ui_role_of(GetDlgCtrlID(child))) {
    case UI_TITLE:
        font = st->title;
        break;
    case UI_STRONG:
        font = st->strong;
        break;
    case UI_BIG:
        font = st->big;
        break;
    default:
        font = st->body;
        break;
    }
    if (font != NULL)
        SendMessageW(child, WM_SETFONT, (WPARAM)font, TRUE);
    return TRUE;
}

/* (Re)create the fonts and the icon for the dialog's current DPI and give
 * them to the controls. The old objects are deleted only afterwards, so no
 * control ever holds a deleted font. */
static void ui_build(ui_state *st, HWND dlg)
{
    ui_state old = *st;
    BOOL variable = ui_have_variable_font();
    const wchar_t *text_face = variable ? L"Segoe UI Variable Text" : L"Segoe UI";
    const wchar_t *display_face = variable ? L"Segoe UI Variable Display" : L"Segoe UI";
    UINT dpi = ui_dpi(dlg);

    memset(st, 0, sizeof(*st));
    st->dpi = dpi;
    st->body = variable ? ui_font(text_face, 90, FW_NORMAL, dpi) : NULL;
    st->strong = ui_font(text_face, 90, FW_SEMIBOLD, dpi);
    st->title = ui_font(text_face, 120, FW_SEMIBOLD, dpi);
    if (GetDlgItem(dlg, IDC_CMP_NUMBER) != NULL)
        st->big = ui_font(display_face, 260, FW_SEMIBOLD, dpi);
    st->icon_px = MulDiv(32, (int)dpi, 96);
    if (GetDlgItem(dlg, IDC_HDR_ICON) != NULL &&
        FAILED(LoadIconWithScaleDown(GetModuleHandleW(NULL), MAKEINTRESOURCEW(IDI_APP),
                                     st->icon_px, st->icon_px, &st->icon)))
        st->icon = NULL;
    EnumChildWindows(dlg, ui_set_font, (LPARAM)st);
    ui_free(&old);
}

static void ui_init(ui_state *st, HWND dlg)
{
    memset(st, 0, sizeof(*st));
    ui_title_bar(dlg, FALSE); /* before the dialog is first shown: no flash */
    ui_build(st, dlg);
}

/* ------------------------------------------------------------------------ */
/* Owner-drawn controls                                                     */
/* ------------------------------------------------------------------------ */

static void ui_draw_number(const ui_state *st, const DRAWITEMSTRUCT *di)
{
    wchar_t text[32];
    RECT r = di->rcItem;
    HDC dc = di->hDC;
    BOOL hc = ui_high_contrast();
    int radius = ui_px(st, 8);
    HGDIOBJ old_pen, old_brush, old_font = NULL;

    /* A light card, like a Windows 11 settings card. */
    old_pen = SelectObject(dc, GetStockObject(DC_PEN));
    old_brush = SelectObject(dc, GetStockObject(DC_BRUSH));
    SetDCPenColor(dc, hc ? GetSysColor(COLOR_WINDOWTEXT) : RGB(0xE5, 0xE5, 0xE5));
    SetDCBrushColor(dc, hc ? GetSysColor(COLOR_WINDOW) : RGB(0xF7, 0xF7, 0xF7));
    RoundRect(dc, r.left, r.top, r.right, r.bottom, radius, radius);
    SelectObject(dc, old_brush);
    SelectObject(dc, old_pen);

    text[0] = 0;
    GetWindowTextW(di->hwndItem, text, (int)ARRAYSIZE(text));
    if (st->big != NULL)
        old_font = SelectObject(dc, st->big);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, GetSysColor(COLOR_WINDOWTEXT));
    DrawTextW(dc, text, -1, &r, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    if (old_font != NULL)
        SelectObject(dc, old_font);
}

static BOOL ui_draw_item(const ui_state *st, const DRAWITEMSTRUCT *di)
{
    RECT r = di->rcItem;

    if (di->CtlType != ODT_STATIC)
        return FALSE;
    switch (ui_role_of((int)di->CtlID)) {
    case UI_ICON:
        FillRect(di->hDC, &r, GetSysColorBrush(COLOR_WINDOW));
        if (st->icon != NULL)
            DrawIconEx(di->hDC, r.left + (r.right - r.left - st->icon_px) / 2,
                       r.top + (r.bottom - r.top - st->icon_px) / 2,
                       st->icon, st->icon_px, st->icon_px, 0, NULL, DI_NORMAL);
        return TRUE;
    case UI_SEPARATOR:
        FillRect(di->hDC, &r, GetSysColorBrush(COLOR_WINDOW));
        r.top = (r.top + r.bottom - ui_px(st, 1)) / 2;
        r.bottom = r.top + ui_px(st, 1);
        ui_fill(di->hDC, &r, ui_line_color());
        return TRUE;
    case UI_BIG:
        FillRect(di->hDC, &r, GetSysColorBrush(COLOR_WINDOW));
        ui_draw_number(st, di);
        return TRUE;
    default:
        return FALSE;
    }
}

/* ------------------------------------------------------------------------ */
/* Messages                                                                 */
/* ------------------------------------------------------------------------ */

/* Call first from a dialog procedure. TRUE: handled, return *result. */
static BOOL ui_dialog_message(ui_state *st, HWND dlg, UINT msg, WPARAM wp, LPARAM lp, INT_PTR *result)
{
    switch (msg) {
    case WM_ERASEBKGND:
        ui_paint_background(st, dlg, (HDC)wp);
        SetWindowLongPtrW(dlg, DWLP_MSGRESULT, TRUE);
        *result = TRUE;
        return TRUE;

    case WM_PRINTCLIENT: /* themed buttons paint their corners from this */
        ui_paint_background(st, dlg, (HDC)wp);
        *result = TRUE;
        return TRUE;

    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORBTN:
        *result = ui_ctlcolor(dlg, (HDC)wp, (HWND)lp);
        return TRUE;

    case WM_CTLCOLORDLG:
        *result = (INT_PTR)GetSysColorBrush(COLOR_WINDOW);
        return TRUE;

    case WM_DRAWITEM:
        if (!ui_draw_item(st, (const DRAWITEMSTRUCT *)lp))
            return FALSE;
        SetWindowLongPtrW(dlg, DWLP_MSGRESULT, TRUE);
        *result = TRUE;
        return TRUE;

    case WM_DPICHANGED:
        /* DefDlgProc resizes the dialog, moves the controls and gives them
         * the template font at the new DPI; ours follow once it is done. */
        PostMessageW(dlg, WM_KB_UI_DPI, 0, 0);
        return FALSE;

    case WM_KB_UI_DPI:
        ui_build(st, dlg);
        RedrawWindow(dlg, NULL, NULL, RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN);
        *result = TRUE;
        return TRUE;

    case WM_SETTINGCHANGE:
        if (lp != 0 && CompareStringOrdinal((const wchar_t *)lp, -1, L"ImmersiveColorSet", -1,
                                            TRUE) == CSTR_EQUAL)
            ui_title_bar(dlg, TRUE);
        return FALSE;

    case WM_SYSCOLORCHANGE:
    case WM_THEMECHANGED: /* includes turning High Contrast on or off */
        ui_title_bar(dlg, TRUE);
        RedrawWindow(dlg, NULL, NULL, RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN);
        return FALSE;

    default:
        return FALSE;
    }
}

#endif
