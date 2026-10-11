/*
 * KeyBridge - the tray flyout (see flyout.h).
 *
 * A Windows 11 style panel drawn with Direct2D and DirectWrite into a
 * per-pixel-alpha layered window (UpdateLayeredWindow), so the rounded
 * corners, the soft shadow and the 1 px border look the same on every PC,
 * including virtual machines where DWM draws neither. Everything is laid out
 * in DIPs; the render target's DPI is the monitor's.
 *
 * This is the only C++ translation unit: it uses the C++ declarations of the
 * Direct2D/DirectWrite interfaces and nothing else from C++ (no STL, no
 * exceptions, no RTTI, no operator new, no static constructors). d2d1.dll,
 * dwrite.dll, dwmapi.dll and shcore.dll are loaded on first use.
 *
 * The manual-address text field is a real EDIT control. A layered window
 * can't host child windows, so the EDIT lives in a small owned popup that is
 * placed over the field the flyout draws.
 *
 * UI thread only.
 */
#include "flyout.h"

#include <shellapi.h>
#include <commctrl.h>
#include <math.h>

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4201 4577)
#endif
#include <d2d1.h>
#include <dwrite.h>
#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include <strsafe.h>

/* ------------------------------------------------------------------------ */
/* Constants                                                                */
/* ------------------------------------------------------------------------ */

#define FLY_CLASS  L"KeyBridgeFlyout"
#define HOST_CLASS L"KeyBridgeFlyoutField"

#define PANEL_W    360.0f
#define SH_L       16.0f /* shadow margins: window = panel inflated by these */
#define SH_T       8.0f
#define SH_R       16.0f
#define SH_B       24.0f
#define FOOTER_H   48.0f

#define WM_FLY_RENDER (WM_APP + 40)
#define WM_FLY_SYNC   (WM_APP + 41)

#define T_FRAME 1
#define T_THEME 2
#define T_POLL  3

#define ITEMS_MAX 48

#define FLY_X(lp) ((int)(short)LOWORD(lp))
#define FLY_Y(lp) ((int)(short)HIWORD(lp))

/* Segoe Fluent Icons / Segoe MDL2 Assets code points. */
#define G_KEYBOARD  0xE765
#define G_LAPTOP    0xE7F8
#define G_DESKTOP   0xE7F4
#define G_LINK      0xE71B
#define G_SETTINGS  0xE713
#define G_POWER     0xE7E8
#define G_BACK      0xE72B
#define G_CHEV_R    0xE76C
#define G_CHEV_D    0xE70D
#define G_CHEV_U    0xE70E
#define G_CLOSE     0xE711
#define G_CHECK     0xE73E
#define G_NOMACS    0xE968
#define G_CLIPBOARD 0xE77F

/* Our own IIDs: no __uuidof, no dxguid.lib. */
static const IID KB_IID_ID2D1Factory = {
    0x06152247, 0x6f50, 0x465a, {0x92, 0x45, 0x11, 0x8b, 0xfd, 0x3b, 0x60, 0x07}};
static const IID KB_IID_IDWriteFactory = {
    0xb859ee5a, 0xd838, 0x4b5b, {0xa2, 0xe8, 0x1a, 0xdc, 0x7d, 0x93, 0xdb, 0x48}};

typedef HRESULT(WINAPI *kb_pfn_d2d_create)(D2D1_FACTORY_TYPE, REFIID, const D2D1_FACTORY_OPTIONS *,
                                           void **);
typedef HRESULT(WINAPI *kb_pfn_dw_create)(DWRITE_FACTORY_TYPE, REFIID, IUnknown **);
typedef HRESULT(WINAPI *kb_pfn_dpi_for_monitor)(HMONITOR, int, UINT *, UINT *);
typedef HRESULT(WINAPI *kb_pfn_dwm_set)(HWND, DWORD, LPCVOID, DWORD);
typedef LONG(WINAPI *kb_pfn_rtl_version)(OSVERSIONINFOW *);

/* Text styles (DirectWrite formats). */
enum {
    F_CAPTION,
    F_BODY,
    F_STRONG,
    F_SUBTITLE,
    F_TITLE,
    F_BOLD11,
    F_I10,
    F_I12,
    F_I16,
    F_I20,
    F_I24,
    F_COUNT
};

/* Views (what the panel shows). */
enum { V_NONE = -1, V_PAIR, V_STATUS, V_COMPARE, V_SUCCESS, V_SETTINGS };

/* Interactive items. */
enum {
    C_NONE = 0,
    C_SETTINGS,
    C_QUIT,
    C_BACK,
    C_MANUAL,
    C_FIELD,
    C_PAIR_ADDR,
    C_CANCEL_PAIR,
    C_SEARCH_AGAIN,
    C_CONFIRM,
    C_CMP_CANCEL,
    C_TRY_NOW,
    C_TOG_CLIP,
    C_TOG_AUTOSTART,
    C_TOG_AUTOUPDATE,
    C_CHECK_NOW,
    C_FORGET,
    C_FORGET_YES,
    C_FORGET_NO,
    C_PAIR_OTHER,
    C_PAIR_NEW,
    C_UPD_INSTALL,
    C_UPD_NOTES,
    C_UPD_CLOSE,
    C_UPD_CANCEL,
    C_UPD_RETRY,
    C_NOTICE_CLOSE,
    C_ROW0 /* + Mac index */
};

enum { K_BUTTON, K_TOGGLE, K_FIELD };
enum { B_ACCENT, B_STD, B_CRIT, B_SUBTLE, B_LINK };
enum { A_LEAD, A_CENTER, A_TRAIL };

typedef struct {
    int   id;
    int   kind;
    float x, y, w, h;
    float r;
} fly_item;

/* Colors are 0xAARRGGBB (straight alpha). */
typedef struct {
    UINT32 panel, border, footer, footer_div, card, card_stroke, divider;
    UINT32 text1, text2, text3, textdis;
    UINT32 accent, accent_text, on_accent, on_accent_pr, on_accent_dis, accent_tint, accent_dis,
        accent_edge;
    UINT32 ctl, ctl_hover, ctl_pr, ctl_dis, ctl_stroke, ctl_edge;
    UINT32 strong, tog_off, tog_off_hover, sub_hover, sub_pr, field_focus, neutral_tile;
    UINT32 success, caution, critical, neutral;
    UINT32 ib_success, ib_caution, ib_critical, success_tint;
    UINT32 focus_outer, focus_inner, shadow;
    BOOL   dark, hc;
} fly_pal;

static struct {
    /* setup */
    HINSTANCE     inst;
    HWND          owner, hwnd, host, edit;
    UINT          uid;
    fly_action_fn fn;
    void         *ctx;
    unsigned      flags;
    /* what to show */
    fly_state st;
    fly_page  page, back_page;
    BOOL      manual, forget_confirm;
    int       drawn_view, nav_dir;
    /* visibility */
    BOOL      visible, hiding, activated, keyboard, want_focus;
    ULONGLONG dismiss_tick, toggle_tick;
    BOOL      dismiss_on_icon, disc_sent, sync_posted, render_posted;
    /* placement (physical pixels) */
    UINT  dpi;
    float s;
    RECT  work;
    UINT  edge;
    int   panel_left, panel_anchor;
    BOOL  anchor_top;
    float radius, gap;
    int   win_x, win_y, win_w, win_h;
    /* animation */
    double qpf;
    int    vis_mode; /* 0 none, 1 enter, 2 exit */
    double vis_t0;
    float  vis_alpha0;
    BOOL   pg_active, h_active;
    double pg_t0;
    float  h_from, h_cur;
    int    tog_id;
    double tog_t0;
    BOOL   ring_seen, motion, timer_on;
    UINT   timer_ms;
    float  slide, alpha;
    /* layout of the last pass */
    fly_item items[ITEMS_MAX];
    int      nitems;
    BOOL     draw, has_footer, field_visible;
    float    ph, fx, fy, fw, fh;
    int      hot, pressed, focus;
    BOOL     show_focus, tracking;
    /* Direct2D / DirectWrite (device independent; kept for the process) */
    BOOL                 d2d_tried, d2d_ok, icons;
    ID2D1Factory        *d2d;
    IDWriteFactory      *dw;
    IDWriteTextFormat   *fmt[F_COUNT];
    IDWriteInlineObject *ell[F_COUNT];
    ID2D1StrokeStyle    *round;
    /* per visible period */
    ID2D1DCRenderTarget  *rt;
    ID2D1SolidColorBrush *br;
    HDC                   memdc;
    HBITMAP               dib, old_bmp;
    int                   dib_w, dib_h;
    /* text field */
    HFONT    edit_font;
    UINT     edit_font_dpi;
    RECT     host_rect;
    BOOL     edit_pending;
    HBRUSH   edit_brush;
    COLORREF edit_bg;
    /* theme */
    fly_pal P;
    BOOL    win11;
} g;

static void render(void);
static void flyout_hide_impl(BOOL deactivated);

/* ------------------------------------------------------------------------ */
/* Small helpers                                                            */
/* ------------------------------------------------------------------------ */

static double now_ms(void)
{
    LARGE_INTEGER c;
    if (g.qpf <= 0.0) {
        LARGE_INTEGER f;
        QueryPerformanceFrequency(&f);
        g.qpf = (double)f.QuadPart;
        if (g.qpf <= 0.0)
            g.qpf = 1000.0;
    }
    QueryPerformanceCounter(&c);
    return (double)c.QuadPart * 1000.0 / g.qpf;
}

static float clamp01(float v)
{
    return v < 0.0f ? 0.0f : (v > 1.0f ? 1.0f : v);
}

static float ease_out3(float t)
{
    float u = 1.0f - t;
    return 1.0f - u * u * u;
}

static float ease_out4(float t)
{
    float u = 1.0f - t;
    return 1.0f - u * u * u * u;
}

static int px(float dip)
{
    return (int)floorf(dip * g.s + 0.5f);
}

static float snap(float v)
{
    return floorf(v * g.s + 0.5f) / g.s;
}

static UINT32 mul_a(UINT32 c, float f)
{
    UINT32 a = (UINT32)((float)(c >> 24) * f + 0.5f);
    if (a > 255u)
        a = 255u;
    return (c & 0x00FFFFFFu) | (a << 24);
}

static UINT32 from_colorref(COLORREF c)
{
    return 0xFF000000u | ((UINT32)GetRValue(c) << 16) | ((UINT32)GetGValue(c) << 8) |
           (UINT32)GetBValue(c);
}

/* fg (with alpha) over an opaque bg, as a COLORREF. */
static COLORREF composite(UINT32 fg, UINT32 bg)
{
    float a = (float)(fg >> 24) / 255.0f;
    int   sh;
    BYTE  out[3];
    int   i;
    for (i = 0; i < 3; i++) {
        sh = 16 - 8 * i;
        float f = (float)((fg >> sh) & 0xFFu), b = (float)((bg >> sh) & 0xFFu);
        out[i] = (BYTE)(f * a + b * (1.0f - a) + 0.5f);
    }
    return RGB(out[0], out[1], out[2]);
}

static void emit(fly_action a, int arg, const wchar_t *msg)
{
    if (g.fn != NULL)
        g.fn(g.ctx, a, arg, msg);
}

static void *load_sys(const wchar_t *dll)
{
    return (void *)LoadLibraryExW(dll, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
}

static BOOL reg_dword(const wchar_t *key, const wchar_t *name, DWORD *out)
{
    DWORD cb = sizeof(*out);
    return RegGetValueW(HKEY_CURRENT_USER, key, name, RRF_RT_REG_DWORD, NULL, out, &cb) == ERROR_SUCCESS;
}

static BOOL motion_enabled(void)
{
    BOOL on = TRUE;
    if (!SystemParametersInfoW(SPI_GETCLIENTAREAANIMATION, 0, &on, 0))
        on = TRUE;
    return on;
}

static void dwm_set(HWND h, DWORD attr, DWORD value)
{
    static kb_pfn_dwm_set fn;
    static BOOL           looked;
    if (!looked) {
        HMODULE m = (HMODULE)load_sys(L"dwmapi.dll");
        FARPROC p = m != NULL ? GetProcAddress(m, "DwmSetWindowAttribute") : NULL;
        if (p != NULL)
            memcpy(&fn, &p, sizeof(fn));
        looked = TRUE;
    }
    if (fn != NULL)
        (void)fn(h, attr, &value, sizeof(value));
}

static BOOL is_win11(void)
{
    HMODULE        nt = GetModuleHandleW(L"ntdll.dll");
    FARPROC        p = nt != NULL ? GetProcAddress(nt, "RtlGetVersion") : NULL;
    kb_pfn_rtl_version fn = NULL;
    OSVERSIONINFOW vi;

    if (p == NULL)
        return TRUE;
    memcpy(&fn, &p, sizeof(fn));
    memset(&vi, 0, sizeof(vi));
    vi.dwOSVersionInfoSize = sizeof(vi);
    if (fn(&vi) != 0)
        return TRUE;
    return vi.dwMajorVersion > 10 || (vi.dwMajorVersion == 10 && vi.dwBuildNumber >= 22000);
}

static UINT monitor_dpi(HMONITOR mon)
{
    static kb_pfn_dpi_for_monitor fn;
    static BOOL                   looked;
    UINT x = 0, y = 0;

    if (!looked) {
        HMODULE m = (HMODULE)load_sys(L"shcore.dll");
        FARPROC p = m != NULL ? GetProcAddress(m, "GetDpiForMonitor") : NULL;
        if (p != NULL)
            memcpy(&fn, &p, sizeof(fn));
        looked = TRUE;
    }
    if (fn != NULL && SUCCEEDED(fn(mon, 0 /* MDT_EFFECTIVE_DPI */, &x, &y)) && x >= 48)
        return x;
    {
        HDC dc = GetDC(NULL);
        int d = dc != NULL ? GetDeviceCaps(dc, LOGPIXELSX) : 96;
        if (dc != NULL)
            ReleaseDC(NULL, dc);
        return d >= 48 ? (UINT)d : 96u;
    }
}

/* ------------------------------------------------------------------------ */
/* Theme                                                                    */
/* ------------------------------------------------------------------------ */

#define KB_PERSONALIZE L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize"

static void accent_load(BOOL dark, UINT32 *fill, UINT32 *link)
{
    BYTE  pal[32];
    DWORD cb = sizeof(pal), abgr = 0;

    if (RegGetValueW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Accent",
                     L"AccentPalette", RRF_RT_REG_BINARY, NULL, pal, &cb) == ERROR_SUCCESS &&
        cb >= sizeof(pal)) {
        int fi = dark ? 1 : 4, ti = dark ? 0 : 5;
        *fill = 0xFF000000u | ((UINT32)pal[fi * 4] << 16) | ((UINT32)pal[fi * 4 + 1] << 8) |
                (UINT32)pal[fi * 4 + 2];
        *link = 0xFF000000u | ((UINT32)pal[ti * 4] << 16) | ((UINT32)pal[ti * 4 + 1] << 8) |
                (UINT32)pal[ti * 4 + 2];
        return;
    }
    if (reg_dword(L"Software\\Microsoft\\Windows\\DWM", L"AccentColor", &abgr)) {
        UINT32 c = 0xFF000000u | ((abgr & 0xFFu) << 16) | (abgr & 0xFF00u) | ((abgr >> 16) & 0xFFu);
        *fill = c;
        *link = c;
        return;
    }
    *fill = dark ? 0xFF4CC2FFu : 0xFF005FB8u;
    *link = dark ? 0xFF99EBFFu : 0xFF003E92u;
}

static void pal_load(void)
{
    fly_pal     *P = &g.P;
    HIGHCONTRASTW hc;
    DWORD        light = 0;
    BOOL         dark;

    memset(&hc, 0, sizeof(hc));
    hc.cbSize = sizeof(hc);
    P->hc = SystemParametersInfoW(SPI_GETHIGHCONTRAST, sizeof(hc), &hc, 0) &&
            (hc.dwFlags & HCF_HIGHCONTRASTON) != 0;
    if (!reg_dword(KB_PERSONALIZE, L"SystemUsesLightTheme", &light))
        light = 0; /* missing: Windows 10 before 1903 (dark taskbar) */
    dark = light == 0;
    P->dark = dark;

    if (P->hc) {
        UINT32 win = from_colorref(GetSysColor(COLOR_WINDOW));
        UINT32 txt = from_colorref(GetSysColor(COLOR_WINDOWTEXT));
        UINT32 hi = from_colorref(GetSysColor(COLOR_HIGHLIGHT));
        UINT32 hit = from_colorref(GetSysColor(COLOR_HIGHLIGHTTEXT));
        UINT32 gray = from_colorref(GetSysColor(COLOR_GRAYTEXT));
        UINT32 link = from_colorref(GetSysColor(COLOR_HOTLIGHT));
        P->panel = P->footer = P->card = P->ctl = P->ctl_hover = P->ctl_pr = P->ctl_dis = win;
        P->field_focus = win;
        P->border = P->footer_div = P->card_stroke = P->divider = P->ctl_stroke = P->ctl_edge = txt;
        P->strong = txt;
        P->text1 = P->text2 = P->text3 = txt;
        P->textdis = gray;
        P->accent = hi;
        P->accent_text = link;
        P->on_accent = P->on_accent_pr = hit;
        P->on_accent_dis = gray;
        P->accent_tint = 0;
        P->accent_dis = gray;
        P->accent_edge = hi;
        P->tog_off = P->tog_off_hover = win;
        P->sub_hover = P->sub_pr = hi;
        P->neutral_tile = 0;
        P->success = P->caution = P->critical = P->neutral = txt;
        P->ib_success = P->ib_caution = P->ib_critical = P->success_tint = win;
        P->focus_outer = txt;
        P->focus_inner = win;
        P->shadow = 0;
        return;
    }

    accent_load(dark, &P->accent, &P->accent_text);
    if (dark) {
        P->panel = 0xFF2C2C2Cu;
        P->border = 0x1AFFFFFFu;
        P->footer = 0xFF202020u;
        P->footer_div = 0x14000000u;
        P->card = 0x0DFFFFFFu;
        P->card_stroke = 0x19000000u;
        P->divider = 0x15FFFFFFu;
        P->text1 = 0xFFFFFFFFu;
        P->text2 = 0xC5FFFFFFu;
        P->text3 = 0x87FFFFFFu;
        P->textdis = 0x5DFFFFFFu;
        P->on_accent = 0xFF000000u;
        P->on_accent_pr = 0x80000000u;
        P->on_accent_dis = 0x87FFFFFFu;
        P->accent_tint = mul_a(P->accent, 0.16f);
        P->accent_dis = 0x28FFFFFFu;
        P->accent_edge = 0x23000000u;
        P->ctl = 0x0FFFFFFFu;
        P->ctl_hover = 0x15FFFFFFu;
        P->ctl_pr = 0x08FFFFFFu;
        P->ctl_dis = 0x0BFFFFFFu;
        P->ctl_stroke = 0x12FFFFFFu;
        P->ctl_edge = 0x18FFFFFFu;
        P->strong = 0x8BFFFFFFu;
        P->tog_off = 0x19000000u;
        P->tog_off_hover = 0x0BFFFFFFu;
        P->sub_hover = 0x0FFFFFFFu;
        P->sub_pr = 0x0AFFFFFFu;
        P->field_focus = 0xFF1F1F1Fu;
        P->neutral_tile = 0x14FFFFFFu;
        P->success = 0xFF6CCB5Fu;
        P->caution = 0xFFFCE100u;
        P->critical = 0xFFFF99A4u;
        P->neutral = 0x8BFFFFFFu;
        P->ib_success = 0xFF393D1Bu;
        P->ib_caution = 0xFF433519u;
        P->ib_critical = 0xFF442726u;
        P->success_tint = mul_a(P->success, 0.16f);
        P->focus_outer = 0xFFFFFFFFu;
        P->focus_inner = 0xB3000000u;
        P->shadow = 0x14000000u;
    } else {
        P->panel = 0xFFF3F3F3u;
        P->border = 0x1A000000u;
        P->footer = 0xFFEBEBEBu;
        P->footer_div = 0x0F000000u;
        P->card = 0xFFFBFBFBu;
        P->card_stroke = 0xFFE5E5E5u;
        P->divider = 0x0F000000u;
        P->text1 = 0xE4000000u;
        P->text2 = 0x9E000000u;
        P->text3 = 0x72000000u;
        P->textdis = 0x5C000000u;
        P->on_accent = 0xFFFFFFFFu;
        P->on_accent_pr = 0xB3FFFFFFu;
        P->on_accent_dis = 0xFFFFFFFFu;
        P->accent_tint = mul_a(P->accent, 0.12f);
        P->accent_dis = 0x37000000u;
        P->accent_edge = 0x66000000u;
        P->ctl = 0xB3FFFFFFu;
        P->ctl_hover = 0x80F9F9F9u;
        P->ctl_pr = 0x4DF9F9F9u;
        P->ctl_dis = 0x4DF9F9F9u;
        P->ctl_stroke = 0x0F000000u;
        P->ctl_edge = 0x29000000u;
        P->strong = 0x72000000u;
        P->tog_off = 0x06000000u;
        P->tog_off_hover = 0x0F000000u;
        P->sub_hover = 0x09000000u;
        P->sub_pr = 0x06000000u;
        P->field_focus = 0xFFFFFFFFu;
        P->neutral_tile = 0x0F000000u;
        P->success = 0xFF0F7B0Fu;
        P->caution = 0xFF9D5D00u;
        P->critical = 0xFFC42B1Cu;
        P->neutral = 0x72000000u;
        P->ib_success = 0xFFDFF6DDu;
        P->ib_caution = 0xFFFFF4CEu;
        P->ib_critical = 0xFFFDE7E9u;
        P->success_tint = mul_a(P->success, 0.12f);
        P->focus_outer = 0xE4000000u;
        P->focus_inner = 0xB3FFFFFFu;
        P->shadow = 0x08000000u;
    }
}

/* ------------------------------------------------------------------------ */
/* Direct2D / DirectWrite                                                   */
/* ------------------------------------------------------------------------ */

template <class T> static void safe_release(T *&p)
{
    if (p != NULL) {
        p->Release();
        p = NULL;
    }
}

static BOOL family_exists(IDWriteFontCollection *fc, const wchar_t *name)
{
    UINT32 i = 0;
    BOOL   e = FALSE;
    if (fc == NULL || FAILED(fc->FindFamilyName(name, &i, &e)))
        return FALSE;
    return e;
}

static IDWriteTextFormat *make_format(int idx, const wchar_t *family, DWRITE_FONT_WEIGHT weight,
                                      float size, float line, BOOL centered)
{
    IDWriteTextFormat *f = NULL;

    if (FAILED(g.dw->CreateTextFormat(family, NULL, weight, DWRITE_FONT_STYLE_NORMAL,
                                      DWRITE_FONT_STRETCH_NORMAL, size, L"en-us", &f)) ||
        f == NULL)
        return NULL;
    (void)f->SetWordWrapping(DWRITE_WORD_WRAPPING_NO_WRAP);
    if (line > 0.0f)
        (void)f->SetLineSpacing(DWRITE_LINE_SPACING_METHOD_UNIFORM, line, line * 0.75f);
    if (centered) {
        (void)f->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_CENTER);
        (void)f->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
    } else {
        IDWriteInlineObject *sign = NULL;
        if (SUCCEEDED(g.dw->CreateEllipsisTrimmingSign(f, &sign)) && sign != NULL) {
            DWRITE_TRIMMING t;
            t.granularity = DWRITE_TRIMMING_GRANULARITY_CHARACTER;
            t.delimiter = 0;
            t.delimiterCount = 0;
            (void)f->SetTrimming(&t, sign);
            g.ell[idx] = sign;
        }
    }
    return f;
}

static BOOL d2d_init(void)
{
    HMODULE               d2, dwm;
    FARPROC               p;
    kb_pfn_d2d_create     d2d_create = NULL;
    kb_pfn_dw_create      dw_create = NULL;
    D2D1_FACTORY_OPTIONS  opt;
    IDWriteFontCollection *fc = NULL;
    const wchar_t        *text_face, *disp_face, *small_face, *icon_face;
    D2D1_STROKE_STYLE_PROPERTIES sp;

    if (g.d2d_tried)
        return g.d2d_ok;
    g.d2d_tried = TRUE;

    d2 = (HMODULE)load_sys(L"d2d1.dll");
    dwm = (HMODULE)load_sys(L"dwrite.dll");
    p = d2 != NULL ? GetProcAddress(d2, "D2D1CreateFactory") : NULL;
    if (p != NULL)
        memcpy(&d2d_create, &p, sizeof(d2d_create));
    p = dwm != NULL ? GetProcAddress(dwm, "DWriteCreateFactory") : NULL;
    if (p != NULL)
        memcpy(&dw_create, &p, sizeof(dw_create));
    if (d2d_create == NULL || dw_create == NULL)
        return FALSE;

    opt.debugLevel = D2D1_DEBUG_LEVEL_NONE;
    if (FAILED(d2d_create(D2D1_FACTORY_TYPE_SINGLE_THREADED, KB_IID_ID2D1Factory, &opt,
                          reinterpret_cast<void **>(&g.d2d))) ||
        g.d2d == NULL)
        return FALSE;
    if (FAILED(dw_create(DWRITE_FACTORY_TYPE_SHARED, KB_IID_IDWriteFactory,
                         reinterpret_cast<IUnknown **>(&g.dw))) ||
        g.dw == NULL)
        return FALSE;

    (void)g.dw->GetSystemFontCollection(&fc, FALSE);
    text_face = family_exists(fc, L"Segoe UI Variable Text") ? L"Segoe UI Variable Text" : L"Segoe UI";
    disp_face = family_exists(fc, L"Segoe UI Variable Display") ? L"Segoe UI Variable Display" : L"Segoe UI";
    small_face = family_exists(fc, L"Segoe UI Variable Small") ? L"Segoe UI Variable Small" : L"Segoe UI";
    icon_face = family_exists(fc, L"Segoe Fluent Icons")  ? L"Segoe Fluent Icons"
                : family_exists(fc, L"Segoe MDL2 Assets") ? L"Segoe MDL2 Assets"
                                                          : NULL;
    safe_release(fc);

    g.fmt[F_CAPTION] = make_format(F_CAPTION, small_face, DWRITE_FONT_WEIGHT_NORMAL, 12.0f, 16.0f, FALSE);
    g.fmt[F_BODY] = make_format(F_BODY, text_face, DWRITE_FONT_WEIGHT_NORMAL, 14.0f, 20.0f, FALSE);
    g.fmt[F_STRONG] = make_format(F_STRONG, text_face, DWRITE_FONT_WEIGHT_SEMI_BOLD, 14.0f, 20.0f, FALSE);
    g.fmt[F_SUBTITLE] = make_format(F_SUBTITLE, disp_face, DWRITE_FONT_WEIGHT_SEMI_BOLD, 20.0f, 28.0f, FALSE);
    g.fmt[F_TITLE] = make_format(F_TITLE, disp_face, DWRITE_FONT_WEIGHT_SEMI_BOLD, 40.0f, 52.0f, FALSE);
    g.fmt[F_BOLD11] = make_format(F_BOLD11, L"Segoe UI", DWRITE_FONT_WEIGHT_BOLD, 11.0f, 0.0f, TRUE);
    if (icon_face != NULL) {
        g.fmt[F_I10] = make_format(F_I10, icon_face, DWRITE_FONT_WEIGHT_NORMAL, 10.0f, 0.0f, TRUE);
        g.fmt[F_I12] = make_format(F_I12, icon_face, DWRITE_FONT_WEIGHT_NORMAL, 12.0f, 0.0f, TRUE);
        g.fmt[F_I16] = make_format(F_I16, icon_face, DWRITE_FONT_WEIGHT_NORMAL, 16.0f, 0.0f, TRUE);
        g.fmt[F_I20] = make_format(F_I20, icon_face, DWRITE_FONT_WEIGHT_NORMAL, 20.0f, 0.0f, TRUE);
        g.fmt[F_I24] = make_format(F_I24, icon_face, DWRITE_FONT_WEIGHT_NORMAL, 24.0f, 0.0f, TRUE);
        g.icons = TRUE;
    }
    if (g.fmt[F_CAPTION] == NULL || g.fmt[F_BODY] == NULL || g.fmt[F_STRONG] == NULL ||
        g.fmt[F_SUBTITLE] == NULL || g.fmt[F_TITLE] == NULL)
        return FALSE;

    memset(&sp, 0, sizeof(sp));
    sp.startCap = D2D1_CAP_STYLE_ROUND;
    sp.endCap = D2D1_CAP_STYLE_ROUND;
    sp.dashCap = D2D1_CAP_STYLE_ROUND;
    sp.lineJoin = D2D1_LINE_JOIN_ROUND;
    sp.miterLimit = 10.0f;
    sp.dashStyle = D2D1_DASH_STYLE_SOLID;
    sp.dashOffset = 0.0f;
    if (FAILED(g.d2d->CreateStrokeStyle(&sp, NULL, 0, &g.round)))
        g.round = NULL;

    g.d2d_ok = TRUE;
    return TRUE;
}

static void device_release(void)
{
    safe_release(g.br);
    safe_release(g.rt);
    if (g.memdc != NULL) {
        if (g.old_bmp != NULL)
            SelectObject(g.memdc, g.old_bmp);
        DeleteDC(g.memdc);
        g.memdc = NULL;
        g.old_bmp = NULL;
    }
    if (g.dib != NULL) {
        DeleteObject(g.dib);
        g.dib = NULL;
    }
    g.dib_w = g.dib_h = 0;
}

static BOOL device_ensure(int w, int h)
{
    if (g.memdc == NULL) {
        HDC screen = GetDC(NULL);
        g.memdc = CreateCompatibleDC(screen);
        if (screen != NULL)
            ReleaseDC(NULL, screen);
        if (g.memdc == NULL)
            return FALSE;
    }
    if (g.dib == NULL || w > g.dib_w || h > g.dib_h) {
        BITMAPINFO bi;
        void      *bits = NULL;
        HBITMAP    dib;
        int        cw = w > g.dib_w ? w : g.dib_w, ch = h > g.dib_h ? h : g.dib_h;

        memset(&bi, 0, sizeof(bi));
        bi.bmiHeader.biSize = sizeof(bi.bmiHeader);
        bi.bmiHeader.biWidth = cw;
        bi.bmiHeader.biHeight = -ch; /* top-down */
        bi.bmiHeader.biPlanes = 1;
        bi.bmiHeader.biBitCount = 32;
        bi.bmiHeader.biCompression = BI_RGB;
        dib = CreateDIBSection(g.memdc, &bi, DIB_RGB_COLORS, &bits, NULL, 0);
        if (dib == NULL)
            return FALSE;
        if (g.dib != NULL) {
            SelectObject(g.memdc, dib);
            DeleteObject(g.dib);
        } else {
            g.old_bmp = (HBITMAP)SelectObject(g.memdc, dib);
        }
        g.dib = dib;
        g.dib_w = cw;
        g.dib_h = ch;
    }
    if (g.rt == NULL) {
        D2D1_RENDER_TARGET_PROPERTIES rp;
        memset(&rp, 0, sizeof(rp));
        rp.type = D2D1_RENDER_TARGET_TYPE_SOFTWARE;
        rp.pixelFormat.format = DXGI_FORMAT_B8G8R8A8_UNORM;
        rp.pixelFormat.alphaMode = D2D1_ALPHA_MODE_PREMULTIPLIED;
        rp.dpiX = 96.0f;
        rp.dpiY = 96.0f;
        rp.usage = D2D1_RENDER_TARGET_USAGE_NONE;
        rp.minLevel = D2D1_FEATURE_LEVEL_DEFAULT;
        if (FAILED(g.d2d->CreateDCRenderTarget(&rp, &g.rt)) || g.rt == NULL)
            return FALSE;
    }
    if (g.br == NULL) {
        D2D1_COLOR_F c;
        c.r = c.g = c.b = 0.0f;
        c.a = 1.0f;
        if (FAILED(g.rt->CreateSolidColorBrush(&c, NULL, &g.br)) || g.br == NULL)
            return FALSE;
    }
    return TRUE;
}

/* ------------------------------------------------------------------------ */
/* Drawing primitives (all in DIPs; they only draw in the drawing pass)     */
/* ------------------------------------------------------------------------ */

static BOOL drawing(void)
{
    return g.draw && g.rt != NULL && g.br != NULL;
}

static void set_brush(UINT32 c)
{
    D2D1_COLOR_F cf;
    cf.a = (float)((c >> 24) & 0xFFu) / 255.0f * g.alpha;
    cf.r = (float)((c >> 16) & 0xFFu) / 255.0f;
    cf.g = (float)((c >> 8) & 0xFFu) / 255.0f;
    cf.b = (float)(c & 0xFFu) / 255.0f;
    g.br->SetColor(&cf);
}

static D2D1_RECT_F rectf(float x, float y, float w, float h)
{
    D2D1_RECT_F r;
    r.left = x;
    r.top = y;
    r.right = x + w;
    r.bottom = y + h;
    return r;
}

static D2D1_POINT_2F ptf(float x, float y)
{
    D2D1_POINT_2F p;
    p.x = x;
    p.y = y;
    return p;
}

static void set_xform(float dx, float dy)
{
    D2D1_MATRIX_3X2_F m;
    memset(&m, 0, sizeof(m));
    m._11 = 1.0f;
    m._22 = 1.0f;
    m._31 = dx;
    m._32 = dy;
    g.rt->SetTransform(&m);
}

static void fill_rr(float x, float y, float w, float h, float r, UINT32 c)
{
    D2D1_ROUNDED_RECT rr;
    float             x0, y0, x1, y1;

    if (!drawing() || (c >> 24) == 0 || w <= 0.0f || h <= 0.0f)
        return;
    x0 = snap(x);
    y0 = snap(y);
    x1 = snap(x + w);
    y1 = snap(y + h);
    rr.rect.left = x0;
    rr.rect.top = y0;
    rr.rect.right = x1;
    rr.rect.bottom = y1;
    rr.radiusX = r;
    rr.radiusY = r;
    set_brush(c);
    if (r > 0.0f)
        g.rt->FillRoundedRectangle(&rr, g.br);
    else
        g.rt->FillRectangle(&rr.rect, g.br);
}

/* A 1 device-pixel stroke just inside the rectangle. */
static void stroke_rr(float x, float y, float w, float h, float r, UINT32 c)
{
    D2D1_ROUNDED_RECT rr;
    float             p = 1.0f / g.s, x0, y0, x1, y1;

    if (!drawing() || (c >> 24) == 0)
        return;
    x0 = snap(x);
    y0 = snap(y);
    x1 = snap(x + w);
    y1 = snap(y + h);
    rr.rect.left = x0 + p * 0.5f;
    rr.rect.top = y0 + p * 0.5f;
    rr.rect.right = x1 - p * 0.5f;
    rr.rect.bottom = y1 - p * 0.5f;
    rr.radiusX = r > p * 0.5f ? r - p * 0.5f : 0.0f;
    rr.radiusY = rr.radiusX;
    set_brush(c);
    if (r > 0.0f)
        g.rt->DrawRoundedRectangle(&rr, g.br, p, NULL);
    else
        g.rt->DrawRectangle(&rr.rect, g.br, p, NULL);
}

/* Stroke only the bottom few pixels: the Fluent "elevation" edge. */
static void bottom_edge(float x, float y, float w, float h, float r, UINT32 c)
{
    D2D1_RECT_F clip;
    if (!drawing() || (c >> 24) == 0)
        return;
    clip = rectf(x - 1.0f, snap(y + h) - 3.0f / g.s, w + 2.0f, 4.0f / g.s);
    g.rt->PushAxisAlignedClip(&clip, D2D1_ANTIALIAS_MODE_ALIASED);
    stroke_rr(x, y, w, h, r, c);
    g.rt->PopAxisAlignedClip();
}

static void fill_circle(float cx, float cy, float r, UINT32 c)
{
    D2D1_ELLIPSE e;
    if (!drawing() || (c >> 24) == 0)
        return;
    e.point = ptf(cx, cy);
    e.radiusX = r;
    e.radiusY = r;
    set_brush(c);
    g.rt->FillEllipse(&e, g.br);
}

static void divider(float x0, float x1, float y)
{
    D2D1_RECT_F r;
    if (!drawing())
        return;
    r.left = snap(x0);
    r.right = snap(x1);
    r.top = snap(y);
    r.bottom = r.top + 1.0f / g.s;
    set_brush(g.P.divider);
    g.rt->FillRectangle(&r, g.br);
}

static void card(float x, float y, float w, float h)
{
    fill_rr(x, y, w, h, 8.0f, g.P.card);
    stroke_rr(x, y, w, h, 8.0f, g.P.card_stroke);
}

/* Draws (in the drawing pass) and measures text; returns its height. */
static float text_ex(const wchar_t *s, int f, float x, float y, float w, float h, UINT32 color, int align,
                     BOOL wrap, float *out_w)
{
    IDWriteTextLayout  *lay = NULL;
    DWRITE_TEXT_METRICS m;
    float               height = 0.0f;

    if (out_w != NULL)
        *out_w = 0.0f;
    if (s == NULL || s[0] == 0 || g.dw == NULL || g.fmt[f] == NULL)
        return 0.0f;
    if (FAILED(g.dw->CreateTextLayout(s, (UINT32)wcslen(s), g.fmt[f], w > 1.0f ? w : 1.0f,
                                      wrap ? 4096.0f : (h > 1.0f ? h : 1.0f), &lay)) ||
        lay == NULL)
        return 0.0f;
    (void)lay->SetTextAlignment(align == A_CENTER  ? DWRITE_TEXT_ALIGNMENT_CENTER
                                : align == A_TRAIL ? DWRITE_TEXT_ALIGNMENT_TRAILING
                                                   : DWRITE_TEXT_ALIGNMENT_LEADING);
    (void)lay->SetWordWrapping(wrap ? DWRITE_WORD_WRAPPING_WRAP : DWRITE_WORD_WRAPPING_NO_WRAP);
    memset(&m, 0, sizeof(m));
    if (SUCCEEDED(lay->GetMetrics(&m))) {
        height = m.height;
        if (out_w != NULL)
            *out_w = m.widthIncludingTrailingWhitespace;
    }
    if (drawing() && (color >> 24) != 0) {
        set_brush(color);
        g.rt->DrawTextLayout(ptf(x, y), lay, g.br, D2D1_DRAW_TEXT_OPTIONS_NONE);
    }
    lay->Release();
    return height;
}

static float text(const wchar_t *s, int f, float x, float y, float w, float h, UINT32 color, int align)
{
    return text_ex(s, f, x, y, w, h, color, align, FALSE, NULL);
}

static float text_wrap(const wchar_t *s, int f, float x, float y, float w, UINT32 color, int align)
{
    return text_ex(s, f, x, y, w, 0.0f, color, align, TRUE, NULL);
}

static float text_width(const wchar_t *s, int f)
{
    float w = 0.0f;
    BOOL  d = g.draw;
    g.draw = FALSE;
    (void)text_ex(s, f, 0.0f, 0.0f, 4096.0f, 100.0f, 0, A_LEAD, FALSE, &w);
    g.draw = d;
    return w;
}

static void glyph(int cp, int size, float cx, float cy, UINT32 color)
{
    int     f;
    wchar_t s[2];
    float   box = (float)size + 8.0f;

    switch (size) {
    case 10:
        f = F_I10;
        break;
    case 12:
        f = F_I12;
        break;
    case 20:
        f = F_I20;
        break;
    case 24:
        f = F_I24;
        break;
    default:
        f = F_I16;
        break;
    }
    if (!g.icons || !drawing())
        return;
    s[0] = (wchar_t)cp;
    s[1] = 0;
    (void)text(s, f, cx - box * 0.5f, cy - box * 0.5f, box, box, color, A_CENTER);
}

/* An indeterminate progress ring centered at (cx, cy). */
static void ring(float cx, float cy, float size)
{
    ID2D1PathGeometry *pg = NULL;
    ID2D1GeometrySink *sink = NULL;
    D2D1_ARC_SEGMENT   arc;
    float              stroke = size >= 24.0f ? 2.5f : 2.0f;
    float              r = (size - stroke) * 0.5f;
    double             t;
    float              rot, ph, tri, e, sweep, a0;

    g.ring_seen = TRUE;
    if (!drawing() || g.d2d == NULL)
        return;
    t = now_ms();
    rot = (float)fmod(t / 1300.0, 1.0) * 6.2831853f;
    ph = (float)fmod(t / 2000.0, 1.0);
    tri = ph < 0.5f ? ph * 2.0f : (1.0f - ph) * 2.0f;
    e = tri * tri * (3.0f - 2.0f * tri);
    sweep = (60.0f + 210.0f * e) * 0.017453293f;
    a0 = rot - 1.5707963f;
    if (FAILED(g.d2d->CreatePathGeometry(&pg)) || pg == NULL)
        return;
    if (SUCCEEDED(pg->Open(&sink)) && sink != NULL) {
        sink->BeginFigure(ptf(cx + r * cosf(a0), cy + r * sinf(a0)), D2D1_FIGURE_BEGIN_HOLLOW);
        arc.point = ptf(cx + r * cosf(a0 + sweep), cy + r * sinf(a0 + sweep));
        arc.size.width = r;
        arc.size.height = r;
        arc.rotationAngle = 0.0f;
        arc.sweepDirection = D2D1_SWEEP_DIRECTION_CLOCKWISE;
        arc.arcSize = sweep > 3.1415926f ? D2D1_ARC_SIZE_LARGE : D2D1_ARC_SIZE_SMALL;
        sink->AddArc(&arc);
        sink->EndFigure(D2D1_FIGURE_END_OPEN);
        (void)sink->Close();
        sink->Release();
        set_brush(g.P.accent);
        g.rt->DrawGeometry(pg, g.br, stroke, g.round);
    }
    pg->Release();
}

/* ------------------------------------------------------------------------ */
/* Controls                                                                 */
/* ------------------------------------------------------------------------ */

static void add_item(int id, int kind, float x, float y, float w, float h, float r)
{
    fly_item *it;
    if (g.nitems >= ITEMS_MAX)
        return;
    it = &g.items[g.nitems++];
    it->id = id;
    it->kind = kind;
    it->x = x;
    it->y = y;
    it->w = w;
    it->h = h;
    it->r = r;
}

static const fly_item *find_item(int id)
{
    int i;
    for (i = 0; i < g.nitems; i++) {
        if (g.items[i].id == id)
            return &g.items[i];
    }
    return NULL;
}

static int hit_test(float x, float y)
{
    int i;
    for (i = 0; i < g.nitems; i++) {
        const fly_item *it = &g.items[i];
        if (x >= it->x && x < it->x + it->w && y >= it->y && y < it->y + it->h)
            return it->id;
    }
    return C_NONE;
}

/* Buttons. label NULL = icon only. A glyph with a label leads it. */
static void button(int id, int style, float x, float y, float w, float h, const wchar_t *label, int gl,
                   int gsize, BOOL enabled)
{
    const fly_pal *P = &g.P;
    BOOL           hot = enabled && g.hot == id && (g.pressed == C_NONE || g.pressed == id);
    BOOL           pr = enabled && g.pressed == id && g.hot == id;
    UINT32         fill, txt;

    if (enabled)
        add_item(id, K_BUTTON, x, y, w, h, 4.0f);
    switch (style) {
    case B_ACCENT:
        fill = !enabled ? P->accent_dis : pr ? mul_a(P->accent, 0.8f) : hot ? mul_a(P->accent, 0.9f) : P->accent;
        txt = !enabled ? P->on_accent_dis : pr ? P->on_accent_pr : P->on_accent;
        fill_rr(x, y, w, h, 4.0f, fill);
        if (enabled)
            bottom_edge(x, y, w, h, 4.0f, P->accent_edge);
        if (P->hc)
            stroke_rr(x, y, w, h, 4.0f, P->text1);
        break;
    case B_STD:
    case B_CRIT:
        fill = !enabled ? P->ctl_dis : pr ? P->ctl_pr : hot ? P->ctl_hover : P->ctl;
        txt = !enabled ? P->textdis : pr ? P->text2 : style == B_CRIT ? P->critical : P->text1;
        fill_rr(x, y, w, h, 4.0f, fill);
        stroke_rr(x, y, w, h, 4.0f, P->ctl_stroke);
        if (enabled)
            bottom_edge(x, y, w, h, 4.0f, P->ctl_edge);
        break;
    default: /* B_SUBTLE, B_LINK */
        fill = pr ? P->sub_pr : hot ? P->sub_hover : 0;
        txt = !enabled ? P->textdis : style == B_LINK ? P->accent_text : P->text1;
        if (P->hc && (hot || pr))
            txt = P->on_accent;
        fill_rr(x, y, w, h, 4.0f, fill);
        break;
    }
    if (label == NULL) {
        glyph(gl, gsize, x + w * 0.5f, y + h * 0.5f, txt);
    } else if (gl != 0) {
        glyph(gl, gsize, x + 12.0f + (float)gsize * 0.5f, y + h * 0.5f, txt);
        (void)text(label, F_BODY, x + 12.0f + (float)gsize + 8.0f, y + (h - 20.0f) * 0.5f,
                   w - 32.0f - (float)gsize, 20.0f, txt, A_LEAD);
    } else {
        (void)text(label, F_BODY, x + 8.0f, y + (h - 20.0f) * 0.5f, w - 16.0f, 20.0f, txt, A_CENTER);
    }
}

/* Width of a text button with padding 12 (accent and standard buttons). */
static float button_w(const wchar_t *label, float min_w)
{
    float w = ceilf(text_width(label, F_BODY)) + 24.0f;
    return w < min_w ? min_w : w;
}

/* A hyperlink-style text button right-aligned to x1; returns its left edge. */
static float link_right(int id, float x1, float y, const wchar_t *label)
{
    float w = ceilf(text_width(label, F_BODY)) + 16.0f;
    button(id, B_LINK, x1 - w, y, w, 32.0f, label, 0, 0, TRUE);
    return x1 - w;
}

static void toggle(int id, float x, float y, BOOL on, BOOL enabled)
{
    const fly_pal *P = &g.P;
    BOOL           hot = enabled && g.hot == id;
    BOOL           pr = enabled && g.pressed == id && g.hot == id;
    float          pos = on ? 1.0f : 0.0f, kw, kh, cx, kx;
    BOOL           lit;
    UINT32         knob;

    if (g.tog_id == id) {
        float t = clamp01((float)((now_ms() - g.tog_t0) / 167.0));
        float e = ease_out3(t);
        pos = on ? e : 1.0f - e;
    }
    lit = pos >= 0.5f;
    if (lit) {
        fill_rr(x, y, 40.0f, 20.0f, 10.0f,
                !enabled ? P->accent_dis : pr ? mul_a(P->accent, 0.8f) : hot ? mul_a(P->accent, 0.9f) : P->accent);
        if (P->hc)
            stroke_rr(x, y, 40.0f, 20.0f, 10.0f, P->text1);
        knob = enabled ? P->on_accent : P->on_accent_dis;
    } else {
        fill_rr(x, y, 40.0f, 20.0f, 10.0f, (hot || pr) ? P->tog_off_hover : P->tog_off);
        stroke_rr(x, y, 40.0f, 20.0f, 10.0f, enabled ? P->strong : P->textdis);
        knob = enabled ? P->text2 : P->textdis;
    }
    kh = (hot || pr) ? 14.0f : 12.0f;
    kw = pr ? 17.0f : kh;
    cx = x + 10.0f + pos * 20.0f;
    kx = lit ? cx + kh * 0.5f - kw : cx - kh * 0.5f;
    fill_rr(kx, y + 10.0f - kh * 0.5f, kw, kh, kh * 0.5f, knob);
}

static void status_dot(float cx, float cy, UINT32 c)
{
    fill_circle(cx, cy, 4.0f, c);
    if (g.P.hc && drawing()) {
        D2D1_ELLIPSE e;
        e.point = ptf(cx, cy);
        e.radiusX = 4.0f;
        e.radiusY = 4.0f;
        set_brush(g.P.text1);
        g.rt->DrawEllipse(&e, g.br, 1.0f / g.s, NULL);
    }
}

/* ------------------------------------------------------------------------ */
/* Views                                                                    */
/* ------------------------------------------------------------------------ */

static int cur_view(void)
{
    if (g.st.pair == FLY_PAIR_COMPARE || g.st.pair == FLY_PAIR_WAIT_MAC)
        return V_COMPARE;
    if (g.st.pair == FLY_PAIR_SUCCESS)
        return V_SUCCESS;
    if (g.page == FLY_PAGE_SETTINGS)
        return V_SETTINGS;
    if (g.page == FLY_PAGE_PAIR || g.st.conn == FLY_CONN_UNPAIRED || g.st.conn == FLY_CONN_NOT_PAIRED)
        return V_PAIR;
    return V_STATUS;
}

static const wchar_t *mac_display_name(void)
{
    return g.st.mac_name[0] != 0 ? g.st.mac_name : L"Your Mac";
}

static int mac_glyph(const wchar_t *name)
{
    return wcsstr(name, L"MacBook") != NULL ? G_LAPTOP : G_DESKTOP;
}

static void hero(int gl, BOOL neutral, const wchar_t *title, UINT32 dot, const wchar_t *status)
{
    const fly_pal *P = &g.P;
    fill_rr(16.0f, 20.0f, 40.0f, 40.0f, 4.0f, neutral ? P->neutral_tile : P->accent_tint);
    if (P->hc)
        stroke_rr(16.0f, 20.0f, 40.0f, 40.0f, 4.0f, P->text1);
    glyph(gl, 20, 36.0f, 40.0f, neutral ? P->text2 : P->accent);
    (void)text(title, F_SUBTITLE, 68.0f, 16.0f, 276.0f, 28.0f, P->text1, A_LEAD);
    if (dot != 0) {
        status_dot(72.0f, 54.0f, dot);
        (void)text(status, F_BODY, 82.0f, 44.0f, 262.0f, 20.0f, P->text2, A_LEAD);
    } else {
        (void)text(status, F_BODY, 68.0f, 44.0f, 276.0f, 20.0f, P->text2, A_LEAD);
    }
}

static void page_header(const wchar_t *title)
{
    button(C_BACK, B_SUBTLE, 12.0f, 12.0f, 32.0f, 32.0f, NULL, G_BACK, 16, TRUE);
    (void)text(title, F_SUBTITLE, 52.0f, 14.0f, 292.0f, 28.0f, g.P.text1, A_LEAD);
}

static void footer(float y, BOOL settings)
{
    const fly_pal *P = &g.P;
    wchar_t        ver[64];
    float          fy = g.draw ? g.ph - FOOTER_H : y;

    if (g.draw && g.rt != NULL)
        g.rt->PopAxisAlignedClip(); /* the body clip pushed by build() */
    g.has_footer = TRUE;
    (void)StringCchPrintfW(ver, ARRAYSIZE(ver), L"KeyBridge %ls", g.st.version);
    (void)text(ver, F_CAPTION, 16.0f, fy + 16.0f, 180.0f, 16.0f, P->text3, A_LEAD);
    if (!settings) {
        button(C_SETTINGS, B_SUBTLE, 272.0f, fy + 8.0f, 32.0f, 32.0f, NULL, G_SETTINGS, 16, TRUE);
        button(C_QUIT, B_SUBTLE, 312.0f, fy + 8.0f, 32.0f, 32.0f, NULL, G_POWER, 16, TRUE);
    } else {
        const wchar_t *q = L"Quit KeyBridge";
        float          w = 12.0f + 16.0f + 8.0f + ceilf(text_width(q, F_BODY)) + 12.0f;
        button(C_QUIT, B_SUBTLE, 344.0f - w, fy + 8.0f, w, 32.0f, q, G_POWER, 16, TRUE);
    }
}

static UINT32 sev_color(fly_sev sev)
{
    switch (sev) {
    case FLY_SEV_SUCCESS:
        return g.P.success;
    case FLY_SEV_CAUTION:
        return g.P.caution;
    case FLY_SEV_CRITICAL:
        return g.P.critical;
    default:
        return g.P.accent;
    }
}

static UINT32 sev_fill(fly_sev sev)
{
    switch (sev) {
    case FLY_SEV_SUCCESS:
        return g.P.ib_success;
    case FLY_SEV_CAUTION:
        return g.P.ib_caution;
    case FLY_SEV_CRITICAL:
        return g.P.ib_critical;
    default:
        return g.P.accent_tint;
    }
}

static void sev_icon(fly_sev sev, float cx, float cy)
{
    UINT32 on = g.P.on_accent;
    fill_circle(cx, cy, 8.0f, sev_color(sev));
    switch (sev) {
    case FLY_SEV_SUCCESS:
        glyph(G_CHECK, 10, cx, cy, on);
        break;
    case FLY_SEV_CRITICAL:
        glyph(G_CLOSE, 10, cx, cy, on);
        break;
    case FLY_SEV_CAUTION:
        (void)text(L"!", F_BOLD11, cx - 8.0f, cy - 8.0f, 16.0f, 16.0f, on, A_CENTER);
        break;
    default:
        (void)text(L"i", F_BOLD11, cx - 8.0f, cy - 8.0f, 16.0f, 16.0f, on, A_CENTER);
        break;
    }
}

/* InfoBar frame + icon + title + message; returns the y below the message. */
static float infobar_top(float y, float h, fly_sev sev, const wchar_t *title, const wchar_t *msg)
{
    fill_rr(16.0f, y, 328.0f, h, 8.0f, sev_fill(sev));
    stroke_rr(16.0f, y, 328.0f, h, 8.0f, g.P.card_stroke);
    sev_icon(sev, 40.0f, y + 22.0f);
    (void)text(title, F_STRONG, 56.0f, y + 12.0f, 244.0f, 20.0f, g.P.text1, A_LEAD);
    return y + 32.0f + text_wrap(msg, F_BODY, 56.0f, y + 32.0f, 272.0f, g.P.text2, A_LEAD);
}

/* The notice set by main.c (errors and warnings). Returns the next y. */
static float notice(float y)
{
    float msg_h, h;
    if (g.st.notice_sev == FLY_SEV_NONE)
        return y;
    msg_h = text_wrap(g.st.notice_text, F_BODY, 0.0f, 0.0f, 272.0f, 0, A_LEAD);
    h = 32.0f + msg_h + 14.0f;
    if (h < 48.0f)
        h = 48.0f;
    (void)infobar_top(y, h, g.st.notice_sev, g.st.notice_title, g.st.notice_text);
    button(C_NOTICE_CLOSE, B_SUBTLE, 304.0f, y + 6.0f, 32.0f, 32.0f, NULL, G_CLOSE, 12, TRUE);
    return y + h + 12.0f;
}

/* The update InfoBar (home and settings). Returns the next y. */
static float update_bar(float y)
{
    const fly_state *st = &g.st;
    wchar_t          title[64], msg[FLY_MSG_MAX + 64], line[64];
    fly_sev          sev = st->upd == FLY_UPD_FAILED ? FLY_SEV_CRITICAL : FLY_SEV_INFO;
    float            msg_h, h, by;

    if (st->upd < FLY_UPD_AVAILABLE)
        return y;
    switch (st->upd) {
    case FLY_UPD_DOWNLOADING:
        (void)StringCchCopyW(title, ARRAYSIZE(title), L"Downloading update");
        (void)StringCchPrintfW(msg, ARRAYSIZE(msg), L"KeyBridge %ls", st->upd_version);
        break;
    case FLY_UPD_INSTALLING:
        (void)StringCchCopyW(title, ARRAYSIZE(title), L"Installing update");
        (void)StringCchPrintfW(msg, ARRAYSIZE(msg), L"KeyBridge %ls", st->upd_version);
        break;
    case FLY_UPD_FAILED:
        (void)StringCchCopyW(title, ARRAYSIZE(title), L"Update failed");
        (void)StringCchCopyW(msg, ARRAYSIZE(msg),
                             st->upd_error[0] != 0 ? st->upd_error : L"Something went wrong on this PC.");
        break;
    default:
        (void)StringCchCopyW(title, ARRAYSIZE(title), L"Update available");
        if (st->upd_installable)
            (void)StringCchPrintfW(msg, ARRAYSIZE(msg), L"KeyBridge %ls is ready to install.",
                                   st->upd_version);
        else
            (void)StringCchPrintfW(msg, ARRAYSIZE(msg),
                                   L"KeyBridge %ls is out. Download it from GitHub to update this copy.",
                                   st->upd_version);
        break;
    }
    msg_h = text_wrap(msg, F_BODY, 0.0f, 0.0f, 272.0f, 0, A_LEAD);
    h = 32.0f + msg_h + 12.0f + 32.0f + 16.0f;
    by = infobar_top(y, h, sev, title, msg) + 12.0f;

    switch (st->upd) {
    case FLY_UPD_DOWNLOADING:
        link_right(C_UPD_CANCEL, 336.0f, y + 6.0f, L"Cancel");
        if (st->upd_permille >= 0) {
            int   pm = st->upd_permille > 1000 ? 1000 : st->upd_permille;
            float w = 272.0f * (float)pm / 1000.0f;
            (void)StringCchPrintfW(line, ARRAYSIZE(line), L"Downloading\x2026 %d%%", pm / 10);
            (void)text(line, F_CAPTION, 56.0f, by + 2.0f, 272.0f, 16.0f, g.P.text2, A_LEAD);
            fill_rr(56.0f, by + 25.0f, 272.0f, 1.0f, 0.0f, g.P.strong);
            if (w > 3.0f)
                fill_rr(56.0f, by + 24.0f, w, 3.0f, 1.5f, g.P.accent);
        } else {
            ring(64.0f, by + 16.0f, 16.0f);
            (void)text(L"Downloading\x2026", F_BODY, 80.0f, by + 6.0f, 248.0f, 20.0f, g.P.text2, A_LEAD);
        }
        break;
    case FLY_UPD_INSTALLING:
        ring(64.0f, by + 16.0f, 16.0f);
        (void)text(L"Installing\x2026", F_BODY, 80.0f, by + 6.0f, 248.0f, 20.0f, g.P.text2, A_LEAD);
        break;
    case FLY_UPD_FAILED:
        button(C_UPD_CLOSE, B_SUBTLE, 304.0f, y + 6.0f, 32.0f, 32.0f, NULL, G_CLOSE, 12, TRUE);
        button(C_UPD_RETRY, B_STD, 56.0f, by, button_w(L"Retry", 96.0f), 32.0f, L"Retry", 0, 0, TRUE);
        break;
    default: {
        const wchar_t *primary = st->upd_installable ? L"Install and restart" : L"Download";
        float          bw = button_w(primary, 120.0f);
        button(C_UPD_CLOSE, B_SUBTLE, 304.0f, y + 6.0f, 32.0f, 32.0f, NULL, G_CLOSE, 12, TRUE);
        button(C_UPD_INSTALL, B_ACCENT, 56.0f, by, bw, 32.0f, primary, 0, 0, TRUE);
        if (st->upd_installable) {
            const wchar_t *n = L"What\x2019s new";
            float          nw = ceilf(text_width(n, F_BODY)) + 16.0f;
            button(C_UPD_NOTES, B_LINK, 56.0f + bw + 8.0f, by, nw, 32.0f, n, 0, 0, TRUE);
        }
        break;
    }
    }
    return y + h + 12.0f;
}

/* The manual-address field and its button, at y. */
static void field_row(float y)
{
    const fly_pal *P = &g.P;
    BOOL           focused = g.edit != NULL && GetFocus() == g.edit;
    BOOL           busy = g.st.pair == FLY_PAIR_BUSY && g.st.pair_mac_id < 0;
    BOOL           enabled = g.st.pair == FLY_PAIR_IDLE;

    g.field_visible = TRUE;
    g.fx = 16.0f;
    g.fy = y;
    g.fw = 240.0f;
    g.fh = 32.0f;
    if (enabled)
        add_item(C_FIELD, K_FIELD, 16.0f, y, 240.0f, 32.0f, 4.0f);
    fill_rr(16.0f, y, 240.0f, 32.0f, 4.0f, !enabled ? P->ctl_dis : focused ? P->field_focus : P->ctl);
    stroke_rr(16.0f, y, 240.0f, 32.0f, 4.0f, P->ctl_stroke);
    if (drawing()) {
        D2D1_RECT_F clip = rectf(16.0f, y + 28.0f, 240.0f, 4.0f);
        g.rt->PushAxisAlignedClip(&clip, D2D1_ANTIALIAS_MODE_ALIASED);
        if (focused)
            fill_rr(16.0f, y + 30.0f, 240.0f, 2.0f, 0.0f, P->accent);
        else
            fill_rr(16.0f, snap(y + 32.0f) - 1.0f / g.s, 240.0f, 1.0f / g.s, 0.0f, P->strong);
        g.rt->PopAxisAlignedClip();
    }
    if (busy) {
        ring(240.0f, y + 16.0f, 16.0f);
        button(C_CANCEL_PAIR, B_STD, 264.0f, y, 80.0f, 32.0f, L"Cancel", 0, 0, TRUE);
    } else {
        button(C_PAIR_ADDR, B_ACCENT, 264.0f, y, 80.0f, 32.0f, L"Pair", 0, 0, enabled);
    }
}

static void mac_row(int i, float y, BOOL target, BOOL disabled)
{
    const fly_pal *P = &g.P;
    const fly_mac *m = &g.st.macs[i];
    int            id = C_ROW0 + i;
    BOOL           hot = !disabled && g.hot == id;
    BOOL           pr = !disabled && g.pressed == id && g.hot == id;
    UINT32         t1 = disabled ? P->textdis : P->text1, t2 = disabled ? P->textdis : P->text2;

    if (!disabled)
        add_item(id, K_BUTTON, 20.0f, y + 2.0f, 320.0f, 52.0f, 4.0f);
    if (pr || hot || target)
        fill_rr(20.0f, y + 2.0f, 320.0f, 52.0f, 4.0f, pr ? P->sub_pr : P->sub_hover);
    if (target)
        fill_rr(20.0f, y + 20.0f, 3.0f, 16.0f, 1.5f, P->accent);
    glyph(mac_glyph(m->name), 20, 42.0f, y + 28.0f, P->hc && hot ? P->on_accent : t2);
    (void)text(m->name, F_STRONG, 64.0f, y + 9.0f, 244.0f, 20.0f, P->hc && hot ? P->on_accent : t1, A_LEAD);
    (void)text(target ? L"Connecting\x2026" : (m->detail[0] != 0 ? m->detail : L"On this network"), F_CAPTION,
               64.0f, y + 29.0f, 244.0f, 16.0f, P->hc && hot ? P->on_accent : t2, A_LEAD);
    if (target)
        ring(322.0f, y + 28.0f, 16.0f);
    else
        glyph(G_CHEV_R, 12, 322.0f, y + 28.0f, disabled ? P->textdis : P->text3);
}

static float view_pair(void)
{
    const fly_pal   *P = &g.P;
    const fly_state *st = &g.st;
    float            y;
    BOOL             busy_row = st->pair == FLY_PAIR_BUSY && st->pair_mac_id >= 0;

    if (g.page == FLY_PAGE_PAIR) {
        page_header(L"Pair with a Mac");
        y = 60.0f;
    } else {
        hero(G_KEYBOARD, FALSE, L"Pair with a Mac", P->neutral, L"Not paired");
        y = 76.0f;
    }
    y = notice(y);
    y += text_wrap(L"On your Mac, click the KeyBridge menu bar icon and choose Pair a Windows PC.", F_BODY,
                   16.0f, y, 328.0f, P->text2, A_LEAD);

    if (!st->discovery_available) {
        y += 16.0f;
        (void)text(L"Enter your Mac\x2019s address", F_STRONG, 16.0f, y, 328.0f, 20.0f, P->text1, A_LEAD);
        y += 28.0f;
        field_row(y);
        return y + 32.0f + 16.0f;
    }

    y += 16.0f;
    (void)text(L"Macs on this network", F_STRONG, 16.0f, y, 240.0f, 20.0f, P->text1, A_LEAD);
    if (busy_row)
        (void)link_right(C_CANCEL_PAIR, 352.0f, y - 6.0f, L"Cancel");
    else if (st->searching && st->nmacs > 0)
        ring(336.0f, y + 10.0f, 16.0f);
    y += 28.0f;

    if (st->nmacs > 0) {
        int   n = st->nmacs > 5 ? 5 : st->nmacs, i;
        float ch = 56.0f * (float)n + (float)(n - 1);
        card(16.0f, y, 328.0f, ch);
        for (i = 0; i < n; i++) {
            float ry = y + 57.0f * (float)i;
            BOOL  target = busy_row && st->macs[i].id == st->pair_mac_id;
            if (i > 0)
                divider(64.0f, 328.0f, ry - 1.0f);
            mac_row(i, ry, target, st->pair != FLY_PAIR_IDLE && !target);
        }
        y += ch;
    } else if (st->search_empty) {
        const wchar_t *cap = L"Open KeyBridge on your Mac and check that both devices are on the same network.";
        float          cap_h = text_wrap(cap, F_CAPTION, 0.0f, 0.0f, 296.0f, 0, A_CENTER);
        float          ch = 12.0f + 24.0f + 4.0f + 20.0f + 2.0f + cap_h + 10.0f + 32.0f + 16.0f;
        float          bw = button_w(L"Search again", 96.0f);
        card(16.0f, y, 328.0f, ch);
        glyph(G_NOMACS, 24, 180.0f, y + 24.0f, P->text3);
        (void)text(L"No Macs found", F_STRONG, 16.0f, y + 40.0f, 328.0f, 20.0f, P->text1, A_CENTER);
        (void)text_wrap(cap, F_CAPTION, 32.0f, y + 62.0f, 296.0f, P->text2, A_CENTER);
        button(C_SEARCH_AGAIN, B_STD, 180.0f - bw * 0.5f, y + 62.0f + cap_h + 10.0f, bw, 32.0f,
               L"Search again", 0, 0, TRUE);
        y += ch;
    } else {
        card(16.0f, y, 328.0f, 100.0f);
        ring(180.0f, y + 30.0f, 24.0f);
        (void)text(L"Looking for Macs\x2026", F_BODY, 16.0f, y + 54.0f, 328.0f, 20.0f, P->text2, A_CENTER);
        y += 100.0f;
    }

    y += 8.0f;
    {
        const wchar_t *lab = L"Enter address manually";
        float          tw = ceilf(text_width(lab, F_BODY));
        float          w = 8.0f + tw + 8.0f + 12.0f + 8.0f;
        BOOL           hot = g.hot == C_MANUAL, pr = hot && g.pressed == C_MANUAL;
        UINT32         c = P->hc && hot ? P->on_accent : P->accent_text;
        add_item(C_MANUAL, K_BUTTON, 8.0f, y, w, 32.0f, 4.0f);
        fill_rr(8.0f, y, w, 32.0f, 4.0f, pr ? P->sub_pr : hot ? P->sub_hover : 0);
        (void)text(lab, F_BODY, 16.0f, y + 6.0f, tw + 2.0f, 20.0f, c, A_LEAD);
        glyph(g.manual ? G_CHEV_U : G_CHEV_D, 12, 16.0f + tw + 8.0f + 6.0f, y + 16.0f, c);
    }
    y += 32.0f;
    if (g.manual) {
        y += 8.0f;
        field_row(y);
        y += 32.0f;
    }
    return y + 16.0f;
}

static float view_status(void)
{
    const fly_pal   *P = &g.P;
    const fly_state *st = &g.st;
    wchar_t          status[64], title[FLY_NAME_MAX + 32];
    BOOL             down = st->conn == FLY_CONN_WAITING || st->conn == FLY_CONN_NOT_FOUND;
    BOOL             connected = st->conn == FLY_CONN_CONNECTED;
    const wchar_t   *name = mac_display_name();
    float            y;

    if (connected) {
        if (st->latency_ms >= 0)
            (void)StringCchPrintfW(status, ARRAYSIZE(status), L"Connected \x00B7 %d ms", st->latency_ms);
        else
            (void)StringCchCopyW(status, ARRAYSIZE(status), L"Connected");
        hero(mac_glyph(name), FALSE, name, P->success, status);
    } else if (down) {
        hero(mac_glyph(name), TRUE, name, P->critical, L"Not connected");
    } else {
        hero(mac_glyph(name), FALSE, name, P->caution, L"Connecting\x2026");
    }
    y = notice(76.0f);
    y = update_bar(y);

    if (down) {
        const wchar_t *cap = st->conn == FLY_CONN_NOT_FOUND
                                 ? L"Check that your Mac is on and on the same network."
                                 : L"Make sure your Mac is awake and on the same network.";
        float          th, cap_h, ch;
        if (st->conn == FLY_CONN_NOT_FOUND)
            (void)StringCchPrintfW(title, ARRAYSIZE(title), L"Can\x2019t find %ls", name);
        else
            (void)StringCchCopyW(title, ARRAYSIZE(title), L"Trying to reconnect\x2026");
        th = text_wrap(title, F_BODY, 0.0f, 0.0f, 184.0f, 0, A_LEAD);
        cap_h = text_wrap(cap, F_CAPTION, 0.0f, 0.0f, 180.0f, 0, A_LEAD);
        ch = 12.0f + th + cap_h + 12.0f;
        if (ch < 80.0f)
            ch = 80.0f;
        card(16.0f, y, 328.0f, ch);
        ring(40.0f, y + 22.0f, 16.0f);
        (void)text_wrap(title, F_BODY, 56.0f, y + 12.0f, 184.0f, P->text1, A_LEAD);
        (void)text_wrap(cap, F_CAPTION, 56.0f, y + 12.0f + th, 180.0f, P->text2, A_LEAD);
        button(C_TRY_NOW, B_STD, 248.0f, y + (ch - 32.0f) * 0.5f, 80.0f, 32.0f, L"Try now", 0, 0, TRUE);
        y += ch + 12.0f;
    }

    card(16.0f, y, 328.0f, 121.0f);
    {
        UINT32 t1 = connected ? P->text1 : P->textdis, t2 = connected ? P->text2 : P->textdis;
        glyph(G_KEYBOARD, 16, 40.0f, y + 30.0f, connected ? P->text1 : P->textdis);
        (void)text(L"Keyboard", F_BODY, 64.0f, y + 10.0f, 264.0f, 20.0f, t1, A_LEAD);
        (void)text(connected ? L"Use Windows mode on your Mac to type here."
                             : L"Available when your Mac is connected.",
                   F_CAPTION, 64.0f, y + 30.0f, 264.0f, 16.0f, t2, A_LEAD);
    }
    divider(32.0f, 328.0f, y + 60.0f);
    add_item(C_TOG_CLIP, K_TOGGLE, 20.0f, y + 63.0f, 320.0f, 54.0f, 4.0f);
    glyph(G_CLIPBOARD, 16, 40.0f, y + 91.0f, P->text1);
    (void)text(L"Share clipboard", F_BODY, 64.0f, y + 71.0f, 216.0f, 20.0f, P->text1, A_LEAD);
    (void)text(L"Copied text works on both devices.", F_CAPTION, 64.0f, y + 91.0f, 216.0f, 16.0f, P->text2,
               A_LEAD);
    toggle(C_TOG_CLIP, 288.0f, y + 81.0f, st->clipboard, TRUE);
    return y + 121.0f + 16.0f;
}

static float view_compare(void)
{
    const fly_pal   *P = &g.P;
    const fly_state *st = &g.st;
    const wchar_t   *hint = L"Make sure your Mac shows the same number.";
    wchar_t          num[16];
    float            hint_h, cy, by;

    hero(G_LINK, FALSE, L"Confirm pairing", 0, st->pair_name[0] != 0 ? st->pair_name : L"Your Mac");
    hint_h = text_wrap(hint, F_BODY, 0.0f, 0.0f, 296.0f, 0, A_CENTER);
    cy = 76.0f;
    card(16.0f, cy, 328.0f, 16.0f + hint_h + 8.0f + 52.0f + 16.0f);
    (void)text_wrap(hint, F_BODY, 32.0f, cy + 16.0f, 296.0f, P->text2, A_CENTER);
    (void)StringCchPrintfW(num, ARRAYSIZE(num), L"%03u %03u", (unsigned)((st->sas / 1000u) % 1000u),
                           (unsigned)(st->sas % 1000u));
    (void)text(num, F_TITLE, 16.0f, cy + 16.0f + hint_h + 8.0f, 328.0f, 52.0f, P->text1, A_CENTER);
    by = cy + 16.0f + hint_h + 8.0f + 52.0f + 16.0f + 16.0f;

    if (st->pair == FLY_PAIR_WAIT_MAC) {
        const wchar_t *w = L"Waiting for your Mac to confirm\x2026";
        if (text_width(w, F_BODY) > 196.0f)
            w = L"Waiting for your Mac\x2026";
        ring(24.0f, by + 16.0f, 16.0f);
        (void)text(w, F_BODY, 40.0f, by + 6.0f, 200.0f, 20.0f, P->text2, A_LEAD);
        button(C_CMP_CANCEL, B_STD, 248.0f, by, 96.0f, 32.0f, L"Cancel", 0, 0, TRUE);
    } else {
        button(C_CONFIRM, B_ACCENT, 16.0f, by, 160.0f, 32.0f, L"Confirm", 0, 0, TRUE);
        button(C_CMP_CANCEL, B_STD, 184.0f, by, 160.0f, 32.0f, L"Cancel", 0, 0, TRUE);
    }
    return by + 32.0f + 16.0f;
}

static float view_success(void)
{
    const fly_pal *P = &g.P;
    wchar_t        title[FLY_NAME_MAX + 32];
    float          th, bh;

    fill_circle(180.0f, 48.0f, 24.0f, P->success_tint);
    glyph(G_CHECK, 24, 180.0f, 48.0f, P->success);
    (void)StringCchPrintfW(title, ARRAYSIZE(title), L"Paired with %ls",
                           g.st.pair_name[0] != 0 ? g.st.pair_name : L"your Mac");
    th = text_wrap(title, F_SUBTITLE, 16.0f, 88.0f, 328.0f, P->text1, A_CENTER);
    bh = text_wrap(L"Switch your Mac to Windows mode to type on this PC.", F_BODY, 16.0f, 92.0f + th, 328.0f,
                   P->text2, A_CENTER);
    return 92.0f + th + bh + 24.0f;
}

static float view_settings(void)
{
    const fly_pal   *P = &g.P;
    const fly_state *st = &g.st;
    BOOL             paired = st->conn != FLY_CONN_UNPAIRED;
    float            y, cy;

    page_header(L"Settings");
    y = notice(60.0f);
    y = update_bar(y);

    /* General */
    (void)text(L"General", F_STRONG, 16.0f, y, 328.0f, 20.0f, P->text1, A_LEAD);
    cy = y + 28.0f;
    card(16.0f, cy, 328.0f, 113.0f);
    add_item(C_TOG_AUTOSTART, K_TOGGLE, 20.0f, cy + 2.0f, 320.0f, 44.0f, 4.0f);
    (void)text(L"Start with Windows", F_BODY, 32.0f, cy + 14.0f, 240.0f, 20.0f, P->text1, A_LEAD);
    toggle(C_TOG_AUTOSTART, 288.0f, cy + 14.0f, st->autostart, TRUE);
    divider(32.0f, 328.0f, cy + 48.0f);
    add_item(C_TOG_CLIP, K_TOGGLE, 20.0f, cy + 51.0f, 320.0f, 60.0f, 4.0f);
    (void)text(L"Share clipboard", F_BODY, 32.0f, cy + 59.0f, 240.0f, 20.0f, P->text1, A_LEAD);
    (void)text(L"Copied text works on both devices.", F_CAPTION, 32.0f, cy + 79.0f, 240.0f, 16.0f, P->text2,
               A_LEAD);
    toggle(C_TOG_CLIP, 288.0f, cy + 71.0f, st->clipboard, TRUE);
    y = cy + 113.0f + 16.0f;

    /* Updates */
    (void)text(L"Updates", F_STRONG, 16.0f, y, 328.0f, 20.0f, P->text1, A_LEAD);
    cy = y + 28.0f;
    card(16.0f, cy, 328.0f, 97.0f);
    add_item(C_TOG_AUTOUPDATE, K_TOGGLE, 20.0f, cy + 2.0f, 320.0f, 44.0f, 4.0f);
    (void)text(L"Check for updates automatically", F_BODY, 32.0f, cy + 14.0f, 248.0f, 20.0f, P->text1, A_LEAD);
    toggle(C_TOG_AUTOUPDATE, 288.0f, cy + 14.0f, st->autoupdate, TRUE);
    divider(32.0f, 328.0f, cy + 48.0f);
    if (st->upd == FLY_UPD_CHECKING) {
        ring(320.0f, cy + 73.0f, 16.0f);
        (void)text(L"Checking for updates\x2026", F_BODY, 32.0f, cy + 63.0f, 264.0f, 20.0f, P->text2, A_LEAD);
    } else {
        BOOL busy = st->upd == FLY_UPD_DOWNLOADING || st->upd == FLY_UPD_INSTALLING;
        (void)text(st->upd_status[0] != 0 ? st->upd_status : L"Version", F_BODY, 32.0f, cy + 63.0f, 200.0f,
                   20.0f, P->text2, A_LEAD);
        button(C_CHECK_NOW, B_STD, 240.0f, cy + 57.0f, 88.0f, 32.0f, L"Check now", 0, 0, !busy);
    }
    y = cy + 97.0f + 16.0f;

    /* Paired Mac */
    (void)text(L"Paired Mac", F_STRONG, 16.0f, y, 328.0f, 20.0f, P->text1, A_LEAD);
    cy = y + 28.0f;
    if (!paired) {
        card(16.0f, cy, 328.0f, 48.0f);
        (void)text(L"No Mac paired", F_BODY, 32.0f, cy + 14.0f, 200.0f, 20.0f, P->text2, A_LEAD);
        button(C_PAIR_NEW, B_ACCENT, 248.0f, cy + 8.0f, 80.0f, 32.0f, L"Pair", 0, 0, TRUE);
        return cy + 48.0f + 16.0f;
    }
    {
        const wchar_t *name = mac_display_name();
        float          r1;
        if (g.forget_confirm) {
            wchar_t q[FLY_NAME_MAX + 64];
            float   qh;
            (void)StringCchPrintfW(q, ARRAYSIZE(q), L"Forget %ls? You\x2019ll need to pair again.", name);
            qh = text_wrap(q, F_BODY, 0.0f, 0.0f, 296.0f, 0, A_LEAD);
            r1 = 12.0f + qh + 12.0f + 32.0f + 12.0f;
            card(16.0f, cy, 328.0f, r1 + 1.0f + 48.0f);
            (void)text_wrap(q, F_BODY, 32.0f, cy + 12.0f, 296.0f, P->text1, A_LEAD);
            button(C_FORGET_YES, B_CRIT, 32.0f, cy + 24.0f + qh, 96.0f, 32.0f, L"Forget", 0, 0, TRUE);
            button(C_FORGET_NO, B_STD, 136.0f, cy + 24.0f + qh, 96.0f, 32.0f, L"Cancel", 0, 0, TRUE);
        } else {
            UINT32         dot;
            const wchar_t *s;
            r1 = 64.0f;
            switch (st->conn) {
            case FLY_CONN_CONNECTED:
                dot = P->success;
                s = L"Connected";
                break;
            case FLY_CONN_WAITING:
                dot = P->critical;
                s = L"Not connected";
                break;
            case FLY_CONN_NOT_FOUND:
                dot = P->critical;
                s = L"Can\x2019t find it on the network";
                break;
            case FLY_CONN_NOT_PAIRED:
                dot = P->caution;
                s = L"Needs to pair again";
                break;
            default:
                dot = P->caution;
                s = L"Connecting\x2026";
                break;
            }
            card(16.0f, cy, 328.0f, 113.0f);
            glyph(mac_glyph(name), 20, 42.0f, cy + 32.0f, P->text2);
            (void)text(name, F_STRONG, 64.0f, cy + 10.0f, 176.0f, 20.0f, P->text1, A_LEAD);
            status_dot(68.0f, cy + 38.0f, dot);
            (void)text(s, F_CAPTION, 78.0f, cy + 30.0f, 162.0f, 16.0f, P->text2, A_LEAD);
            button(C_FORGET, B_STD, 248.0f, cy + 16.0f, 80.0f, 32.0f, L"Forget", 0, 0, TRUE);
        }
        divider(32.0f, 328.0f, cy + r1);
        {
            float ry = cy + r1 + 1.0f;
            BOOL  hot = g.hot == C_PAIR_OTHER, pr = hot && g.pressed == C_PAIR_OTHER;
            UINT32 tc = P->hc && hot ? P->on_accent : P->text1;
            add_item(C_PAIR_OTHER, K_BUTTON, 20.0f, ry + 2.0f, 320.0f, 44.0f, 4.0f);
            fill_rr(20.0f, ry + 2.0f, 320.0f, 44.0f, 4.0f, pr ? P->sub_pr : hot ? P->sub_hover : 0);
            (void)text(L"Pair with a different Mac", F_BODY, 32.0f, ry + 14.0f, 270.0f, 20.0f, tc, A_LEAD);
            glyph(G_CHEV_R, 12, 322.0f, ry + 24.0f, P->hc && hot ? P->on_accent : P->text3);
        }
        return cy + r1 + 1.0f + 48.0f + 16.0f;
    }
}

/* Lays out (and, in the drawing pass, draws) the current view. Returns the
 * panel height. */
static float build(void)
{
    float y;
    int   v = cur_view();

    g.nitems = 0;
    g.has_footer = FALSE;
    g.field_visible = FALSE;
    if (g.draw && g.rt != NULL) {
        float       bottom = (v == V_COMPARE || v == V_SUCCESS) ? g.ph : g.ph - FOOTER_H;
        D2D1_RECT_F clip = rectf(-SH_L, 0.0f, PANEL_W + SH_L + SH_R, bottom);
        g.rt->PushAxisAlignedClip(&clip, D2D1_ANTIALIAS_MODE_ALIASED);
    }
    switch (v) {
    case V_COMPARE:
        y = view_compare();
        break;
    case V_SUCCESS:
        y = view_success();
        break;
    case V_SETTINGS:
        y = view_settings();
        footer(y, TRUE);
        y += FOOTER_H;
        break;
    case V_PAIR:
        y = view_pair();
        footer(y, FALSE);
        y += FOOTER_H;
        break;
    default:
        y = view_status();
        footer(y, FALSE);
        y += FOOTER_H;
        break;
    }
    if (!g.has_footer && g.draw && g.rt != NULL)
        g.rt->PopAxisAlignedClip();
    return ceilf(y);
}

static void draw_focus(void)
{
    const fly_item *it;
    D2D1_ROUNDED_RECT rr;

    if (!g.show_focus || g.focus == C_NONE || !drawing())
        return;
    it = find_item(g.focus);
    if (it == NULL)
        return;
    rr.rect = rectf(snap(it->x) - 2.0f, snap(it->y) - 2.0f, snap(it->w) + 4.0f, snap(it->h) + 4.0f);
    rr.radiusX = rr.radiusY = it->r + 2.0f;
    set_brush(g.P.focus_outer);
    g.rt->DrawRoundedRectangle(&rr, g.br, 2.0f, NULL);
    rr.rect = rectf(snap(it->x) - 0.5f, snap(it->y) - 0.5f, snap(it->w) + 1.0f, snap(it->h) + 1.0f);
    rr.radiusX = rr.radiusY = it->r + 0.5f;
    set_brush(g.P.focus_inner);
    g.rt->DrawRoundedRectangle(&rr, g.br, 1.0f, NULL);
}

/* ------------------------------------------------------------------------ */
/* Placement                                                                */
/* ------------------------------------------------------------------------ */

static void place(POINT anchor)
{
    NOTIFYICONIDENTIFIER nii;
    APPBARDATA           abd;
    MONITORINFO          mi;
    RECT                 icon, tb, work, tmp;
    BOOL                 have_icon, have_tb, tb_here;
    HMONITOR             mon;
    POINT                c;
    int                  m, w;

    memset(&nii, 0, sizeof(nii));
    SetRectEmpty(&icon);
    nii.cbSize = sizeof(nii);
    nii.hWnd = g.owner;
    nii.uID = g.uid;
    have_icon = g.owner != NULL && SUCCEEDED(Shell_NotifyIconGetRect(&nii, &icon));
    memset(&abd, 0, sizeof(abd));
    abd.cbSize = sizeof(abd);
    have_tb = SHAppBarMessage(ABM_GETTASKBARPOS, &abd) != 0;
    tb = abd.rc;
    if (have_icon && have_tb && !IntersectRect(&tmp, &icon, &tb))
        have_icon = FALSE; /* in the overflow */

    if (have_icon) {
        c.x = (icon.left + icon.right) / 2;
        c.y = (icon.top + icon.bottom) / 2;
    } else if (anchor.x == -1 && anchor.y == -1) {
        if (!GetCursorPos(&c)) {
            c.x = 0;
            c.y = 0;
        }
    } else {
        c = anchor;
    }
    mon = MonitorFromPoint(c, MONITOR_DEFAULTTONEAREST);
    memset(&mi, 0, sizeof(mi));
    mi.cbSize = sizeof(mi);
    if (!GetMonitorInfoW(mon, &mi)) {
        SetRect(&mi.rcWork, 0, 0, GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN));
    }
    work = mi.rcWork;
    tb_here = have_tb && MonitorFromRect(&tb, MONITOR_DEFAULTTONULL) == mon;
    g.edge = tb_here ? abd.uEdge : ABE_BOTTOM;
    if (tb_here) {
        switch (g.edge) {
        case ABE_BOTTOM:
            if (tb.top < work.bottom && tb.top > work.top)
                work.bottom = tb.top;
            break;
        case ABE_TOP:
            if (tb.bottom > work.top && tb.bottom < work.bottom)
                work.top = tb.bottom;
            break;
        case ABE_LEFT:
            if (tb.right > work.left && tb.right < work.right)
                work.left = tb.right;
            break;
        case ABE_RIGHT:
            if (tb.left < work.right && tb.left > work.left)
                work.right = tb.left;
            break;
        default:
            break;
        }
    }
    g.work = work;
    g.dpi = monitor_dpi(mon);
    g.s = (float)g.dpi / 96.0f;
    m = MulDiv((int)g.gap, (int)g.dpi, 96);
    w = (int)ceilf(PANEL_W * g.s);
    g.panel_left = g.edge == ABE_LEFT ? work.left + m : work.right - m - w;
    if (g.panel_left < work.left + m)
        g.panel_left = work.left + m;
    g.anchor_top = g.edge == ABE_TOP;
    g.panel_anchor = g.anchor_top ? work.top + m : work.bottom - m;
}

/* Window rectangle (without the enter/exit offset) for panel height ph. */
static void window_rect(float ph)
{
    int ph_px = (int)ceilf(ph * g.s - 0.01f);
    int top = g.anchor_top ? g.panel_anchor : g.panel_anchor - ph_px;
    g.win_x = g.panel_left - px(SH_L);
    g.win_y = top - px(SH_T);
    g.win_w = (int)ceilf(PANEL_W * g.s) + px(SH_L) + px(SH_R);
    g.win_h = ph_px + px(SH_T) + px(SH_B);
}

static float max_panel_h(void)
{
    int m = MulDiv((int)g.gap, (int)g.dpi, 96);
    float h = (float)(g.work.bottom - g.work.top - 2 * m) / g.s;
    return h > 120.0f ? h : 120.0f;
}

/* ------------------------------------------------------------------------ */
/* Present                                                                  */
/* ------------------------------------------------------------------------ */

static void vis_values(float *alpha, float *off)
{
    double t = now_ms() - g.vis_t0;
    *alpha = 1.0f;
    *off = 0.0f;
    if (g.vis_mode == 1) {
        float dur = g.motion ? 200.0f : 83.0f, fade = g.motion ? 100.0f : 83.0f;
        float p = clamp01((float)t / dur);
        *alpha = clamp01((float)t / fade);
        *off = g.motion ? 16.0f * (1.0f - ease_out4(p)) : 0.0f;
    } else if (g.vis_mode == 2) {
        float dur = g.motion ? 100.0f : 83.0f;
        float p = clamp01((float)t / dur);
        *alpha = g.vis_alpha0 * (1.0f - p);
        *off = g.motion ? 8.0f * p * p : 0.0f;
    }
}

static void offset_px(float off, int *dx, int *dy)
{
    int o = px(off);
    *dx = 0;
    *dy = 0;
    switch (g.edge) {
    case ABE_TOP:
        *dy = -o;
        break;
    case ABE_LEFT:
        *dx = -o;
        break;
    case ABE_RIGHT:
        *dx = o;
        break;
    default:
        *dy = o;
        break;
    }
}

static void ulw(BOOL bits)
{
    POINT         dst, src;
    SIZE          sz;
    BLENDFUNCTION bf;
    float         a, off;
    int           dx, dy;

    vis_values(&a, &off);
    offset_px(off, &dx, &dy);
    dst.x = g.win_x + dx;
    dst.y = g.win_y + dy;
    src.x = 0;
    src.y = 0;
    sz.cx = g.win_w;
    sz.cy = g.win_h;
    bf.BlendOp = AC_SRC_OVER;
    bf.BlendFlags = 0;
    bf.SourceConstantAlpha = (BYTE)(clamp01(a) * 255.0f + 0.5f);
    bf.AlphaFormat = AC_SRC_ALPHA;
    if (bits)
        (void)UpdateLayeredWindow(g.hwnd, NULL, &dst, &sz, g.memdc, &src, 0, &bf, ULW_ALPHA);
    else
        (void)UpdateLayeredWindow(g.hwnd, NULL, &dst, NULL, NULL, NULL, 0, &bf, ULW_ALPHA);
}

static BOOL animating_layout(void)
{
    return g.pg_active || g.h_active || g.vis_mode != 0;
}

static void host_sync(void)
{
    BOOL show = g.visible && !g.hiding && g.field_visible && !animating_layout() && g.host != NULL;
    if (show) {
        float a, off;
        int   dx, dy, x0, y0, x1, y1;
        vis_values(&a, &off);
        offset_px(off, &dx, &dy);
        x0 = g.win_x + dx + px(SH_L + g.slide + g.fx + 11.0f);
        y0 = g.win_y + dy + px(SH_T + g.fy + 6.0f);
        x1 = g.win_x + dx + px(SH_L + g.slide + g.fx + g.fw - 8.0f);
        y1 = g.win_y + dy + px(SH_T + g.fy + g.fh - 7.0f);
        if (!IsWindowVisible(g.host) || g.host_rect.left != x0 || g.host_rect.top != y0 ||
            g.host_rect.right != x1 || g.host_rect.bottom != y1) {
            SetRect(&g.host_rect, x0, y0, x1, y1);
            SetWindowPos(g.host, HWND_TOPMOST, x0, y0, x1 - x0, y1 - y0, SWP_NOACTIVATE | SWP_SHOWWINDOW);
            if (g.edit != NULL)
                SetWindowPos(g.edit, NULL, 0, 0, x1 - x0, y1 - y0, SWP_NOZORDER | SWP_NOACTIVATE);
        }
        if (g.edit_pending && g.edit != NULL) {
            g.edit_pending = FALSE;
            SetFocus(g.edit);
        }
    } else if (g.host != NULL && IsWindowVisible(g.host)) {
        if (GetFocus() == g.edit && g.visible)
            SetFocus(g.hwnd);
        ShowWindow(g.host, SW_HIDE);
    }
}

static void choose_initial_focus(void)
{
    int i;
    g.want_focus = FALSE;
    if (cur_view() == V_COMPARE) {
        g.focus = C_CMP_CANCEL;
        return;
    }
    if (!g.keyboard) {
        g.focus = C_NONE;
        return;
    }
    for (i = 0; i < g.nitems; i++) {
        if (g.items[i].id != C_BACK) {
            g.focus = g.items[i].id;
            return;
        }
    }
    g.focus = g.nitems > 0 ? g.items[0].id : C_NONE;
}

static void render(void)
{
    float  H, e = 1.0f, maxh;
    int    v;
    double t;
    HRESULT hr;
    RECT   bind;

    if (!g.visible || g.hwnd == NULL || !g.d2d_ok)
        return;

    /* Measure. */
    g.draw = FALSE;
    g.alpha = 1.0f;
    g.ring_seen = FALSE;
    H = build();
    maxh = max_panel_h();
    if (H > maxh)
        H = maxh;
    v = cur_view();
    t = now_ms();
    if (g.drawn_view != V_NONE && v != g.drawn_view) {
        g.pg_active = TRUE;
        g.h_active = FALSE;
        g.pg_t0 = t;
        g.h_from = g.h_cur;
        if (cur_view() == V_COMPARE)
            g.focus = C_CMP_CANCEL;
        else if (g.focus != C_NONE && find_item(g.focus) == NULL)
            g.focus = C_NONE;
    } else if (g.drawn_view == V_NONE) {
        g.h_cur = H;
    } else if (!g.pg_active && !g.h_active && fabsf(H - g.h_cur) > 0.5f) {
        g.h_active = TRUE;
        g.pg_t0 = t;
        g.h_from = g.h_cur;
    }
    g.drawn_view = v;
    if (g.want_focus)
        choose_initial_focus();

    g.slide = 0.0f;
    g.alpha = 1.0f;
    if (g.pg_active || g.h_active) {
        float p = clamp01((float)((t - g.pg_t0) / 167.0));
        e = ease_out3(p);
        if (!g.motion)
            e = 1.0f;
        g.h_cur = g.h_from + (H - g.h_from) * e;
        if (g.pg_active) {
            g.slide = g.motion ? 24.0f * (1.0f - e) * (float)g.nav_dir : 0.0f;
            g.alpha = g.motion ? clamp01(p) : 1.0f;
        }
        if (p >= 1.0f || !g.motion) {
            g.pg_active = FALSE;
            g.h_active = FALSE;
            g.h_cur = H;
            g.slide = 0.0f;
            g.alpha = 1.0f;
            g.nav_dir = 0;
        }
    } else {
        g.h_cur = H;
    }
    g.ph = ceilf(g.h_cur * g.s - 0.01f) / g.s;

    window_rect(g.ph);
    if (!device_ensure(g.win_w, g.win_h)) {
        device_release();
        return;
    }
    bind.left = 0;
    bind.top = 0;
    bind.right = g.win_w;
    bind.bottom = g.win_h;
    if (FAILED(g.rt->BindDC(g.memdc, &bind))) {
        device_release();
        return;
    }

    g.rt->BeginDraw();
    g.rt->SetDpi((float)g.dpi, (float)g.dpi);
    g.rt->SetTextAntialiasMode(D2D1_TEXT_ANTIALIAS_MODE_GRAYSCALE);
    g.rt->SetAntialiasMode(D2D1_ANTIALIAS_MODE_PER_PRIMITIVE);
    {
        D2D1_COLOR_F clear;
        clear.r = clear.g = clear.b = clear.a = 0.0f;
        g.rt->Clear(&clear);
    }
    g.draw = TRUE;
    {
        float          a = g.alpha, R = g.radius;
        const fly_pal *P = &g.P;
        int            i;

        g.alpha = 1.0f;
        set_xform(SH_L, SH_T);
        /* Shadow, clipped to the work area so nothing lands on the taskbar. */
        if (P->shadow != 0) {
            D2D1_RECT_F clip;
            clip.left = (float)(g.work.left - g.win_x) / g.s - SH_L;
            clip.top = (float)(g.work.top - g.win_y) / g.s - SH_T;
            clip.right = (float)(g.work.right - g.win_x) / g.s - SH_L;
            clip.bottom = (float)(g.work.bottom - g.win_y) / g.s - SH_T;
            g.rt->PushAxisAlignedClip(&clip, D2D1_ANTIALIAS_MODE_ALIASED);
            for (i = 0; i < 8; i++) {
                float d = 2.0f * (float)(i + 1);
                D2D1_ROUNDED_RECT rr;
                rr.rect = rectf(-d, 6.0f - d, PANEL_W + 2.0f * d, g.ph + 2.0f * d);
                rr.radiusX = rr.radiusY = R + d;
                set_brush(P->shadow);
                g.rt->FillRoundedRectangle(&rr, g.br);
            }
            g.rt->PopAxisAlignedClip();
        }
        /* Panel and footer band. */
        if (v != V_COMPARE && v != V_SUCCESS) {
            float F = g.ph - FOOTER_H;
            fill_rr(0.0f, 0.0f, PANEL_W, g.ph, R, P->footer);
            fill_rr(0.0f, 0.0f, PANEL_W, F + R, R, P->panel);
            fill_rr(0.0f, F, PANEL_W, R, 0.0f, P->footer);
            if (P->hc)
                divider(0.0f, PANEL_W, F);
            else
                fill_rr(0.0f, F, PANEL_W, 1.0f / g.s, 0.0f, P->footer_div);
        } else {
            fill_rr(0.0f, 0.0f, PANEL_W, g.ph, R, P->panel);
        }
        /* Content. */
        set_xform(SH_L + g.slide, SH_T);
        g.alpha = a;
        (void)build();
        draw_focus();
        g.alpha = 1.0f;
        /* Border. */
        set_xform(SH_L, SH_T);
        stroke_rr(0.0f, 0.0f, PANEL_W, g.ph, R, P->border);
    }
    g.draw = FALSE;
    hr = g.rt->EndDraw(NULL, NULL);
    if (FAILED(hr)) { /* D2DERR_RECREATE_TARGET included: start over next frame */
        device_release();
        return;
    }
    GdiFlush();
    ulw(TRUE);
    host_sync();
}

/* ------------------------------------------------------------------------ */
/* Timers, invalidation, sync                                               */
/* ------------------------------------------------------------------------ */

static void schedule(void);

static void invalidate(void)
{
    if (g.hwnd == NULL || !g.visible || g.render_posted)
        return;
    g.render_posted = TRUE;
    PostMessageW(g.hwnd, WM_FLY_RENDER, 0, 0);
}

static void post_sync(void)
{
    if (g.hwnd == NULL || g.sync_posted)
        return;
    g.sync_posted = TRUE;
    PostMessageW(g.hwnd, WM_FLY_SYNC, 0, 0);
}

static BOOL want_discovery(void)
{
    return g.visible && !g.hiding && cur_view() == V_PAIR && g.st.discovery_available &&
           (g.st.pair == FLY_PAIR_IDLE || g.st.pair == FLY_PAIR_BUSY);
}

static void do_sync(void)
{
    BOOL want;
    g.sync_posted = FALSE;
    want = want_discovery();
    if (want != g.disc_sent) {
        g.disc_sent = want;
        emit(FLY_ACT_DISCOVERY, want ? 1 : 0, NULL);
    }
}

static void finish_hide(void)
{
    g.vis_mode = 0;
    g.visible = FALSE;
    g.hiding = FALSE;
    if (g.host != NULL)
        ShowWindow(g.host, SW_HIDE);
    ShowWindow(g.hwnd, SW_HIDE);
    KillTimer(g.hwnd, T_POLL);
    device_release();
    g.forget_confirm = FALSE;
    emit(FLY_ACT_HIDDEN, 0, NULL);
    post_sync();
}

static void tick(void)
{
    double t = now_ms();
    BOOL   need_render = g.pg_active || g.h_active || g.ring_seen;
    BOOL   moving = g.vis_mode != 0;

    if (g.tog_id != C_NONE) {
        if (t - g.tog_t0 >= 167.0)
            g.tog_id = C_NONE;
        need_render = TRUE;
    }
    if (g.vis_mode == 1 && t - g.vis_t0 >= (g.motion ? 200.0 : 83.0)) {
        g.vis_mode = 0;
        need_render = TRUE; /* final position; shows the text field */
    } else if (g.vis_mode == 2 && t - g.vis_t0 >= (g.motion ? 100.0 : 83.0)) {
        finish_hide();
        schedule();
        return;
    }
    if (g.visible) {
        if (need_render)
            render();
        else if (moving)
            ulw(FALSE);
    }
    schedule();
}

/* Run the frame timer only while something moves. */
static void schedule(void)
{
    UINT ms = 0;
    if (g.visible && (g.vis_mode != 0 || g.pg_active || g.h_active || g.tog_id != C_NONE))
        ms = 15;
    else if (g.visible && g.ring_seen)
        ms = 33;
    if (ms == 0) {
        if (g.timer_on)
            KillTimer(g.hwnd, T_FRAME);
        g.timer_on = FALSE;
    } else if (!g.timer_on || g.timer_ms != ms) {
        SetTimer(g.hwnd, T_FRAME, ms, NULL);
        g.timer_on = TRUE;
        g.timer_ms = ms;
    }
}

/* ------------------------------------------------------------------------ */
/* Actions                                                                  */
/* ------------------------------------------------------------------------ */

static void go_page(fly_page p, int dir)
{
    if (g.page == p)
        return;
    if (p == FLY_PAGE_PAIR)
        g.back_page = g.page;
    g.page = p;
    g.nav_dir = dir;
    g.forget_confirm = FALSE;
    g.focus = C_NONE;
    g.hot = C_NONE;
    g.want_focus = g.keyboard || g.show_focus;
    invalidate();
    post_sync();
}

static void focus_field(void)
{
    if (g.edit == NULL)
        return;
    g.focus = C_FIELD;
    host_sync();
    if (IsWindowVisible(g.host))
        SetFocus(g.edit);
    invalidate();
}

static void read_field(wchar_t *out, int cap)
{
    out[0] = 0;
    if (g.edit != NULL)
        (void)GetWindowTextW(g.edit, out, cap);
}

static void activate(int id)
{
    wchar_t buf[FLY_ADDR_MAX + 16];

    if (id >= C_ROW0 && id < C_ROW0 + FLY_MAX_MACS) {
        int i = id - C_ROW0;
        if (i < g.st.nmacs)
            emit(FLY_ACT_PAIR_MAC, g.st.macs[i].id, NULL);
        return;
    }
    switch (id) {
    case C_SETTINGS:
        go_page(FLY_PAGE_SETTINGS, 1);
        break;
    case C_QUIT:
        emit(FLY_ACT_QUIT, 0, NULL);
        break;
    case C_BACK:
        go_page(g.page == FLY_PAGE_PAIR ? g.back_page : FLY_PAGE_HOME, -1);
        break;
    case C_MANUAL:
        g.manual = !g.manual;
        if (g.manual) {
            g.focus = C_FIELD;
            g.edit_pending = TRUE;
        } else {
            g.edit_pending = FALSE;
            if (g.edit != NULL && GetFocus() == g.edit)
                SetFocus(g.hwnd);
        }
        invalidate();
        break;
    case C_FIELD:
        focus_field();
        break;
    case C_PAIR_ADDR:
        read_field(buf, (int)ARRAYSIZE(buf));
        emit(FLY_ACT_PAIR_ADDRESS, 0, buf);
        break;
    case C_CANCEL_PAIR:
    case C_CMP_CANCEL:
        emit(FLY_ACT_CANCEL_PAIR, 0, NULL);
        break;
    case C_SEARCH_AGAIN:
        emit(FLY_ACT_SEARCH_AGAIN, 0, NULL);
        break;
    case C_CONFIRM:
        g.focus = C_CMP_CANCEL;
        emit(FLY_ACT_CONFIRM, 0, NULL);
        break;
    case C_TRY_NOW:
        emit(FLY_ACT_RECONNECT, 0, NULL);
        break;
    case C_TOG_CLIP:
        g.st.clipboard = !g.st.clipboard;
        g.tog_id = id;
        g.tog_t0 = now_ms();
        invalidate();
        schedule();
        emit(FLY_ACT_SET_CLIPBOARD, g.st.clipboard ? 1 : 0, NULL);
        break;
    case C_TOG_AUTOSTART:
        g.st.autostart = !g.st.autostart;
        g.tog_id = id;
        g.tog_t0 = now_ms();
        invalidate();
        schedule();
        emit(FLY_ACT_SET_AUTOSTART, g.st.autostart ? 1 : 0, NULL);
        break;
    case C_TOG_AUTOUPDATE:
        g.st.autoupdate = !g.st.autoupdate;
        g.tog_id = id;
        g.tog_t0 = now_ms();
        invalidate();
        schedule();
        emit(FLY_ACT_SET_AUTOUPDATE, g.st.autoupdate ? 1 : 0, NULL);
        break;
    case C_CHECK_NOW:
        emit(FLY_ACT_CHECK_UPDATE, 0, NULL);
        break;
    case C_FORGET:
        g.forget_confirm = TRUE;
        g.focus = C_FORGET_NO;
        invalidate();
        break;
    case C_FORGET_YES:
        g.forget_confirm = FALSE;
        g.focus = C_NONE;
        invalidate();
        emit(FLY_ACT_FORGET, 0, NULL);
        break;
    case C_FORGET_NO:
        g.forget_confirm = FALSE;
        g.focus = g.show_focus ? C_FORGET : C_NONE;
        invalidate();
        break;
    case C_PAIR_OTHER:
    case C_PAIR_NEW:
        go_page(FLY_PAGE_PAIR, 1);
        break;
    case C_UPD_INSTALL:
    case C_UPD_RETRY:
        emit(FLY_ACT_INSTALL_UPDATE, 0, NULL);
        break;
    case C_UPD_NOTES:
        emit(FLY_ACT_WHATS_NEW, 0, NULL);
        break;
    case C_UPD_CLOSE:
        emit(FLY_ACT_SKIP_UPDATE, 0, NULL);
        break;
    case C_UPD_CANCEL:
        emit(FLY_ACT_CANCEL_UPDATE, 0, NULL);
        break;
    case C_NOTICE_CLOSE:
        g.st.notice_sev = FLY_SEV_NONE;
        invalidate();
        emit(FLY_ACT_NOTICE_CLOSED, 0, NULL);
        break;
    default:
        break;
    }
}

static BOOL light_dismiss_allowed(void)
{
    return (g.flags & FLY_INIT_STICKY) == 0 && cur_view() != V_COMPARE;
}

static void escape(void)
{
    if (cur_view() == V_COMPARE) {
        emit(FLY_ACT_CANCEL_PAIR, 0, NULL);
        return;
    }
    if (g.forget_confirm) {
        g.forget_confirm = FALSE;
        invalidate();
        return;
    }
    if (g.page == FLY_PAGE_SETTINGS) {
        go_page(FLY_PAGE_HOME, -1);
        return;
    }
    if (g.page == FLY_PAGE_PAIR) {
        go_page(g.back_page, -1);
        return;
    }
    if ((g.flags & FLY_INIT_STICKY) == 0) {
        flyout_hide_impl(FALSE);
        if (g.keyboard && g.owner != NULL) {
            NOTIFYICONDATAW nid;
            memset(&nid, 0, sizeof(nid));
            nid.cbSize = sizeof(nid);
            nid.hWnd = g.owner;
            nid.uID = g.uid;
            (void)Shell_NotifyIconW(NIM_SETFOCUS, &nid);
        }
    }
}

/* Tab order: the order items were laid out in. */
static void move_focus(int delta)
{
    int i, cur = -1, n = g.nitems;
    if (n == 0)
        return;
    for (i = 0; i < n; i++) {
        if (g.items[i].id == g.focus) {
            cur = i;
            break;
        }
    }
    if (cur < 0)
        cur = delta > 0 ? n - 1 : 0;
    cur = (cur + delta + n) % n;
    g.focus = g.items[cur].id;
    g.show_focus = TRUE;
    if (g.focus == C_FIELD) {
        focus_field();
    } else {
        if (g.edit != NULL && GetFocus() == g.edit)
            SetFocus(g.hwnd);
        invalidate();
    }
}

/* ------------------------------------------------------------------------ */
/* Windows                                                                  */
/* ------------------------------------------------------------------------ */

static BOOL is_ours(HWND w)
{
    int i;
    for (i = 0; i < 4 && w != NULL; i++) {
        if (w == g.hwnd || (g.host != NULL && w == g.host))
            return TRUE;
        w = GetWindow(w, GW_OWNER);
    }
    return FALSE;
}

static BOOL cursor_on_icon(void)
{
    NOTIFYICONIDENTIFIER nii;
    RECT                 r;
    POINT                p;
    memset(&nii, 0, sizeof(nii));
    nii.cbSize = sizeof(nii);
    nii.hWnd = g.owner;
    nii.uID = g.uid;
    return GetCursorPos(&p) && SUCCEEDED(Shell_NotifyIconGetRect(&nii, &r)) && PtInRect(&r, p);
}

static void on_deactivate(HWND to)
{
    if (!g.visible || g.hiding || is_ours(to) || !g.activated || !light_dismiss_allowed())
        return;
    g.dismiss_on_icon = cursor_on_icon();
    g.dismiss_tick = GetTickCount64();
    flyout_hide_impl(TRUE);
}

static void theme_changed(void)
{
    pal_load();
    if (g.edit_brush != NULL) {
        DeleteObject(g.edit_brush);
        g.edit_brush = NULL;
    }
    invalidate();
    if (g.edit != NULL)
        InvalidateRect(g.edit, NULL, TRUE);
}

static void panel_point(LPARAM lp, float *x, float *y)
{
    *x = (float)FLY_X(lp) / g.s - SH_L;
    *y = (float)FLY_Y(lp) / g.s - SH_T;
}

static BOOL in_panel(float x, float y)
{
    return x >= 0.0f && y >= 0.0f && x < PANEL_W && y < g.ph;
}

static LRESULT CALLBACK fly_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    float x, y;

    switch (msg) {
    case WM_MOUSEMOVE: {
        int hit;
        if (!g.tracking) {
            TRACKMOUSEEVENT tme;
            tme.cbSize = sizeof(tme);
            tme.dwFlags = TME_LEAVE;
            tme.hwndTrack = hwnd;
            tme.dwHoverTime = 0;
            g.tracking = TrackMouseEvent(&tme);
        }
        panel_point(lp, &x, &y);
        hit = animating_layout() ? C_NONE : hit_test(x, y);
        if (hit != g.hot) {
            g.hot = hit;
            invalidate();
        }
        return 0;
    }
    case WM_MOUSELEAVE:
        g.tracking = FALSE;
        if (g.hot != C_NONE) {
            g.hot = C_NONE;
            invalidate();
        }
        return 0;
    case WM_LBUTTONDOWN:
    case WM_LBUTTONDBLCLK:
        panel_point(lp, &x, &y);
        g.show_focus = FALSE;
        if (!in_panel(x, y)) {
            if (light_dismiss_allowed())
                flyout_hide_impl(TRUE);
            return 0;
        }
        g.hot = animating_layout() ? C_NONE : hit_test(x, y);
        g.pressed = g.hot;
        if (g.pressed != C_NONE)
            SetCapture(hwnd);
        if (g.pressed != C_FIELD) {
            g.edit_pending = FALSE;
            if (g.edit != NULL && GetFocus() == g.edit)
                SetFocus(hwnd);
        }
        invalidate();
        return 0;
    case WM_LBUTTONUP: {
        int was = g.pressed;
        panel_point(lp, &x, &y);
        g.pressed = C_NONE;
        if (GetCapture() == hwnd)
            ReleaseCapture();
        if (was != C_NONE && hit_test(x, y) == was) {
            const fly_item *it = find_item(was);
            if (it != NULL && it->kind != K_FIELD)
                g.focus = was;
            activate(was);
        }
        invalidate();
        return 0;
    }
    case WM_CAPTURECHANGED:
        if (g.pressed != C_NONE) {
            g.pressed = C_NONE;
            invalidate();
        }
        return 0;
    case WM_KEYDOWN:
        switch (wp) {
        case VK_TAB:
            move_focus(GetKeyState(VK_SHIFT) < 0 ? -1 : 1);
            return 0;
        case VK_DOWN:
        case VK_RIGHT:
            move_focus(1);
            return 0;
        case VK_UP:
        case VK_LEFT:
            move_focus(-1);
            return 0;
        case VK_RETURN:
        case VK_SPACE:
            if (g.focus != C_NONE && find_item(g.focus) != NULL) {
                g.show_focus = TRUE;
                activate(g.focus);
            } else if (wp == VK_SPACE || cur_view() != V_COMPARE) {
                g.show_focus = TRUE;
                move_focus(1);
            }
            return 0;
        case VK_ESCAPE:
            escape();
            return 0;
        default:
            break;
        }
        break;
    case WM_ACTIVATE:
        if (LOWORD(wp) == WA_INACTIVE) {
            on_deactivate((HWND)lp);
        } else {
            g.activated = TRUE;
            KillTimer(hwnd, T_POLL);
        }
        return 0;
    case WM_MOUSEACTIVATE:
        return MA_ACTIVATE;
    case WM_TIMER:
        if (wp == T_FRAME) {
            tick();
        } else if (wp == T_THEME) {
            KillTimer(hwnd, T_THEME);
            theme_changed();
        } else if (wp == T_POLL) {
            POINT p;
            RECT  r;
            if (!g.visible || g.hiding || g.activated) {
                KillTimer(hwnd, T_POLL);
            } else if ((GetAsyncKeyState(VK_LBUTTON) & 0x8000) != 0 && GetCursorPos(&p) &&
                       GetWindowRect(hwnd, &r) && !PtInRect(&r, p) && light_dismiss_allowed()) {
                g.dismiss_on_icon = cursor_on_icon();
                g.dismiss_tick = GetTickCount64();
                flyout_hide_impl(TRUE);
            }
        }
        return 0;
    case WM_FLY_RENDER:
        g.render_posted = FALSE;
        render();
        schedule();
        return 0;
    case WM_FLY_SYNC:
        do_sync();
        return 0;
    case WM_SETTINGCHANGE:
        if (wp == SPI_SETWORKAREA && g.visible && !g.hiding) {
            POINT a;
            a.x = -1;
            a.y = -1;
            place(a);
            invalidate();
        }
        if (wp == SPI_SETCLIENTAREAANIMATION)
            g.motion = motion_enabled();
        SetTimer(hwnd, T_THEME, 100, NULL);
        return 0;
    case WM_THEMECHANGED:
    case WM_SYSCOLORCHANGE:
    case WM_DWMCOLORIZATIONCOLORCHANGED:
        SetTimer(hwnd, T_THEME, 100, NULL);
        return 0;
    case WM_DISPLAYCHANGE:
    case WM_DPICHANGED:
        if (g.visible && !g.hiding) {
            if ((g.flags & FLY_INIT_STICKY) != 0 || msg == WM_DPICHANGED) {
                POINT a;
                a.x = -1;
                a.y = -1;
                place(a);
                if (g.edit_font != NULL && g.edit_font_dpi != g.dpi && g.edit != NULL) {
                    HFONT f = CreateFontW(-MulDiv(14, (int)g.dpi, 96), 0, 0, 0, FW_NORMAL, FALSE, FALSE,
                                          FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                          ANTIALIASED_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
                    if (f != NULL) {
                        SendMessageW(g.edit, WM_SETFONT, (WPARAM)f, TRUE);
                        DeleteObject(g.edit_font);
                        g.edit_font = f;
                        g.edit_font_dpi = g.dpi;
                    }
                }
                invalidate();
            } else {
                flyout_hide_impl(FALSE);
            }
        }
        return 0;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        if (BeginPaint(hwnd, &ps) != NULL)
            EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_SETCURSOR:
        SetCursor(LoadCursorW(NULL, IDC_ARROW));
        return TRUE;
    case WM_CLOSE:
        if ((g.flags & FLY_INIT_STICKY) == 0)
            flyout_hide_impl(FALSE);
        return 0;
    case WM_DESTROY:
        KillTimer(hwnd, T_FRAME);
        KillTimer(hwnd, T_THEME);
        KillTimer(hwnd, T_POLL);
        g.timer_on = FALSE;
        return 0;
    default:
        break;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

/* The text field's host popup. */
static LRESULT CALLBACK edit_sub(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp, UINT_PTR id, DWORD_PTR ref)
{
    UNREFERENCED_PARAMETER(id);
    UNREFERENCED_PARAMETER(ref);
    switch (msg) {
    case WM_KEYDOWN:
        if (wp == VK_TAB) {
            g.focus = C_FIELD;
            SetFocus(g.hwnd);
            move_focus(GetKeyState(VK_SHIFT) < 0 ? -1 : 1);
            return 0;
        }
        if (wp == VK_RETURN) {
            activate(C_PAIR_ADDR);
            return 0;
        }
        if (wp == VK_ESCAPE) {
            SetFocus(g.hwnd);
            escape();
            return 0;
        }
        break;
    case WM_CHAR:
        if (wp == L'\t' || wp == L'\r' || wp == 0x1B)
            return 0;
        break;
    case WM_SETFOCUS:
    case WM_KILLFOCUS: {
        LRESULT r = DefSubclassProc(hwnd, msg, wp, lp);
        if (msg == WM_SETFOCUS)
            g.focus = C_FIELD;
        theme_changed(); /* the field's colors depend on focus */
        return r;
    }
    case WM_NCDESTROY:
        RemoveWindowSubclass(hwnd, edit_sub, 1);
        break;
    default:
        break;
    }
    return DefSubclassProc(hwnd, msg, wp, lp);
}

static COLORREF field_bg(void)
{
    BOOL focused = g.edit != NULL && GetFocus() == g.edit;
    return focused ? composite(g.P.field_focus, g.P.panel) : composite(g.P.ctl, g.P.panel);
}

static LRESULT CALLBACK host_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORSTATIC: {
        HDC      dc = (HDC)wp;
        COLORREF bg = field_bg();
        if (g.edit_brush == NULL || g.edit_bg != bg) {
            if (g.edit_brush != NULL)
                DeleteObject(g.edit_brush);
            g.edit_brush = CreateSolidBrush(bg);
            g.edit_bg = bg;
        }
        SetTextColor(dc, composite(g.P.text1, (UINT32)0xFF000000u | ((UINT32)GetRValue(bg) << 16) |
                                                  ((UINT32)GetGValue(bg) << 8) | (UINT32)GetBValue(bg)));
        SetBkColor(dc, bg);
        return (LRESULT)g.edit_brush;
    }
    case WM_ACTIVATE:
        if (LOWORD(wp) == WA_INACTIVE)
            on_deactivate((HWND)lp);
        else
            g.activated = TRUE;
        return 0;
    case WM_SETFOCUS:
        if (g.edit != NULL)
            SetFocus(g.edit);
        return 0;
    case WM_ERASEBKGND:
        return 1;
    case WM_MOUSEACTIVATE:
        return MA_ACTIVATE;
    default:
        break;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static void ensure_host(void)
{
    if (g.host != NULL)
        return;
    g.host = CreateWindowExW(WS_EX_TOOLWINDOW | WS_EX_TOPMOST, HOST_CLASS, L"", WS_POPUP | WS_CLIPCHILDREN,
                             0, 0, 10, 10, g.hwnd, NULL, g.inst, NULL);
    if (g.host == NULL)
        return;
    g.edit = CreateWindowExW(0, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 0, 0, 10, 10, g.host,
                             NULL, g.inst, NULL);
    if (g.edit == NULL)
        return;
    g.edit_font = CreateFontW(-MulDiv(14, (int)g.dpi, 96), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                              DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, ANTIALIASED_QUALITY,
                              DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    g.edit_font_dpi = g.dpi;
    if (g.edit_font != NULL)
        SendMessageW(g.edit, WM_SETFONT, (WPARAM)g.edit_font, FALSE);
    SendMessageW(g.edit, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, 0);
    SendMessageW(g.edit, EM_LIMITTEXT, FLY_ADDR_MAX, 0);
    SendMessageW(g.edit, EM_SETCUEBANNER, TRUE, (LPARAM)L"Camerons-MacBook.local or 192.168.1.20");
    SetWindowSubclass(g.edit, edit_sub, 1, 0);
}

/* ------------------------------------------------------------------------ */
/* Public API                                                               */
/* ------------------------------------------------------------------------ */

extern "C" BOOL flyout_init(HINSTANCE inst, HWND owner, UINT tray_uid, fly_action_fn fn, void *ctx,
                            unsigned flags)
{
    WNDCLASSEXW wc;

    g.inst = inst;
    g.owner = owner;
    g.uid = tray_uid;
    g.fn = fn;
    g.ctx = ctx;
    g.flags = flags;
    g.drawn_view = V_NONE;
    g.dpi = 96;
    g.s = 1.0f;
    g.alpha = 1.0f;
    g.st.pair_mac_id = -1;
    g.st.latency_ms = -1;
    g.st.upd_permille = -1;
    g.win11 = is_win11();
    g.radius = g.win11 ? 8.0f : 0.0f;
    g.gap = g.win11 ? 12.0f : 0.0f;

    memset(&wc, 0, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = fly_proc;
    wc.hInstance = inst;
    wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wc.lpszClassName = FLY_CLASS;
    if (!RegisterClassExW(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
        return FALSE;
    wc.lpfnWndProc = host_proc;
    wc.lpszClassName = HOST_CLASS;
    wc.hCursor = LoadCursorW(NULL, IDC_IBEAM);
    if (!RegisterClassExW(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
        return FALSE;

    g.hwnd = CreateWindowExW(WS_EX_LAYERED | WS_EX_TOOLWINDOW | WS_EX_TOPMOST, FLY_CLASS, L"KeyBridge",
                             WS_POPUP, 0, 0, 1, 1, NULL, NULL, inst, NULL);
    if (g.hwnd == NULL)
        return FALSE;
    dwm_set(g.hwnd, 3 /* DWMWA_TRANSITIONS_FORCEDISABLED */, TRUE);
    dwm_set(g.hwnd, 33 /* DWMWA_WINDOW_CORNER_PREFERENCE */, 1 /* DWMWCP_DONOTROUND */);
    pal_load();
    return TRUE;
}

extern "C" void flyout_set_state(const fly_state *s)
{
    fly_pair old_pair = g.st.pair;
    if (s == NULL)
        return;
    g.st = *s;
    if (g.st.nmacs < 0)
        g.st.nmacs = 0;
    if (g.st.nmacs > FLY_MAX_MACS)
        g.st.nmacs = FLY_MAX_MACS;
    if (s->pair == FLY_PAIR_SUCCESS && old_pair != FLY_PAIR_SUCCESS) {
        g.page = FLY_PAGE_HOME;
        g.manual = FALSE;
        if (g.edit != NULL)
            SetWindowTextW(g.edit, L"");
    }
    if (s->conn == FLY_CONN_UNPAIRED)
        g.forget_confirm = FALSE;
    invalidate();
    post_sync();
}

extern "C" BOOL flyout_show(POINT anchor, fly_page page, unsigned show_flags)
{
    float a = 0.0f, off = 0.0f;

    if (g.hwnd == NULL || !d2d_init())
        return FALSE;
    if (g.visible && !g.hiding) {
        if (page != g.page)
            go_page(page, page == FLY_PAGE_HOME ? -1 : 1);
        SetForegroundWindow(g.hwnd);
        return TRUE;
    }
    if (g.hiding)
        vis_values(&a, &off);
    g.page = page;
    g.back_page = FLY_PAGE_HOME;
    g.forget_confirm = FALSE;
    g.keyboard = (show_flags & FLY_SHOW_KEYBOARD) != 0;
    g.show_focus = g.keyboard;
    g.want_focus = TRUE;
    g.focus = C_NONE;
    g.hot = C_NONE;
    g.pressed = C_NONE;
    g.activated = FALSE;
    g.motion = motion_enabled();
    g.manual = !g.st.discovery_available ? FALSE : g.manual;
    pal_load();
    place(anchor);
    ensure_host();

    g.visible = TRUE;
    g.hiding = FALSE;
    g.drawn_view = V_NONE;
    g.pg_active = FALSE;
    g.h_active = FALSE;
    g.vis_mode = 1;
    g.vis_t0 = now_ms() - (double)a * (g.motion ? 100.0 : 83.0);
    render();
    SetWindowPos(g.hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
    SetForegroundWindow(g.hwnd);
    if (GetForegroundWindow() == g.hwnd)
        g.activated = TRUE;
    else if ((g.flags & FLY_INIT_STICKY) == 0)
        SetTimer(g.hwnd, T_POLL, 250, NULL);
    schedule();
    emit(FLY_ACT_SHOWN, 0, NULL);
    post_sync();
    return TRUE;
}

extern "C" BOOL flyout_toggle(POINT anchor, unsigned show_flags)
{
    ULONGLONG now = GetTickCount64();

    if (now - g.toggle_tick < 200)
        return TRUE; /* NIN_KEYSELECT can arrive twice */
    g.toggle_tick = now;
    if (g.visible && !g.hiding) {
        flyout_hide_impl(FALSE);
        return TRUE;
    }
    if (g.dismiss_on_icon && now - g.dismiss_tick < 800) {
        g.dismiss_on_icon = FALSE; /* this click is the one that just closed it */
        return TRUE;
    }
    g.dismiss_on_icon = FALSE;
    return flyout_show(anchor, FLY_PAGE_HOME, show_flags);
}

static void flyout_hide_impl(BOOL deactivated)
{
    UNREFERENCED_PARAMETER(deactivated);
    if (!g.visible || g.hiding || g.hwnd == NULL)
        return;
    {
        float a, off;
        vis_values(&a, &off);
        g.vis_alpha0 = a;
    }
    g.hiding = TRUE;
    g.vis_mode = 2;
    g.vis_t0 = now_ms();
    g.pressed = C_NONE;
    g.hot = C_NONE;
    if (GetCapture() == g.hwnd)
        ReleaseCapture();
    if (g.host != NULL)
        ShowWindow(g.host, SW_HIDE);
    KillTimer(g.hwnd, T_POLL);
    schedule();
    post_sync();
}

extern "C" void flyout_hide(void)
{
    flyout_hide_impl(FALSE);
}

extern "C" BOOL flyout_visible(void)
{
    return g.visible && !g.hiding;
}

extern "C" void flyout_shutdown(void)
{
    int i;
    if (g.host != NULL) {
        DestroyWindow(g.host);
        g.host = NULL;
        g.edit = NULL;
    }
    if (g.hwnd != NULL) {
        DestroyWindow(g.hwnd);
        g.hwnd = NULL;
    }
    g.visible = FALSE;
    device_release();
    for (i = 0; i < F_COUNT; i++) {
        safe_release(g.fmt[i]);
        safe_release(g.ell[i]);
    }
    safe_release(g.round);
    safe_release(g.dw);
    safe_release(g.d2d);
    g.d2d_ok = FALSE;
    if (g.edit_font != NULL) {
        DeleteObject(g.edit_font);
        g.edit_font = NULL;
    }
    if (g.edit_brush != NULL) {
        DeleteObject(g.edit_brush);
        g.edit_brush = NULL;
    }
}
