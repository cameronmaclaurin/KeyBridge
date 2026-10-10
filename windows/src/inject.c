/*
 * KeyBridge - SendInput key injection (see inject.h).
 */
#include "inject.h"

#define HELD_NORMAL   1
#define HELD_EXTENDED 2

/* Keys that need KEYEVENTF_EXTENDEDKEY (E0-prefixed scan codes). Without it
 * Windows treats the navigation keys as their numpad twins, which breaks
 * Shift+Arrow selection and friends. */
static BOOL is_extended_vk(unsigned vk)
{
    switch (vk) {
    case VK_INSERT: case VK_DELETE: case VK_HOME:  case VK_END:
    case VK_PRIOR:  case VK_NEXT:
    case VK_LEFT:   case VK_RIGHT:  case VK_UP:    case VK_DOWN:
    case VK_RCONTROL: case VK_RMENU:
    case VK_LWIN:   case VK_RWIN:   case VK_APPS:
    case VK_DIVIDE: case VK_NUMLOCK: case VK_SNAPSHOT:
        return TRUE;
    default:
        return FALSE;
    }
}

static void fill_input(INPUT *in, unsigned vk, BOOL extended, BOOL down)
{
    memset(in, 0, sizeof(*in));
    in->type = INPUT_KEYBOARD;
    in->ki.wVk = (WORD)vk;
    /* Real scan codes too: games and remote-desktop clients read those. */
    in->ki.wScan = (WORD)MapVirtualKeyW(vk, MAPVK_VK_TO_VSC);
    in->ki.dwFlags = (down ? 0 : KEYEVENTF_KEYUP) | (extended ? KEYEVENTF_EXTENDEDKEY : 0);
}

void inject_key(kb_keys *k, unsigned vk, BOOL extended, BOOL down)
{
    INPUT in;
    BOOL ext;

    if (vk < 1 || vk > 254)
        return;
    /* A key-up uses the same extended flag as its key-down. */
    if (!down && k->held[vk] != 0)
        ext = (k->held[vk] == HELD_EXTENDED);
    else
        ext = extended || is_extended_vk(vk);

    fill_input(&in, vk, ext, down);
    SendInput(1, &in, (int)sizeof(INPUT));
    k->held[vk] = (uint8_t)(down ? (ext ? HELD_EXTENDED : HELD_NORMAL) : 0);
}

void inject_release_all(kb_keys *k)
{
    INPUT ins[254];
    UINT n = 0;
    unsigned vk;

    for (vk = 1; vk <= 254; vk++) {
        if (k->held[vk] != 0) {
            fill_input(&ins[n++], vk, k->held[vk] == HELD_EXTENDED, FALSE);
            k->held[vk] = 0;
        }
    }
    if (n != 0)
        SendInput(n, ins, (int)sizeof(INPUT));
    memset(k->held, 0, sizeof(k->held));
}
