/*
 * KeyBridge - keystroke injection with SendInput, tracking which keys are
 * held so they can always be released (RELEASE_ALL, disconnect, quit).
 * One kb_keys per connection worker; not shared between threads.
 */
#ifndef KB_INJECT_H
#define KB_INJECT_H

#include "common.h"

typedef struct {
    uint8_t held[256]; /* 0 = up; otherwise the flags used for the key-down */
} kb_keys;

/* Inject one key event. Ignores vk outside 1..254. */
void inject_key(kb_keys *k, unsigned vk, BOOL extended, BOOL down);
/* Key-up for every key this kb_keys has pressed and not yet released. */
void inject_release_all(kb_keys *k);

#endif
