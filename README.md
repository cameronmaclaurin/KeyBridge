# KeyBridge ⌨️🌉

> Use your Mac keyboard to type on your Windows PC — no extra hardware, no runtimes, tiny native apps.

KeyBridge is a native two-part app: a Swift menu-bar app on your Mac that captures keystrokes and a C client on Windows that injects them. Press a hotkey to flip between which machine receives your typing.

## Downloads

Go to [**Releases**](../../releases) and grab the latest:

| File | Platform |
|------|----------|
| `KeyBridge-mac.zip` | macOS 13+ (Apple Silicon & Intel) |
| `keybridge.exe` | Windows 10/11 (64-bit) |

Neither app is code-signed by a paid developer account, so the first launch needs one extra click:
- **Mac:** System Settings → Privacy & Security → **Open Anyway**
- **Windows:** SmartScreen → **More info → Run anyway**

---

## How it works

```
  [Mac keyboard]
        │ CGEventTap
  KeyBridge.app  ── TCP · TCP_NODELAY · binary frames ──►  keybridge.exe
  (menu bar)                                                (system tray)
```

Both machines must be on the same network. Mac is the server (port 9876); Windows connects to it. The binary frame protocol is 4 bytes per key event — no JSON, no parsing overhead.

---

## Setup

### Mac

1. Unzip `KeyBridge-mac.zip` and move `KeyBridge.app` to `/Applications`.
2. Double-click it — a **⌨️** appears in your menu bar.
3. Grant **Accessibility** permission when macOS prompts you  
   *(System Settings → Privacy & Security → Accessibility → enable KeyBridge)*.  
   KeyBridge picks up the permission automatically — no relaunch needed.

### Windows

1. Find your **Mac's local IP**: System Settings → Wi-Fi → Details, or run `ifconfig en0` in Terminal.
2. Place `keybridge.exe` anywhere and run:

```
keybridge.exe 192.168.1.42
```

   A KeyBridge icon appears in the system tray. It connects to your Mac and auto-reconnects if the connection drops.

---

## Switching

| Action | Result |
|--------|--------|
| **Ctrl + Shift + `** | Toggle Local ↔ Windows mode |
| Click **⌨️** → *Switch to Windows Mode* | Same, via menu |

- **⌨️** = Local mode — keystrokes go to this Mac  
- **🟢** = Windows mode — keystrokes go to the Windows PC

Switching to Windows mode only works while a Windows PC is connected, so your keyboard never goes "dead". Any keys held at the moment you switch back are released on Windows so nothing sticks.

Mac **Command** maps to the Windows key and **Option** maps to Alt.

---

## Technical highlights

| | Mac | Windows |
|-------|-----|---------|
| Key capture / injection | `CGEventTap` at the HID level | `SendInput` with scan codes |
| Network | `Network.framework` TCP listener | Winsock2 TCP client |
| Latency | `TCP_NODELAY`, sends on the event-tap thread with no queue hop | `TCP_NODELAY`, batched `recv` |
| Protocol | 4-byte binary frame per key event | same |
| App size | ~300 KB universal binary | single `.exe`, no runtime |
| Memory | ~11 MB footprint (measured) | a few MB |
| Language | Swift | C |

In practice the delay you'll feel is your network's round-trip — wired Ethernet or 5 GHz Wi-Fi on the same router is best.

---

## Build from source

### Mac

```bash
mac/build_app.sh
# → mac/KeyBridge.app (universal, ad-hoc signed)
```

Requires Xcode Command Line Tools (`xcode-select --install`).

### Windows (MinGW)

```bat
cd windows
gcc -O2 -o keybridge.exe keybridge.c -lws2_32 -mwindows
```

Or run `build.bat` which tries MinGW then MSVC automatically.

---

## License

MIT
