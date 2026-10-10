# KeyBridge ⌨️🌉

> Use your Mac keyboard to type on your Windows PC — no extra hardware, sub-millisecond relay latency.

KeyBridge is a native two-part app: a Swift menu-bar app on your Mac that captures keystrokes and a C client on Windows that injects them. Press a hotkey to flip between which machine receives your typing.

## Downloads

Go to [**Releases**](../../releases) and grab the latest:

| File | Platform |
|------|----------|
| `KeyBridge-mac.zip` | macOS 13+ |
| `keybridge.exe` | Windows 10/11 (64-bit) |

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

---

## Technical highlights

| Thing | Mac | Windows |
|-------|-----|---------|
| Key capture | `CGEventTap` (kernel-level) | — |
| Key injection | — | `SendInput` (Win32) |
| Network | `NWConnection` TCP server | Winsock2 TCP client |
| Latency trick | `TCP_NODELAY` on both ends | `TCP_NODELAY` |
| Protocol | 4-byte binary frame | same |
| RAM | ~3 MB | ~1 MB |
| Language | Swift 5.9 | C99 |

---

## Build from source

### Mac

```bash
cd mac
chmod +x build_app.sh
./build_app.sh
# → mac/KeyBridge.app
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
