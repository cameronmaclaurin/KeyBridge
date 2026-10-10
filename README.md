# KeyBridge ⌨️🌉

> Use your Mac keyboard to type on your Windows PC — no extra hardware needed.

KeyBridge is a tiny two-part app: a Mac menu-bar app that captures your keystrokes and a Windows client that injects them. Press a hotkey to toggle which machine receives your typing.

---

## How it works

```
  [Mac keyboard]
       │
  keybridge_mac.py   ──── TCP over LAN ────►  keybridge_windows.py
  (menu bar app)                               (Windows background app)
```

Both machines must be on the same network (Wi-Fi or Ethernet). The Mac acts as the server; Windows connects to it.

---

## Setup

### Mac

```bash
pip install -r requirements_mac.txt
python keybridge_mac.py
```

> **Accessibility permission required.**  
> macOS will prompt you to grant Accessibility access so KeyBridge can capture global keystrokes. Go to **System Settings → Privacy & Security → Accessibility** and enable it for your terminal / Python.

A ⌨️ icon appears in your menu bar. Your Mac starts as the server on port **9876**.

---

### Windows

Find your **Mac's local IP** (System Settings → Wi-Fi → Details, or `ifconfig en0` in Terminal).

```bash
pip install -r requirements_windows.txt
python keybridge_windows.py 192.168.1.42   # ← your Mac's IP
```

The Windows client connects automatically and reconnects if the connection drops.

---

## Switching

| Action | Result |
|--------|--------|
| **Ctrl + Shift + \`** | Toggle between Local (Mac) and Windows mode |
| Click the ⌨️ menu bar icon → *Switch to Windows Mode* | Same toggle, via menu |

- **⌨️** in the menu bar = Local mode (your Mac receives keystrokes)  
- **🟢** in the menu bar = Windows mode (your Windows PC receives keystrokes)

---

## Notes

- All keys are relayed: letters, numbers, modifiers (Shift, Ctrl, Alt/Option, Win/Cmd), function keys, arrow keys, etc.
- The switch hotkey always works, even while in Windows mode.
- If the Windows client disconnects, KeyBridge will automatically reconnect when the client restarts.
- Both apps must be running at the same time for relay to work.

---

## Requirements

| Side | Python | Packages |
|------|--------|---------|
| Mac | 3.8+ | `rumps`, `pynput` |
| Windows | 3.8+ | `pynput` |

---

## License

MIT
