#!/usr/bin/env python3
"""
KeyBridge - Mac side
Captures your Mac keyboard and relays it to a connected Windows PC.
Switch with Ctrl+Shift+` (backtick)
"""
import json
import socket
import threading
import rumps
from pynput import keyboard
from pynput.keyboard import Key, KeyCode, Listener, Controller

PORT = 9876
ICON_LOCAL = "⌨️"
ICON_REMOTE = "🟢"


def key_to_str(key):
    if isinstance(key, KeyCode):
        if key.char:
            return key.char
        return f"vk:{key.vk}"
    return str(key)  # e.g. "Key.space"


class KeyBridgeApp(rumps.App):
    def __init__(self):
        super().__init__(ICON_LOCAL, quit_button=None)

        self.remote_mode = False
        self.client_conn = None
        self.listener = None
        self._pressed = set()

        self._status = rumps.MenuItem("Mode: Local  (keystrokes go to this Mac)")
        self._toggle = rumps.MenuItem("Switch to Windows Mode", callback=self.toggle_mode)
        self._conn_status = rumps.MenuItem("Windows: not connected", callback=None)
        self._quit = rumps.MenuItem("Quit KeyBridge", callback=lambda _: rumps.quit_application())

        self.menu = [
            self._status,
            self._conn_status,
            None,
            self._toggle,
            None,
            rumps.MenuItem("Hotkey: Ctrl + Shift + `", callback=None),
            None,
            self._quit,
        ]

        threading.Thread(target=self._run_server, daemon=True).start()
        self._start_listener()

    # ── TCP server ────────────────────────────────────────────────────────────

    def _run_server(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", PORT))
        srv.listen(1)
        while True:
            conn, addr = srv.accept()
            self.client_conn = conn
            rumps.notification("KeyBridge", "Windows PC connected", f"From {addr[0]}")
            self._conn_status.title = f"Windows: {addr[0]}"

    def _send(self, event_type, key):
        conn = self.client_conn
        if conn is None:
            return
        try:
            data = json.dumps({"type": event_type, "key": key_to_str(key)}) + "\n"
            conn.sendall(data.encode())
        except OSError:
            self.client_conn = None
            self._conn_status.title = "Windows: disconnected"

    # ── Keyboard listener ─────────────────────────────────────────────────────

    def _start_listener(self):
        if self.listener:
            self.listener.stop()
        self.listener = Listener(
            on_press=self._on_press,
            on_release=self._on_release,
            suppress=self.remote_mode,
        )
        self.listener.start()

    def _is_switch_combo(self):
        has_ctrl = any(k in self._pressed for k in (Key.ctrl, Key.ctrl_l, Key.ctrl_r))
        has_shift = any(k in self._pressed for k in (Key.shift, Key.shift_l, Key.shift_r))
        has_tick = KeyCode.from_char("`") in self._pressed
        return has_ctrl and has_shift and has_tick

    def _on_press(self, key):
        self._pressed.add(key)
        if self._is_switch_combo():
            self.toggle_mode(None)
            return
        if self.remote_mode:
            self._send("press", key)

    def _on_release(self, key):
        self._pressed.discard(key)
        if self.remote_mode:
            self._send("release", key)

    # ── Toggle ────────────────────────────────────────────────────────────────

    @rumps.clicked("Switch to Windows Mode")
    def toggle_mode(self, _):
        self.remote_mode = not self.remote_mode
        if self.remote_mode:
            self.title = ICON_REMOTE
            self._status.title = "Mode: Windows  (keystrokes go to Windows PC)"
            self._toggle.title = "Switch to Local Mode"
            if self.client_conn is None:
                rumps.notification("KeyBridge", "No Windows client connected",
                                   "Start keybridge_windows.py on your PC first.")
        else:
            self.title = ICON_LOCAL
            self._status.title = "Mode: Local  (keystrokes go to this Mac)"
            self._toggle.title = "Switch to Windows Mode"
        self._pressed.clear()
        self._start_listener()


if __name__ == "__main__":
    KeyBridgeApp().run()
