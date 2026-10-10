#!/usr/bin/env python3
"""
KeyBridge - Windows client
Connects to the Mac server and injects received keystrokes locally.
Run: python keybridge_windows.py <mac-ip>
"""
import json
import socket
import sys
import time
import threading
from pynput.keyboard import Key, KeyCode, Controller

PORT = 9876
RECONNECT_DELAY = 3  # seconds


def str_to_key(key_str: str):
    if key_str.startswith("Key."):
        attr = key_str[4:]
        try:
            return getattr(Key, attr)
        except AttributeError:
            return None
    if key_str.startswith("vk:"):
        try:
            return KeyCode.from_vk(int(key_str[3:]))
        except Exception:
            return None
    if len(key_str) == 1:
        return KeyCode.from_char(key_str)
    return None


def run(mac_ip: str):
    kb = Controller()
    print(f"[KeyBridge] Connecting to Mac at {mac_ip}:{PORT} …")

    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((mac_ip, PORT))
            print(f"[KeyBridge] Connected! Receiving keystrokes …")
            buf = ""
            while True:
                chunk = sock.recv(4096).decode(errors="replace")
                if not chunk:
                    break
                buf += chunk
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        evt = json.loads(line)
                        key = str_to_key(evt["key"])
                        if key is None:
                            continue
                        if evt["type"] == "press":
                            kb.press(key)
                        elif evt["type"] == "release":
                            kb.release(key)
                    except (json.JSONDecodeError, KeyError):
                        pass
        except (ConnectionRefusedError, OSError) as e:
            print(f"[KeyBridge] Disconnected ({e}). Retrying in {RECONNECT_DELAY}s …")
        finally:
            try:
                sock.close()
            except Exception:
                pass
        time.sleep(RECONNECT_DELAY)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python keybridge_windows.py <mac-ip-address>")
        print("Example: python keybridge_windows.py 192.168.1.42")
        sys.exit(1)
    run(sys.argv[1])
