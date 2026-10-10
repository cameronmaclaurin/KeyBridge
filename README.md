<p align="center">
  <img src="assets/logo.png" width="128" height="128" alt="KeyBridge app icon: two keycaps joined by an arrow">
</p>

<h1 align="center">KeyBridge</h1>

<p align="center">
  <strong>Use your Mac's keyboard to type on a Windows PC over your local network.</strong><br>
  A Mac menu-bar app captures your keys. Press <kbd>Ctrl</kbd> + <kbd>Shift</kbd> + <kbd>&#96;</kbd> and they go to a Windows tray app instead.<br>
  Native, tiny, encrypted.
</p>

<p align="center">
  <a href="https://github.com/cameronmaclaurin/KeyBridge/releases/latest"><img src="https://img.shields.io/github/v/release/cameronmaclaurin/KeyBridge" alt="Latest release"></a>
  <a href="https://github.com/cameronmaclaurin/KeyBridge/actions/workflows/ci.yml"><img src="https://github.com/cameronmaclaurin/KeyBridge/actions/workflows/ci.yml/badge.svg" alt="CI status"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT license"></a>
  <img src="https://img.shields.io/badge/platforms-macOS%2013%2B%20%7C%20Windows%2010%2F11-lightgrey" alt="Platforms: macOS 13+ and Windows 10/11">
</p>

---

## Download

| | File | What it is |
|---|---|---|
| **Mac**<br><sub>macOS 13+, Apple Silicon & Intel</sub> | [**KeyBridge-macOS.pkg**](https://github.com/cameronmaclaurin/KeyBridge/releases/latest/download/KeyBridge-macOS.pkg) | Installer, **recommended**. Installs KeyBridge into Applications. |
| | [KeyBridge-macOS.dmg](https://github.com/cameronmaclaurin/KeyBridge/releases/latest/download/KeyBridge-macOS.dmg) | Disk image. Drag KeyBridge to Applications. |
| **Windows**<br><sub>Windows 10/11, 64-bit</sub> | [**KeyBridge-Windows-Setup.exe**](https://github.com/cameronmaclaurin/KeyBridge/releases/latest/download/KeyBridge-Windows-Setup.exe) | Installer, **recommended**. |
| | [KeyBridge-Windows-Portable.exe](https://github.com/cameronmaclaurin/KeyBridge/releases/latest/download/KeyBridge-Windows-Portable.exe) | A single exe. Nothing to install. |
| **Checksums** | [SHA256SUMS.txt](https://github.com/cameronmaclaurin/KeyBridge/releases/latest/download/SHA256SUMS.txt) | Check that your download is intact ([how](#verify-your-download)). |

You need both halves: the Mac app on the Mac whose keyboard you type on, and the Windows app on the PC. Older versions are on the [Releases](https://github.com/cameronmaclaurin/KeyBridge/releases) page.

## How it works

```mermaid
flowchart LR
    kb["Mac keyboard"] --> mac["KeyBridge for Mac<br/>(menu bar)"]
    mac -- "Local mode" --> macapps["Apps on your Mac"]
    mac == "Windows mode<br/>encrypted, over your LAN" ==> win["KeyBridge for Windows<br/>(system tray)"]
    win --> pcapps["Apps on your PC"]
```

The Mac app listens on TCP port 9876 and the Windows app connects to it. In **Local mode** your keyboard works normally. Press the hotkey to switch to **Windows mode**: each key press and release is encrypted and sent to the PC, which types it. Press the hotkey again to switch back.

- **Keyboard only.** No mouse sharing. Both computers must be on the same local network.
- **Native and small.** Swift/AppKit on the Mac (a ~300 KB universal app, under 20 MB of memory when measured). C/Win32 on Windows (one exe, no runtime).
- **Low latency.** `TCP_NODELAY` is on, and each key event is one 20-byte encrypted record. Most of the delay you feel comes from your network, so wired Ethernet or 5 GHz Wi-Fi works best.
- **Encrypted.** Each keystroke is encrypted and authenticated, and only a PC you've paired can connect. See [Security](#security).

| On your Mac | On your PC |
|---|---|
| Menu-bar app with no Dock icon | System-tray app |
| Pairing window that shows the Mac's address and pairing code | Setup window where you enter the Mac's address and pairing code |
| Launch at Login | Start with Windows |
| A warning when macOS Secure Input blocks key capture | Reconnects automatically, and takes either the Mac's `Name.local` address or its IP |

## Install & set up

### 1. Mac

1. **Install.** Open **KeyBridge-macOS.pkg** and follow the installer. Or open **KeyBridge-macOS.dmg** and drag **KeyBridge** to **Applications**.
2. **Open KeyBridge** from Applications. The first time, macOS blocks it because the app isn't signed with a paid Apple certificate:
   open **System Settings → Privacy & Security**, scroll down, click **Open Anyway**, and confirm.
3. **Grant Accessibility.** KeyBridge needs it to read the keyboard. When macOS asks, open **System Settings → Privacy & Security → Accessibility** and turn on **KeyBridge**. If you missed the prompt, the KeyBridge menu has a **Grant Accessibility Permission…** item.

KeyBridge appears in the menu bar as a keyboard icon. It doesn't get a Dock icon. To start it automatically, choose **Launch at Login** in its menu.

### 2. Windows

1. Run **KeyBridge-Windows-Setup.exe**. If SmartScreen shows *"Windows protected your PC"*, click **More info → Run anyway**. The builds aren't signed with a paid Microsoft certificate yet.
   If you'd rather not install anything, run **KeyBridge-Windows-Portable.exe** from any folder.
2. KeyBridge starts in the system tray. It may be hidden under the **^** overflow arrow. If its setup window isn't open, open it from the tray icon.

### 3. Pair them (once)

1. On the Mac, click the KeyBridge icon in the menu bar and choose **Pair a Windows PC…**. The window shows your Mac's address (such as `Your-Mac.local`) and a one-time pairing code (such as `ABCDE-FGHJK-MNPQR-STVWX`).
2. On the PC, type the address and the code into the KeyBridge setup window and connect. Case and dashes in the code don't matter.
3. Optional: turn on **Start with Windows**.

When the PC connects, the Windows tray icon turns from gray to color. That's it. Press <kbd>Ctrl</kbd> + <kbd>Shift</kbd> + <kbd>&#96;</kbd> on the Mac and start typing on the PC.

## Using it

**Switching:** press <kbd>Ctrl</kbd> + <kbd>Shift</kbd> + <kbd>&#96;</kbd> on the Mac (that's Control, Shift and the backtick key, left of <kbd>1</kbd> on US keyboards). You can also choose **Switch to Windows Mode** or **Switch to Local Mode** from the KeyBridge menu. Keys you're holding down are released when you switch or when the connection drops, so nothing gets stuck.

**What the icons mean**

| Where | Icon | Meaning |
|---|---|---|
| Mac menu bar | Keyboard | **Local mode.** You're typing on the Mac. |
| Mac menu bar | Computer | **Windows mode.** You're typing on the PC. |
| Mac menu bar | Warning triangle | Windows mode, but macOS Secure Input is blocking capture, so keys stay on the Mac ([fix](#troubleshooting)). |
| Windows tray | Color | Connected to your Mac. |
| Windows tray | Gray | Not connected. KeyBridge keeps trying to reconnect. |

The KeyBridge menu on the Mac also shows the current mode and connection status.

**Key mapping**

| Mac key | Sent to Windows as |
|---|---|
| <kbd>Command ⌘</kbd> | <kbd>Windows</kbd> key |
| <kbd>Option ⌥</kbd> | <kbd>Alt</kbd> |
| <kbd>Control ⌃</kbd> | <kbd>Ctrl</kbd> |

For example, <kbd>⌘</kbd> opens the Start menu, and Windows shortcuts like <kbd>Ctrl</kbd> + <kbd>C</kbd> use the Mac's Control key.

## Security

- **Pairing.** The Mac shows a one-time pairing code with about 100 bits of randomness. Both sides prove they know the code before any keystroke is sent. A device without the code can't receive your typing or inject keys into your PC.
- **Encryption.** Every keystroke is encrypted and authenticated with AES-256-GCM.
- **Forward secrecy.** Each connection uses fresh keys from an ECDH P-256 exchange, so recorded traffic stays secret even if the pairing code leaks later.
- **No stuck keys.** Held keys are released when you switch modes or the connection drops.

The full threat model is in [`SECURITY.md`](SECURITY.md) and the wire protocol in [`docs/PROTOCOL.md`](docs/PROTOCOL.md).

### Verify your download

Each release includes `SHA256SUMS.txt` and build-provenance attestations. In the folder where you saved your downloads, run:

```bash
shasum -a 256 -c SHA256SUMS.txt                                  # macOS / Linux
gh attestation verify <file> --repo cameronmaclaurin/KeyBridge   # needs the GitHub CLI
```

On Windows, `Get-FileHash .\KeyBridge-Windows-Setup.exe` in PowerShell prints the hash to compare with `SHA256SUMS.txt`.

## Troubleshooting

<details>
<summary><strong>The PC can't connect to the Mac</strong></summary>

- Check that both computers are on the **same local network**. Guest and public Wi-Fi networks often keep devices from talking to each other.
- **Firewall:** the PC connects to the Mac on **TCP port 9876**. If the macOS firewall is on, allow KeyBridge to accept incoming connections. On the PC, make sure security software isn't blocking KeyBridge.
- **Try the IP instead of `.local`.** Some networks don't resolve `Name.local`. Find the Mac's IP under **System Settings → Wi-Fi → Details… → TCP/IP** (or **Network → Ethernet → Details…**) and enter that in the Windows setup window.
- Make sure KeyBridge is running on the Mac. Look for its icon in the menu bar.

</details>

<details>
<summary><strong>"Pairing code doesn't match"</strong></summary>

Generate a new code in the Mac's **Pair a Windows PC…** window, then type it into the Windows setup window again. The code is easy to mistype. Case and dashes don't matter, but every character does.

</details>

<details>
<summary><strong>Keys aren't captured on the Mac</strong></summary>

KeyBridge needs **Accessibility** permission. Check **System Settings → Privacy & Security → Accessibility** and make sure **KeyBridge** is turned on.

**After updating:** these builds are unsigned, so macOS can treat a new version as a different app and keep the old permission. Select KeyBridge in the Accessibility list, remove it with **–**, then add it back with **+** (or reopen KeyBridge and grant permission again).

</details>

<details>
<summary><strong>Secure Input warning</strong></summary>

When a password field is focused, or an app such as Terminal has *Secure Keyboard Entry* on, macOS turns on Secure Input and no app can capture keystrokes. KeyBridge shows a warning, and your keys stay on the Mac. Click out of the password field or quit the app that's holding Secure Input.

</details>

<details>
<summary><strong>Windows says "Windows protected your PC"</strong></summary>

That's SmartScreen warning about an unsigned app. Click **More info → Run anyway**. To confirm the file is genuine first, [verify your download](#verify-your-download).

</details>

## Build from source

**Mac.** Requires Xcode Command Line Tools (`xcode-select --install`).

```bash
mac/build_app.sh    # build KeyBridge.app (universal)
mac/package.sh      # package it as the .pkg and .dmg
```

**Windows.** Run these from a *Developer Command Prompt for Visual Studio*. The installer step needs [Inno Setup](https://jrsoftware.org/isinfo.php) (`iscc`).

```bat
windows\build.bat 1.1.0
iscc /DAppVersion=1.1.0 windows\installer.iss
```

**Icons.** Every icon in [`assets/`](assets) is generated from code. To regenerate them, run `swift assets/src/make_icons.swift` from the repository root.

## FAQ

**Does it share the mouse too?**
Not yet. KeyBridge is keyboard only.

**Does it work over the internet?**
No. It only works on your local network, by design.

**Why do macOS and Windows show security warnings?**
The builds aren't signed with paid Apple or Microsoft certificates yet. The CI pipeline already supports signing, so it can be turned on once certificates are added. Until then, you can [verify your download](#verify-your-download) yourself.

**Which systems are supported?**
macOS 13 or later on Apple Silicon or Intel, and 64-bit Windows 10 or 11.

## License

[MIT](LICENSE) © 2026 Cameron MacLaurin
