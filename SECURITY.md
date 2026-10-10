# Security policy

KeyBridge sends your keystrokes across the network, so we treat security bugs as the most important kind of bug.

## Supported versions

| Version | Supported |
|---|---|
| Latest release | Yes |
| Older releases that use the KBP2 protocol | No. Please upgrade both computers to the latest release. |
| Releases before KBP2 (downloads named `KeyBridge-mac.zip` and `keybridge.exe`) | No. **These are insecure.** They send keystrokes unencrypted, and anyone on your network could read them or type on your PC. Uninstall them. |

Security fixes go into a new release. The Mac app and the Windows app should always be the same version.

## Reporting a vulnerability

Please report security problems privately, not in a public issue:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Tell us the KeyBridge version, your macOS and Windows versions, what you found, and how to reproduce it.

We'll reply as soon as we can, usually within a week, and keep you updated until it's fixed. Once a fix is released we'll publish an advisory and credit you, unless you'd rather stay anonymous.

## Threat model

### What KeyBridge protects

- **Only the PC you paired receives your keystrokes.** Before the Mac sends any keystrokes, the PC must prove that it knows the pairing code. A device that doesn't know the code never gets a keystroke.
- **Only your paired Mac can type on your PC.** The PC accepts keystrokes only from a Mac that has proved it knows the same pairing code. Another device on your network can't inject keys.
- **Keystrokes are encrypted and tamper-proof on the network.** Every key event is encrypted and authenticated (AES-256-GCM). If anything is changed, replayed, reordered or inserted, the connection is dropped.
- **Forward secrecy.** Every connection uses new, single-use keys (ECDH on P-256). Someone who records your traffic today can't decrypt it later, even if they learn the pairing code afterwards.
- **The pairing code can't be guessed.** It is 20 random characters (about 100 bits). Someone who connects to your Mac gets enough to test guesses on their own computer, but there are far too many possible codes for that to work.
- **Connecting without the code doesn't affect you.** A connection that hasn't proved it knows the code never replaces or interferes with your current session.

### What KeyBridge does not protect against

- **A compromised Mac or PC.** If malware or another person controls either computer, they can read what you type there, and they can steal the pairing code. The Mac keeps the code in the Keychain. Windows keeps it encrypted for your Windows account.
- **macOS Secure Input.** When a password field has focus, or another app turns on Secure Input (some terminals and password managers do this), macOS stops KeyBridge from seeing the keyboard. Your typing then goes to the Mac and not the PC until that app releases Secure Input. This is a macOS protection for your passwords and KeyBridge can't override it.
- **Keystroke timing.** Encryption hides *which* keys you press, but someone watching your network can see that KeyBridge is in use and *when* each key is pressed or released. In theory, timing patterns can reveal something about what you type.
- **Use beyond your local network.** KeyBridge is designed for computers on the same home or office network. Don't forward port 9876 from the internet to your Mac. Someone on your network can also block or interrupt the connection. They can't read or inject keystrokes, but they can stop KeyBridge from working.
- **Someone who sees your pairing code.** Anyone who sees the code (over your shoulder or in a screenshot) can pair a PC. Treat it like a password, and change it if it's exposed (see below).
- **Unsigned downloads.** Builds that aren't code-signed don't carry a publisher identity that macOS or Windows can check. Before you run one, verify it (see [Verifying a download](#verifying-a-download)).

## Changing (rotating) the pairing code

Change the code if it was exposed, or if you've given away, sold or lost a PC that was paired:

1. On the Mac, click KeyBridge in the menu bar, then **Pair a Windows PC…**.
2. Click **Generate New Code**.
3. Enter the new code on each PC you still want to use.

A PC that only knows the old code can no longer connect.

## Verifying a download

Each release includes `SHA256SUMS.txt`, and GitHub keeps a signed build-provenance attestation for every file. The attestation proves the file was built from this repository by GitHub Actions.

```sh
# macOS or Linux, in the folder you downloaded to
shasum -a 256 -c SHA256SUMS.txt --ignore-missing
gh attestation verify KeyBridge-macOS.pkg --repo cameronmaclaurin/KeyBridge
```

```powershell
# Windows PowerShell: compare the hash with the matching line in SHA256SUMS.txt
Get-FileHash .\KeyBridge-Windows-Setup.exe -Algorithm SHA256
gh attestation verify .\KeyBridge-Windows-Setup.exe --repo cameronmaclaurin/KeyBridge
```

## Protocol details

The wire protocol, KBP2, is specified in [docs/PROTOCOL.md](docs/PROTOCOL.md). It covers the pairing code, the handshake, the key schedule, the encrypted record format and the security properties. The Mac app, the Windows app and the Python reference implementation in [`tests/reference/kbp2.py`](tests/reference/kbp2.py) all follow it. CI checks that the Mac and Windows apps interoperate with the reference, and that the test hooks are not present in shipping builds.
