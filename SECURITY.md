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

### How pairing works

You pair a PC with the Mac once. The two computers run an ECDH (P-256) key exchange with a commitment, both show the same 6-digit number, and you click **Confirm** on both after checking that the numbers match. Each side then stores a new random 32-byte key: the Mac in its Keychain, the PC encrypted for your Windows account. This is the "Numeric Comparison" method from Bluetooth LE Secure Connections. No secret is ever shown or typed.

KeyBridge 1.1 paired with a typed 20-character code. That method has been removed, and 1.1 pairings stop working after the upgrade: pair once more.

### What KeyBridge protects

- **Only the PC you paired receives your keystrokes.** Before the Mac sends any keystrokes, the PC must prove that it holds the key from pairing. A device that doesn't have it never gets a keystroke.
- **Only your paired Mac can type on your PC.** The PC accepts keystrokes only from a Mac that has proved it holds the same key. Another device on your network can't inject keys.
- **Pairing resists a man in the middle.** A device on your network that intercepts pairing ends up with two separate connections, and the Mac and the PC then show different numbers. Because of the commitment, it can't choose its values to make the numbers match: each attempt succeeds with a chance of 1 in 1,000,000, and every attempt needs you to click **Confirm** on both computers.
- **Pairing happens only when you ask.** The Mac accepts a pairing connection only while its Pairing window is open, for at most 3 minutes, and one at a time. The PC pairs only when you click **Pair**. A pairing that is cancelled, times out or fails saves nothing.
- **Keystrokes are encrypted and tamper-proof on the network.** Every key event is encrypted and authenticated (AES-256-GCM). If anything is changed, replayed, reordered or inserted, the connection is dropped.
- **Forward secrecy.** Every connection uses new, single-use keys (ECDH on P-256). Someone who records your traffic today can't decrypt it later, even if they steal the pairing key afterwards.
- **Connecting without the key doesn't affect you.** A connection that hasn't proved it holds the key never replaces or interferes with your current session.

### What you need to do

- **Actually compare the numbers.** The protection against a man in the middle works only if you check that the Mac and the PC show the same number before you click **Confirm**. If they differ, click **Cancel**.
- **Compare on both real screens.** Look at the number on your Mac and on your PC, side by side. If the Mac shows a pairing request while your PC isn't pairing, or the PC shows a number while your Mac's Pairing window isn't open, click **Cancel**: another device on your network may be trying to pair. The names on the confirmation screens help, but anyone can choose any name.
- **Close the Pairing window when you're done.** Pairing mode ends on its own after 3 minutes, on success, or when you close the window.

### What KeyBridge does not protect against

- **Clicking Confirm without comparing.** If someone on your network intercepts pairing and you confirm different numbers anyway, that device can sit between your Mac and your PC and read your keystrokes. The 6-digit number is your protection. It isn't secret, and it's never typed.
- **Discovery is not trusted.** The list of Macs on the PC comes from Bonjour, and any device on your network can announce itself under any name, including your Mac's. A fake entry is caught the same way as a man in the middle: your real Mac shows no number, or a different one. That's why you compare the number on the PC with the number on **your Mac's own screen**, not just click Confirm on the PC. Security comes only from that comparison, pairing and the encrypted connection.
- **A compromised Mac or PC.** If malware or another person controls either computer, they can read what you type there, and they can steal the pairing key. The Mac keeps the key in the Keychain. Windows keeps it encrypted for your Windows account.
- **macOS Secure Input.** When a password field has focus, or another app turns on Secure Input (some terminals and password managers do this), macOS stops KeyBridge from seeing the keyboard. Your typing then goes to the Mac and not the PC until that app releases Secure Input. This is a macOS protection for your passwords and KeyBridge can't override it.
- **Keystroke timing.** Encryption hides *which* keys you press, but someone watching your network can see that KeyBridge is in use and *when* each key is pressed or released. In theory, timing patterns can reveal something about what you type.
- **Use beyond your local network.** KeyBridge is designed for computers on the same home or office network. Don't forward port 9876 from the internet to your Mac. Someone on your network can also block or interrupt the connection, or keep pairing from completing. They can't read or inject keystrokes, but they can stop KeyBridge from working.
- **Unsigned downloads.** Builds that aren't code-signed don't carry a publisher identity that macOS or Windows can check. Before you run one, verify it (see [Verifying a download](#verifying-a-download)).

## Removing or replacing a pairing

Do this if you've given away, sold or lost a paired PC, or if you think a pairing was confirmed by mistake:

- **Forget:** on the Mac, click KeyBridge in the menu bar and choose **Forget This PC…**. On the PC, choose **Forget** in the KeyBridge setup window. Forgetting on either side deletes that side's key, and the two can't connect again until you pair them.
- **Re-pair:** pairing again replaces the old key on both computers. The Mac pairs with one PC at a time, so pairing a new PC also cuts off the old one, and any current session is dropped.

## Automatic updates

- The apps install an update only if `update-manifest.txt` carries a valid ECDSA P-256 signature from KeyBridge's update key, the version is newer than the one running (so no downgrades), every download URL points at this repository's releases, and the downloaded installer matches the signed size and SHA-256. HTTPS alone isn't trusted: a stolen GitHub token could swap release files, but it can't sign them.
- The private update key exists only as the GitHub Actions secret `KEYBRIDGE_UPDATE_SIGNING_KEY` and in an offline backup. If it ever leaks, it gets rotated and a release ships with the new public key. Installs older than that release then need one manual update.
- Mac release builds are signed with a self-signed KeyBridge certificate. It doesn't make Gatekeeper trust the app; the first launch still needs **Open Anyway**. It does keep the app's code identity stable, so macOS permissions survive updates.

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

The wire protocol, KBP2, is specified in [docs/PROTOCOL.md](docs/PROTOCOL.md). It covers Bonjour discovery, numeric-comparison pairing, the handshake, the key schedule, the encrypted record format and the security properties. The Mac app, the Windows app and the Python reference implementation in [`tests/reference/kbp2.py`](tests/reference/kbp2.py) all follow it. CI checks that the Mac and Windows apps interoperate with the reference, and that the test hooks are not present in shipping builds.
