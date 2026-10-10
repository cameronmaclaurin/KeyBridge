# KeyBridge updates

How the Mac and Windows apps find, verify and install new versions. Both apps and the release workflow MUST follow this exactly.

## 1. What the release publishes

Every GitHub release (tag `vX.Y.Z`, not a pre-release) has two extra assets next to the installers:

- **`update-manifest.txt`**: UTF-8 text, LF line endings, one `key value` pair per line (a single space after the key), in this order:

  ```
  keybridge-update-manifest 1
  version 1.4.0
  notes-url https://github.com/cameronmaclaurin/KeyBridge/releases/tag/v1.4.0
  mac-url https://github.com/cameronmaclaurin/KeyBridge/releases/download/v1.4.0/KeyBridge-macOS.pkg
  mac-sha256 <64 lowercase hex>
  mac-size <bytes, decimal>
  windows-url https://github.com/cameronmaclaurin/KeyBridge/releases/download/v1.4.0/KeyBridge-Windows-Setup.exe
  windows-sha256 <64 lowercase hex>
  windows-size <bytes, decimal>
  ```

- **`update-manifest.sig`**: the ECDSA P-256 / SHA-256 signature over the **exact bytes** of `update-manifest.txt`, as 64 raw bytes `r || s` (each 32-byte big-endian), base64-encoded on one line (88 characters; a trailing newline is allowed and ignored).

The signing key is held only by the release workflow (secret `KEYBRIDGE_UPDATE_SIGNING_KEY`). The apps embed the public key:

```
04290216611bac006bab98e63c0a3fa68f3c6bb49293fd65cec42c7b323f2caea9cbe542a9b238561284afe444746c091ab8cfc37aa50a01c40cf3477968d8df33
```

(uncompressed X9.63 P-256 point, 65 bytes, hex).

## 2. Checking

- Fetch over HTTPS, following redirects, with normal certificate validation:
  - `https://github.com/cameronmaclaurin/KeyBridge/releases/latest/download/update-manifest.txt`
  - `https://github.com/cameronmaclaurin/KeyBridge/releases/latest/download/update-manifest.sig`
- Reject responses larger than 16 KB.
- **Verify the signature before reading anything else.** Then parse strictly: the first line must be exactly `keybridge-update-manifest 1`, all nine keys must be present exactly once, and unknown keys are ignored. `version` must be `MAJOR.MINOR.PATCH` (decimal, no leading zeros except a lone `0`), the sha256 values must be 64 lowercase hex characters, and the sizes must be decimal values from 1 to 200,000,000.
- `mac-url` and `windows-url` must start with `https://github.com/cameronmaclaurin/KeyBridge/releases/download/`, and `notes-url` with `https://github.com/cameronmaclaurin/KeyBridge/releases/`. URLs containing `..`, whitespace or control characters are invalid.
- Lines end with LF only, and none may be empty. A line without a space between key and value is invalid.
- Offer an update only if `version` is **greater** than the running version, comparing numerically per component. Equal or older → "You're up to date". This blocks downgrades even with an old, validly signed manifest.
- When to check: at launch (after a 10 s delay) and every 24 h while running, if **"Automatically check for updates"** is on (default **on**), plus whenever the user clicks **Check for Updates…**. Automatic checks fail silently. A manual check reports errors ("Couldn't check for updates: …").
- If the user picks **Skip This Version**, remember that version and don't offer it again automatically. A manual check still offers it.

## 3. Installing

1. Download the platform's installer from its `*-url` to a new private temporary directory, rejecting anything larger than `*-size`.
2. Check the size equals `*-size` and the SHA-256 equals `*-sha256`. On any mismatch, delete the file and report "The update was damaged or tampered with" without running anything.
3. Platform steps:
   - **macOS**: open the `.pkg` with the system Installer (`NSWorkspace.open`). The user clicks through and authenticates. The package's preinstall quits KeyBridge and its postinstall relaunches it. If KeyBridge is running from somewhere other than `/Applications`, say the update installs into Applications.
   - **Windows (installed copy)**: run `KeyBridge-Windows-Setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /RELAUNCH`, then exit so the installer can replace the exe. The installer relaunches KeyBridge when it gets `/RELAUNCH`. A per-user install needs no UAC prompt.
   - **Windows (portable copy**, i.e. not running from the per-user install directory): don't install. Show "KeyBridge 1.4.0 is available" with a **Download** button that opens `notes-url`.
4. Downloaded files never get a quarantine flag or Mark-of-the-Web, and they are always verified first, so Gatekeeper and SmartScreen don't prompt again for updates. That's safe only because the signature and hash checks above always run.

## 4. UI

- **Update prompt:** "KeyBridge <new> is available — you have <current>." Buttons: **Install Update**, **Later**, **Skip This Version**, plus a "Release notes" link that opens `notes-url`.
- **Progress:** "Downloading update…", then "Installing…".
- **Mac:** menu item **Check for Updates…**. Settings checkbox **Automatically check for updates**.
- **Windows:** tray menu item **Check for Updates…**. Tray menu checkbox **Automatically Check for Updates**.

## 5. Security notes

- The manifest signature is the trust root. HTTPS alone isn't enough: a stolen GitHub token could replace release assets, but it can't produce a valid signature.
- The signing key lives only in the GitHub Actions secret and in an offline backup (the maintainer's Keychain). If it's lost, a new key needs one manual reinstall. If it leaks, rotate the key and ship a release that embeds the new public key.

## 6. Conformance test hooks

Selftest builds only (`KEYBRIDGE_SELFTEST`), using the same verification code as the app:

`KeyBridge --selftest-verify-update <manifest-file> <sig-file> --current <X.Y.Z> [--pubkey <130 hex>]`
`KeyBridge-selftest.exe --selftest-verify-update <manifest-file> <sig-file> --current <X.Y.Z> [--pubkey <130 hex>]`

`--pubkey` replaces the embedded key so tests can use a throwaway key (selftest builds only; shipping builds always use the embedded key). The single source of truth for the embedded key is `tools/update_pubkey.txt`; CI checks that both apps embed exactly that value.

Each prints exactly one line and exits:

| Output | Exit | Meaning |
|---|---|---|
| `UPDATE <version> <platform-url> <platform-sha256> <platform-size>` | 0 | Valid, and newer than `--current` |
| `CURRENT` | 0 | Valid, but not newer |
| `INVALID` | 2 | Bad signature, bad format, or a bad URL |

`<platform-url>` is the mac or windows URL for the build's platform. `tools/update_manifest.py` creates manifests and signatures, including deliberately broken ones, for tests.
