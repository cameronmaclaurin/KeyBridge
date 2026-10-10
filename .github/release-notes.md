## KeyBridge {{VERSION}}

Type on your Windows PC with your Mac's keyboard, over your local network. The Mac and the PC pair with a one-time code, and every keystroke between them is encrypted and authenticated.

### macOS (13 Ventura or later, Apple Silicon and Intel)

- **Recommended: `KeyBridge-macOS.pkg`.** Open it and follow the installer. KeyBridge is installed in `/Applications`.
- **Alternative: `KeyBridge-macOS.dmg`.** Open it and drag **KeyBridge** into **Applications**.

Open KeyBridge from Applications. When macOS asks, allow **Accessibility** access (System Settings → Privacy & Security → Accessibility → KeyBridge). KeyBridge then appears in the menu bar.

**If this build is not signed** and macOS says it can't verify KeyBridge (or the installer): click **Done**, open **System Settings → Privacy & Security**, scroll down to the message about KeyBridge and click **Open Anyway**, then confirm. You only need to do this once.

### Windows (10 and 11, 64-bit)

- **Recommended: `KeyBridge-Windows-Setup.exe`.** Run it and follow the installer.
- **Alternative: `KeyBridge-Windows-Portable.exe`.** A single program with nothing to install. Put it anywhere and run it.

**If this build is not signed** and you see "Windows protected your PC" (SmartScreen): click **More info**, then **Run anyway**.

### Pair the PC with the Mac

1. On the Mac, click KeyBridge in the menu bar, then **Pair a Windows PC…**. This shows the Mac's address and a pairing code like `ABCDE-FGHJK-MNPQR-STVWX`.
2. On the PC, type that address and code into the KeyBridge setup window. Upper or lower case both work, and the dashes are optional.
3. Once the PC connects, press **Ctrl + Shift + `** on the Mac to switch between typing on the Mac and typing on the PC.

To pair a different PC or to revoke access, open **Pair a Windows PC…** on the Mac and choose **Generate New Code**. A PC that only knows the old code can't connect again until you enter the new code on it.

Both computers must be on the same local network.

### Verify your download

Each file is listed in `SHA256SUMS.txt`, and GitHub has a signed build-provenance attestation for each one, which proves the file was built from this repository by GitHub Actions.

macOS or Linux, in the folder you downloaded to:

```sh
shasum -a 256 -c SHA256SUMS.txt --ignore-missing
gh attestation verify KeyBridge-macOS.pkg --repo cameronmaclaurin/KeyBridge
```

Windows (PowerShell): compare this output with the matching line in `SHA256SUMS.txt`, then check the attestation:

```powershell
Get-FileHash .\KeyBridge-Windows-Setup.exe -Algorithm SHA256
gh attestation verify .\KeyBridge-Windows-Setup.exe --repo cameronmaclaurin/KeyBridge
```

For how KeyBridge protects your keystrokes, and what it does not protect against, see [SECURITY.md](https://github.com/cameronmaclaurin/KeyBridge/blob/master/SECURITY.md).
