#!/usr/bin/env bash
# Packages mac/build/KeyBridge.app into:
#   dist/KeyBridge-macOS.dmg   drag-to-Applications disk image
#   dist/KeyBridge-macOS.pkg   installer that always installs to /Applications
#
# Runs mac/build_app.sh first if the app hasn't been built yet.
#
# Environment:
#   KEYBRIDGE_VERSION        package version (default 0.0.0; a leading "v" is dropped)
#   MAC_SIGN_IDENTITY        if set, the .dmg is signed with it (the app is signed by build_app.sh)
#   MAC_INSTALLER_IDENTITY   if set, the .pkg is signed with it ("Developer ID Installer: …")
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST="$REPO_ROOT/dist"
APP="$SCRIPT_DIR/build/KeyBridge.app"
VERSION="${KEYBRIDGE_VERSION:-0.0.0}"
VERSION="${VERSION#v}"

if [[ ! -d "$APP" ]]; then
    "$SCRIPT_DIR/build_app.sh"
fi
codesign --verify --strict "$APP"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/keybridge-package.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$DIST"

# ── Disk image ──────────────────────────────────────────────────────────────
DMG="$DIST/KeyBridge-macOS.dmg"
echo "==> Building $DMG"
mkdir -p "$WORK/dmg"
ditto "$APP" "$WORK/dmg/KeyBridge.app"
ln -s /Applications "$WORK/dmg/Applications"
rm -f "$DMG"
hdiutil create -quiet -volname "KeyBridge" -srcfolder "$WORK/dmg" -fs HFS+ -format UDZO -ov "$DMG"
if [[ -n "${MAC_SIGN_IDENTITY:-}" ]]; then
    codesign --force --timestamp --sign "$MAC_SIGN_IDENTITY" "$DMG"
fi
hdiutil verify -quiet "$DMG"

# ── Installer package ───────────────────────────────────────────────────────
PKG="$DIST/KeyBridge-macOS.pkg"
echo "==> Building $PKG"
mkdir -p "$WORK/root" "$WORK/scripts" "$WORK/packages"
ditto "$APP" "$WORK/root/KeyBridge.app"

# BundleIsRelocatable=false: otherwise Installer "upgrades" an existing copy of the app
# wherever it lives (e.g. ~/Downloads) instead of installing into /Applications.
pkgbuild --analyze --root "$WORK/root" "$WORK/component.plist" >/dev/null
/usr/libexec/PlistBuddy -c "Set :0:BundleIsRelocatable false" "$WORK/component.plist"
/usr/libexec/PlistBuddy -c "Set :0:BundleIsVersionChecked false" "$WORK/component.plist"
/usr/libexec/PlistBuddy -c "Set :0:BundleOverwriteAction upgrade" "$WORK/component.plist"

cat > "$WORK/scripts/preinstall" <<'EOF'
#!/bin/sh
# Quit a running KeyBridge so its files can be replaced.
/usr/bin/pkill -x KeyBridge || true
sleep 1
exit 0
EOF

cat > "$WORK/scripts/postinstall" <<'EOF'
#!/bin/sh
# Open KeyBridge for the user at the console (never as root). Skipped for installs to
# another volume and when nobody is logged in to the GUI (e.g. remote `installer` runs).
[ "$3" = "/" ] || exit 0
APP="/Applications/KeyBridge.app"
[ -d "$APP" ] || exit 0
USER_NAME="$(/usr/bin/stat -f %Su /dev/console 2>/dev/null)"
case "$USER_NAME" in ""|root|loginwindow|_mbsetupuser) exit 0 ;; esac
USER_ID="$(/usr/bin/id -u "$USER_NAME" 2>/dev/null)" || exit 0
/bin/launchctl asuser "$USER_ID" /usr/bin/sudo -u "$USER_NAME" /usr/bin/open "$APP" || true
exit 0
EOF
chmod 755 "$WORK/scripts/preinstall" "$WORK/scripts/postinstall"

pkgbuild --quiet \
    --root "$WORK/root" \
    --component-plist "$WORK/component.plist" \
    --identifier com.keybridge.app.pkg \
    --version "$VERSION" \
    --install-location /Applications \
    --scripts "$WORK/scripts" \
    "$WORK/packages/KeyBridge.pkg"

# Product archive: titled installer, macOS 13+, native on Apple silicon (no Rosetta prompt).
cat > "$WORK/distribution.xml" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>KeyBridge</title>
    <options customize="never" require-scripts="false" hostArchitectures="arm64,x86_64"/>
    <domains enable_anywhere="false" enable_currentUserHome="false" enable_localSystem="true"/>
    <volume-check>
        <allowed-os-versions><os-version min="13.0"/></allowed-os-versions>
    </volume-check>
    <choices-outline>
        <line choice="default"><line choice="com.keybridge.app.pkg"/></line>
    </choices-outline>
    <choice id="default"/>
    <choice id="com.keybridge.app.pkg" visible="false">
        <pkg-ref id="com.keybridge.app.pkg"/>
    </choice>
    <pkg-ref id="com.keybridge.app.pkg" version="$VERSION" onConclusion="none">KeyBridge.pkg</pkg-ref>
</installer-gui-script>
EOF

SIGN_ARGS=()
if [[ -n "${MAC_INSTALLER_IDENTITY:-}" ]]; then
    SIGN_ARGS=(--sign "$MAC_INSTALLER_IDENTITY" --timestamp)
fi
rm -f "$PKG"
productbuild --quiet \
    --distribution "$WORK/distribution.xml" \
    --package-path "$WORK/packages" \
    --identifier com.keybridge.app.installer \
    --version "$VERSION" \
    ${SIGN_ARGS[@]+"${SIGN_ARGS[@]}"} \
    "$PKG"
if [[ -n "${MAC_INSTALLER_IDENTITY:-}" ]]; then
    pkgutil --check-signature "$PKG"
fi

echo "==> Done:"
ls -lh "$DMG" "$PKG"
