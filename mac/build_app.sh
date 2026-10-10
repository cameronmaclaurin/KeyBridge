#!/usr/bin/env bash
# Builds mac/build/KeyBridge.app (release, universal arm64 + x86_64) and signs it.
#
# Environment:
#   KEYBRIDGE_VERSION   version for CFBundleVersion / CFBundleShortVersionString (default 0.0.0;
#                       a leading "v" is dropped, so tags like v1.2.3 work)
#   MAC_SIGN_IDENTITY   codesign identity (e.g. "Developer ID Application: …"); ad-hoc if unset
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VERSION="${KEYBRIDGE_VERSION:-0.0.0}"
VERSION="${VERSION#v}"
BUNDLE_VERSION="${VERSION%%[!0-9.]*}"   # CFBundleVersion must be numeric (1.2.3-beta → 1.2.3)
BUNDLE_VERSION="${BUNDLE_VERSION:-0.0.0}"

BUILD_ARGS=(--package-path "$SCRIPT_DIR" -c release --arch arm64 --arch x86_64)

echo "==> Building KeyBridge $VERSION (release, universal)"
swift build "${BUILD_ARGS[@]}"
BIN="$(swift build "${BUILD_ARGS[@]}" --show-bin-path)/KeyBridge"
[[ -f "$BIN" ]] || { echo "error: built binary not found at $BIN" >&2; exit 1; }

APP="$SCRIPT_DIR/build/KeyBridge.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

cp "$BIN" "$APP/Contents/MacOS/KeyBridge"
strip -x "$APP/Contents/MacOS/KeyBridge"   # drop local symbols (smaller download, same code)
cp "$SCRIPT_DIR/Resources/Info.plist" "$APP/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $VERSION" "$APP/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $BUNDLE_VERSION" "$APP/Contents/Info.plist"
plutil -lint "$APP/Contents/Info.plist" >/dev/null
printf 'APPL????' > "$APP/Contents/PkgInfo"

ICON="$REPO_ROOT/assets/AppIcon.icns"
if [[ -f "$ICON" ]]; then
    cp "$ICON" "$APP/Contents/Resources/AppIcon.icns"
else
    echo "warning: $ICON not found; building without an app icon" >&2
fi

if [[ -n "${MAC_SIGN_IDENTITY:-}" ]]; then
    echo "==> Signing with identity: $MAC_SIGN_IDENTITY"
    codesign --force --options runtime --timestamp --sign "$MAC_SIGN_IDENTITY" "$APP"
else
    # Ad-hoc: macOS still ties the Accessibility grant to this signature.
    echo "==> Signing ad-hoc (set MAC_SIGN_IDENTITY to use a real identity)"
    codesign --force --options runtime --sign - "$APP"
fi
codesign --verify --strict --verbose=2 "$APP"

echo "==> Built $APP ($(lipo -archs "$APP/Contents/MacOS/KeyBridge"))"
