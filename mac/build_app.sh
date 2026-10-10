#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "Building KeyBridge (release, universal)…"
BUILD_ARGS=(-c release --arch arm64 --arch x86_64)
swift build "${BUILD_ARGS[@]}"
BIN="$(swift build "${BUILD_ARGS[@]}" --show-bin-path)/KeyBridge"

APP="KeyBridge.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
cp "$BIN" "$APP/Contents/MacOS/KeyBridge"
cp Resources/Info.plist "$APP/Contents/Info.plist"

# Ad-hoc sign so macOS ties the Accessibility grant to the app bundle.
codesign --force --sign - "$APP"

echo "Created $(pwd)/$APP"
