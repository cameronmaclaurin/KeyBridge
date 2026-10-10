#!/usr/bin/env bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "Building KeyBridge (release)…"
swift build -c release 2>&1

BIN=".build/release/KeyBridge"
APP="KeyBridge.app"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
cp "$BIN"             "$APP/Contents/MacOS/KeyBridge"
cp "Resources/Info.plist" "$APP/Contents/Info.plist"

echo "Created $SCRIPT_DIR/$APP"
echo ""
echo "First run: double-click KeyBridge.app, then grant Accessibility access in"
echo "  System Settings → Privacy & Security → Accessibility"
