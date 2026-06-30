#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$SCRIPT_DIR/.."
SRC="$ROOT/xpc-config/Sources/main.swift"
OUT_DIR="$ROOT/xpc-config/build"
BUNDLE_ID="com.wiredog.vpn.macos.config"
BINARY_NAME="com.wiredog.vpn.macos.config"

mkdir -p "$OUT_DIR"

echo "Building VPN config XPC service..."
swiftc \
  -target arm64-apple-macos12.0 \
  -framework Foundation \
  -framework NetworkExtension \
  -o "$OUT_DIR/$BINARY_NAME" \
  "$SRC"

echo "Assembling XPC bundle..."
BUNDLE="$OUT_DIR/$BUNDLE_ID.xpc"
rm -rf "$BUNDLE"
mkdir -p "$BUNDLE/Contents/MacOS"
cp "$OUT_DIR/$BINARY_NAME" "$BUNDLE/Contents/MacOS/$BINARY_NAME"
cp "$ROOT/xpc-config/Info.plist" "$BUNDLE/Contents/Info.plist"

echo "XPC service built at: $BUNDLE"
