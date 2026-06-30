#!/bin/bash
# Build the native Swift N-API addon
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT/native"

echo "=== Building WireDogNative Swift library ==="
swift build -c release

# Refresh the committed Swift-ObjC bridging header so node-gyp sees new @objc classes
echo "=== Updating include/WireDogNative-Swift.h from build output ==="
ARCH=$(uname -m)
SWIFT_HEADER=".build/${ARCH}-apple-macosx/release/WireDogNative.build/include/WireDogNative-Swift.h"
[ -f "$SWIFT_HEADER" ] && cp "$SWIFT_HEADER" include/WireDogNative-Swift.h || echo "Warning: generated header not found at $SWIFT_HEADER"

echo "=== Building N-API addon with node-gyp ==="
npx node-gyp rebuild --arch=$(uname -m)

# Copy dylib next to the .node file so @loader_path resolves correctly at runtime
echo "=== Copying dylib alongside .node for runtime linking ==="
ARCH=$(uname -m)
cp ".build/${ARCH}-apple-macosx/release/libWireDogNative.dylib" build/Release/libWireDogNative.dylib

echo "=== Native addon built successfully ==="
ls -la build/Release/wiredog_native.node build/Release/libWireDogNative.dylib
