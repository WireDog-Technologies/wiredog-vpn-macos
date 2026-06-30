#!/bin/bash
# Build the helper daemon (kill switch via pf)
# Produces a universal binary (arm64 + x86_64) for distribution.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT/helper"

mkdir -p build

# Check if we can build universal (requires both architectures available)
ARCH=$(uname -m)

echo "=== Building wiredog-helper daemon ==="

if [ "$1" = "--universal" ] || [ "$ARCH" = "arm64" ]; then
  # Build for both architectures and create universal binary
  echo "Building arm64..."
  swift build -c release --arch arm64

  echo "Building x86_64..."
  swift build -c release --arch x86_64

  echo "Creating universal binary with lipo..."
  lipo -create \
    .build/arm64-apple-macosx/release/wiredog-helper \
    .build/x86_64-apple-macosx/release/wiredog-helper \
    -output build/wiredog-helper

  echo "Universal binary architectures:"
  lipo -info build/wiredog-helper
else
  # Single architecture build (development)
  echo "Building for current architecture ($ARCH)..."
  swift build -c release
  cp .build/release/wiredog-helper build/
fi

# Copy install script and plist alongside the binary
cp install-helper.sh build/
cp com.wiredog.vpn.helper.plist build/

# Sign the helper binary with NE entitlements
ENTITLEMENTS="$PROJECT_ROOT/entitlements.helper.plist"
SIGNING_IDENTITY="${DEVELOPER_ID_APPLICATION:-${CSC_NAME:-Developer ID Application}}"

echo "=== Signing helper daemon ==="
echo "Identity: $SIGNING_IDENTITY"
echo "Entitlements: $ENTITLEMENTS"

codesign --force --options runtime --timestamp \
  --sign "$SIGNING_IDENTITY" \
  --entitlements "$ENTITLEMENTS" \
  "build/wiredog-helper"

echo "=== Helper daemon built and signed successfully ==="
ls -la build/wiredog-helper
codesign -dvvv build/wiredog-helper 2>&1 | grep -E "(Authority|Entitlements|runtime)"
