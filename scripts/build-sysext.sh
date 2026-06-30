#!/bin/bash
# Build the system extension activation tool.
# Produces a universal binary (arm64 + x86_64) signed with system-extension.install entitlement.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT/sysext-activate"

mkdir -p build

ARCH=$(uname -m)

echo "=== Building wiredog-sysext-activate ==="

if [ "$1" = "--universal" ] || [ "$ARCH" = "arm64" ]; then
  echo "Building arm64..."
  swift build -c release --arch arm64

  echo "Building x86_64..."
  swift build -c release --arch x86_64

  echo "Creating universal binary with lipo..."
  lipo -create \
    .build/arm64-apple-macosx/release/wiredog-sysext-activate \
    .build/x86_64-apple-macosx/release/wiredog-sysext-activate \
    -output build/wiredog-sysext-activate

  echo "Universal binary architectures:"
  lipo -info build/wiredog-sysext-activate
else
  echo "Building for current architecture ($ARCH)..."
  swift build -c release
  cp .build/release/wiredog-sysext-activate build/
fi

# Sign with system-extension.install entitlement
ENTITLEMENTS="$PROJECT_ROOT/entitlements.sysext.plist"
SIGNING_IDENTITY="${DEVELOPER_ID_APPLICATION:-${CSC_NAME:-Developer ID Application}}"

echo "=== Signing wiredog-sysext-activate ==="
echo "Identity: $SIGNING_IDENTITY"
echo "Entitlements: $ENTITLEMENTS"

codesign --force --options runtime --timestamp \
  --sign "$SIGNING_IDENTITY" \
  --entitlements "$ENTITLEMENTS" \
  "build/wiredog-sysext-activate"

echo "=== sysext-activate built and signed successfully ==="
ls -la build/wiredog-sysext-activate
codesign -dvvv build/wiredog-sysext-activate 2>&1 | grep -E "(Authority|Entitlements|runtime)"
