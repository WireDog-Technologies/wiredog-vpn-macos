#!/bin/bash
# Build the WireDogFilter transparent proxy extension (NETransparentProxyProvider)
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT/extension"

# Regenerate Xcode project so the new WireDogFilter target is included.
# xcodegen generate is fast and idempotent.
echo "=== Regenerating Xcode project with xcodegen ==="
if command -v xcodegen &> /dev/null; then
  xcodegen generate
else
  echo "ERROR: xcodegen not installed. Install with: brew install xcodegen"
  exit 1
fi

# Build for Release
# We build WITHOUT signing here — signing is done explicitly below with the
# correct certificate and entitlements (same pattern as build-extension.sh).
echo "=== Building WireDogFilter extension ==="
DERIVED_DATA="build/DerivedData"
xcodebuild -project WireDogTunnel.xcodeproj \
  -scheme WireDogFilter \
  -configuration Release \
  -destination "generic/platform=macOS" \
  -derivedDataPath "$DERIVED_DATA" \
  ONLY_ACTIVE_ARCH=NO \
  CODE_SIGN_IDENTITY="-" \
  CODE_SIGNING_REQUIRED=NO \
  CODE_SIGNING_ALLOWED=NO \
  PRODUCT_BUNDLE_IDENTIFIER=com.wiredog.vpn.macos.filter \
  build

# Extract the .appex from derived data
echo "=== Extracting WireDogFilter.appex ==="
mkdir -p build

APPEX_NAME="WireDogFilter.appex"
APPEX_PATH=$(find "$DERIVED_DATA/Build/Products" -name "$APPEX_NAME" -type d | head -1)

if [ -z "$APPEX_PATH" ] || [ ! -d "$APPEX_PATH" ]; then
  echo "ERROR: Could not find $APPEX_NAME in build products"
  find "$DERIVED_DATA" -name "*.appex" 2>/dev/null
  exit 1
fi

rm -rf "build/$APPEX_NAME"
cp -R "$APPEX_PATH" "build/$APPEX_NAME"

echo "=== WireDogFilter.appex extracted ==="
ls -la "build/$APPEX_NAME"

# ===== SIGNING =====
echo ""
echo "=== Signing WireDogFilter with Apple Development certificate ==="

# Apple Development certificate SHA-1 fingerprint (Team ID cert, required for NE extensions).
# Set APPLE_DEVELOPMENT_CERT_ID in your environment, or override below.
# Retrieve with: security find-certificate -c "Apple Development" -Z
CERT_ID="${APPLE_DEVELOPMENT_CERT_ID:-YOUR_APPLE_DEVELOPMENT_CERT_SHA1}"
ENTITLEMENTS="$PROJECT_ROOT/extension/WireDogFilter/WireDogFilter.entitlements"

if [ ! -f "$ENTITLEMENTS" ]; then
  echo "ERROR: Entitlements file not found at $ENTITLEMENTS"
  exit 1
fi

if codesign -f -s "$CERT_ID" --entitlements "$ENTITLEMENTS" "build/$APPEX_NAME"; then
  echo "✅ WireDogFilter signed with Apple Development certificate"

  if codesign -dvvv "build/$APPEX_NAME" 2>&1 | grep -q "Authority=Apple Development"; then
    echo "✅ Signature verified: Apple Development certificate"
  else
    echo "WARNING: Signature verification inconclusive. Check logs above."
    codesign -dvvv "build/$APPEX_NAME" 2>&1 | grep "Authority"
  fi
else
  echo "ERROR: Failed to sign WireDogFilter extension"
  echo "Certificate: $CERT_ID"
  exit 1
fi

echo "=== WireDogFilter build complete ==="
