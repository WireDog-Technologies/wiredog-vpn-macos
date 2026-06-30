#!/bin/bash
# Build the Network Extension (NEPacketTunnelProvider)
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT/extension"

# Always regenerate the Xcode project from project.yml so changes to
# product type (e.g. app-extension → system-extension) take effect.
echo "=== Generating Xcode project with xcodegen ==="
if command -v xcodegen &> /dev/null; then
  xcodegen generate
else
  echo "ERROR: xcodegen not installed. Install with: brew install xcodegen"
  exit 1
fi

# Resolve Swift Package Manager dependencies
echo "=== Resolving SPM dependencies (WireGuardKit) ==="
xcodebuild -resolvePackageDependencies \
  -project WireDogTunnel.xcodeproj \
  -scheme WireDogTunnel

# Build for Release
# We build WITHOUT signing here — afterpack.js handles signing with
# the correct Developer ID identity and entitlements during packaging.
echo "=== Building WireDogTunnel Network Extension ==="
DERIVED_DATA="build/DerivedData"
WG_GO_LIB="$(pwd)/wireguard-apple/Sources/WireGuardKitGo/out"
xcodebuild -project WireDogTunnel.xcodeproj \
  -scheme WireDogTunnel \
  -configuration Release \
  -destination "generic/platform=macOS" \
  -derivedDataPath "$DERIVED_DATA" \
  ONLY_ACTIVE_ARCH=NO \
  CODE_SIGN_IDENTITY="-" \
  CODE_SIGNING_REQUIRED=NO \
  CODE_SIGNING_ALLOWED=NO \
  PRODUCT_BUNDLE_IDENTIFIER=com.wiredog.vpn.macos.tunnel \
  LIBRARY_SEARCH_PATHS="$WG_GO_LIB" \
  build

# Extract the .systemextension from derived data build products
echo "=== Extracting .systemextension ==="
mkdir -p build

BUNDLE_NAME="com.wiredog.vpn.macos.tunnel.systemextension"
BUNDLE_PATH=$(find "$DERIVED_DATA/Build/Products" -name "$BUNDLE_NAME" -type d | head -1)

if [ -z "$BUNDLE_PATH" ] || [ ! -d "$BUNDLE_PATH" ]; then
  echo "ERROR: Could not find $BUNDLE_NAME in build products"
  find "$DERIVED_DATA" -name "*.systemextension" -o -name "*.appex" 2>/dev/null | head -5
  exit 1
fi

rm -rf "build/$BUNDLE_NAME"
cp -R "$BUNDLE_PATH" "build/$BUNDLE_NAME"

echo "=== Network System Extension built successfully ==="
ls -la "build/$BUNDLE_NAME"
BINARY_TYPE=$(file "build/$BUNDLE_NAME/Contents/MacOS/com.wiredog.vpn.macos.tunnel")
echo "$BINARY_TYPE"
if echo "$BINARY_TYPE" | grep -q "bundle"; then
  echo "WARNING: Binary is MH_BUNDLE — must be MH_EXECUTE."
  echo "Check MACH_O_TYPE in project.yml (should be mh_execute)."
  exit 1
fi
echo "Binary is MH_EXECUTE."

# System extensions are signed by afterpack.js with Developer ID Application.
# No intermediate signing step needed here.
echo "=== Build Complete — afterpack.js will sign with Developer ID ==="
