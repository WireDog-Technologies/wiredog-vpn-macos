#!/bin/bash
# Full production build for WireDog VPN macOS
# Builds all native components, the React frontend, and packages the Electron app.
#
# Prerequisites:
#   - Xcode + command line tools
#   - Swift toolchain
#   - Node.js + npm
#   - xcodegen (brew install xcodegen)
#   - Code signing identity (DEVELOPER_ID_APPLICATION env var or default)
#
# For signed + notarized builds, set:
#   APPLE_ID, APPLE_APP_SPECIFIC_PASSWORD, APPLE_TEAM_ID, CSC_LINK, CSC_KEY_PASSWORD
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

# Auto-load build credentials if .env.build exists
if [ -f "$PROJECT_ROOT/.env.build" ]; then
  echo "Loading build credentials from .env.build"
  source "$PROJECT_ROOT/.env.build"
fi

echo "========================================"
echo " WireDog VPN macOS — Full Production Build"
echo "========================================"
echo ""

# ---- Step 1: Network Extension ----
echo "=== [1/5] Building Network Extension ==="
# Skip rebuild if extension already exists (Xcode 26 beta Go compatibility issue)
if [ ! -f "extension/build/WireDogTunnel.appex/Contents/MacOS/WireDogTunnel" ]; then
  bash scripts/build-extension.sh
else
  echo "Using pre-built extension (skipping rebuild due to Xcode 26 beta SPM/Go compatibility)"
fi
echo ""

# ---- Step 2: Filter Extension (split tunnel transparent proxy) ----
echo "=== [2/5] Building WireDogFilter Transparent Proxy Extension ==="
if [ ! -f "extension/build/WireDogFilter.appex/Contents/MacOS/WireDogFilter" ]; then
  bash scripts/build-filter.sh
else
  echo "Using pre-built WireDogFilter extension"
fi
echo ""

# ---- Step 3: Helper Daemon ----
echo "=== [3/5] Building Helper Daemon ==="
bash scripts/build-helper.sh
echo ""

# ---- Step 4: React Frontend ----
echo "=== [4/5] Building React Frontend ==="
npm run build
echo ""

# ---- Step 5: Package Electron App ----
echo "=== [5/5] Packaging Electron App (sign + notarize + DMG) ==="
npx electron-builder --mac
# electron-builder handles:
#   - Bundling all components
#   - Code signing (via CSC_LINK / CSC_KEY_PASSWORD)
#   - Notarization (via afterSign hook in notarize.js)
#   - DMG creation
echo ""

echo "========================================"
echo " Build complete!"
echo " Output: $PROJECT_ROOT/release/"
echo "========================================"
ls -lh release/*.dmg release/*.zip 2>/dev/null || echo "(No DMG/ZIP found — check for build errors above)"
