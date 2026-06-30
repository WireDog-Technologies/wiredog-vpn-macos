#!/bin/bash
set -e

# WireDog VPN Extension Rebuild, Sign & Deploy Script
# Usage: bash rebuild-extension.sh
# This script builds the extension in Xcode, manually signs it, and deploys it to the app bundle

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EXTENSION_DIR="$REPO_ROOT/extension"
BUILD_DIR="$EXTENSION_DIR/build"
APPEX_BUILD="$BUILD_DIR/WireDogTunnel.appex"
ENTITLEMENTS="$EXTENSION_DIR/WireDogTunnel/WireDogTunnel.entitlements"

# Apple Development certificate SHA-1 fingerprint.
# Set APPLE_DEVELOPMENT_CERT_ID in your environment, or override below.
# Retrieve with: security find-certificate -c "Apple Development" -Z
CERT_ID="${APPLE_DEVELOPMENT_CERT_ID:-YOUR_APPLE_DEVELOPMENT_CERT_SHA1}"

# Provisioning profile — path to your WireDogTunnel Developer ID profile
PROFILE_SRC="${WIREDOG_PROFILE_DIR:-$HOME/Documents/wiredog/certs}/WireDog_macOS_Tunnel.provisionprofile"

# Target app location
APP_PATH="/Applications/WireDog VPN.app"
APPEX_DEST="$APP_PATH/Contents/PlugIns/WireDogTunnel.appex"

echo "================================"
echo "WireDog Extension Rebuild Script"
echo "================================"
echo ""

# Step 1: Verify files exist
echo "[1/6] Verifying prerequisites..."
if [ ! -f "$ENTITLEMENTS" ]; then
    echo "❌ Error: Entitlements file not found at $ENTITLEMENTS"
    exit 1
fi

if [ ! -f "$PROFILE_SRC" ]; then
    echo "❌ Error: Provisioning profile not found at $PROFILE_SRC"
    exit 1
fi

if [ ! -d "$APP_PATH" ]; then
    echo "❌ Error: App not found at $APP_PATH"
    exit 1
fi

echo "✅ All prerequisites found"
echo ""

# Step 2: Build in Xcode
echo "[2/6] Building extension in Xcode..."
cd "$EXTENSION_DIR"
xcodebuild -project WireDogTunnel.xcodeproj -target WireDogTunnel -configuration Release 2>&1 | tail -5

if [ ! -d "$APPEX_BUILD" ]; then
    echo "❌ Build failed - .appex not found at $APPEX_BUILD"
    exit 1
fi

echo "✅ Build succeeded"
echo ""

# Step 3: Manually sign the extension
echo "[3/6] Signing extension with Apple Development certificate..."
codesign -f -s "$CERT_ID" --entitlements "$ENTITLEMENTS" "$APPEX_BUILD" 2>&1 | grep -v "replacing existing signature"

echo "✅ Signed"
echo ""

# Step 4: Verify signature
echo "[4/6] Verifying signature..."
SIGNATURE_CHECK=$(codesign -dvvv "$APPEX_BUILD" 2>&1 | grep -E "Authority|Team|Signature" | head -4)

if echo "$SIGNATURE_CHECK" | grep -q "Authority=Apple Development"; then
    echo "✅ Signature verified:"
    echo "$SIGNATURE_CHECK"
else
    echo "❌ Signature verification failed. Output:"
    echo "$SIGNATURE_CHECK"
    exit 1
fi

if ! echo "$SIGNATURE_CHECK" | grep -q "TeamIdentifier=${APPLE_TEAM_ID:-YOURTEAMID}"; then
    echo "❌ Team ID not set correctly (expected APPLE_TEAM_ID=${APPLE_TEAM_ID})"
    exit 1
fi

echo ""

# Step 5: Deploy
echo "[5/6] Deploying to app bundle..."
sudo rm -rf "$APPEX_DEST"
sudo cp -R "$APPEX_BUILD" "$APPEX_DEST"
sudo cp "$PROFILE_SRC" "$APPEX_DEST/Contents/embedded.provisionprofile"

echo "✅ Deployed to $APPEX_DEST"
echo ""

# Step 6: Done
echo "[6/6] Complete!"
echo ""
echo "================================"
echo "✅ SUCCESS"
echo "================================"
echo ""
echo "Next steps:"
echo "1. Quit WireDog VPN completely"
echo "2. Relaunch WireDog VPN"
echo "3. Click Connect to test"
echo ""
