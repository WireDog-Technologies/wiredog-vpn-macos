#!/bin/bash
# Sign and notarize the macOS app bundle
# Requires: APPLE_ID, APPLE_APP_SPECIFIC_PASSWORD, APPLE_TEAM_ID, DEVELOPER_ID_APPLICATION
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

IDENTITY="${DEVELOPER_ID_APPLICATION:-Developer ID Application: WireDog Technologies, LLC}"

echo "=== Signing with identity: $IDENTITY ==="

# Sign the helper daemon
echo "Signing helper daemon..."
codesign --force --options runtime --sign "$IDENTITY" \
  "$PROJECT_ROOT/helper/build/wiredog-helper"

# Sign the Network Extension
echo "Signing Network Extension..."
codesign --force --options runtime --sign "$IDENTITY" \
  --entitlements "$PROJECT_ROOT/extension/WireDogTunnel/WireDogTunnel.entitlements" \
  "$PROJECT_ROOT/extension/build/WireDogTunnel.appex"

# Build the Electron app (electron-builder handles app signing + notarization via afterSign hook)
echo "=== Building and signing Electron app ==="
cd "$PROJECT_ROOT"
npm run dist

echo "=== Done ==="
