#!/bin/bash
set -e

# WireDog Extension Code Signing Script
# This script re-signs the built extension with the correct Apple Development certificate
# Run this after Xcode builds the extension, before deploying to the app bundle

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Configuration
# Set APPLE_DEVELOPMENT_CERT_ID in your environment, or override below.
# Retrieve with: security find-certificate -c "Apple Development" -Z
CERT_ID="${APPLE_DEVELOPMENT_CERT_ID:-YOUR_APPLE_DEVELOPMENT_CERT_SHA1}"
APPEX="${PROJECT_ROOT}/extension/build/WireDogTunnel.appex"
ENTITLEMENTS="${PROJECT_ROOT}/extension/WireDogTunnel/WireDogTunnel.entitlements"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== WireDog Extension Signing ===${NC}"
echo ""

# Check if extension exists
if [ ! -d "$APPEX" ]; then
  echo -e "${RED}❌ Error: Extension not found at $APPEX${NC}"
  echo "   Make sure you've built the extension in Xcode first (Cmd+B)"
  exit 1
fi

# Check if entitlements file exists
if [ ! -f "$ENTITLEMENTS" ]; then
  echo -e "${RED}❌ Error: Entitlements file not found at $ENTITLEMENTS${NC}"
  exit 1
fi

# Re-sign the extension
echo -e "${YELLOW}Step 1: Re-signing extension with Apple Development certificate${NC}"
if codesign -f -s "$CERT_ID" --entitlements "$ENTITLEMENTS" "$APPEX"; then
  echo -e "${GREEN}✅ Extension re-signed${NC}"
else
  echo -e "${RED}❌ Failed to re-sign extension${NC}"
  exit 1
fi

echo ""
echo -e "${YELLOW}Step 2: Verifying signature${NC}"

# Verify the signature
SIGNATURE_OUTPUT=$(codesign -dvvv "$APPEX" 2>&1)

# Check for correct certificate type (Apple Development, not Developer ID)
if echo "$SIGNATURE_OUTPUT" | grep -q "Authority=Apple Development"; then
  echo -e "${GREEN}✅ Correct certificate type: Apple Development${NC}"
else
  echo -e "${RED}❌ ERROR: Certificate type is incorrect!${NC}"
  echo "$SIGNATURE_OUTPUT" | grep "Authority"
  exit 1
fi

# Check for Team ID
if echo "$SIGNATURE_OUTPUT" | grep -q "TeamIdentifier=${APPLE_TEAM_ID:-YOURTEAMID}"; then
  echo -e "${GREEN}✅ Team ID is correct: ${APPLE_TEAM_ID}${NC}"
else
  echo -e "${RED}❌ ERROR: Team ID is missing or incorrect!${NC}"
  exit 1
fi

# Check for Developer ID (should NOT be present)
if echo "$SIGNATURE_OUTPUT" | grep -q "Authority=Developer ID"; then
  echo -e "${RED}❌ ERROR: Extension is signed with Developer ID!${NC}"
  echo "   It MUST be signed with Apple Development (team cert) for NE validation to pass"
  exit 1
fi

echo ""
echo -e "${GREEN}=== Signature Verification Passed ===${NC}"
echo ""
echo "Full signature details:"
echo "$SIGNATURE_OUTPUT" | grep -E "Authority|TeamIdentifier|Signature" | sed 's/^/  /'

echo ""
echo -e "${GREEN}✅ Extension is ready to deploy!${NC}"
echo ""
echo "Next steps:"
echo "  1. sudo rm -rf \"/Applications/WireDog VPN.app/Contents/PlugIns/WireDogTunnel.appex\""
echo "  2. sudo cp -R $APPEX \"/Applications/WireDog VPN.app/Contents/PlugIns/\""
echo "  3. sudo cp <path-to>/WireDog_macOS_Tunnel.provisionprofile \"/Applications/WireDog VPN.app/Contents/PlugIns/WireDogTunnel.appex/Contents/embedded.provisionprofile\""
echo "  4. Quit and relaunch WireDog VPN"
echo "  5. Test the connection"
echo ""
