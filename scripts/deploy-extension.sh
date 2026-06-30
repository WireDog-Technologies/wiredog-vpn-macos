#!/bin/bash
set -e

# WireDog Extension Deployment Script
# This script deploys the built and signed extension to the running app bundle

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Configuration
APPEX_SOURCE="${PROJECT_ROOT}/extension/build/WireDogTunnel.appex"
APPEX_DEST="/Applications/WireDog VPN.app/Contents/PlugIns/WireDogTunnel.appex"
PROFILE_SOURCE="$HOME/Documents/wiredog/certs/WireDog_macOS_Tunnel.provisionprofile"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== WireDog Extension Deployment ===${NC}"
echo ""

# Check if extension exists
if [ ! -d "$APPEX_SOURCE" ]; then
  echo -e "${RED}❌ Error: Built extension not found at $APPEX_SOURCE${NC}"
  echo "   Run: bash scripts/build-extension.sh"
  exit 1
fi

# Check if provisioning profile exists
if [ ! -f "$PROFILE_SOURCE" ]; then
  echo -e "${RED}❌ Error: Provisioning profile not found at $PROFILE_SOURCE${NC}"
  exit 1
fi

# Check if app exists
if [ ! -d "/Applications/WireDog VPN.app" ]; then
  echo -e "${RED}❌ Error: WireDog VPN.app not found in /Applications${NC}"
  exit 1
fi

echo -e "${YELLOW}Step 1: Removing old extension${NC}"
if sudo rm -rf "$APPEX_DEST"; then
  echo -e "${GREEN}✅ Old extension removed${NC}"
else
  echo -e "${RED}❌ Failed to remove old extension${NC}"
  exit 1
fi

echo ""
echo -e "${YELLOW}Step 2: Copying new extension${NC}"
if sudo cp -R "$APPEX_SOURCE" "$APPEX_DEST"; then
  echo -e "${GREEN}✅ Extension copied${NC}"
else
  echo -e "${RED}❌ Failed to copy extension${NC}"
  exit 1
fi

echo ""
echo -e "${YELLOW}Step 3: Embedding provisioning profile${NC}"
if sudo cp "$PROFILE_SOURCE" "$APPEX_DEST/Contents/embedded.provisionprofile"; then
  echo -e "${GREEN}✅ Provisioning profile embedded${NC}"
else
  echo -e "${RED}❌ Failed to embed provisioning profile${NC}"
  exit 1
fi

echo ""
echo -e "${YELLOW}Step 4: Verifying deployment${NC}"
if [ -d "$APPEX_DEST" ] && [ -f "$APPEX_DEST/Contents/embedded.provisionprofile" ]; then
  echo -e "${GREEN}✅ Extension deployed successfully${NC}"
  echo ""
  echo -e "${YELLOW}Next steps:${NC}"
  echo "  1. Quit WireDog VPN (close it completely)"
  echo "  2. Relaunch WireDog VPN"
  echo "  3. Click 'Connect'"
  echo "  4. Status should change to 'connected' and STAY connected"
  echo ""
  echo -e "${YELLOW}To monitor connection:${NC}"
  echo "  log stream --predicate 'process == \"neagent\"' 2>&1 | grep -i provider"
else
  echo -e "${RED}❌ Deployment verification failed${NC}"
  exit 1
fi
