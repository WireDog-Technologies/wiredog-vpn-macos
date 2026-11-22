#!/bin/bash
# Manual reinstall of the helper daemon (development/support). Uses the same install script as the app,
# so the helper ends up root-owned in /Library/PrivilegedHelperTools with the launch constraint, never
# running from the app bundle.
set -e

APP="${1:-/Applications/WireDog VPN.app}"

echo "Removing old VPN config..."
sudo networksetup -removenetworkservice "WireDog VPN" 2>/dev/null || true

echo "Installing the helper from $APP..."
sudo bash "$APP/Contents/Resources/helper/install-helper.sh" \
  "$APP/Contents/MacOS/wiredog-helper" \
  "$APP/Contents/Resources/helper/com.wiredog.vpn.helper.plist"

echo ""
echo "=== Status ==="
sudo launchctl list | grep wiredog || echo "NOT RUNNING"
ls -l /Library/PrivilegedHelperTools/com.wiredog.vpn.helper
echo ""
echo "=== Helper log ==="
tail -20 /var/log/wiredog-helper.log
