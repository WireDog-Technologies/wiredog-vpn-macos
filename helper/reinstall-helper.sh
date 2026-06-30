#!/bin/bash
# Reinstall helper daemon pointing to binary inside app bundle
set -e

echo "Stopping old helper..."
sudo launchctl unload /Library/LaunchDaemons/com.wiredog.vpn.helper.plist 2>/dev/null || true

echo "Removing old VPN config..."
sudo networksetup -removenetworkservice "WireDog VPN" 2>/dev/null || true

echo "Removing old helper binaries..."
sudo rm -f /Library/PrivilegedHelperTools/com.wiredog.vpn.helper 2>/dev/null || true
sudo rm -rf /Library/PrivilegedHelperTools/com.wiredog.vpn.helper.app 2>/dev/null || true

echo "Writing new LaunchDaemon plist..."
sudo tee /Library/LaunchDaemons/com.wiredog.vpn.helper.plist > /dev/null <<'PLISTEOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.wiredog.vpn.helper</string>
    <key>Program</key>
    <string>/Applications/WireDog VPN.app/Contents/MacOS/wiredog-helper</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Applications/WireDog VPN.app/Contents/MacOS/wiredog-helper</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/wiredog-helper.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/wiredog-helper.log</string>
</dict>
</plist>
PLISTEOF

echo "Loading daemon..."
sudo launchctl load -w /Library/LaunchDaemons/com.wiredog.vpn.helper.plist

sleep 2
echo ""
echo "=== Status ==="
sudo launchctl list | grep wiredog || echo "NOT RUNNING"
echo ""
echo "=== Helper log ==="
tail -20 /var/log/wiredog-helper.log
