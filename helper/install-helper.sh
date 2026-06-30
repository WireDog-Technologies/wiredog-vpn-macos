#!/bin/bash
# Install the WireDog VPN helper daemon as a LaunchDaemon.
# This script must be run with administrator privileges (via osascript).
#
# Usage: bash install-helper.sh <helper_binary_path> <plist_path>
#
# The helper binary stays inside the Electron app bundle (Contents/MacOS/)
# so that Bundle.main resolves to the app, allowing NETunnelProviderManager
# to find the Network Extension in Contents/PlugIns/.
set -e

HELPER_BIN="$1"  # Path to helper binary inside app bundle (Contents/MacOS/wiredog-helper)
PLIST_SRC="$2"   # Path to LaunchDaemon plist in app resources

PLIST_DEST="/Library/LaunchDaemons/com.wiredog.vpn.helper.plist"

# Validate inputs
if [ -z "$HELPER_BIN" ] || [ -z "$PLIST_SRC" ]; then
  echo "Usage: install-helper.sh <helper_binary> <plist_file>"
  exit 1
fi

if [ ! -f "$HELPER_BIN" ]; then
  echo "ERROR: Helper binary not found at: $HELPER_BIN"
  exit 1
fi

if [ ! -f "$PLIST_SRC" ]; then
  echo "ERROR: Plist file not found at: $PLIST_SRC"
  exit 1
fi

# Stop existing daemon using the modern launchctl API (macOS 13+).
# Fall back to the legacy 'unload' for older systems.
if launchctl list 2>/dev/null | grep -q "com.wiredog.vpn.helper"; then
  echo "Stopping existing helper daemon..."
  launchctl bootout system/com.wiredog.vpn.helper 2>/dev/null \
    || launchctl unload "$PLIST_DEST" 2>/dev/null \
    || true
  sleep 1
fi

# Remove old standalone helper if it exists (migration from old format)
rm -f "/Library/PrivilegedHelperTools/com.wiredog.vpn.helper" 2>/dev/null || true
rm -rf "/Library/PrivilegedHelperTools/com.wiredog.vpn.helper.app" 2>/dev/null || true

# Write the LaunchDaemon plist with the correct binary path baked in.
# The binary lives inside the app bundle so Bundle.main resolves to the app,
# which lets NETunnelProviderManager find the Network Extension in PlugIns/.
cat > "$PLIST_DEST" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.wiredog.vpn.helper</string>
    <key>Program</key>
    <string>${HELPER_BIN}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${HELPER_BIN}</string>
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
EOF
chmod 644 "$PLIST_DEST"
chown root:wheel "$PLIST_DEST"

# Set up pf anchor in main config if not already present
PF_CONF="/etc/pf.conf"
ANCHOR_LINE='anchor "com.wiredog.vpn"'
if ! grep -q "$ANCHOR_LINE" "$PF_CONF" 2>/dev/null; then
  echo "Adding pf anchor to $PF_CONF..."
  echo "" >> "$PF_CONF"
  echo "# WireDog VPN kill switch anchor" >> "$PF_CONF"
  echo "$ANCHOR_LINE" >> "$PF_CONF"
fi

# Create anchor file directory
mkdir -p /etc/pf.anchors

# Enable the service so launchd will auto-start it (required on macOS 13+).
launchctl enable system/com.wiredog.vpn.helper 2>/dev/null || true

# Load the daemon using the modern bootstrap API, falling back to legacy load.
echo "Loading helper daemon..."
if ! launchctl bootstrap system "$PLIST_DEST" 2>/dev/null; then
  echo "bootstrap failed, trying legacy load..."
  launchctl load -w "$PLIST_DEST" 2>/dev/null || true
fi

# Give the daemon time to start, then verify the socket exists.
for i in 1 2 3 4 5; do
  sleep 1
  if [ -S /var/run/wiredog.sock ]; then
    echo "Helper daemon installed and running (socket ready)"
    exit 0
  fi
done

if launchctl list 2>/dev/null | grep -q "com.wiredog.vpn.helper"; then
  echo "Helper daemon registered — socket not yet ready, check /var/log/wiredog-helper.log"
else
  echo "ERROR: Helper daemon failed to register — check /var/log/wiredog-helper.log"
  exit 1
fi
