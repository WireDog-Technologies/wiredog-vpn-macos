#!/bin/bash
# Install the WireDog VPN helper daemon as a LaunchDaemon.
# This script must be run with administrator privileges (via osascript).
#
# Usage: bash install-helper.sh <helper_binary_path> <plist_path>
#
# The helper is copied to /Library/PrivilegedHelperTools (root:wheel 0755) and the LaunchDaemon runs it
# from there, not from the app bundle: a drag-installed bundle belongs to the user, and a root daemon run
# from a user-writable file is a local privilege escalation (anything running as the user could replace
# it). Later helper updates need no password: the running helper replaces itself (selfUpdate RPC,
# helper/Sources/SelfUpdater.swift) after checking the new copy is signed by the same team.
# (The helper's NETunnelProviderManager code is unused: the app's native addon does all tunnel work.)
set -e

HELPER_BIN="$1"  # Path to helper binary inside app bundle (Contents/MacOS/wiredog-helper)
PLIST_SRC="$2"   # Path to LaunchDaemon plist in app resources

PLIST_DEST="/Library/LaunchDaemons/com.wiredog.vpn.helper.plist"
HELPER_DEST_DIR="/Library/PrivilegedHelperTools"
HELPER_DEST="$HELPER_DEST_DIR/com.wiredog.vpn.helper"

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

# Remove the old bundle-style helper if one is left over from an early format.
rm -rf "$HELPER_DEST_DIR/com.wiredog.vpn.helper.app" 2>/dev/null || true

# Install the helper as a root-owned copy (no extended attributes such as quarantine carried over).
mkdir -p "$HELPER_DEST_DIR"
cp -X -f "$HELPER_BIN" "$HELPER_DEST.tmp"
chown root:wheel "$HELPER_DEST.tmp"
chmod 755 "$HELPER_DEST.tmp"
mv -f "$HELPER_DEST.tmp" "$HELPER_DEST"
echo "Helper installed at $HELPER_DEST"

# macOS 13+: launchd will only start a binary signed by our team with this identifier (team-based, not
# per build, so silent self-updates still launch). Skipped for development builds without a team.
SIGN_INFO=$(codesign -dv "$HELPER_DEST" 2>&1 || true)
TEAM_ID=$(echo "$SIGN_INFO" | sed -n 's/^TeamIdentifier=//p')
SIGN_ID=$(echo "$SIGN_INFO" | sed -n 's/^Identifier=//p')
SPAWN_CONSTRAINT=""
if [ -n "$TEAM_ID" ] && [ "$TEAM_ID" != "not set" ] && [ -n "$SIGN_ID" ]; then
  SPAWN_CONSTRAINT="    <key>SpawnConstraint</key>
    <dict>
        <key>team-identifier</key>
        <string>${TEAM_ID}</string>
        <key>signing-identifier</key>
        <string>${SIGN_ID}</string>
    </dict>"
  echo "Launch constraint: team ${TEAM_ID}, identifier ${SIGN_ID}"
else
  echo "No team identifier on the helper (development build?): no launch constraint"
fi

# Write the LaunchDaemon plist pointing at the root-owned copy.
cat > "$PLIST_DEST" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.wiredog.vpn.helper</string>
    <key>Program</key>
    <string>${HELPER_DEST}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${HELPER_DEST}</string>
    </array>
${SPAWN_CONSTRAINT}
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
