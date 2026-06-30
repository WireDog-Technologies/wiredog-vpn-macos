#!/bin/bash
# Runs detached after the main app quits.
# $1 = path to downloaded DMG

set -e

DMG_PATH="$1"
APP_NAME="WireDog VPN"
INSTALL_DIR="/Applications"
MOUNT_POINT="/tmp/WireDogVPNUpdate_$$"

if [ -z "$DMG_PATH" ] || [ ! -f "$DMG_PATH" ]; then
  echo "install-update: DMG not found at '$DMG_PATH'" >&2
  exit 1
fi

# Give the app a moment to fully quit before touching its bundle
sleep 2

hdiutil attach "$DMG_PATH" -mountpoint "$MOUNT_POINT" -nobrowse -quiet

# Replace the existing app bundle
rm -rf "$INSTALL_DIR/$APP_NAME.app"
cp -R "$MOUNT_POINT/$APP_NAME.app" "$INSTALL_DIR/"

hdiutil detach "$MOUNT_POINT" -quiet
rm -f "$DMG_PATH"

open "$INSTALL_DIR/$APP_NAME.app"
