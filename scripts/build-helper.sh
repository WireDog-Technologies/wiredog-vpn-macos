#!/bin/bash
# Build the helper daemon (kill switch via pf)
# Produces a universal binary (arm64 + x86_64) for distribution.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT/helper"

mkdir -p build

# Check if we can build universal (requires both architectures available)
ARCH=$(uname -m)

echo "=== Building wiredog-helper daemon ==="

# IMPORTANT: wiredog-helper must be signed with a completely EMPTY entitlements dict.
# Not just no restricted entitlement — no entitlements at all, not even
# com.apple.application-identifier / com.apple.developer.team-identifier.
# It ships as a bare (non-bundle) Mach-O executable, and per Apple's own docs
# ("Inside Code Signing: Provisioning Profiles" / "Signing a daemon with a restricted
# entitlement"), a standalone executable structurally cannot hold a restricted
# entitlement — there is no way to embed an authorizing provisioning profile in it,
# and no linker-section trick works around this (confirmed the hard way — see
# VPN_CONNECTION_DEBUG.md Session 8/10).
#
# Confirmed EMPIRICALLY (Session 10) that this goes further than "no restricted
# entitlement": merely declaring com.apple.application-identifier, with zero
# restricted capability entitlements otherwise, was ALSO enough to make
# taskgated-helper reject exec() with "no eligible provisioning profiles found"
# (AMFI Code=-413) for this root-LaunchDaemon-spawned binary. Only a fully empty
# entitlements dict lets it exec cleanly. Do not add application-identifier or
# team-identifier back without re-testing on a genuinely clean machine.
#
# The daemon's actual jobs (pf-based kill switch, calling NETunnelProviderManager /
# OSSystemExtensionManager) do not require this entitlement on the calling process —
# see VPN_CONNECTION_DEBUG.md Session 10 for the evidence. If a future restricted
# entitlement is genuinely required here, wrap the daemon in its own small app-like
# bundle (its own Info.plist + Contents/embedded.provisionprofile) instead of adding
# it to this bare binary's entitlements.

if [ "$1" = "--universal" ] || [ "$ARCH" = "arm64" ]; then
  # Build for both architectures and create universal binary
  echo "Building arm64..."
  swift build -c release --arch arm64

  echo "Building x86_64..."
  swift build -c release --arch x86_64

  echo "Creating universal binary with lipo..."
  lipo -create \
    .build/arm64-apple-macosx/release/wiredog-helper \
    .build/x86_64-apple-macosx/release/wiredog-helper \
    -output build/wiredog-helper

  echo "Universal binary architectures:"
  lipo -info build/wiredog-helper
else
  # Single architecture build (development)
  echo "Building for current architecture ($ARCH)..."
  swift build -c release
  cp .build/release/wiredog-helper build/
fi

# Copy install script and plist alongside the binary
cp install-helper.sh build/
cp com.wiredog.vpn.helper.plist build/

# Sign the helper binary
ENTITLEMENTS="$PROJECT_ROOT/entitlements.helper.plist"
SIGNING_IDENTITY="${DEVELOPER_ID_APPLICATION:-${CSC_NAME:-Developer ID Application}}"

# Guard against ever re-introducing ANY entitlement key on this bare executable
# (see the big comment above — even application-identifier alone breaks exec() on
# every clean machine, not just restricted capability entitlements).
if grep -q "<key>" "$ENTITLEMENTS"; then
  echo "ERROR: $ENTITLEMENTS declares entitlement key(s). wiredog-helper is a bare" >&2
  echo "root-LaunchDaemon executable and must be signed with a fully empty" >&2
  echo "entitlements dict — even application-identifier/team-identifier alone make" >&2
  echo "AMFI reject exec() on any clean machine (see VPN_CONNECTION_DEBUG.md Session 10)." >&2
  exit 1
fi

echo "=== Signing helper daemon ==="
echo "Identity: $SIGNING_IDENTITY"
echo "Entitlements: $ENTITLEMENTS"

codesign --force --options runtime --timestamp \
  --sign "$SIGNING_IDENTITY" \
  --entitlements "$ENTITLEMENTS" \
  "build/wiredog-helper"

echo "=== Helper daemon built and signed successfully ==="
ls -la build/wiredog-helper
codesign -dvvv build/wiredog-helper 2>&1 | grep -E "(Authority|Entitlements|runtime)"
