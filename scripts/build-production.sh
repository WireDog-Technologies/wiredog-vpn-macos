#!/bin/bash
# WireDog VPN macOS — One-stop production build script
#
# Cleans and rebuilds everything from scratch, signs with Developer ID,
# and produces an installable DMG.
#
# Usage:
#   bash scripts/build-production.sh --local             # signed, no notarization
#   bash scripts/build-production.sh --local --cleanup   # also quit app, kill helper, remove old /Applications copy, flush pf, clear KS state (sudo)
#   bash scripts/build-production.sh --notarize          # signed + notarized
#   bash scripts/build-production.sh --config            # print config and exit
#   bash scripts/build-production.sh --local --verbose   # detailed logging
#
# Notarization env vars (required with --notarize):
#   APPLE_ID                         Apple Developer account email
#   APPLE_APP_SPECIFIC_PASSWORD      App-specific password from appleid.apple.com
#
# Optional env vars:
#   SKIP_NATIVE_MODULE=1   Skip the native N-API module build (not shipped, safe to skip)
#   PROVISIONING_PROFILES_DIR=...    Override default profile location

set -euo pipefail

# Load local credentials if present (gitignored — never commit this file)
SCRIPT_DIR_EARLY="$(cd "$(dirname "$0")" && pwd)"
LOCAL_ENV="$(dirname "$SCRIPT_DIR_EARLY")/.env.local"
# shellcheck source=/dev/null
[ -f "$LOCAL_ENV" ] && source "$LOCAL_ENV"

# ============================================================================
# Configuration — set via environment variables or edit here before building
# ============================================================================
# DEVELOPER_ID_APPLICATION: codesign identity string from your keychain
#   e.g. "Developer ID Application: Your Name, LLC (TEAMID)"
# APPLE_DEVELOPMENT_CERT_ID: SHA-1 fingerprint of your Apple Development cert
#   Retrieve with: security find-certificate -c "Apple Development" -Z
# APPLE_TEAM_ID: 10-character Apple Developer Team ID
DEVELOPER_ID_APPLICATION="${DEVELOPER_ID_APPLICATION:-Developer ID Application: WireDog Technologies, LLC (YOURTEAMID)}"
APPLE_DEVELOPMENT_CERT_ID="${APPLE_DEVELOPMENT_CERT_ID:-YOUR_APPLE_DEVELOPMENT_CERT_SHA1}"
APPLE_TEAM_ID="${APPLE_TEAM_ID:-YOURTEAMID}"

# ============================================================================
# Paths
# ============================================================================
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

PROVISIONING_PROFILES_DIR="${PROVISIONING_PROFILES_DIR:-${HOME}/Documents/wiredog/certs}"
export PROVISIONING_PROFILES_DIR

# ============================================================================
# Flag parsing
# ============================================================================
LOCAL=0
NOTARIZE=0
CONFIG_ONLY=0
CLEANUP=0
VERBOSE="${VERBOSE:-0}"
SKIP_NATIVE_MODULE="${SKIP_NATIVE_MODULE:-0}"

for arg in "$@"; do
  case "$arg" in
    --local)    LOCAL=1 ;;
    --notarize) NOTARIZE=1 ;;
    --config)   CONFIG_ONLY=1 ;;
    --cleanup)  CLEANUP=1 ;;
    --verbose)  VERBOSE=1 ;;
    -h|--help)
      grep -E '^# ' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "ERROR: Unknown flag: $arg"
      echo "Run: bash scripts/build-production.sh --help"
      exit 1
      ;;
  esac
done

if [ "$LOCAL" = "0" ] && [ "$NOTARIZE" = "0" ] && [ "$CONFIG_ONLY" = "0" ]; then
  echo "ERROR: Specify one of: --local, --notarize, or --config"
  echo "Run: bash scripts/build-production.sh --help"
  exit 1
fi

# ============================================================================
# Color helpers
# ============================================================================
if [ -t 1 ]; then
  C_RESET='\033[0m'
  C_BOLD='\033[1m'
  C_RED='\033[31m'
  C_GREEN='\033[32m'
  C_YELLOW='\033[33m'
  C_BLUE='\033[34m'
  C_DIM='\033[2m'
else
  C_RESET='' C_BOLD='' C_RED='' C_GREEN='' C_YELLOW='' C_BLUE='' C_DIM=''
fi

step()    { printf "\n${C_BOLD}${C_BLUE}==> %s${C_RESET}\n" "$*"; }
ok()      { printf "${C_GREEN}✓${C_RESET} %s\n" "$*"; }
warn()    { printf "${C_YELLOW}⚠${C_RESET}  %s\n" "$*"; }
fail()    { printf "${C_RED}✗ %s${C_RESET}\n" "$*" >&2; exit 1; }
verbose() { [ "$VERBOSE" = "1" ] && printf "${C_DIM}  %s${C_RESET}\n" "$*" || true; }

trap 'printf "\n${C_RED}${C_BOLD}BUILD FAILED${C_RESET} at line $LINENO\n" >&2' ERR

# ============================================================================
# Configuration summary
# ============================================================================
print_config() {
  cat <<EOF
${C_BOLD}WireDog VPN macOS — Production Build${C_RESET}

${C_BOLD}BUILD CONFIGURATION (Hardcoded):${C_RESET}
  Developer ID Application : ${DEVELOPER_ID_APPLICATION}
  Apple Development Cert   : ${APPLE_DEVELOPMENT_CERT_ID}
  Apple Team ID            : ${APPLE_TEAM_ID}
  Provisioning profiles    : ${PROVISIONING_PROFILES_DIR}

${C_BOLD}BUILD OPTIONS:${C_RESET}
  Mode                     : $([ "$NOTARIZE" = "1" ] && echo 'SIGNED + NOTARIZED (distribution)' || echo 'SIGNED LOCAL (no notarization)')
  Skip native module       : $([ "$SKIP_NATIVE_MODULE" = "1" ] && echo 'yes' || echo 'no')
  Verbose                  : $([ "$VERBOSE" = "1" ] && echo 'yes' || echo 'no')

EOF
}

print_config

if [ "$CONFIG_ONLY" = "1" ]; then
  ok "Configuration printed (no build performed)"
  exit 0
fi

# ============================================================================
# Step 0: Pre-flight checks
# ============================================================================
step "[0/9] Pre-flight checks"

command -v xcodegen >/dev/null 2>&1 || fail "xcodegen not installed. Install with: brew install xcodegen"
ok "xcodegen: $(xcodegen --version 2>&1 | head -1)"

command -v swift >/dev/null 2>&1 || fail "swift not found. Install Xcode command line tools."
ok "swift: $(swift --version 2>&1 | head -1)"

command -v npm >/dev/null 2>&1 || fail "npm not found. Install Node.js."
ok "node: $(node --version)  npm: $(npm --version)"

command -v xcode-select >/dev/null 2>&1 || fail "xcode-select not found."
ok "xcode path: $(xcode-select -p)"

# Verify the EXACT hardcoded Developer ID identity is in the keychain
if ! security find-identity -v -p codesigning | grep -qF "$DEVELOPER_ID_APPLICATION"; then
  echo
  echo "Hardcoded identity: $DEVELOPER_ID_APPLICATION"
  echo "Identities currently available:"
  security find-identity -v -p codesigning | sed 's/^/  /'
  fail "Hardcoded DEVELOPER_ID_APPLICATION does not match any keychain identity.
   Fix: edit DEVELOPER_ID_APPLICATION at the top of scripts/build-production.sh to match one of the strings above."
fi
ok "Developer ID identity matches keychain"

# Note: APPLE_DEVELOPMENT_CERT_ID is no longer used for the tunnel extension —
# system extensions are signed with Developer ID Application (same cert as the main app).
# It may still be used for WireDogFilter.appex (split tunnel, deferred feature).
ok "Apple Development cert check skipped (system extension uses Developer ID)"

# Verify notarization credentials if --notarize
if [ "$NOTARIZE" = "1" ]; then
  [ -n "${APPLE_ID:-}" ] || fail "--notarize requires APPLE_ID environment variable"
  [ -n "${APPLE_APP_SPECIFIC_PASSWORD:-}" ] || fail "--notarize requires APPLE_APP_SPECIFIC_PASSWORD"
  ok "Notarization credentials: APPLE_ID=${APPLE_ID}"
fi

# Provisioning profiles (warn only — afterpack.js handles missing profiles).
# NOTE: wiredog-helper (the daemon) intentionally has NO provisioning profile of its
# own and never should — it's a bare executable claiming no restricted entitlements.
# See VPN_CONNECTION_DEBUG.md Session 10. Do not reintroduce a HELPER_PROFILE check
# here or in build-helper.sh.
MAIN_PROFILE="${PROVISIONING_PROFILES_DIR}/WireDog_macOS_Main.provisionprofile"
TUNNEL_PROFILE="${PROVISIONING_PROFILES_DIR}/WireDog_macOS_Tunnel.provisionprofile"
FILTER_PROFILE="${PROVISIONING_PROFILES_DIR}/WireDog_macOS_Filter.provisionprofile"
[ -f "$MAIN_PROFILE" ]   && ok "Main provisioning profile found"   || warn "Main profile missing: $MAIN_PROFILE"
[ -f "$TUNNEL_PROFILE" ] && ok "Tunnel provisioning profile found" || warn "Tunnel profile missing: $TUNNEL_PROFILE"
[ -f "$FILTER_PROFILE" ] && ok "Filter provisioning profile found" || warn "Filter profile missing: $FILTER_PROFILE (required for split tunneling)"

# Guard against ever re-introducing ANY entitlement key on the bare helper
# executable — confirmed empirically (Session 10) that even application-identifier
# alone, with zero restricted capability entitlements, is enough to make AMFI
# reject exec() on a clean machine. entitlements.helper.plist must stay <dict/>.
if grep -q "<key>" entitlements.helper.plist; then
  fail "entitlements.helper.plist declares entitlement key(s) — wiredog-helper is a bare root-LaunchDaemon executable and must be signed with a fully empty entitlements dict. See VPN_CONNECTION_DEBUG.md Session 10."
fi
ok "Helper entitlements: empty (correct)"

# ============================================================================
# Step 1: Clean all build artifacts
# ============================================================================
step "[1/9] Cleaning all build artifacts"

rm -rf extension/build
rm -rf helper/build helper/.build
rm -rf native/build native/.build
rm -rf native-sysext/build
rm -rf sysext-activator/build
rm -rf dist
rm -rf release
rm -f  .env.build
ok "Cleaned: extension/build, helper/.build, native/build, sysext-activator/build, dist, release, .env.build"

# ============================================================================
# Step 2: Build Network Extension
# ============================================================================
step "[2/9] Building Network Extension (.appex)"

# build-extension.sh handles: xcodegen, xcodebuild, MH_EXECUTE check, and
# signing with the Apple Development cert (hardcoded to APPLE_DEVELOPMENT_CERT_ID).
if [ "$VERBOSE" = "1" ]; then
  bash scripts/build-extension.sh
else
  bash scripts/build-extension.sh > /tmp/wiredog-extension-build.log 2>&1 || {
    tail -40 /tmp/wiredog-extension-build.log
    fail "Extension build failed. Full log: /tmp/wiredog-extension-build.log"
  }
fi

APPEX_PATH="extension/build/com.wiredog.vpn.macos.tunnel.systemextension"
[ -d "$APPEX_PATH" ] || fail "System extension bundle not produced at $APPEX_PATH"

# Verify binary type
if ! file "$APPEX_PATH/Contents/MacOS/com.wiredog.vpn.macos.tunnel" | grep -q "executable"; then
  fail "Extension binary is not MH_EXECUTE. Check MACH_O_TYPE in project.yml."
fi
ok "System extension binary is MH_EXECUTE"
ok "System extension built (signing will be applied by afterpack.js with Developer ID)"

# ============================================================================
# Step 3: Build WireDogFilter extension (transparent proxy for split tunneling)
# ============================================================================
step "[3/9] Building WireDogFilter Transparent Proxy Extension (.appex)"

if [ "$VERBOSE" = "1" ]; then
  bash scripts/build-filter.sh
else
  bash scripts/build-filter.sh > /tmp/wiredog-filter-build.log 2>&1 || {
    tail -40 /tmp/wiredog-filter-build.log
    fail "WireDogFilter build failed. Full log: /tmp/wiredog-filter-build.log"
  }
fi

FILTER_APPEX_PATH="extension/build/WireDogFilter.appex"
[ -d "$FILTER_APPEX_PATH" ] || fail "Filter extension bundle not produced at $FILTER_APPEX_PATH"

# Verify signature
FILTER_SIG=$(codesign -dvvv "$FILTER_APPEX_PATH" 2>&1)
echo "$FILTER_SIG" | grep -q "Authority=Apple Development"   || fail "Filter extension not signed with Apple Development cert"
echo "$FILTER_SIG" | grep -q "Authority=Developer ID"        && fail "Filter extension wrongly signed with Developer ID (must be Apple Development)"
echo "$FILTER_SIG" | grep -q "TeamIdentifier=$APPLE_TEAM_ID" || fail "Filter extension Team ID mismatch (expected $APPLE_TEAM_ID)"
ok "Filter extension signed with Apple Development cert (Team $APPLE_TEAM_ID)"

# ============================================================================
# Step 4: Build helper daemon
# ============================================================================
step "[4/9] Building helper daemon (universal binary, signed)"

# Export identity so build-helper.sh picks it up for codesign
export DEVELOPER_ID_APPLICATION

if [ "$VERBOSE" = "1" ]; then
  bash scripts/build-helper.sh --universal
else
  bash scripts/build-helper.sh --universal > /tmp/wiredog-helper-build.log 2>&1 || {
    tail -40 /tmp/wiredog-helper-build.log
    fail "Helper build failed. Full log: /tmp/wiredog-helper-build.log"
  }
fi

HELPER_BIN="helper/build/wiredog-helper"
[ -f "$HELPER_BIN" ] || fail "Helper binary not produced at $HELPER_BIN"

# --- Build VPN config XPC service ---
# Separate process that holds packet-tunnel-provider-systemextension (no JIT).
# Electron cannot hold both JIT and the NE entitlement — RunningBoard blocks launch.
step "[4b/9] Building VPN config XPC service"
if [ "$VERBOSE" = "1" ]; then
  bash scripts/build-xpc-config.sh
else
  bash scripts/build-xpc-config.sh > /tmp/wiredog-xpc-build.log 2>&1 || {
    tail -20 /tmp/wiredog-xpc-build.log
    fail "XPC config service build failed. Full log: /tmp/wiredog-xpc-build.log"
  }
fi
[ -d "xpc-config/build/com.wiredog.vpn.macos.config.xpc" ] || fail "XPC config bundle not produced"

# Verify universal
if ! lipo -info "$HELPER_BIN" | grep -qE "arm64.*x86_64|x86_64.*arm64"; then
  warn "Helper is not universal: $(lipo -info "$HELPER_BIN")"
else
  ok "Helper is universal (arm64 + x86_64)"
fi

# Verify signature
HELPER_SIG=$(codesign -dvvv "$HELPER_BIN" 2>&1)
echo "$HELPER_SIG" | grep -q "Authority=Developer ID Application" || fail "Helper not signed with Developer ID Application"
echo "$HELPER_SIG" | grep -q "flags=.*runtime"                    || warn "Helper missing runtime flag (required for notarization)"
ok "Helper signed with Developer ID Application + runtime"

# ============================================================================
# Step 4: Build native N-API module (optional)
# ============================================================================
step "[5/9] Building native N-API module"

if [ "$SKIP_NATIVE_MODULE" = "1" ]; then
  warn "Skipping native module build (SKIP_NATIVE_MODULE=1)"
else
  if [ -f native/binding.gyp ]; then
    (
      cd native
      if [ "$VERBOSE" = "1" ]; then
        swift build -c release 2>&1 || true
        # Refresh the Swift-ObjC bridging header so node-gyp sees new @objc classes
        NATIVE_ARCH=$(uname -m)
        SWIFT_HEADER=".build/${NATIVE_ARCH}-apple-macosx/release/WireDogNative.build/include/WireDogNative-Swift.h"
        [ -f "$SWIFT_HEADER" ] && cp "$SWIFT_HEADER" include/WireDogNative-Swift.h || true
        npx node-gyp rebuild 2>&1
      else
        swift build -c release > /tmp/wiredog-native-swift.log 2>&1 || warn "native Swift build had warnings (see /tmp/wiredog-native-swift.log)"
        # Refresh the Swift-ObjC bridging header so node-gyp sees new @objc classes
        NATIVE_ARCH=$(uname -m)
        SWIFT_HEADER=".build/${NATIVE_ARCH}-apple-macosx/release/WireDogNative.build/include/WireDogNative-Swift.h"
        [ -f "$SWIFT_HEADER" ] && cp "$SWIFT_HEADER" include/WireDogNative-Swift.h || true
        npx node-gyp rebuild > /tmp/wiredog-native-gyp.log 2>&1 || {
          tail -40 /tmp/wiredog-native-gyp.log
          fail "Native module node-gyp build failed. Full log: /tmp/wiredog-native-gyp.log"
        }
      fi
    )
    # Copy dylib next to .node so @loader_path resolves correctly at runtime
    NATIVE_ARCH=$(uname -m)
    DYLIB_SRC="native/.build/${NATIVE_ARCH}-apple-macosx/release/libWireDogNative.dylib"
    DYLIB_DEST="native/build/Release/libWireDogNative.dylib"
    if [ -f "$DYLIB_SRC" ]; then
      cp "$DYLIB_SRC" "$DYLIB_DEST"
      ok "Copied libWireDogNative.dylib to build/Release/"
    else
      warn "libWireDogNative.dylib not found at $DYLIB_SRC — addon will fail to load"
    fi

    NATIVE_MODULE="native/build/Release/wiredog_native.node"
    if [ -f "$NATIVE_MODULE" ]; then
      if file "$NATIVE_MODULE" | grep -q "Mach-O.*shared library"; then
        ok "Native module built: $NATIVE_MODULE"
      else
        warn "Native module built but does not look like a Mach-O shared library"
      fi
    else
      warn "Native module artifact not at expected path: $NATIVE_MODULE"
    fi
  else
    warn "No native/binding.gyp — skipping"
  fi
fi

# ============================================================================
# Step 5b: Build native-sysext addon (OSSystemExtensionManager bridge)
# ============================================================================
step "[5b/9] Building native-sysext addon (system extension activation)"

if [ -f native-sysext/binding.gyp ]; then
  (
    cd native-sysext
    if [ "$VERBOSE" = "1" ]; then
      npx node-gyp rebuild 2>&1
    else
      npx node-gyp rebuild > /tmp/wiredog-sysext-gyp.log 2>&1 || {
        tail -40 /tmp/wiredog-sysext-gyp.log
        fail "native-sysext node-gyp build failed. Full log: /tmp/wiredog-sysext-gyp.log"
      }
    fi
  )
  SYSEXT_MODULE="native-sysext/build/Release/wiredog_sysext.node"
  if [ -f "$SYSEXT_MODULE" ]; then
    ok "native-sysext addon built: $SYSEXT_MODULE"
  else
    warn "native-sysext addon artifact not found at expected path"
  fi
else
  warn "No native-sysext/binding.gyp — skipping sysext addon build"
fi

# ============================================================================
# Step 5c: Build sysext activator (standalone binary — invoked by Electron to
#          call OSSystemExtensionManager without JIT/NE entitlement conflict)
# ============================================================================
step "[5c/9] Building sysext activator (WireDogActivator)"

mkdir -p sysext-activator/build
if [ "$VERBOSE" = "1" ]; then
  swiftc \
    -target arm64-apple-macosx12.0 \
    -framework Foundation \
    -framework SystemExtensions \
    sysext-activator/main.swift \
    -o sysext-activator/build/WireDogActivator
else
  swiftc \
    -target arm64-apple-macosx12.0 \
    -framework Foundation \
    -framework SystemExtensions \
    sysext-activator/main.swift \
    -o sysext-activator/build/WireDogActivator \
    > /tmp/wiredog-activator-build.log 2>&1 || {
    cat /tmp/wiredog-activator-build.log
    fail "WireDogActivator build failed"
  }
fi

ACTIVATOR_BIN="sysext-activator/build/WireDogActivator"
[ -f "$ACTIVATOR_BIN" ] || fail "WireDogActivator binary not produced"
file "$ACTIVATOR_BIN" | grep -q "arm64" || fail "WireDogActivator is not arm64"
ok "WireDogActivator built (signing will be applied by afterpack.js)"

# ============================================================================
# Step 5: Build React frontend
# ============================================================================
step "[6/9] Building React frontend (Vite)"

if [ "$VERBOSE" = "1" ]; then
  npm run build
else
  npm run build > /tmp/wiredog-vite-build.log 2>&1 || {
    tail -40 /tmp/wiredog-vite-build.log
    fail "Vite build failed. Full log: /tmp/wiredog-vite-build.log"
  }
fi

[ -f dist/index.html ] || fail "dist/index.html not produced"
ok "React bundle built"

# ============================================================================
# Step 6: Write .env.build for electron-builder / afterpack.js
# ============================================================================
step "[7/9] Writing .env.build and exporting signing environment"

cat > .env.build <<EOF
# Auto-generated by scripts/build-production.sh — DO NOT COMMIT
DEVELOPER_ID_APPLICATION="${DEVELOPER_ID_APPLICATION}"
APPLE_DEVELOPMENT_CERT_ID="${APPLE_DEVELOPMENT_CERT_ID}"
APPLE_TEAM_ID="${APPLE_TEAM_ID}"
CSC_NAME="${DEVELOPER_ID_APPLICATION}"
CSC_IDENTITY_AUTO_DISCOVERY=false
EOF
ok "Wrote .env.build"

# Export for child processes (electron-builder, afterpack.js, notarize.js)
export DEVELOPER_ID_APPLICATION
export APPLE_DEVELOPMENT_CERT_ID
export APPLE_TEAM_ID
export CSC_NAME="$DEVELOPER_ID_APPLICATION"
export CSC_IDENTITY_AUTO_DISCOVERY=false

if [ "$NOTARIZE" = "1" ]; then
  export APPLE_ID
  export APPLE_APP_SPECIFIC_PASSWORD
  export APPLE_TEAM_ID
  ok "Notarization env exported"
else
  # Ensure notarize.js early-returns by unsetting APPLE_ID
  unset APPLE_ID 2>/dev/null || true
fi

# ============================================================================
# Step 7: Package Electron app (electron-builder + afterpack.js)
# ============================================================================
step "[8/9] Packaging Electron app (electron-builder)"

if [ "$VERBOSE" = "1" ]; then
  npm run package:mac
else
  npm run package:mac 2>&1 | tee /tmp/wiredog-package.log | grep -iE "(signing|notariz|afterPack|ERROR|error|building)" || true
  if [ ! -d "release/mac-arm64/WireDog VPN.app" ]; then
    tail -60 /tmp/wiredog-package.log
    fail "Packaging failed. Full log: /tmp/wiredog-package.log"
  fi
fi

APP_PATH="release/mac-arm64/WireDog VPN.app"
[ -d "$APP_PATH" ] || fail "App bundle not produced at $APP_PATH"
ok "App bundle produced"

# ============================================================================
# Step 8: Post-build verification
# ============================================================================
step "[9/9] Verifying final artifacts"

# --- Main app signature ---
APP_SIG=$(codesign -dvvv "$APP_PATH" 2>&1)
echo "$APP_SIG" | grep -q "Authority=Developer ID Application" || fail "Main app not signed with Developer ID"
ok "Main app: Developer ID Application"

# --- Helper signature ---
INSTALLED_HELPER="$APP_PATH/Contents/MacOS/wiredog-helper"
[ -f "$INSTALLED_HELPER" ] || fail "Helper missing from Contents/MacOS/"
HSIG=$(codesign -dvvv "$INSTALLED_HELPER" 2>&1)
echo "$HSIG" | grep -q "Authority=Developer ID Application" || fail "Installed helper not signed with Developer ID"
echo "$HSIG" | grep -q "flags=.*runtime"                    || warn "Installed helper missing runtime flag"
ok "Installed helper: Developer ID Application + runtime"

# Verify the shipped helper binary claims NO entitlements at all — a bare
# root-LaunchDaemon executable can't hold even application-identifier without AMFI
# demanding a matching provisioning profile it structurally cannot have. Confirmed
# empirically (Session 10) that even application-identifier alone, with zero
# restricted capability entitlements, reproduces OS_REASON_EXEC / AMFI "no eligible
# provisioning profiles found" on a clean machine.
INSTALLED_HELPER_ENT=$(codesign -d --entitlements - --xml "$INSTALLED_HELPER" 2>/dev/null || true)
echo "$INSTALLED_HELPER_ENT" | grep -q "<key>" \
  && fail "Installed helper has entitlement key(s): $INSTALLED_HELPER_ENT — wiredog-helper must be signed with a fully empty entitlements dict. See VPN_CONNECTION_DEBUG.md Session 10."
ok "Installed helper: no entitlements (correct)"

# --- Extension signature (WireDogTunnel system extension) ---
INSTALLED_APPEX="$APP_PATH/Contents/Library/SystemExtensions/com.wiredog.vpn.macos.tunnel.systemextension"
[ -d "$INSTALLED_APPEX" ] || fail "Network System Extension missing from Contents/Library/SystemExtensions/"
ESIG=$(codesign -dvvv "$INSTALLED_APPEX" 2>&1)
echo "$ESIG" | grep -q "Authority=Developer ID Application"  || fail "Installed tunnel system extension not signed with Developer ID Application"
echo "$ESIG" | grep -q "TeamIdentifier=$APPLE_TEAM_ID"       || fail "Installed tunnel system extension Team ID mismatch"
ok "Installed com.wiredog.vpn.macos.tunnel.systemextension: Developer ID Application (Team $APPLE_TEAM_ID)"

# --- Filter extension signature (WireDogFilter) ---
INSTALLED_FILTER="$APP_PATH/Contents/PlugIns/WireDogFilter.appex"
if [ -d "$INSTALLED_FILTER" ]; then
  FSIG=$(codesign -dvvv "$INSTALLED_FILTER" 2>&1)
  echo "$FSIG" | grep -q "Authority=Developer ID Application"  || fail "Installed filter appex not signed with Developer ID Application"
  echo "$FSIG" | grep -q "TeamIdentifier=$APPLE_TEAM_ID"       || fail "Installed filter appex Team ID mismatch"
  ok "Installed WireDogFilter.appex: Developer ID Application (Team $APPLE_TEAM_ID)"
else
  warn "WireDogFilter.appex not found in Contents/PlugIns/ — afterpack.js may need updating to bundle it"
fi

# --- Required file manifest ---
REQUIRED_FILES=(
  "$APP_PATH/Contents/MacOS/WireDog VPN"
  "$APP_PATH/Contents/MacOS/wiredog-helper"
  "$APP_PATH/Contents/MacOS/WireDogActivator"
  "$APP_PATH/Contents/Library/SystemExtensions/com.wiredog.vpn.macos.tunnel.systemextension/Contents/MacOS/com.wiredog.vpn.macos.tunnel"
  "$APP_PATH/Contents/Resources/app.asar"
  "$APP_PATH/Contents/Resources/helper/install-helper.sh"
  "$APP_PATH/Contents/Resources/helper/com.wiredog.vpn.helper.plist"
)
for f in "${REQUIRED_FILES[@]}"; do
  [ -e "$f" ] || fail "Missing required file: $f"
  verbose "found: $f"
done
ok "All required files present in app bundle"

# --- DMG / ZIP ---
DMG_FILE=$(ls release/*.dmg 2>/dev/null | head -1 || true)
ZIP_FILE=$(ls release/*.zip 2>/dev/null | head -1 || true)
[ -n "$DMG_FILE" ] && ok "DMG: $DMG_FILE ($(du -h "$DMG_FILE" | cut -f1))" || warn "No DMG produced"
[ -n "$ZIP_FILE" ] && ok "ZIP: $ZIP_FILE ($(du -h "$ZIP_FILE" | cut -f1))" || warn "No ZIP produced"

# --- Notarization (if requested) ---
if [ "$NOTARIZE" = "1" ]; then
  step "Verifying notarization"

  # NOTE: plain `spctl ... | grep accepted` is NOT sufficient here — on the machine
  # that holds the Developer ID signing certificate, Gatekeeper can report "accepted"
  # purely from local keychain trust of that cert, even for a build that was never
  # actually notarized. The only reliable signal is the `source=` field specifically
  # saying "Notarized Developer ID", plus `stapler validate` confirming a real ticket
  # is attached — check both.
  SPCTL_OUT=$(spctl -a -vvv -t install "$APP_PATH" 2>&1)
  echo "$SPCTL_OUT" > /tmp/wiredog-spctl.log
  if echo "$SPCTL_OUT" | grep -q "source=Notarized Developer ID"; then
    ok "spctl confirms source=Notarized Developer ID"
  else
    cat /tmp/wiredog-spctl.log
    fail "spctl did NOT report 'source=Notarized Developer ID' — this build is signed but not confirmed notarized. Do not ship it. (A bare 'accepted' result is not sufficient — see comment above.)"
  fi

  if xcrun stapler validate "$APP_PATH" > /tmp/wiredog-stapler.log 2>&1; then
    ok "stapler validate confirms a genuine notarization ticket is attached"
  else
    cat /tmp/wiredog-stapler.log
    fail "xcrun stapler validate failed — no valid notarization ticket attached. Do not ship this build."
  fi
fi

# ============================================================================
# Optional: Clean up old install so next manual install is a clean slate
# ============================================================================
if [ "$CLEANUP" = "1" ]; then
  step "[cleanup] Removing old install, killing helper, clearing KS state"

  # Quit any running copy of the app (ignore errors if not running)
  osascript -e 'quit app "WireDog VPN"' 2>/dev/null || true
  ok "Quit request sent to WireDog VPN (if running)"

  # Remove stale VPN configuration from the NE preferences store.
  # Uses scutil --nc delete directly (bypasses NETunnelProviderManager/loadAllFromPreferences,
  # which hangs when the config references a changed extension binary).
  # Stale configs cause loadAllFromPreferences() to hang after a rebuild.
  VPN_IDS=$(scutil --nc list 2>/dev/null | grep -i "wiredog" | awk '{print $2}' | tr -d '*') || true
  if [ -n "$VPN_IDS" ]; then
    REMOVED=0
    while IFS= read -r VPN_ID; do
      [ -z "$VPN_ID" ] && continue
      if sudo scutil --nc delete "$VPN_ID" 2>/dev/null; then
        ok "Removed VPN config: $VPN_ID"
        REMOVED=$((REMOVED+1))
      else
        warn "Could not delete VPN config $VPN_ID (scutil failed)"
      fi
    done <<< "$VPN_IDS"
    [ "$REMOVED" -gt 0 ] && ok "Removed $REMOVED stale WireDog VPN configuration(s)" || warn "Could not remove VPN config — remove manually from System Settings → VPN"
  else
    ok "No WireDog VPN configuration found to remove"
  fi

  # Kill any lingering helper process
  if pgrep -x wiredog-helper >/dev/null 2>&1; then
    sudo kill $(pgrep -x wiredog-helper) 2>/dev/null || true
    sleep 1
    if pgrep -x wiredog-helper >/dev/null 2>&1; then
      sudo kill -9 $(pgrep -x wiredog-helper) 2>/dev/null || true
    fi
    ok "Killed running wiredog-helper process(es)"
  else
    ok "No wiredog-helper process running"
  fi

  # Remove the old installed app bundle
  if [ -d "/Applications/WireDog VPN.app" ]; then
    if sudo rm -rf "/Applications/WireDog VPN.app" 2>/dev/null; then
      ok "Removed /Applications/WireDog VPN.app"
    else
      warn "Could not remove /Applications/WireDog VPN.app (sudo required) — remove manually before installing"
    fi
  else
    ok "No prior /Applications/WireDog VPN.app to remove"
  fi

  # Clear persisted kill switch state so next launch starts fresh
  sudo rm -f /var/run/wiredog-ks-state.json 2>/dev/null || true
  ok "Cleared /var/run/wiredog-ks-state.json (or not present)"

  # Flush any stale pf rules under our anchor
  sudo pfctl -a com.wiredog.vpn -F all >/dev/null 2>&1 || true
  ok "Flushed pf rules under anchor com.wiredog.vpn"
fi

# ============================================================================
# Final summary
# ============================================================================
cat <<EOF

${C_GREEN}${C_BOLD}======================================
✅ PRODUCTION BUILD COMPLETE
======================================${C_RESET}

${C_BOLD}BUILD CONFIGURATION:${C_RESET}
  Developer ID Account   : ${DEVELOPER_ID_APPLICATION}
  Team ID                : ${APPLE_TEAM_ID}
  Apple Development Cert : ${APPLE_DEVELOPMENT_CERT_ID}
  Notarization           : $([ "$NOTARIZE" = "1" ] && echo 'COMPLETED' || echo 'SKIPPED (--local)')

${C_BOLD}ARTIFACTS:${C_RESET}
  App bundle : ${APP_PATH}
  DMG        : ${DMG_FILE:-<none>}
  ZIP        : ${ZIP_FILE:-<none>}

${C_BOLD}QUICK START:${C_RESET}
$([ "$CLEANUP" = "1" ] && printf '  (cleanup already performed: app quit, helper killed, old bundle removed, KS state cleared, pf flushed)\n  1. Open the DMG:              open "%s"\n  2. Drag WireDog VPN to /Applications, then launch it.' "${DMG_FILE:-release/*.dmg}" || printf '  1. Quit any running copy:     osascript -e '"'"'quit app "WireDog VPN"'"'"'\n  2. Remove the old app:        sudo rm -rf "/Applications/WireDog VPN.app"\n  3. Clear stale KS state:      sudo rm -f /var/run/wiredog-ks-state.json\n  4. Flush stale pf rules:      sudo pfctl -a com.wiredog.vpn -F all 2>/dev/null || true\n  5. Open the DMG:              open "%s"\n  6. Drag WireDog VPN to /Applications, then launch it.\n  (Tip: pass --cleanup to have the script do steps 1-4 for you.)' "${DMG_FILE:-release/*.dmg}")

${C_BOLD}TEST 2 VERIFICATION:${C_RESET}
  # In one terminal — watch the NEW helper's logs:
  log stream --predicate 'process == "wiredog-helper"' --level info

  # In another — watch pf rules:
  watch -n 1 'sudo pfctl -s rules -a com.wiredog.vpn 2>&1'

  # In the app: enable Kill Switch (Always-On off) → Connect.
  # Expected helper log line:
  #   Kill switch state: bootstrap (server: X.X.X.X, advancedEnabled: false)
  # Expected pf: bootstrap ruleset under anchor com.wiredog.vpn.

${C_BOLD}NOTES:${C_RESET}
  - .env.build is regenerated per build (gitignored via .env.*)
  - Helper is universal (arm64 + x86_64)
  - Extension is signed with Apple Development cert (team cert, NOT Developer ID)
  - To build for distribution:  bash scripts/build-production.sh --notarize

${C_GREEN}${C_BOLD}======================================${C_RESET}
EOF
