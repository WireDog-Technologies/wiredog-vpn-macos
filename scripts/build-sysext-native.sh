#!/bin/bash
# Build the system extension activation N-API addon.
# Pure ObjC++ — no Swift library needed.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT/native-sysext"

echo "=== Building wiredog-sysext N-API addon ==="
npx node-gyp rebuild --arch=$(uname -m)

echo "=== wiredog_sysext.node built successfully ==="
ls -la build/Release/wiredog_sysext.node
