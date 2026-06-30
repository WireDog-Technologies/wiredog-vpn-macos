#!/bin/bash
# Development environment setup for WireDog VPN macOS
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=== WireDog VPN macOS Dev Setup ==="

# Check prerequisites
echo "Checking prerequisites..."

if ! command -v node &> /dev/null; then
  echo "ERROR: Node.js is not installed. Install via: brew install node"
  exit 1
fi
echo "  Node.js: $(node --version)"

if ! command -v npm &> /dev/null; then
  echo "ERROR: npm is not installed."
  exit 1
fi
echo "  npm: $(npm --version)"

if ! command -v swift &> /dev/null; then
  echo "WARNING: Swift is not installed. Native addon and helper daemon won't build."
  echo "  Install Xcode from the App Store."
else
  echo "  Swift: $(swift --version 2>&1 | head -1)"
fi

if ! command -v xcodebuild &> /dev/null; then
  echo "WARNING: Xcode command line tools not installed."
  echo "  Run: xcode-select --install"
else
  echo "  Xcode: $(xcodebuild -version 2>&1 | head -1)"
fi

# Install npm dependencies
echo ""
echo "Installing npm dependencies..."
cd "$PROJECT_ROOT"
npm install

echo ""
echo "=== Setup complete ==="
echo ""
echo "To start development:"
echo "  npm run dev          # Full dev (Vite + Electron)"
echo "  npm run dev:vite     # Frontend only"
echo ""
echo "To build native components (requires macOS):"
echo "  scripts/build-native.sh     # Swift N-API addon"
echo "  scripts/build-extension.sh  # Network Extension"
echo "  scripts/build-helper.sh     # Helper daemon"
