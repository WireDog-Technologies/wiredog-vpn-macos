# WireDog VPN - macOS Application

Copyright (c) 2026 WireDog Technologies

[![License: GPLv3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Swift 5.9+](https://img.shields.io/badge/Swift-5.9%2B-orange.svg)](https://swift.org)
[![macOS 12+](https://img.shields.io/badge/macOS-12%2B-green.svg)](https://www.apple.com/macos/)

## Features

- **WireGuard VPN Protocol** - Modern, efficient, and secure VPN implementation
- **Secure Authentication** - Email/password and anonymous account options
- **Kill Switch** - Prevents data leaks if VPN connection drops
- **Auto-Connect** - Automatically reconnect to VPN on network changes
- **Server Selection** - Choose from multiple VPN servers with favorites/recents
- **Subscription Management** - Built-in subscription validation and management
- **Network Extension** - Native macOS integration using NetworkExtension framework
- **On-Device Logging** - Privacy-respecting debug logs with PII redaction

## Requirements

- **macOS**: 12.0 or later
- **Xcode**: 14.0 or later
- **Swift**: 5.9 or later
- **Node.js**: 18+ and npm
- **Developer Account**: Apple Developer Program membership (required for VPN entitlements)

### VPN Entitlements

Building this project requires special VPN entitlements from Apple:

1. **Network Extension Capability** - For VPN tunnel implementation
2. **App Group Capability** - For keychain sharing between app and network extension
3. **VPN Configuration** - Request through Apple Developer Portal

To enable VPN capabilities:

1. Log in to [Apple Developer Portal](https://developer.apple.com)
2. Go to **Certificates, Identifiers & Profiles** → **Identifiers**
3. Select your app identifier and enable the required capabilities:
   - Network Extension
   - App Groups
4. Save and update your provisioning profiles
5. In Xcode, go to **Signing & Capabilities** and confirm all entitlements are present

## Setup

1. **Clone the repository**

2. **Install Node.js dependencies**
   ```bash
   npm install
   ```

3. **Configure environment**
   ```bash
   cp .env.local.example .env.local
   # Edit .env.local and fill in your values
   ```

4. **Set up Xcode**
   - Generate the Network Extension project:
     ```bash
     cd extension && xcodegen generate
     ```
   - Open `extension/WireDogTunnel.xcodeproj` in Xcode
   - Go to **Signing & Capabilities** → Select your team
   - Update bundle identifiers and Team ID for all targets (replace `YOUR_TEAM_ID`)
   - Clean build folder: Cmd+Shift+K

## Project Structure

```
wiredog-vpn-macos/
├── src/                      # React frontend
│   ├── pages/                # Page components
│   ├── components/           # Reusable UI components
│   ├── contexts/             # React contexts
│   └── types/                # TypeScript types
├── electron/                 # Electron main process
│   ├── main.js               # App entry point
│   ├── preload.js            # Preload script
│   └── ipc/                  # IPC handlers
├── native/                   # Swift N-API addon for tunnel control
├── extension/                # Xcode project for Network Extension
│   └── WireDogTunnel/        # NEPacketTunnelProvider implementation
├── helper/                   # Swift LaunchDaemon for pf kill switch
├── scripts/                  # Build and utility scripts
```

## Building

### Prerequisites

- Xcode with command line tools: `xcode-select --install`
- Node.js 18+ and npm
- Swift 5.9+ (bundled with Xcode)

### Full Production Build

Build, sign, and package the complete app:

```bash
bash scripts/build-production.sh --local --cleanup
```

This:
1. ✅ Cleans all build artifacts
2. ✅ Builds and signs Network Extension
3. ✅ Builds and signs helper daemon
4. ✅ Builds React frontend
5. ✅ Packages signed DMG
6. ✅ Verifies all signatures

**Output:** `release/WireDog VPN-*.dmg` (signed, ready to install)

### Local Testing

1. Double-click the DMG to mount it
2. Drag `WireDog VPN.app` to `/Applications/`
3. Launch the app and test the VPN connection

### Development

```bash
npm run dev        # Vite dev server + Electron (hot reload)
```

### Rebuilding the Network Extension

When making changes to the tunnel provider:

```bash
bash scripts/rebuild-extension.sh
```

Then relaunch the app:

```bash
killall "WireDog VPN" && open "/Applications/WireDog VPN.app"
```

## Production (Notarized Distribution)

For distribution outside your local machine:

```bash
export APPLE_ID="your-apple-id@example.com"
export APPLE_APP_SPECIFIC_PASSWORD="xxxx-xxxx-xxxx-xxxx"

bash scripts/build-production.sh --notarize --cleanup
```

This produces a notarized DMG ready for user distribution.

## Security Issues

**Do not open public GitHub issues for security vulnerabilities.**

If you believe you have found a security vulnerability, please email support@wiredogvpn.com with a description of the vulnerability, steps to reproduce, potential impact, and suggested fix if available.

## License

Licensed under the **GNU General Public License v3 (GPLv3)**. See [`LICENSE`](LICENSE) for details.

This project includes WireGuardKit (MIT License). See [`ACKNOWLEDGMENTS.md`](ACKNOWLEDGMENTS.md) for full attribution.

## Questions?

- Open a [GitHub Issue](https://github.com/wiredogtechnologies/wiredog-vpn-macos/issues)
- Read [`CONTRIBUTING.md`](CONTRIBUTING.md) for contribution guidelines
