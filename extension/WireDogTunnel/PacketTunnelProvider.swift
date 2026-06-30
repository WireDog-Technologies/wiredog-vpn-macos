import NetworkExtension
import WireGuardKit
import os.log
import Foundation

/// WireGuard packet tunnel provider for WireDog VPN.
///
/// This Network Extension runs as a system extension process, separate from the main Electron app.
/// It uses WireGuardKit (wireguard-go) to create and manage the WireGuard tunnel.
///
/// Communication with the main app:
/// - Receives config via startTunnel options or App Group shared container
/// - Responds to app messages (stats requests) via handleAppMessage
/// - Status changes are observed by the main app via NETunnelProviderManager KVO
class PacketTunnelProvider: NEPacketTunnelProvider {

    private let logger = Logger(subsystem: "com.wiredog.vpn.macos.tunnel", category: "PacketTunnelProvider")

    /// Shared App Group container for config fallback and logging
    private let appGroupId = "group.com.wiredog.vpn.macos"

    private func diagLog(_ message: String) {
        let line = "[\(Date())] \(message)\n"
        // 1. NSLog always goes to system log (visible via log stream)
        NSLog("[WireDog-Ext] %@", message)
        // 2. os_log fault (always stored, appears in Console.app)
        logger.fault("\(message, privacy: .public)")
        // 2. /tmp file — no entitlement needed
        let tmpURL = URL(fileURLWithPath: "/private/tmp/wiredog-ext.log")
        if let data = line.data(using: .utf8) {
            if let handle = try? FileHandle(forWritingTo: tmpURL) {
                handle.seekToEndOfFile(); handle.write(data); try? handle.close()
            } else { try? data.write(to: tmpURL) }
        }
        // 3. App Group UserDefaults — append to a running log string
        let ud = UserDefaults(suiteName: appGroupId)
        let existing = ud?.string(forKey: "extensionDiagLog") ?? ""
        ud?.set(existing + line, forKey: "extensionDiagLog")
        // 4. App Group container file
        if let containerURL = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroupId) {
            let fileURL = containerURL.appendingPathComponent("extension-diag.log")
            if let data = line.data(using: .utf8) {
                if let handle = try? FileHandle(forWritingTo: fileURL) {
                    handle.seekToEndOfFile(); handle.write(data); try? handle.close()
                } else { try? data.write(to: fileURL) }
            }
        }
    }

    override init() {
        super.init()
        diagLog("=== PacketTunnelProvider init() — process started ===")
    }

    /// WireGuardKit adapter wrapping wireguard-go
    private lazy var wireGuardAdapter: WireGuardAdapter = {
        return WireGuardAdapter(with: self) { [weak self] logLevel, message in
            self?.diagLog("[WG] \(message)")
        }
    }()

    // MARK: - Tunnel Lifecycle

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        diagLog("=== startTunnel() called ===")
        diagLog("Options provided: \(options != nil ? "yes" : "no")")
        if let opts = options { diagLog("Option keys: \(opts.keys.joined(separator: ", "))") }

        // 1. Read config from options (passed by native addon via startVPNTunnel)
        if let configData = options?["config"] as? Data {
            diagLog("Found config in options (\(configData.count) bytes), attempting to parse...")
            startWithConfigData(configData, completionHandler: completionHandler)
            return
        }

        // 2. Fallback: read from App Group shared container
        let sharedDefaults = UserDefaults(suiteName: appGroupId)
        if let configString = sharedDefaults?.string(forKey: "tunnelConfig"),
           let data = configString.data(using: .utf8) {
            diagLog("Found config in App Group container, attempting to parse...")
            startWithConfigData(data, completionHandler: completionHandler)
            return
        }

        // 3. No config found
        let error = NSError(
            domain: "com.wiredog.vpn.macos.tunnel",
            code: 1,
            userInfo: [NSLocalizedDescriptionKey: "No tunnel configuration provided"]
        )
        diagLog("ERROR: No tunnel configuration found in options or App Group container")
        completionHandler(error)
    }

    private func startWithConfigData(_ configData: Data, completionHandler: @escaping (Error?) -> Void) {
        diagLog("=== startWithConfigData() called ===")

        // Log raw JSON for diagnosis (keys visible, values present/absent only)
        if let json = try? JSONSerialization.jsonObject(with: configData) as? [String: Any] {
            diagLog("Config JSON keys: \(json.keys.sorted().joined(separator: ", "))")
            diagLog("address=\(json["address"] as? String ?? "MISSING")")
            diagLog("dns=\(json["dns"] as? String ?? "MISSING")")
            diagLog("endpoint=\(json["endpoint"] as? String ?? "MISSING")")
            diagLog("allowedIPs=\(json["allowedIPs"] as? String ?? "MISSING")")
            diagLog("persistentKeepalive=\(json["persistentKeepalive"] ?? "MISSING")")
            diagLog("privateKey present=\((json["privateKey"] as? String).map { !$0.isEmpty } ?? false)")
            diagLog("serverPublicKey present=\((json["serverPublicKey"] as? String).map { !$0.isEmpty } ?? false)")
        } else {
            diagLog("ERROR: Could not parse config as JSON dict")
        }

        guard let config = try? JSONDecoder().decode(TunnelConfig.self, from: configData) else {
            let error = NSError(
                domain: "com.wiredog.vpn.macos.tunnel",
                code: 2,
                userInfo: [NSLocalizedDescriptionKey: "Invalid tunnel configuration JSON"]
            )
            diagLog("ERROR: Failed to decode TunnelConfig struct")
            completionHandler(error)
            return
        }

        diagLog("TunnelConfig decoded — endpoint: \(config.endpoint)")

        guard let privateKey = PrivateKey(base64Key: config.privateKey) else {
            let error = NSError(
                domain: "com.wiredog.vpn.macos.tunnel",
                code: 3,
                userInfo: [NSLocalizedDescriptionKey: "Invalid private key in configuration"]
            )
            diagLog("ERROR: Invalid private key (length=\(config.privateKey.count))")
            completionHandler(error)
            return
        }
        diagLog("Private key parsed OK")

        var interfaceConfig = InterfaceConfiguration(privateKey: privateKey)
        let addressParts = config.address.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        diagLog("Parsing addresses: \(addressParts)")
        interfaceConfig.addresses = addressParts.compactMap { IPAddressRange(from: $0) }
        diagLog("Interface addresses parsed: \(interfaceConfig.addresses.count) — \(interfaceConfig.addresses.map { $0.stringRepresentation })")

        let dnsParts = config.dns.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        interfaceConfig.dns = dnsParts.compactMap { DNSServer(from: $0) }
        diagLog("DNS servers parsed: \(interfaceConfig.dns.count)")

        // AWG obfuscation params — base-10 decimal strings per Go layer contract.
        // Magic headers (H1-H4) come from the backend as signed Int32 values stored in Int.
        // Go's ParseUint requires unsigned decimal — reinterpret via UInt32(bitPattern:).
        if let jc = config.awgJc { interfaceConfig.junkPacketCount = UInt16(jc) }
        if let jmin = config.awgJmin { interfaceConfig.junkPacketMinSize = UInt16(jmin) }
        if let jmax = config.awgJmax { interfaceConfig.junkPacketMaxSize = UInt16(jmax) }
        if let s1 = config.awgS1 { interfaceConfig.initPacketJunkSize = UInt16(s1) }
        if let s2 = config.awgS2 { interfaceConfig.responsePacketJunkSize = UInt16(s2) }
        if let h1 = config.awgH1 { interfaceConfig.initPacketMagicHeader = String(UInt32(bitPattern: Int32(truncatingIfNeeded: h1))) }
        if let h2 = config.awgH2 { interfaceConfig.responsePacketMagicHeader = String(UInt32(bitPattern: Int32(truncatingIfNeeded: h2))) }
        if let h3 = config.awgH3 { interfaceConfig.underloadPacketMagicHeader = String(UInt32(bitPattern: Int32(truncatingIfNeeded: h3))) }
        if let h4 = config.awgH4 { interfaceConfig.transportPacketMagicHeader = String(UInt32(bitPattern: Int32(truncatingIfNeeded: h4))) }
        diagLog("AWG params applied: Jc=\(config.awgJc.map(String.init) ?? "nil") H1=\(interfaceConfig.initPacketMagicHeader ?? "nil") H2=\(interfaceConfig.responsePacketMagicHeader ?? "nil") H3=\(interfaceConfig.underloadPacketMagicHeader ?? "nil") H4=\(interfaceConfig.transportPacketMagicHeader ?? "nil")")

        guard let serverPublicKey = PublicKey(base64Key: config.serverPublicKey) else {
            let error = NSError(
                domain: "com.wiredog.vpn.macos.tunnel",
                code: 4,
                userInfo: [NSLocalizedDescriptionKey: "Invalid server public key in configuration"]
            )
            diagLog("ERROR: Invalid server public key (length=\(config.serverPublicKey.count))")
            completionHandler(error)
            return
        }
        diagLog("Server public key parsed OK")

        var peerConfig = PeerConfiguration(publicKey: serverPublicKey)
        peerConfig.endpoint = Endpoint(from: config.endpoint)
        diagLog("Peer endpoint set: \(config.endpoint)")

        let allowedIPParts = config.allowedIPs.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        diagLog("Parsing allowedIPs: \(allowedIPParts)")
        peerConfig.allowedIPs = allowedIPParts.compactMap { IPAddressRange(from: $0) }
        diagLog("AllowedIPs parsed: \(peerConfig.allowedIPs.count) — \(peerConfig.allowedIPs.map { $0.stringRepresentation })")

        if config.persistentKeepalive > 0 {
            peerConfig.persistentKeepAlive = UInt16(config.persistentKeepalive)
        }

        let tunnelConfiguration = TunnelConfiguration(name: "WireDog", interface: interfaceConfig, peers: [peerConfig])
        diagLog("TunnelConfiguration built: \(interfaceConfig.addresses.count) addr(s), \(peerConfig.allowedIPs.count) allowedIP(s)")

        diagLog("Calling wireGuardAdapter.start()...")
        wireGuardAdapter.start(tunnelConfiguration: tunnelConfiguration) { [weak self] adapterError in
            guard let self = self else { return }

            if let adapterError = adapterError {
                self.diagLog("ERROR: WireGuard adapter start failed: \(adapterError.localizedDescription) (domain=\((adapterError as NSError).domain) code=\((adapterError as NSError).code))")
                completionHandler(adapterError)
                return
            }

            let sharedDefaults = UserDefaults(suiteName: self.appGroupId)
            sharedDefaults?.set(String(data: configData, encoding: .utf8), forKey: "tunnelConfig")

            self.diagLog("Tunnel started successfully")
            completionHandler(nil)
        }
    }

    /// Intercept setTunnelNetworkSettings so we can log what IPv4/IPv6 addresses
    /// WireGuardKit is actually configuring — logged at error level so it survives
    /// to disk and appears in `log show` without real-time stream timing issues.
    override func setTunnelNetworkSettings(_ tunnelNetworkSettings: NETunnelNetworkSettings?, completionHandler: (@Sendable ((any Error)?) -> Void)?) {
        if let settings = tunnelNetworkSettings as? NEPacketTunnelNetworkSettings {
            let v4addrs = settings.ipv4Settings?.addresses ?? []
            let v4masks = settings.ipv4Settings?.subnetMasks ?? []
            let v6addrs = settings.ipv6Settings?.addresses ?? []
            let dns    = settings.dnsSettings?.servers ?? []
            diagLog("setTunnelNetworkSettings — IPv4: \(v4addrs) masks: \(v4masks) | IPv6: \(v6addrs) | DNS: \(dns)")
            let v4routes = settings.ipv4Settings?.includedRoutes?.map { "\($0.destinationAddress)/\($0.destinationSubnetMask)" } ?? []
            diagLog("setTunnelNetworkSettings — IPv4 includedRoutes: \(v4routes)")
            let v6routes = settings.ipv6Settings?.includedRoutes?.map { "\($0.destinationAddress)/\($0.destinationNetworkPrefixLength)" } ?? []
            diagLog("setTunnelNetworkSettings — IPv6 includedRoutes: \(v6routes)")
        } else if tunnelNetworkSettings == nil {
            diagLog("setTunnelNetworkSettings — called with nil (clearing settings)")
        }
        super.setTunnelNetworkSettings(tunnelNetworkSettings, completionHandler: completionHandler)
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        diagLog("Stopping tunnel (reason: \(reason.rawValue))")

        wireGuardAdapter.stop { [weak self] error in
            if let error = error {
                self?.diagLog("WireGuard adapter stop error: \(error.localizedDescription)")
            } else {
                self?.diagLog("Tunnel stopped successfully")
            }
            completionHandler()
        }
    }

    // MARK: - App Messages

    /// Handle messages from the main app (e.g., stats requests, config updates)
    override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)?
    ) {
        guard let message = String(data: messageData, encoding: .utf8) else {
            completionHandler?(nil)
            return
        }

        diagLog("Received app message: \(message)")

        switch message {
        case "stats":
            handleStatsRequest(completionHandler: completionHandler)

        case "update-config":
            // Future: allow config updates without full tunnel restart
            completionHandler?(nil)

        default:
            completionHandler?(nil)
        }
    }

    /// Parse traffic statistics from WireGuardKit runtime configuration.
    /// WireGuardKit's getRuntimeConfiguration() returns a UAPI-format string containing
    /// rx_bytes and tx_bytes for each peer.
    private func handleStatsRequest(completionHandler: ((Data?) -> Void)?) {
        diagLog("[Stats] Received stats request from main app")
        wireGuardAdapter.getRuntimeConfiguration { [weak self] runtimeConfig in
            guard let self = self else {
                completionHandler?(nil)
                return
            }

            guard let configString = runtimeConfig else {
                self.diagLog("[Stats] getRuntimeConfiguration() returned nil")
                let stats = TrafficStats(bytesIn: 0, bytesOut: 0)
                let encoded = try? JSONEncoder().encode(stats)
                completionHandler?(encoded)
                return
            }

            self.diagLog("[Stats] getRuntimeConfiguration() returned \(configString.count) bytes")

            // Parse rx_bytes and tx_bytes from the UAPI config string
            // Format: key=value lines, one per line
            var totalRxBytes: UInt64 = 0
            var totalTxBytes: UInt64 = 0
            var foundRx = false
            var foundTx = false

            for line in configString.split(separator: "\n") {
                let parts = line.split(separator: "=", maxSplits: 1)
                guard parts.count == 2 else { continue }

                let key = parts[0].trimmingCharacters(in: .whitespaces)
                let value = parts[1].trimmingCharacters(in: .whitespaces)

                if key == "rx_bytes", let bytes = UInt64(value) {
                    totalRxBytes += bytes
                    foundRx = true
                } else if key == "tx_bytes", let bytes = UInt64(value) {
                    totalTxBytes += bytes
                    foundTx = true
                }
            }

            self.diagLog("[Stats] Parsing complete: rx=\(totalRxBytes) tx=\(totalTxBytes)")
            let stats = TrafficStats(bytesIn: totalRxBytes, bytesOut: totalTxBytes)
            let encoded = try? JSONEncoder().encode(stats)
            completionHandler?(encoded)
        }
    }

    // MARK: - Wake/Sleep

    override func wake() {
        diagLog("System woke from sleep — reasserting tunnel")
        // WireGuardKit handles reconnection automatically via wireguard-go
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        diagLog("System going to sleep")
        completionHandler()
    }
}

// MARK: - Data Models

struct TunnelConfig: Codable {
    let privateKey: String
    let address: String
    let dns: String
    let serverPublicKey: String
    let endpoint: String
    let allowedIPs: String
    let persistentKeepalive: Int
    // AWG obfuscation params (always present per backend contract)
    let awgJc: Int?
    let awgJmin: Int?
    let awgJmax: Int?
    let awgS1: Int?
    let awgS2: Int?
    let awgH1: Int?
    let awgH2: Int?
    let awgH3: Int?
    let awgH4: Int?
}

struct TrafficStats: Codable {
    let bytesIn: UInt64
    let bytesOut: UInt64
}
