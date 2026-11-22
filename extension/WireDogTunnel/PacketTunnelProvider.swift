import NetworkExtension
import Network
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

    // MARK: - Diagnostics (read by the app's Verbose Diagnostic Mode through the health snapshot)

    private let processStartedAt = Date()
    private let diagLock = NSLock()
    private var startTunnelAt: Date?
    private var lastStartMs: Int?
    private var lastStopMs: Int?
    private var diagWrites = 0
    private var diagWriteTotalMs = 0.0
    private var diagWriteMaxMs = 0.0
    private var diagFileBytes = 0

    /// " [+N ms since startTunnel]" while a start is in progress, so the system log shows where it spends its time.
    private func sinceStartMarker() -> String {
        diagLock.lock()
        let begun = startTunnelAt
        diagLock.unlock()
        guard let begun = begun else { return "" }
        return " [+\(Int(Date().timeIntervalSince(begun) * 1000))ms since startTunnel]"
    }

    /// Records the cost of one diagLog file write (both capped files). Up to extension 1.0.13 every line also
    /// rewrote one ever-growing UserDefaults string, which could make each line slow on a Mac that had run the
    /// extension for months; this shows what a line costs now. Reported straight to the system log (going
    /// through diagLog would measure itself).
    private func recordDiagWrite(ms: Double, bytes: Int) {
        diagLock.lock()
        diagWrites += 1
        diagWriteTotalMs += ms
        if ms > diagWriteMaxMs { diagWriteMaxMs = ms }
        diagFileBytes = bytes
        let writes = diagWrites
        let avg = diagWriteTotalMs / Double(diagWrites)
        let maxMs = diagWriteMaxMs
        diagLock.unlock()
        if writes == 1 || writes % 50 == 0 || ms > 100 {
            NSLog("[WireDog-Ext] [Diag] log file %ld bytes; this write %.1f ms (avg %.1f ms, max %.1f ms over %ld writes)", bytes, ms, avg, maxMs, writes)
        }
    }

    /// Sizes of every place diagLog writes to (and of the legacy UserDefaults store, before it is removed),
    /// logged at process start and at each startTunnel.
    private func logDiagStoreSizes(_ context: String) {
        let udBytes = UserDefaults(suiteName: appGroupId)?.string(forKey: "extensionDiagLog")?.utf8.count ?? 0
        let tmpBytes = (try? FileManager.default.attributesOfItem(atPath: "/private/tmp/wiredog-ext.log")[.size] as? Int) ?? nil
        var groupBytes: Int?
        if let containerURL = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroupId) {
            let path = containerURL.appendingPathComponent("extension-diag.log").path
            groupBytes = (try? FileManager.default.attributesOfItem(atPath: path)[.size] as? Int) ?? nil
        }
        let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "?"
        let build = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "?"
        NSLog("[WireDog-Ext] [Diag] %@: extension %@ (%@), pid %d, up %.0f s; legacy UserDefaults store %ld bytes, /tmp log %ld bytes, group file %ld bytes",
              context, version, build, ProcessInfo.processInfo.processIdentifier,
              Date().timeIntervalSince(processStartedAt), udBytes, tmpBytes ?? -1, groupBytes ?? -1)
    }

    private func diagLog(_ message: String) {
        let since = sinceStartMarker()
        let line = "[\(Date())] \(message)\(since)\n"
        // 1. NSLog always goes to system log (visible via log stream)
        NSLog("[WireDog-Ext] %@%@", message, since)
        // 2. os_log fault (always stored, appears in Console.app)
        logger.fault("\(message, privacy: .public)\(since, privacy: .public)")
        // 3. Two capped files (timed: see recordDiagWrite). The old third copy, one App Group UserDefaults
        // string that grew forever and was rewritten whole on every line, is gone (see removeLegacyDiagStore).
        guard let data = line.data(using: .utf8) else { return }
        let writeStarted = Date()
        fileLock.lock()
        let newestSize = appendCapped(data, to: URL(fileURLWithPath: "/private/tmp/wiredog-ext.log"))
        if let containerURL = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroupId) {
            appendCapped(data, to: containerURL.appendingPathComponent("extension-diag.log"))
        }
        fileLock.unlock()
        recordDiagWrite(ms: Date().timeIntervalSince(writeStarted) * 1000, bytes: Int(newestSize))
    }

    /// Each diagnostic log file stays under this size: past it the file becomes "<name>.1" (replacing the
    /// previous .1) and a new file starts. The newest lines are always kept and each log uses at most
    /// twice this on disk.
    private static let diagFileCap: UInt64 = 5 * 1024 * 1024
    private let fileLock = NSLock()

    /// Appends one line and rotates the file once it passes the cap. Returns the file's size after the write.
    @discardableResult
    private func appendCapped(_ data: Data, to url: URL) -> UInt64 {
        guard let handle = try? FileHandle(forWritingTo: url) else {
            try? data.write(to: url)
            return UInt64(data.count)
        }
        let size = handle.seekToEndOfFile() + UInt64(data.count)
        handle.write(data)
        try? handle.close()
        if size > Self.diagFileCap {
            let previous = url.appendingPathExtension("1")
            try? FileManager.default.removeItem(at: previous)
            try? FileManager.default.moveItem(at: url, to: previous)
        }
        return size
    }

    /// Removes the old UserDefaults log copy once. Nothing ever read it (the app cannot reach this root
    /// process's App Group container), and its size is logged first (logDiagStoreSizes) as evidence of
    /// what it cost.
    private func removeLegacyDiagStore() {
        let ud = UserDefaults(suiteName: appGroupId)
        guard ud?.object(forKey: "extensionDiagLog") != nil else { return }
        ud?.removeObject(forKey: "extensionDiagLog")
        NSLog("[WireDog-Ext] [Diag] removed the legacy extensionDiagLog UserDefaults store")
    }

    override init() {
        super.init()
        logDiagStoreSizes("process start")
        removeLegacyDiagStore()
        diagLog("=== PacketTunnelProvider init() — process started ===")
    }

    /// WireGuardKit adapter wrapping wireguard-go
    private lazy var wireGuardAdapter: WireGuardAdapter = {
        return WireGuardAdapter(with: self) { [weak self] logLevel, message in
            self?.diagLog("[WG] \(message)")
        }
    }()

    // MARK: - Tunnel health (served on loopback)
    //
    // The app cannot ask the extension for its state (sendProviderMessage is unreliable from the Electron
    // process; stats are read from the utun counters instead), and the counters say nothing about whether
    // the server ever answered. This extension is sandboxed and runs as root, so it cannot write a file the
    // user's app can read (its /tmp and App Group container are not visible to the user session). It does
    // have the network-server entitlement, so while the tunnel is up it serves a small JSON snapshot on
    // 127.0.0.1 only, and the app reads it:
    //   { "updatedAt": <epoch s>, "lastHandshake": <epoch s, 0 = never>, "rxBytes": n, "txBytes": n }
    // The data is not secret (timestamps and byte counters). The app treats an unreachable or stale
    // snapshot as "unknown", never as a failure, so this can only cost it the check, not break connecting.

    static let healthPort: UInt16 = 51873
    private let healthQueue = DispatchQueue(label: "com.wiredog.vpn.macos.tunnel.health")
    private var healthTimer: DispatchSourceTimer?
    private var healthListener: NWListener?
    private var healthBody = Data("{}".utf8)
    private var healthWrittenOnce = false

    private func startHealthServer() {
        stopHealthServer()
        guard let port = NWEndpoint.Port(rawValue: PacketTunnelProvider.healthPort) else { return }
        let params = NWParameters.tcp
        params.allowLocalEndpointReuse = true
        // Loopback only: 127.0.0.1, never a routable address.
        params.requiredLocalEndpoint = NWEndpoint.hostPort(host: .ipv4(.loopback), port: port)
        guard let listener = try? NWListener(using: params) else {
            diagLog("[Health] could not create the loopback listener on \(PacketTunnelProvider.healthPort)")
            return
        }
        listener.newConnectionHandler = { [weak self] connection in
            guard let self = self else { connection.cancel(); return }
            connection.start(queue: self.healthQueue)
            // Read the request first: closing with it unread can reset the connection before the client reads.
            connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { [weak self] _, _, _, _ in
                guard let self = self else { connection.cancel(); return }
                let head = "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: \(self.healthBody.count)\r\nConnection: close\r\n\r\n"
                var response = Data(head.utf8)
                response.append(self.healthBody)
                connection.send(content: response, completion: .contentProcessed { _ in connection.cancel() })
            }
        }
        listener.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready: self?.diagLog("[Health] serving the tunnel snapshot on 127.0.0.1:\(PacketTunnelProvider.healthPort)")
            case .failed(let error): self?.diagLog("[Health] listener failed: \(error)")
            default: break
            }
        }
        listener.start(queue: healthQueue)
        healthListener = listener

        let timer = DispatchSource.makeTimerSource(queue: healthQueue)
        timer.schedule(deadline: .now() + 1, repeating: 3)
        timer.setEventHandler { [weak self] in self?.refreshHealthSnapshot() }
        timer.resume()
        healthTimer = timer
    }

    private func stopHealthServer() {
        healthTimer?.cancel()
        healthTimer = nil
        healthListener?.cancel()
        healthListener = nil
        healthBody = Data("{}".utf8)
        healthWrittenOnce = false
    }

    private func refreshHealthSnapshot() {
        wireGuardAdapter.getRuntimeConfiguration { [weak self] runtimeConfig in
            guard let self = self, let configString = runtimeConfig else { return }
            var lastSec: Int64 = 0
            var rx: UInt64 = 0
            var tx: UInt64 = 0
            for line in configString.split(separator: "\n") {
                let parts = line.split(separator: "=", maxSplits: 1)
                guard parts.count == 2 else { continue }
                let key = parts[0].trimmingCharacters(in: .whitespaces)
                let value = parts[1].trimmingCharacters(in: .whitespaces)
                switch key {
                case "last_handshake_time_sec": lastSec = max(lastSec, Int64(value) ?? 0)
                case "rx_bytes": rx += UInt64(value) ?? 0
                case "tx_bytes": tx += UInt64(value) ?? 0
                default: break
                }
            }
            var snapshot: [String: Any] = [
                "updatedAt": Int64(Date().timeIntervalSince1970),
                "lastHandshake": lastSec,
                "rxBytes": rx,
                "txBytes": tx,
            ]
            // Diagnostics for Verbose Diagnostic Mode: which extension build is running, for how long, how
            // long the last start and stop took, and what a diagnostic log line costs.
            self.diagLock.lock()
            snapshot["extVersion"] = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "?"
            snapshot["extBuild"] = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "?"
            snapshot["extUptimeSec"] = Int(Date().timeIntervalSince(self.processStartedAt))
            if let start = self.lastStartMs { snapshot["lastStartMs"] = start }
            if let stop = self.lastStopMs { snapshot["lastStopMs"] = stop }
            snapshot["diagFileBytes"] = self.diagFileBytes
            snapshot["diagWrites"] = self.diagWrites
            snapshot["diagWriteAvgMs"] = self.diagWrites > 0 ? (self.diagWriteTotalMs / Double(self.diagWrites) * 10).rounded() / 10 : 0
            snapshot["diagWriteMaxMs"] = (self.diagWriteMaxMs * 10).rounded() / 10
            self.diagLock.unlock()
            guard let data = try? JSONSerialization.data(withJSONObject: snapshot) else { return }
            self.healthQueue.async {
                self.healthBody = data
                if !self.healthWrittenOnce {
                    self.healthWrittenOnce = true
                    self.diagLog("[Health] first snapshot ready, lastHandshake=\(lastSec)")
                }
            }
        }
    }

    // MARK: - Tunnel Lifecycle

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler originalCompletion: @escaping (Error?) -> Void
    ) {
        // Every line from here to the completion carries "+N ms since startTunnel", and the total is kept
        // for the health snapshot, so a slow start can be read step by step.
        let begun = Date()
        diagLock.lock()
        startTunnelAt = begun
        diagLock.unlock()
        logDiagStoreSizes("startTunnel")
        let completionHandler: (Error?) -> Void = { [weak self] error in
            let ms = Int(Date().timeIntervalSince(begun) * 1000)
            self?.diagLog("startTunnel finished in \(ms) ms (\(error.map { "error: \($0.localizedDescription)" } ?? "ok"))")
            if let self = self {
                self.diagLock.lock()
                self.lastStartMs = ms
                self.startTunnelAt = nil
                self.diagLock.unlock()
            }
            originalCompletion(error)
        }
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
            self.startHealthServer()
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
        let begun = Date()
        stopHealthServer()

        wireGuardAdapter.stop { [weak self] error in
            let ms = Int(Date().timeIntervalSince(begun) * 1000)
            if let error = error {
                self?.diagLog("WireGuard adapter stop error after \(ms) ms: \(error.localizedDescription)")
            } else {
                self?.diagLog("Tunnel stopped successfully in \(ms) ms")
            }
            if let self = self {
                self.diagLock.lock()
                self.lastStopMs = ms
                self.diagLock.unlock()
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
