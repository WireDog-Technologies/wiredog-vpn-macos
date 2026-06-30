import Foundation
import NetworkExtension
import SystemExtensions

/// Manages the NETunnelProviderManager for WireGuard tunnel control.
/// Runs inside the helper daemon so the NE entitlement lives outside the Electron process,
/// avoiding the AMFI conflict between JIT and packet-tunnel-provider-systemextension.
class TunnelManager {
    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?

    /// Callback invoked when tunnel status changes; wired to SocketServer.broadcast in main.swift
    var onStatusChange: ((String) -> Void)?

    /// First IPv4 address from the active tunnel's `address` config, stripped of CIDR suffix.
    /// Used to locate the utun interface for stats readout, since
    /// NETunnelProviderSession.sendProviderMessage is silently blocked when called from
    /// a separately-signed helper process rather than the extension's containing app.
    private var tunnelLocalAddress: String?

    private let log = HelperLogger.shared

    /// Load or create the VPN configuration profile
    func loadManager() async throws {
        log.info("[TunnelManager] === loadManager() START ===")

        // Debug: check our own NE entitlement via SecTask
        if let task = SecTaskCreateFromSelf(nil) {
            var error: Unmanaged<CFError>?
            let neValue = SecTaskCopyValueForEntitlement(task, "com.apple.developer.networking.networkextension" as CFString, &error)
            log.info("[TunnelManager] Helper NE entitlement: \(neValue ?? "nil" as AnyObject)")
            if let err = error?.takeRetainedValue() {
                log.error("[TunnelManager] Entitlement query error: \(err)")
            }
        }

        log.info("[TunnelManager] Calling NETunnelProviderManager.loadAllFromPreferences()...")
        let managers = try await loadAllPreferencesWithTimeout()
        log.info("[TunnelManager] Loaded \(managers.count) existing manager(s)")

        if let existing = managers.first {
            log.info("[TunnelManager] Using existing manager: \(existing.localizedDescription ?? "(nil)")")
            if let proto = existing.protocolConfiguration as? NETunnelProviderProtocol {
                log.info("[TunnelManager] Existing providerBundleIdentifier: \(proto.providerBundleIdentifier ?? "(nil)")")
            }
            self.manager = existing
        } else {
            log.info("[TunnelManager] No existing manager — creating new one")
            let newManager = NETunnelProviderManager()
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = "com.wiredog.vpn.macos.tunnel"
            proto.serverAddress = "WireDog VPN"
            newManager.protocolConfiguration = proto
            newManager.localizedDescription = "WireDog VPN"
            newManager.isEnabled = true
            log.info("[TunnelManager] Calling saveToPreferences() with providerBundleIdentifier: \(proto.providerBundleIdentifier ?? "(nil)")")
            do {
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                    DispatchQueue.main.async {
                        newManager.saveToPreferences { error in
                            if let error = error { continuation.resume(throwing: error) }
                            else { continuation.resume() }
                        }
                    }
                }
                log.info("[TunnelManager] saveToPreferences() SUCCESS")
            } catch {
                log.error("[TunnelManager] saveToPreferences() FAILED: \(error.localizedDescription)")
                log.error("[TunnelManager] Error domain: \((error as NSError).domain), code: \((error as NSError).code)")
                log.error("[TunnelManager] Error userInfo: \((error as NSError).userInfo)")
                throw error
            }
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                DispatchQueue.main.async {
                    newManager.loadFromPreferences { error in
                        if let error = error { continuation.resume(throwing: error) }
                        else { continuation.resume() }
                    }
                }
            }
            self.manager = newManager
            log.info("[TunnelManager] New manager created and loaded")
        }

        // Observe status changes on the main queue (required by NEVPNStatusDidChange).
        // Remove any existing observer first — loadManager() may be called more than once
        // (startup Task + RPC loadTunnelManager), and duplicate observers would fire
        // multiple tunnelStatusChanged notifications per NE event.
        if let old = statusObserver {
            NotificationCenter.default.removeObserver(old)
            statusObserver = nil
        }
        guard let connection = manager?.connection else { return }
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: connection,
            queue: .main
        ) { [weak self] notification in
            guard let conn = notification.object as? NEVPNConnection else { return }
            self?.onStatusChange?(Self.statusString(from: conn.status))
        }
    }

    /// Start the VPN tunnel with the given WireGuard configuration
    func startTunnel(config: [String: Any]) throws {
        guard let manager = manager else {
            throw TunnelError.managerNotLoaded
        }

        // Cache the tunnel's local IPv4 for later utun lookup in getStats().
        if let addressString = config["address"] as? String {
            let firstIPv4 = addressString
                .split(separator: ",")
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .first { !$0.contains(":") && !$0.isEmpty }
            if let first = firstIPv4 {
                let ip = String(first.split(separator: "/").first ?? "").trimmingCharacters(in: .whitespaces)
                self.tunnelLocalAddress = ip.isEmpty ? nil : ip
                log.info("[TunnelManager] Cached tunnel local address for stats: \(self.tunnelLocalAddress ?? "nil")")
            }
        }

        manager.isEnabled = true

        if let proto = manager.protocolConfiguration as? NETunnelProviderProtocol {
            proto.includeAllNetworks = config["includeAllNetworks"] as? Bool ?? false
            proto.excludeLocalNetworks = config["excludeLocalNetworks"] as? Bool ?? true
            if let endpoint = config["endpoint"] as? String {
                proto.serverAddress = String(endpoint.split(separator: ":").first ?? "WireDog VPN")
            }
            manager.protocolConfiguration = proto
        }

        Task { @MainActor in
            do {
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                    manager.saveToPreferences { error in
                        if let error = error { continuation.resume(throwing: error) }
                        else { continuation.resume() }
                    }
                }
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                    manager.loadFromPreferences { error in
                        if let error = error { continuation.resume(throwing: error) }
                        else { continuation.resume() }
                    }
                }
            } catch {
                self.log.error("[TunnelManager] saveToPreferences failed (non-fatal): \(error.localizedDescription)")
            }

            do {
                self.log.info("[TunnelManager] About to start VPN tunnel...")
                let session = manager.connection as? NETunnelProviderSession
                let configData = try JSONSerialization.data(withJSONObject: config)
                self.log.info("[TunnelManager] Calling startVPNTunnel with config...")
                try session?.startVPNTunnel(options: [
                    "config": configData as NSData
                ] as [String: NSObject])
                self.log.info("[TunnelManager] startVPNTunnel call succeeded")
            } catch {
                self.log.error("[TunnelManager] startVPNTunnel error: \(error.localizedDescription)")
                self.log.error("[TunnelManager] Error domain: \((error as NSError).domain), code: \((error as NSError).code)")
                self.onStatusChange?("disconnected")
            }
        }
    }

    /// Stop the VPN tunnel
    func stopTunnel() {
        manager?.connection.stopVPNTunnel()
    }

    /// Remove all VPN configurations for this app from the system preferences store.
    /// Called by the build script's --cleanup phase to prevent stale configs from causing
    /// loadAllFromPreferences() to hang after a rebuild with different signing.
    func removeAllConfigs() async throws {
        log.info("[TunnelManager] removeAllConfigs() — loading all managers to delete...")
        let managers = try await loadAllPreferencesWithTimeout()
        log.info("[TunnelManager] removeAllConfigs() — found \(managers.count) manager(s) to remove")
        for mgr in managers {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                DispatchQueue.main.async {
                    mgr.removeFromPreferences { error in
                        if let error = error {
                            continuation.resume(throwing: error)
                        } else {
                            continuation.resume()
                        }
                    }
                }
            }
            log.info("[TunnelManager] Removed manager: \(mgr.localizedDescription ?? "(nil)")")
        }
        self.manager = nil
        log.info("[TunnelManager] removeAllConfigs() complete")
    }

    /// Current tunnel status as a string
    var status: String {
        guard let connection = manager?.connection else {
            return "disconnected"
        }
        return Self.statusString(from: connection.status)
    }

    /// Read traffic statistics for the active tunnel.
    ///
    /// We read directly from the utun interface's kernel byte counters instead of
    /// asking the extension via sendProviderMessage, because Apple's NetworkExtension
    /// framework silently drops provider messages originating from a separately-signed
    /// helper daemon (the call succeeds, responseHandler fires with nil).
    ///
    /// Semantics: for a tun device, kernel-side ifi_ibytes is traffic read from the
    /// tunnel into the host (VPN → apps = download) and ifi_obytes is traffic written
    /// from the host into the tunnel (apps → VPN = upload).
    func getStats() async throws -> (bytesIn: UInt64, bytesOut: UInt64) {
        guard let tunnelAddr = tunnelLocalAddress else {
            throw TunnelError.statsUnavailable("tunnel local address not set")
        }
        guard let iface = Self.findUtunInterface(matchingAddress: tunnelAddr) else {
            throw TunnelError.statsUnavailable("no utun interface found for \(tunnelAddr)")
        }
        guard let counters = Self.readInterfaceCounters(interfaceName: iface) else {
            throw TunnelError.statsUnavailable("failed to read counters for \(iface)")
        }
        return counters
    }

    /// Scan getifaddrs() for a utunN interface whose IPv4 address equals `address`.
    private static func findUtunInterface(matchingAddress address: String) -> String? {
        var ifap: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifap) == 0, let first = ifap else { return nil }
        defer { freeifaddrs(ifap) }

        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let ptr = cursor {
            defer { cursor = ptr.pointee.ifa_next }
            let name = String(cString: ptr.pointee.ifa_name)
            guard name.hasPrefix("utun"), let sa = ptr.pointee.ifa_addr else { continue }
            guard sa.pointee.sa_family == UInt8(AF_INET) else { continue }

            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let len = socklen_t(sa.pointee.sa_len)
            guard getnameinfo(sa, len, &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 else { continue }
            if String(cString: host) == address {
                return name
            }
        }
        return nil
    }

    /// Read ifi_ibytes / ifi_obytes for a named interface via its AF_LINK entry.
    private static func readInterfaceCounters(interfaceName: String) -> (bytesIn: UInt64, bytesOut: UInt64)? {
        var ifap: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifap) == 0, let first = ifap else { return nil }
        defer { freeifaddrs(ifap) }

        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let ptr = cursor {
            defer { cursor = ptr.pointee.ifa_next }
            let name = String(cString: ptr.pointee.ifa_name)
            guard name == interfaceName, let sa = ptr.pointee.ifa_addr else { continue }
            guard sa.pointee.sa_family == UInt8(AF_LINK), let dataPtr = ptr.pointee.ifa_data else { continue }

            let ifData = dataPtr.assumingMemoryBound(to: if_data.self).pointee
            return (UInt64(ifData.ifi_ibytes), UInt64(ifData.ifi_obytes))
        }
        return nil
    }

    /// Activate the WireDogTunnel system extension via OSSystemExtensionManager.
    /// This must be called once before startTunnel will actually route traffic.
    /// macOS prompts the user for approval in System Settings on first run.
    func activateExtension(completion: @escaping (Result<String, Error>) -> Void) {
        let extensionID = "com.wiredog.vpn.macos.tunnel"
        log.info("[TunnelManager] Submitting system extension activation request for \(extensionID)")

        let delegate = SystemExtensionDelegate(log: log, completion: completion)
        // Hold delegate alive for the duration of the async request
        self.sextDelegate = delegate

        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: extensionID,
            queue: .main
        )
        request.delegate = delegate
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    // Retained reference so the delegate isn't deallocated before the callback fires
    private var sextDelegate: AnyObject?

    /// loadAllFromPreferences with a timeout to prevent infinite hang when the extension
    /// binary changed since the config was saved (version-mismatch triggers an sysextd
    /// re-validation that never completes from a LaunchDaemon context).
    private func loadAllPreferencesWithTimeout(seconds: Double = 8) async throws -> [NETunnelProviderManager] {
        // Thread-safe gate: whichever of (callback, timeout) fires first resumes the
        // continuation; the other is silently discarded.
        final class Once: @unchecked Sendable {
            private let lock = NSLock()
            private var fired = false
            func run(_ block: () -> Void) {
                lock.lock(); defer { lock.unlock() }
                guard !fired else { return }
                fired = true
                block()
            }
        }
        let once = Once()
        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.main.async {
                NETunnelProviderManager.loadAllFromPreferences { managers, error in
                    once.run {
                        if let error = error {
                            continuation.resume(throwing: error)
                        } else {
                            continuation.resume(returning: managers ?? [])
                        }
                    }
                }
            }
            DispatchQueue.global().asyncAfter(deadline: .now() + seconds) {
                once.run {
                    continuation.resume(throwing: NSError(
                        domain: "com.wiredog.vpn.macos.helper",
                        code: -1001,
                        userInfo: [NSLocalizedDescriptionKey:
                            "loadAllFromPreferences timed out (\(Int(seconds))s). " +
                            "The VPN config is stale (extension binary changed). " +
                            "Remove 'WireDog VPN' from System Settings → VPN, then restart the app."]
                    ))
                }
            }
        }
    }

    deinit {
        if let observer = statusObserver {
            NotificationCenter.default.removeObserver(observer)
        }
    }

    private static func statusString(from status: NEVPNStatus) -> String {
        switch status {
        case .invalid:      return "invalid"
        case .disconnected: return "disconnected"
        case .connecting:   return "connecting"
        case .connected:    return "connected"
        case .reasserting:  return "reasserting"
        case .disconnecting: return "disconnecting"
        @unknown default:   return "disconnected"
        }
    }
}

private class SystemExtensionDelegate: NSObject, OSSystemExtensionRequestDelegate {
    private let log: HelperLogger
    private let completion: (Result<String, Error>) -> Void

    init(log: HelperLogger, completion: @escaping (Result<String, Error>) -> Void) {
        self.log = log
        self.completion = completion
    }

    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        log.info("[TunnelManager] System extension replacing \(existing.bundleVersion) with \(ext.bundleVersion)")
        return .replace
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        log.info("[TunnelManager] System extension needs user approval — direct user to System Settings > General > Login Items & Extensions")
        completion(.success("needsApproval"))
    }

    func request(_ request: OSSystemExtensionRequest,
                 didFinishWithResult result: OSSystemExtensionRequest.Result) {
        switch result {
        case .completed:
            log.info("[TunnelManager] System extension activated successfully")
            completion(.success("activated"))
        case .willCompleteAfterReboot:
            log.info("[TunnelManager] System extension will activate after reboot")
            completion(.success("willCompleteAfterReboot"))
        @unknown default:
            log.info("[TunnelManager] System extension activation result: \(result.rawValue)")
            completion(.success("unknown"))
        }
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        log.error("[TunnelManager] System extension activation failed: \(error.localizedDescription)")
        completion(.failure(error))
    }
}

enum TunnelError: LocalizedError {
    case managerNotLoaded
    case statsUnavailable(String)

    var errorDescription: String? {
        switch self {
        case .managerNotLoaded:
            return "VPN manager not loaded. Call loadTunnelManager first."
        case .statsUnavailable(let reason):
            return "Tunnel stats unavailable: \(reason)"
        }
    }
}
