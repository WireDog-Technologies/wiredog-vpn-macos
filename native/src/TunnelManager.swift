import Foundation
import NetworkExtension
import Darwin

/// Shared protocol between the native addon and the VPN config XPC service.
/// The service (com.wiredog.vpn.macos.config) holds packet-tunnel-provider-systemextension
/// without JIT, so it can call saveToPreferences() where the Electron process cannot.
@objc protocol VPNConfigServiceProtocol {
    func createVPNConfiguration(reply: @escaping (Bool, String?) -> Void)
}

/// Manages the NETunnelProviderManager for WireGuard tunnel control.
/// This class is the core bridge between Electron (via N-API) and Apple's VPN framework.
@objc public class TunnelManager: NSObject {
    private var manager: NETunnelProviderManager?
    private var statusObserver: StatusObserver?

    /// The IPv4 address of the WireGuard tunnel interface (e.g. "10.2.0.2").
    /// Stored at startTunnel time so getStats can locate the utun by IP.
    private var vpnInterfaceAddress: String?

    /// Callback invoked when tunnel status changes
    @objc public var onStatusChange: ((String) -> Void)?

    /// Load or create the VPN configuration profile
    @objc public func loadManager() async throws {
        let managers = try await NETunnelProviderManager.loadAllFromPreferences()

        let ourBundleId = "com.wiredog.vpn.macos.tunnel"
        let existing = managers.first {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == ourBundleId
        }

        // Always route through the XPC service. If a config already exists but has a stale
        // pluginType (bound to a previous saving process's bundle ID), the service will delete and
        // recreate it with pluginType = com.wiredog.vpn.macos.tunnel so nesessionmanager launches
        // the system extension rather than the XPC config service.
        let storedPluginType = (existing?.protocolConfiguration as? NETunnelProviderProtocol)?.value(forKey: "pluginType") as? String
        if existing == nil || storedPluginType != ourBundleId {
            try await createConfigViaXPCService()
        }

        let reloaded = try await NETunnelProviderManager.loadAllFromPreferences()
        guard let loaded = reloaded.first(where: {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == ourBundleId
        }) else {
            throw TunnelError.notConfigured
        }
        self.manager = loaded

        // Set up status observation
        statusObserver = StatusObserver(connection: manager?.connection) { [weak self] status in
            self?.onStatusChange?(status)
        }
    }

    /// Start the VPN tunnel with the given WireGuard configuration
    @objc public func startTunnel(config: [String: Any]) throws {
        guard let manager = manager else {
            throw TunnelError.managerNotLoaded
        }

        // Store the first IPv4 address (e.g. "10.2.0.2") for interface stats lookup.
        // config["address"] may be "10.2.0.2/32" or "10.2.0.2/32,fd00::1/128".
        if let addressField = config["address"] as? String {
            let firstAddr = addressField.split(separator: ",").first.map(String.init) ?? addressField
            let ip = String(firstAddr.split(separator: "/").first ?? Substring(firstAddr))
                        .trimmingCharacters(in: .whitespaces)
            // Only store IPv4 addresses (contains only digits and dots)
            if ip.allSatisfy({ $0.isNumber || $0 == "." }) {
                vpnInterfaceAddress = ip
            }
        }

        // Must be enabled or startVPNTunnel will silently fail
        manager.isEnabled = true

        // Update protocol configuration with kill switch settings
        if let proto = manager.protocolConfiguration as? NETunnelProviderProtocol {
            proto.includeAllNetworks = config["includeAllNetworks"] as? Bool ?? false
            proto.excludeLocalNetworks = config["excludeLocalNetworks"] as? Bool ?? true
            // Keep serverAddress in sync for display purposes
            if let endpoint = config["endpoint"] as? String {
                proto.serverAddress = String(endpoint.split(separator: ":").first ?? "WireDog VPN")
            }
            manager.protocolConfiguration = proto
        }

        // Attempt to persist kill switch settings; non-fatal if permission denied
        // (WireGuard config is passed via tunnel options, not saved prefs)
        Task {
            do {
                try await manager.saveToPreferences()
                try await manager.loadFromPreferences()
            } catch {
                NSLog("[WireDog] saveToPreferences failed (non-fatal, kill switch settings not persisted): %@", error.localizedDescription)
            }

            // Start the tunnel regardless — config arrives via startVPNTunnel options
            do {
                let session = manager.connection as? NETunnelProviderSession
                let configData = try JSONSerialization.data(withJSONObject: config)
                try session?.startVPNTunnel(options: [
                    "config": configData as NSData
                ] as [String: NSObject])
            } catch {
                NSLog("[WireDog] startVPNTunnel error: %@", error.localizedDescription)
            }
        }
    }

    /// Stop the VPN tunnel
    @objc public func stopTunnel() {
        manager?.connection.stopVPNTunnel()
    }

    /// Get the current tunnel status as a string
    @objc public var status: String {
        guard let connection = manager?.connection else {
            return "disconnected"
        }

        switch connection.status {
        case .invalid:
            return "invalid"
        case .disconnected:
            return "disconnected"
        case .connecting:
            return "connecting"
        case .connected:
            return "connected"
        case .reasserting:
            return "reasserting"
        case .disconnecting:
            return "disconnecting"
        @unknown default:
            return "disconnected"
        }
    }

    /// Ask the embedded XPC service to call saveToPreferences(), creating the VPN config.
    /// The service runs in its own process with NE entitlements and no JIT.
    private func createConfigViaXPCService() async throws {
        return try await withCheckedThrowingContinuation { continuation in
            let connection = NSXPCConnection(serviceName: "com.wiredog.vpn.macos.config")
            connection.remoteObjectInterface = NSXPCInterface(with: VPNConfigServiceProtocol.self)
            connection.resume()

            let proxy = connection.remoteObjectProxyWithErrorHandler { error in
                connection.invalidate()
                continuation.resume(throwing: error)
            } as? VPNConfigServiceProtocol

            guard let proxy = proxy else {
                connection.invalidate()
                continuation.resume(throwing: TunnelError.configurationInvalid)
                return
            }

            proxy.createVPNConfiguration { success, errorMsg in
                connection.invalidate()
                if success {
                    continuation.resume()
                } else {
                    continuation.resume(throwing: NSError(
                        domain: "com.wiredog.vpn.config",
                        code: -1,
                        userInfo: [NSLocalizedDescriptionKey: errorMsg ?? "XPC config service failed"]
                    ))
                }
            }
        }
    }

    /// Read traffic statistics directly from the WireGuard utun network interface
    /// using getifaddrs. This bypasses sendProviderMessage entirely, which is
    /// unreliable from Electron because it requires a native AppKit run loop.
    @objc public func getStats(completion: @escaping (NSError?, NSNumber?, NSNumber?) -> Void) {
        guard let targetIP = vpnInterfaceAddress, !targetIP.isEmpty else {
            completion(nil, NSNumber(value: 0 as UInt64), NSNumber(value: 0 as UInt64))
            return
        }

        var ifap: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifap) == 0, let ifList = ifap else {
            completion(nil, NSNumber(value: 0 as UInt64), NSNumber(value: 0 as UInt64))
            return
        }
        defer { freeifaddrs(ifList) }

        // Pass 1: find the interface name whose IPv4 address matches our VPN IP
        var tunnelIfName: String?
        var cursor: UnsafeMutablePointer<ifaddrs>? = ifList
        while let ifa = cursor {
            defer { cursor = ifa.pointee.ifa_next }
            guard let addr = ifa.pointee.ifa_addr,
                  addr.pointee.sa_family == sa_family_t(AF_INET) else { continue }
            let ip = addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sinPtr -> String? in
                var inAddr = sinPtr.pointee.sin_addr
                var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                guard inet_ntop(AF_INET, &inAddr, &buf, socklen_t(INET_ADDRSTRLEN)) != nil else { return nil }
                return String(cString: buf)
            }
            if ip == targetIP {
                tunnelIfName = String(cString: ifa.pointee.ifa_name)
                break
            }
        }

        guard let ifName = tunnelIfName else {
            completion(nil, NSNumber(value: 0 as UInt64), NSNumber(value: 0 as UInt64))
            return
        }

        // Pass 2: find the AF_LINK entry for that interface to read byte counters
        cursor = ifList
        while let ifa = cursor {
            defer { cursor = ifa.pointee.ifa_next }
            guard String(cString: ifa.pointee.ifa_name) == ifName,
                  let addr = ifa.pointee.ifa_addr,
                  addr.pointee.sa_family == sa_family_t(AF_LINK),
                  let data = ifa.pointee.ifa_data else { continue }
            let ifData = data.assumingMemoryBound(to: if_data.self).pointee
            let bytesIn  = UInt64(ifData.ifi_ibytes)
            let bytesOut = UInt64(ifData.ifi_obytes)
            completion(nil, NSNumber(value: bytesIn), NSNumber(value: bytesOut))
            return
        }

        completion(nil, NSNumber(value: 0 as UInt64), NSNumber(value: 0 as UInt64))
    }
}

/// Tunnel-related errors
enum TunnelError: LocalizedError {
    case managerNotLoaded
    case notConfigured
    case configurationInvalid

    var errorDescription: String? {
        switch self {
        case .managerNotLoaded:
            return "VPN manager not loaded. Call loadManager() first."
        case .notConfigured:
            return "VPN configuration not yet created. Waiting for system extension activator."
        case .configurationInvalid:
            return "Invalid tunnel configuration."
        }
    }
}
