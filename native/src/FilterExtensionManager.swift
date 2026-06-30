import Foundation
import NetworkExtension

/// Manages the NEAppProxyProviderManager for the WireDogFilter transparent proxy extension.
///
/// This class runs inside the Electron app process (which has the app-proxy-provider
/// entitlement). The helper daemon cannot hold this entitlement because AMFI rejects
/// app-proxy-provider on standalone daemon binaries — only .app and .appex bundles
/// are allowed to claim it.
@objc public class FilterExtensionManager: NSObject {
    private var manager: NEAppProxyProviderManager?
    private let bundleIdentifier = "com.wiredog.vpn.macos.filter"

    // MARK: - Setup

    @objc public func loadManager(completion: @escaping (NSError?) -> Void) {
        Task {
            do {
                let managers = try await NEAppProxyProviderManager.loadAllFromPreferences()
                if let existing = managers.first(where: {
                    ($0.protocolConfiguration as? NETunnelProviderProtocol)?
                        .providerBundleIdentifier == bundleIdentifier
                }) {
                    self.manager = existing
                    NSLog("[FilterExtensionManager] Using existing manager (isEnabled=%d)", existing.isEnabled)
                } else {
                    NSLog("[FilterExtensionManager] Creating new manager")
                    let newManager = NEAppProxyProviderManager()
                    let proto = NETunnelProviderProtocol()
                    proto.providerBundleIdentifier = bundleIdentifier
                    proto.serverAddress = "WireDog Split Tunnel"
                    newManager.protocolConfiguration = proto
                    newManager.localizedDescription = "WireDog Split Tunnel"
                    newManager.isEnabled = true
                    try await newManager.saveToPreferences()
                    try await newManager.loadFromPreferences()
                    self.manager = newManager
                    NSLog("[FilterExtensionManager] New manager created and loaded")
                }
                completion(nil)
            } catch {
                NSLog("[FilterExtensionManager] loadManager failed: %@", error.localizedDescription)
                completion(error as NSError)
            }
        }
    }

    // MARK: - Lifecycle

    /// Start the filter extension with the given mode and app bundle IDs.
    /// If the extension is already running, sends a live config update instead of restarting.
    @objc public func startFilter(mode: String, apps: NSArray, completion: @escaping (NSError?) -> Void) {
        guard let manager = manager else {
            let err = NSError(
                domain: "com.wiredog.filter", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "Filter manager not loaded — call loadManager first"]
            )
            completion(err)
            return
        }

        manager.isEnabled = true

        Task {
            // Persist enabled=true so NE system tracks the manager as active
            do {
                try await manager.saveToPreferences()
                try await manager.loadFromPreferences()
            } catch {
                NSLog("[FilterExtensionManager] saveToPreferences non-fatal: %@", error.localizedDescription)
            }

            guard let session = manager.connection as? NETunnelProviderSession else {
                let err = NSError(
                    domain: "com.wiredog.filter", code: 2,
                    userInfo: [NSLocalizedDescriptionKey: "No NETunnelProviderSession available"]
                )
                completion(err)
                return
            }

            let status = session.status
            NSLog("[FilterExtensionManager] Session status before start: %ld", status.rawValue)

            // Config JSON matches SplitTunnelFilterConfig in the extension
            let config: [String: Any] = ["mode": mode, "apps": apps, "enabled": true]
            guard let configData = try? JSONSerialization.data(withJSONObject: config) else {
                let err = NSError(
                    domain: "com.wiredog.filter", code: 3,
                    userInfo: [NSLocalizedDescriptionKey: "Failed to encode filter config as JSON"]
                )
                completion(err)
                return
            }

            // If already running, send live config update (no restart)
            if status == .connected || status == .connecting {
                NSLog("[FilterExtensionManager] Extension already running — sending config update")
                do {
                    try session.sendProviderMessage(configData) { _ in }
                    completion(nil)
                } catch {
                    completion(error as NSError)
                }
                return
            }

            // Start the extension, passing config as launch options
            NSLog("[FilterExtensionManager] Starting extension (mode=%@, apps=%lu)", mode, apps.count)
            do {
                try session.startVPNTunnel(options: ["config": configData as NSData])
                NSLog("[FilterExtensionManager] startVPNTunnel succeeded")
                completion(nil)
            } catch {
                NSLog("[FilterExtensionManager] startVPNTunnel failed: %@", error.localizedDescription)
                completion(error as NSError)
            }
        }
    }

    /// Stop the filter extension.
    @objc public func stopFilter() {
        NSLog("[FilterExtensionManager] stopFilter()")
        manager?.connection.stopVPNTunnel()
    }
}
