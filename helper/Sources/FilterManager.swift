import Foundation
import NetworkExtension

/// Manages the NEAppProxyProviderManager for the WireDogFilter transparent proxy extension.
///
/// The filter extension intercepts per-app network flows and routes them based on the
/// user's split tunnel include/exclude list. This manager handles the lifecycle of that
/// extension from inside the helper daemon (alongside TunnelManager for the VPN tunnel).
class FilterManager {
    private var manager: NEAppProxyProviderManager?
    private let log = HelperLogger.shared

    private let bundleIdentifier = "com.wiredog.vpn.macos.filter"

    // MARK: - Setup

    /// Load an existing NEAppProxyProviderManager for the filter extension, or create one
    /// if none exists. Must be called before startFilter or stopFilter.
    func loadManager() async throws {
        log.info("[FilterManager] loadManager() called")

        let managers = try await NEAppProxyProviderManager.loadAllFromPreferences()
        log.info("[FilterManager] Found \(managers.count) existing filter manager(s)")

        // Find our manager by bundle identifier
        if let existing = managers.first(where: {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == bundleIdentifier
        }) {
            log.info("[FilterManager] Using existing manager")
            self.manager = existing
            return
        }

        // No existing manager — create one
        log.info("[FilterManager] Creating new filter manager")
        let newManager = NEAppProxyProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = bundleIdentifier
        proto.serverAddress = "WireDog Split Tunnel"
        newManager.protocolConfiguration = proto
        newManager.localizedDescription = "WireDog Split Tunnel"
        newManager.isEnabled = true

        do {
            try await newManager.saveToPreferences()
            log.info("[FilterManager] saveToPreferences() succeeded")
        } catch {
            log.error("[FilterManager] saveToPreferences() failed: \(error.localizedDescription)")
            throw error
        }

        try await newManager.loadFromPreferences()
        self.manager = newManager
        log.info("[FilterManager] New filter manager created and loaded")
    }

    // MARK: - Lifecycle

    /// Start the filter extension with the given split tunnel configuration.
    /// The config is passed as JSON in the launch options so the extension can apply
    /// rules immediately without waiting for a subsequent handleAppMessage call.
    func startFilter(config: SplitTunnelFilterConfig) throws {
        guard let manager = manager else {
            log.error("[FilterManager] startFilter failed — manager not loaded")
            throw FilterError.managerNotLoaded
        }

        log.info("[FilterManager] startFilter — mode=\(config.mode) apps=\(config.apps.count) apps=\(config.apps.joined(separator: ","))")

        manager.isEnabled = true

        Task {
            do {
                try await manager.saveToPreferences()
                log.info("[FilterManager] saveToPreferences succeeded")
                try await manager.loadFromPreferences()
                log.info("[FilterManager] loadFromPreferences succeeded — isEnabled=\(manager.isEnabled)")
            } catch {
                self.log.warn("[FilterManager] saveToPreferences failed before start (non-fatal): \(error.localizedDescription)")
            }

            guard let session = manager.connection as? NETunnelProviderSession else {
                self.log.error("[FilterManager] No NETunnelProviderSession available — cannot start extension")
                return
            }

            let connStatus = session.status
            self.log.info("[FilterManager] Session status before start: \(connStatus.rawValue)")

            // If already running, push config update instead of restarting
            if connStatus == .connected || connStatus == .connecting {
                self.log.info("[FilterManager] Extension already running — sending config update")
                if let data = try? JSONEncoder().encode(config) {
                    do {
                        try session.sendProviderMessage(data) { [weak self] _ in
                            self?.log.info("[FilterManager] Config pushed to already-running extension")
                        }
                    } catch {
                        self.log.error("[FilterManager] sendProviderMessage failed: \(error.localizedDescription)")
                    }
                }
                return
            }

            var options: [String: NSObject]? = nil
            if let configData = try? JSONEncoder().encode(config) {
                options = ["config": configData as NSData]
                self.log.info("[FilterManager] Config encoded (\(configData.count) bytes), passing in launch options")
            } else {
                self.log.error("[FilterManager] Failed to encode config — extension will start without initial config")
            }

            do {
                try session.startVPNTunnel(options: options)
                self.log.info("[FilterManager] startVPNTunnel succeeded — extension process should now be launching")
            } catch {
                self.log.error("[FilterManager] startVPNTunnel failed: \(error.localizedDescription) (code=\((error as NSError).code))")
            }
        }
    }

    /// Stop the filter extension.
    func stopFilter() {
        log.info("[FilterManager] stopFilter()")
        manager?.connection.stopVPNTunnel()
    }

    /// Push an updated configuration to the running filter extension.
    /// The extension applies the new rules live via handleAppMessage — no restart required.
    func updateConfig(_ config: SplitTunnelFilterConfig) throws {
        guard let session = manager?.connection as? NETunnelProviderSession else {
            log.warn("[FilterManager] updateConfig — no active session, skipping")
            return
        }

        guard let data = try? JSONEncoder().encode(config) else {
            throw FilterError.encodingFailed
        }

        log.info("[FilterManager] Pushing config update — mode=\(config.mode) apps=\(config.apps.count) enabled=\(config.enabled)")

        do {
            try session.sendProviderMessage(data) { [weak self] _ in
                self?.log.info("[FilterManager] Config update acknowledged by extension")
            }
        } catch {
            log.error("[FilterManager] sendProviderMessage failed: \(error.localizedDescription)")
            throw error
        }
    }
}

// MARK: - Errors

enum FilterError: LocalizedError {
    case managerNotLoaded
    case encodingFailed

    var errorDescription: String? {
        switch self {
        case .managerNotLoaded:
            return "Filter manager not loaded. Call loadFilterManager first."
        case .encodingFailed:
            return "Failed to encode split tunnel filter configuration."
        }
    }
}
