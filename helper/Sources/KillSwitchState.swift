import Foundation

/// Kill switch states (mirrors Windows WFP state machine)
enum KillSwitchState: String, Codable {
    case disabled
    case bootstrap
    case connected
    case persistentBlock = "persistent_block"
}

/// Kill switch state machine managing transitions and pf rule updates
class KillSwitchStateMachine {
    private(set) var state: KillSwitchState = .disabled
    private(set) var advancedEnabled: Bool = false
    private let pfManager: PfManager
    private var lastServerIp: String?
    private var lastServerPort: UInt16 = 443
    private var lastTunnelInterface: String?

    /// Persistent state file path (survives daemon restarts)
    private let stateFilePath = "/var/run/wiredog-ks-state.json"

    init(pfManager: PfManager) {
        self.pfManager = pfManager
    }

    // MARK: - Public API

    func enable() throws {
        advancedEnabled = true
        saveState()
        logger.info("Advanced kill switch enabled")
    }

    func disable() throws {
        advancedEnabled = false
        state = .disabled
        try pfManager.flushRules()
        saveState()
        logger.info("Advanced kill switch disabled, pf rules flushed")
    }

    func transitionToBootstrap(serverIp: String, serverPort: UInt16) throws {
        lastServerIp = serverIp
        lastServerPort = serverPort
        try pfManager.applyBootstrapRules(serverIp: serverIp, serverPort: serverPort)
        state = .bootstrap
        saveState()
        logger.info("Kill switch state: bootstrap (server: \(serverIp):\(serverPort), advancedEnabled: \(advancedEnabled))")
    }

    func transitionToConnected(serverIp: String, serverPort: UInt16, tunnelInterface: String) throws {
        lastServerIp = serverIp
        lastServerPort = serverPort
        lastTunnelInterface = tunnelInterface
        try pfManager.applyConnectedRules(serverIp: serverIp, serverPort: serverPort, tunnelInterface: tunnelInterface)
        state = .connected
        saveState()
        logger.info("Kill switch state: connected (server: \(serverIp):\(serverPort), interface: \(tunnelInterface), advancedEnabled: \(advancedEnabled))")
    }

    /// Flush bootstrap/connected rules without touching the Always-On flag.
    /// Used on normal disconnect when Always-On is off.
    func transitionToDisabled() throws {
        try pfManager.flushRules()
        state = .disabled
        saveState()
        logger.info("Kill switch state: disabled (rules flushed, advancedEnabled preserved: \(advancedEnabled))")
    }

    func transitionToPersistentBlock() throws {
        guard advancedEnabled else {
            logger.warn("transitionToPersistentBlock skipped: advancedEnabled is false")
            return
        }
        try pfManager.applyPersistentBlockRules(serverIp: lastServerIp)
        state = .persistentBlock
        saveState()
        logger.info("Kill switch state: persistent block")
    }

    func emergencyReset() throws {
        try pfManager.flushRules()
        state = .disabled
        advancedEnabled = false
        lastServerIp = nil
        lastTunnelInterface = nil
        saveState()
        logger.info("Emergency reset: all pf rules flushed, kill switch disabled")
    }

    // MARK: - State Persistence

    func restoreState() throws {
        guard let data = FileManager.default.contents(atPath: stateFilePath),
              let saved = try? JSONDecoder().decode(SavedState.self, from: data) else {
            return
        }

        guard saved.advancedEnabled else { return }

        advancedEnabled = true
        lastServerIp = saved.lastServerIp
        lastServerPort = saved.lastServerPort ?? 443

        // If we were active before (connected or persistent block), restore persistent block.
        // The app will reconnect and transition to the appropriate state.
        if saved.state != .disabled {
            try pfManager.applyPersistentBlockRules(serverIp: saved.lastServerIp)
            state = .persistentBlock
            logger.info("Restored persistent block from saved state (server: \(saved.lastServerIp ?? "none"))")
        }
    }

    private func saveState() {
        let saved = SavedState(
            state: state,
            advancedEnabled: advancedEnabled,
            lastServerIp: lastServerIp,
            lastServerPort: lastServerPort
        )
        if let data = try? JSONEncoder().encode(saved) {
            try? data.write(to: URL(fileURLWithPath: stateFilePath))
        }
    }
}

/// Serializable state for persistence across daemon restarts
private struct SavedState: Codable {
    let state: KillSwitchState
    let advancedEnabled: Bool
    let lastServerIp: String?
    let lastServerPort: UInt16?
}
