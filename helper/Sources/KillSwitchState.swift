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

    /// Saved state: survives daemon restarts AND reboots, so the block comes back at boot.
    /// It must NOT live in /var/run or /tmp: macOS empties both at every boot, which is exactly when
    /// this file is needed (v1.0.0 to v1.2.0-dev kept it in /var/run, so a reboot dropped Always-On).
    /// /var/db is persistent and root-only.
    private let stateDirPath = "/var/db/wiredog"
    private var stateFilePath: String { stateDirPath + "/ks-state.json" }
    /// Where older helpers wrote it. Read once if the new file is missing (an upgrade without a reboot).
    private let legacyStateFilePath = "/var/run/wiredog-ks-state.json"

    /// Transitions come from several socket clients and from the watchdog timer; one at a time.
    private let lock = NSRecursiveLock()
    private var watchdog: DispatchSourceTimer?
    private var watchdogTicks = 0
    private var unreadableChecks = 0
    private var repairFailures = 0
    private var lastRepairAttempt = Date.distantPast

    init(pfManager: PfManager) {
        self.pfManager = pfManager
    }

    // MARK: - Public API

    func enable() throws {
        lock.lock(); defer { lock.unlock() }
        advancedEnabled = true
        saveState()
        logger.info("Advanced kill switch enabled")
    }

    func disable() throws {
        lock.lock(); defer { lock.unlock() }
        advancedEnabled = false
        state = .disabled
        saveState()
        try pfManager.flushRules()
        logger.info("Advanced kill switch disabled, pf rules flushed")
    }

    /// Rescue Relay addresses the block must keep reachable (TCP 443 only). Sanitized by PfManager
    /// (public IPv4, at most four). Saved with the state so a block restored at boot has them, and
    /// applied at once to a block that is already up so a refreshed list does not wait for the next one.
    var relayCount: Int { pfManager.relayIps.count }

    /// Read-only firewall report for Verbose Diagnostic Mode (see PfManager.diagnosticsReport).
    func firewallDiagnostics() -> [String: Any] { pfManager.diagnosticsReport() }

    func setApiRelays(_ ips: [String]) throws {
        lock.lock(); defer { lock.unlock() }
        let before = pfManager.relayIps
        pfManager.setRelayIps(ips)
        guard pfManager.relayIps != before else { return }
        logger.info("Relay addresses set: \(pfManager.relayIps.count)")
        saveState()
        switch state {
        case .bootstrap:
            if let ip = lastServerIp { try pfManager.applyBootstrapRules(serverIp: ip, serverPort: lastServerPort) }
        case .connected:
            if let ip = lastServerIp, let iface = lastTunnelInterface {
                try pfManager.applyConnectedRules(serverIp: ip, serverPort: lastServerPort, tunnelInterface: iface)
            }
        case .persistentBlock:
            try pfManager.applyPersistentBlockRules(serverIp: lastServerIp)
        case .disabled:
            break
        }
    }

    func transitionToBootstrap(serverIp: String, serverPort: UInt16) throws {
        lock.lock(); defer { lock.unlock() }
        lastServerIp = serverIp
        lastServerPort = serverPort
        try pfManager.applyBootstrapRules(serverIp: serverIp, serverPort: serverPort)
        state = .bootstrap
        saveState()
        logger.info("Kill switch state: bootstrap (server: \(serverIp):\(serverPort), advancedEnabled: \(advancedEnabled))")
    }

    func transitionToConnected(serverIp: String, serverPort: UInt16, tunnelInterface: String) throws {
        lock.lock(); defer { lock.unlock() }
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
        lock.lock(); defer { lock.unlock() }
        try pfManager.flushRules()
        state = .disabled
        saveState()
        logger.info("Kill switch state: disabled (rules flushed, advancedEnabled preserved: \(advancedEnabled))")
    }

    func transitionToPersistentBlock() throws {
        lock.lock(); defer { lock.unlock() }
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
        lock.lock(); defer { lock.unlock() }
        state = .disabled
        advancedEnabled = false
        lastServerIp = nil
        lastTunnelInterface = nil
        saveState()
        try pfManager.flushRules()
        logger.info("Emergency reset: all pf rules flushed, kill switch disabled")
    }

    // MARK: - State Persistence

    func restoreState() throws {
        lock.lock(); defer { lock.unlock() }
        let data = FileManager.default.contents(atPath: stateFilePath)
            ?? FileManager.default.contents(atPath: legacyStateFilePath)
        guard let data = data, let saved = try? JSONDecoder().decode(SavedState.self, from: data) else {
            logger.info("No saved kill switch state found at \(stateFilePath)")
            return
        }
        logger.info("Saved kill switch state found: state=\(saved.state.rawValue) advancedEnabled=\(saved.advancedEnabled)")

        // Before the block is rebuilt: the relay must be in it from the first rule.
        pfManager.setRelayIps(saved.apiRelayIps ?? [])

        guard saved.advancedEnabled else { return }

        advancedEnabled = true
        lastServerIp = saved.lastServerIp
        lastServerPort = saved.lastServerPort ?? 443

        // If we were active before (connected or persistent block), restore persistent block.
        // The app will reconnect and transition to the appropriate state.
        if saved.state != .disabled {
            // State first: if pf is not ready this early in boot and the apply fails, the watchdog
            // sees a block that should be up and keeps rebuilding it.
            state = .persistentBlock
            do {
                try pfManager.applyPersistentBlockRules(serverIp: saved.lastServerIp)
                logger.info("Restored persistent block from saved state (server: \(saved.lastServerIp ?? "none"))")
            } catch {
                logger.error("Could not apply the restored persistent block yet (\(error.localizedDescription)); the watchdog will retry")
            }
        }
    }

    private func saveState() {
        let saved = SavedState(
            state: state,
            advancedEnabled: advancedEnabled,
            lastServerIp: lastServerIp,
            lastServerPort: lastServerPort,
            apiRelayIps: pfManager.relayIps
        )
        do {
            try FileManager.default.createDirectory(
                atPath: stateDirPath, withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700])
            let data = try JSONEncoder().encode(saved)
            try data.write(to: URL(fileURLWithPath: stateFilePath), options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: stateFilePath)
        } catch {
            // Silent before: a save that never lands means no block after a reboot, so say so.
            logger.error("Could not save kill switch state to \(stateFilePath): \(error.localizedDescription)")
        }
    }

    // MARK: - Watchdog

    /// Keeps the block real. pf rules live in the kernel and anyone can replace them: macOS itself runs
    /// `pfctl -f /etc/pf.conf` at every boot (com.apple.pfctl), which can land AFTER the block was
    /// restored here and silently drop the anchor reference, and another VPN or firewall tool can do
    /// the same while the Mac runs. While a block is meant to be up, check often right after start
    /// (the boot race), then every 10 s, and rebuild the rules for the current state when they are gone.
    func startWatchdog() {
        lock.lock(); defer { lock.unlock() }
        guard watchdog == nil else { return }
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue(label: "com.wiredog.helper.watchdog", qos: .utility))
        timer.schedule(deadline: .now() + 2, repeating: 2)
        timer.setEventHandler { [weak self] in self?.watchdogTick() }
        watchdog = timer
        timer.resume()
    }

    private func watchdogTick() {
        watchdogTicks += 1
        if watchdogTicks == 30 { watchdog?.schedule(deadline: .now() + 10, repeating: 10) }
        lock.lock(); let current = state; lock.unlock()
        guard current != .disabled else { return }

        // The check only reads pf, and right after boot it can take many seconds (7.9 s was seen). It
        // must NOT hold the lock meanwhile: every request from the app that needs the lock (relay
        // addresses, state changes) waited behind it, so the app's first calls after a reboot came back
        // seconds late. Only the repair takes the lock, and re-checks once it has it.
        let checkStart = Date()
        let reading = pfManager.isBlockIntact()
        let took = Date().timeIntervalSince(checkStart)
        if took > 1.0 { logger.warn("Watchdog: the block check took \(Int(took * 1000)) ms") }

        // A descriptor leak once showed up only as a failure hours in (see PfManager.capturePfctl): say so early.
        if watchdogTicks % 30 == 0 {
            let open = PfManager.openDescriptorCount()
            if open > 120 { logger.warn("Watchdog: \(open) open file descriptors") }
        }

        // Could not read pf at all: say so (rarely), do not "repair" a block nobody saw missing.
        guard let intact = reading else {
            unreadableChecks += 1
            if unreadableChecks == 1 || unreadableChecks % 30 == 0 {
                logger.warn("Watchdog: could not read pf (\(unreadableChecks) times in a row); leaving the block alone")
            }
            return
        }
        unreadableChecks = 0
        if intact { repairFailures = 0; return }

        // After a failed repair wait before the next one (1 min, then 2, 4 ... up to 10): a repair that cannot
        // succeed, repeated every 10 s for hours, only reloads the real rules for nothing (193 times on 2026-11-15).
        if repairFailures > 0 {
            let wait = min(600.0, 60.0 * pow(2.0, Double(repairFailures - 1)))
            if Date().timeIntervalSince(lastRepairAttempt) < wait { return }
        }

        lock.lock(); defer { lock.unlock() }
        guard state != .disabled, pfManager.isBlockIntact() == false else { return }
        lastRepairAttempt = Date()
        logger.warn("Watchdog: the pf block is gone or not evaluated while state is \(state.rawValue); rebuilding it")
        do {
            switch state {
            case .bootstrap:
                if let ip = lastServerIp { try pfManager.applyBootstrapRules(serverIp: ip, serverPort: lastServerPort) }
                else { try pfManager.applyPersistentBlockRules(serverIp: nil) }
            case .connected:
                if let ip = lastServerIp, let iface = lastTunnelInterface {
                    try pfManager.applyConnectedRules(serverIp: ip, serverPort: lastServerPort, tunnelInterface: iface)
                } else { try pfManager.applyPersistentBlockRules(serverIp: nil) }
            case .persistentBlock:
                try pfManager.applyPersistentBlockRules(serverIp: lastServerIp)
            case .disabled:
                break
            }
            repairFailures = 0
            logger.info("Watchdog: block rebuilt for state \(state.rawValue)")
        } catch {
            repairFailures += 1
            logger.error("Watchdog: could not rebuild the block (failure \(repairFailures)): \(error.localizedDescription)")
        }
    }
}

/// Serializable state for persistence across daemon restarts
private struct SavedState: Codable {
    let state: KillSwitchState
    let advancedEnabled: Bool
    let lastServerIp: String?
    let lastServerPort: UInt16?
    // Optional so a state file written by an older helper still decodes.
    let apiRelayIps: [String]?
}
