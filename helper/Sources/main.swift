import Foundation

/// WireDog VPN Helper Daemon
///
/// Lightweight LaunchDaemon that manages:
/// - pf (packet filter) rules for the always-on/persistent kill switch
/// - NETunnelProviderManager for WireGuard tunnel control
///
/// The NE entitlement lives here rather than on the Electron app binary,
/// which avoids the AMFI conflict between JIT and packet-tunnel-provider-systemextension.
///
/// Runs as root, communicates with the Electron app via Unix domain socket
/// using JSON-RPC 2.0.

let logger = HelperLogger.shared

logger.info("WireDog VPN Helper Daemon starting...")
logger.info("Version: 1.0.0")
logger.info("PID: \(ProcessInfo.processInfo.processIdentifier)")

// Initialize components
let pfManager = PfManager()
let killSwitchState = KillSwitchStateMachine(pfManager: pfManager)
let tunnelManager = TunnelManager()
let filterManager = FilterManager()
let jsonRpcHandler = JsonRpcHandler(killSwitchState: killSwitchState, tunnelManager: tunnelManager, filterManager: filterManager)

// Restore kill switch state from previous run (boot-time protection)
do {
    try killSwitchState.restoreState()
    logger.info("Kill switch state restored: \(killSwitchState.state.rawValue)")
} catch {
    logger.error("Failed to restore kill switch state: \(error.localizedDescription)")
}

// Start Unix domain socket server
let isDev = ProcessInfo.processInfo.environment["WIREDOG_DEV"] != nil
let socketPath = isDev ? "/tmp/wiredog-dev.sock" : "/var/run/wiredog.sock"

let socketServer = SocketServer(path: socketPath, handler: jsonRpcHandler)

do {
    try socketServer.start()
    logger.info("Listening on \(socketPath)")
} catch {
    logger.error("Failed to start socket server: \(error.localizedDescription)")
    exit(1)
}

// Wire tunnel status changes → broadcast JSON-RPC notification to all connected clients
tunnelManager.onStatusChange = { status in
    let notification = "{\"jsonrpc\":\"2.0\",\"method\":\"tunnelStatusChanged\",\"params\":{\"status\":\"\(status)\"}}\n"
    socketServer.broadcast(notification)
    logger.info("Tunnel status changed: \(status)")
}

// NETunnelProviderManager is loaded on-demand via the loadTunnelManager RPC call
// from the Electron app, not at daemon startup. Loading at startup caused the daemon
// to be killed by the NE system (exit 78 / EX_CONFIG) due to entitlement validation
// that fires asynchronously after loadAllFromPreferences() returns.
// The Electron app calls loadTunnelManager immediately on connect, so the manager
// is available before any startTunnel call.
// Similarly, FilterManager is loaded on first use via loadFilterManager RPC.

// Keep the daemon running. dispatchMain() is used instead of RunLoop.main.run() because
// RunLoop.main.run() returns immediately when no input sources are attached — and none of
// our long-lived work (SocketServer on DispatchQueue.global, Swift concurrency Tasks)
// installs a runloop source. The result was a race where the main function returned
// before NotificationCenter observers were registered, and launchd saw the daemon exit
// ~1 second after startup.
dispatchMain()

// MARK: - Simple Logger

class HelperLogger {
    static let shared = HelperLogger()
    private let logPath = "/var/log/wiredog-helper.log"
    private let fileHandle: FileHandle?

    private init() {
        // Create log file if it doesn't exist
        FileManager.default.createFile(atPath: logPath, contents: nil)
        fileHandle = FileHandle(forWritingAtPath: logPath)
        fileHandle?.seekToEndOfFile()
    }

    func log(_ level: String, _ message: String) {
        let timestamp = ISO8601DateFormatter().string(from: Date())
        let line = "[\(timestamp)] [\(level)] \(message)\n"
        if let data = line.data(using: .utf8) {
            fileHandle?.write(data)
        }
        print(line, terminator: "")
    }

    func info(_ message: String) { log("INFO", message) }
    func warn(_ message: String) { log("WARN", message) }
    func error(_ message: String) { log("ERROR", message) }
}
