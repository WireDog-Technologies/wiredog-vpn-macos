import Foundation
import NetworkExtension
import os.log

// Boot diagnostic: runs before startSystemExtensionMode() to confirm binary was launched.
// Remove after debugging confirms stable launch. Two outputs:
//   1. os_log fault → always lands in unified log even if sandbox blocks file I/O
//   2. App Group container file → readable without sudo
func writeBootLog() {
    let pid = ProcessInfo.processInfo.processIdentifier
    let timestamp = Date()

    // 1. os_log (survives sandbox, no container needed)
    let logger = Logger(subsystem: "com.wiredog.vpn.macos.tunnel", category: "Boot")
    logger.fault("BOOT main.swift reached — PID \(pid, privacy: .public) at \(timestamp, privacy: .public)")

    // 2. App Group container file
    let appGroup = "group.com.wiredog.vpn.macos"
    guard let containerURL = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup) else { return }
    try? FileManager.default.createDirectory(at: containerURL, withIntermediateDirectories: true)
    let logURL = containerURL.appendingPathComponent("boot.log")
    let line = "[\(timestamp)] BOOT: main.swift reached — PID \(pid)\n"
    if let fh = try? FileHandle(forWritingTo: logURL) {
        fh.seekToEndOfFile()
        fh.write(line.data(using: .utf8)!)
        try? fh.close()
    } else {
        try? line.data(using: .utf8)?.write(to: logURL)
    }
}

let bootLogger = Logger(subsystem: "com.wiredog.vpn.macos.tunnel", category: "Boot")
writeBootLog()

// Log runtime-visible NEMachServiceName — confirms what launchd registered matches what
// startSystemExtensionMode() will try to check in to.
if let infoDict = Bundle.main.infoDictionary,
   let neDict = infoDict["NetworkExtension"] as? [String: Any],
   let machServiceName = neDict["NEMachServiceName"] as? String {
    bootLogger.fault("MACH-SERVICE-NAME: \(machServiceName, privacy: .public)")
} else {
    bootLogger.fault("MACH-SERVICE-NAME: NOT FOUND in Info.plist")
}

// startSystemExtensionMode() registers the Mach service listener on a dispatch queue and
// returns immediately — it does NOT block. dispatchMain() below keeps the process alive
// to process NE events. Without dispatchMain(), the process exits and nesessionmanager
// reports PID 0 / NEAgentErrorDomain Code=2.
bootLogger.fault("PRE-SEXT: calling startSystemExtensionMode()")
autoreleasepool {
    NEProvider.startSystemExtensionMode()
}
bootLogger.fault("POST-SEXT: startSystemExtensionMode() returned (expected, always non-blocking) — entering dispatchMain() to keep process alive")
dispatchMain()
