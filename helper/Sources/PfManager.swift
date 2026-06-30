import Foundation
import os.log

/// Manages pf (packet filter) rules for the always-on kill switch.
/// All traffic is blocked except what's explicitly allowed.
class PfManager {
    private let anchorName = "com.wiredog.vpn"
    private let logger = Logger(subsystem: "com.wiredog.vpn.macos.helper", category: "PfManager")

    // MARK: - Input validation

    /// Validates that a string is a bare IPv4 address (no newlines, spaces, or shell metacharacters).
    /// pf rules are written to a temp file, not a shell, but an adversarially crafted IP could
    /// inject additional pf rule lines.  Only accept strings that match x.x.x.x.
    private func isValidIPv4(_ s: String) -> Bool {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return false }
        return parts.allSatisfy { part in
            guard let n = Int(part), n >= 0, n <= 255 else { return false }
            return true
        }
    }

    /// Validates that a string is a safe network interface name (alphanumeric only, max 16 chars).
    private func isValidInterface(_ s: String) -> Bool {
        guard !s.isEmpty, s.count <= 16 else { return false }
        return s.allSatisfy { $0.isLetter || $0.isNumber }
    }

    /// Bootstrap rules: Block everything except VPN server + LAN + DHCP + DNS
    func applyBootstrapRules(serverIp: String, serverPort: UInt16) throws {
        guard isValidIPv4(serverIp) else {
            throw PfError.invalidInput("serverIp is not a valid IPv4 address: \(serverIp)")
        }
        let rules = """
        # WireDog VPN Kill Switch - Bootstrap
        block drop all
        pass quick on lo0 all
        pass quick proto udp from any to any port 67:68
        pass quick proto {tcp, udp} from any to any port 53
        pass quick proto udp from any to \(serverIp) port \(serverPort)
        pass quick from any to 10.0.0.0/8
        pass quick from any to 172.16.0.0/12
        pass quick from any to 192.168.0.0/16
        pass quick from any to 169.254.0.0/16
        """
        try applyRules(rules)
    }

    /// Connected rules: Allow tunnel interface + VPN server
    func applyConnectedRules(serverIp: String, serverPort: UInt16, tunnelInterface: String) throws {
        guard isValidIPv4(serverIp) else {
            throw PfError.invalidInput("serverIp is not a valid IPv4 address: \(serverIp)")
        }
        guard isValidInterface(tunnelInterface) else {
            throw PfError.invalidInput("tunnelInterface contains invalid characters: \(tunnelInterface)")
        }
        let rules = """
        # WireDog VPN Kill Switch - Connected
        block drop all
        pass quick on lo0 all
        pass quick on \(tunnelInterface) all
        pass quick proto udp from any to any port 67:68
        pass quick proto {tcp, udp} from any to any port 53
        pass quick proto udp from any to \(serverIp) port \(serverPort)
        pass quick from any to 10.0.0.0/8
        pass quick from any to 172.16.0.0/12
        pass quick from any to 192.168.0.0/16
        pass quick from any to 169.254.0.0/16
        """
        try applyRules(rules)
    }

    /// Persistent block: terminal blocked state. Everything off except loopback,
    /// DHCP, and LAN. User must click Connect, which transitions back through
    /// bootstrap (which re-adds DNS + VPN server permits) before the tunnel attempt.
    func applyPersistentBlockRules(serverIp: String?) throws {
        _ = serverIp
        let rules = """
        # WireDog VPN Kill Switch - Persistent Block
        block drop all
        pass quick on lo0 all
        pass quick proto udp from any to any port 67:68
        pass quick from any to 10.0.0.0/8
        pass quick from any to 172.16.0.0/12
        pass quick from any to 192.168.0.0/16
        pass quick from any to 169.254.0.0/16
        """
        try applyRules(rules)
    }

    /// Flush all WireDog pf rules
    func flushRules() throws {
        try runPfctl(["-a", anchorName, "-F", "all"])
        logger.info("pf rules flushed for anchor \(self.anchorName)")
    }

    // MARK: - Private

    private func applyRules(_ rules: String) throws {
        let tempFile = "/tmp/wiredog-pf-rules.conf"
        // pfctl reports a syntax error on the last line if the file has no
        // trailing newline — Swift's `"""` literal omits one.
        let normalized = rules.hasSuffix("\n") ? rules : rules + "\n"
        try normalized.write(toFile: tempFile, atomically: true, encoding: .utf8)

        // Load rules into our anchor
        try runPfctl(["-a", anchorName, "-f", tempFile])

        // Ensure pf is enabled
        try runPfctl(["-e"])

        // Clean up temp file
        try? FileManager.default.removeItem(atPath: tempFile)

        logger.info("pf rules applied to anchor \(self.anchorName)")
    }

    private func runPfctl(_ args: [String]) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/sbin/pfctl")
        process.arguments = args
        let errPipe = Pipe()
        process.standardOutput = FileHandle.nullDevice
        process.standardError = errPipe
        try process.run()
        process.waitUntilExit()

        let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
        let errText = String(data: errData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

        // pfctl -e returns 1 if pf is already enabled — that's OK
        if process.terminationStatus != 0 && !(args.contains("-e") && process.terminationStatus == 1) {
            logger.error("pfctl \(args.joined(separator: " "), privacy: .public) failed (status \(process.terminationStatus, privacy: .public)): \(errText, privacy: .public)")
            throw PfError.commandFailed(status: process.terminationStatus, args: args, stderr: errText)
        }
    }
}

enum PfError: LocalizedError {
    case commandFailed(status: Int32, args: [String], stderr: String)
    case invalidInput(String)

    var errorDescription: String? {
        switch self {
        case .commandFailed(let status, let args, let stderr):
            let suffix = stderr.isEmpty ? "" : ": \(stderr)"
            return "pfctl \(args.joined(separator: " ")) failed with status \(status)\(suffix)"
        case .invalidInput(let reason):
            return "PfManager: invalid input — \(reason)"
        }
    }
}
