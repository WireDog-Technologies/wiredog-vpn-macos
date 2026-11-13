import Foundation
import os.log

/// Manages pf (packet filter) rules for the always-on kill switch.
/// All traffic is blocked except what's explicitly allowed.
class PfManager {
    private let anchorName = "com.wiredog.vpn"
    private let logger = Logger(subsystem: "com.wiredog.vpn.macos.helper", category: "PfManager")

    // MARK: - Rescue Relay
    //
    // Addresses of the Rescue Relay (a no-log pass-through to the WireDog backend). While a block is
    // up, TCP 443 to exactly these addresses stays permitted so the app can still reach the backend
    // (to sign in, ask for a new session, release one). Set by the app from the backend's app config;
    // validated and capped here so a bad list can never open a wider hole.
    private(set) var relayIps: [String] = []

    /// Public IPv4 only (no private, loopback, link-local, CGNAT, multicast/reserved), at most four.
    static func sanitizeRelayIps(_ raw: [String]) -> [String] {
        var out: [String] = []
        for item in raw {
            let candidate = item.trimmingCharacters(in: .whitespaces)
            let parts = candidate.split(separator: ".", omittingEmptySubsequences: false).compactMap { Int($0) }
            guard parts.count == 4, candidate.split(separator: ".").count == 4,
                  parts.allSatisfy({ $0 >= 0 && $0 <= 255 }) else { continue }
            let a = parts[0], b = parts[1]
            if a == 0 || a == 10 || a == 127 || a >= 224 { continue }
            if a == 100 && b >= 64 && b <= 127 { continue }
            if a == 169 && b == 254 { continue }
            if a == 172 && b >= 16 && b <= 31 { continue }
            if a == 192 && b == 168 { continue }
            if !out.contains(candidate) { out.append(candidate) }
            if out.count >= 4 { break }
        }
        return out
    }

    func setRelayIps(_ ips: [String]) {
        relayIps = PfManager.sanitizeRelayIps(ips)
    }

    /// One pass line per relay address, spliced into every ruleset.
    private var relayRules: String {
        relayIps.map { "pass quick inet proto tcp from any to \($0) port 443" }.joined(separator: "\n")
    }

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

    // Every permit below is IPv4-only (`inet`). Without the family, `port 53` and `port 67:68` also
    // matched IPv6, so under a block IPv6 DNS queries still left the machine (the same gap Windows
    // closed by re-adding its IPv6 block when it falls back to Bootstrap). IPv6 over the tunnel is
    // carried by `pass quick on <utun> all`, which is unaffected.

    /// Bootstrap rules: Block everything except VPN server + LAN + DHCP + DNS
    func applyBootstrapRules(serverIp: String, serverPort: UInt16) throws {
        guard isValidIPv4(serverIp) else {
            throw PfError.invalidInput("serverIp is not a valid IPv4 address: \(serverIp)")
        }
        let rules = """
        # WireDog VPN Kill Switch - Bootstrap
        block drop all
        pass quick on lo0 all
        pass quick inet proto udp from any to any port 67:68
        pass quick inet proto {tcp, udp} from any to any port 53
        pass quick inet proto udp from any to \(serverIp) port \(serverPort)
        \(relayRules)
        pass quick inet from any to 10.0.0.0/8
        pass quick inet from any to 172.16.0.0/12
        pass quick inet from any to 192.168.0.0/16
        pass quick inet from any to 169.254.0.0/16
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
        pass quick inet proto udp from any to any port 67:68
        pass quick inet proto {tcp, udp} from any to any port 53
        pass quick inet proto udp from any to \(serverIp) port \(serverPort)
        \(relayRules)
        pass quick inet from any to 10.0.0.0/8
        pass quick inet from any to 172.16.0.0/12
        pass quick inet from any to 192.168.0.0/16
        pass quick inet from any to 169.254.0.0/16
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
        pass quick inet proto udp from any to any port 67:68
        \(relayRules)
        pass quick inet from any to 10.0.0.0/8
        pass quick inet from any to 172.16.0.0/12
        pass quick inet from any to 192.168.0.0/16
        pass quick inet from any to 169.254.0.0/16
        """
        try applyRules(rules)
    }

    /// Flush all WireDog pf rules
    func flushRules() throws {
        try runPfctl(["-a", anchorName, "-F", "all"])
        logger.info("pf rules flushed for anchor \(self.anchorName)")
        unhookAnchor()
    }

    // MARK: - Private

    private func applyRules(_ rules: String) throws {
        let tempFile = "/tmp/wiredog-pf-rules.conf"
        // pfctl reports a syntax error on the last line if the file has no
        // trailing newline — Swift's `"""` literal omits one.
        let normalized = rules.hasSuffix("\n") ? rules : rules + "\n"
        try normalized.write(toFile: tempFile, atomically: true, encoding: .utf8)

        // pf only evaluates an anchor the main ruleset points to. The system ruleset knows only
        // `com.apple/*`, so rules loaded into our own anchor do nothing until we add the reference.
        try hookAnchor()

        // Load rules into our anchor
        try runPfctl(["-a", anchorName, "-f", tempFile])

        // Ensure pf is enabled
        try runPfctl(["-e"])

        // Clean up temp file
        try? FileManager.default.removeItem(atPath: tempFile)

        logger.info("pf rules applied to anchor \(self.anchorName)")
    }

    // MARK: - Diagnostics

    /// [TEMP] A snapshot of what pf is really doing, so the app log can show it without sudo.
    func diagnostics() -> [String: Any] {
        let info = (try? capturePfctl(["-s", "info"])) ?? ""
        let enabled = info.contains("Status: Enabled")
        let mainRules = ((try? capturePfctl(["-s", "rules"])) ?? "")
            .split(separator: "\n").filter { !$0.isEmpty }
        let anchorRules = ((try? capturePfctl(["-a", anchorName, "-s", "rules"])) ?? "")
            .split(separator: "\n").filter { !$0.isEmpty }
        let blockAll = anchorRules.contains { $0.hasPrefix("block drop all") }
        return [
            "pfEnabled": enabled,
            "anchorHooked": anchorIsHooked(),
            "mainRules": mainRules.count,
            "anchorRules": anchorRules.count,
            "blockAllInAnchor": blockAll,
            "relayIps": relayIps.count,
        ]
    }

    // MARK: - Anchor hook

    private let mainRulesetPath = "/etc/pf.conf"

    /// True when the live main ruleset contains a rule that evaluates our anchor.
    private func anchorIsHooked() -> Bool {
        guard let rules = try? capturePfctl(["-s", "rules"]) else { return false }
        return rules.contains("anchor \"\(anchorName)\"")
    }

    /// Makes the main ruleset evaluate our anchor: the system ruleset plus one `anchor` line at the
    /// END, so our block-all is the last match for anything our passes do not release. Idempotent.
    private func hookAnchor() throws {
        if anchorIsHooked() { return }
        guard let base = try? String(contentsOfFile: mainRulesetPath, encoding: .utf8),
              !base.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            // Loading a ruleset that is only our anchor would drop the system's own anchors.
            throw PfError.invalidInput("cannot read \(mainRulesetPath) to add the kill switch anchor")
        }
        let separator = base.hasSuffix("\n") ? "" : "\n"
        let combined = base + separator + "\n# WireDog VPN kill switch\nanchor \"\(anchorName)\"\n"
        let tempFile = "/tmp/wiredog-pf-main.conf"
        try combined.write(toFile: tempFile, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: tempFile) }

        try runPfctl(["-f", tempFile])
        guard anchorIsHooked() else { throw PfError.anchorNotEvaluated }
        logger.info("pf main ruleset now evaluates anchor \(self.anchorName)")
    }

    /// Puts the system ruleset back when the kill switch is off. Best effort: a leftover reference to
    /// an empty anchor does nothing.
    private func unhookAnchor() {
        guard anchorIsHooked() else { return }
        do {
            try runPfctl(["-f", mainRulesetPath])
            logger.info("pf main ruleset restored from \(self.mainRulesetPath, privacy: .public)")
        } catch {
            logger.error("could not restore the pf main ruleset: \(error.localizedDescription, privacy: .public)")
        }
    }

    private func capturePfctl(_ args: [String]) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/sbin/pfctl")
        process.arguments = args
        let outPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = FileHandle.nullDevice
        try process.run()
        let data = outPipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return String(data: data, encoding: .utf8) ?? ""
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
    case anchorNotEvaluated

    var errorDescription: String? {
        switch self {
        case .commandFailed(let status, let args, let stderr):
            let suffix = stderr.isEmpty ? "" : ": \(stderr)"
            return "pfctl \(args.joined(separator: " ")) failed with status \(status)\(suffix)"
        case .invalidInput(let reason):
            return "PfManager: invalid input — \(reason)"
        case .anchorNotEvaluated:
            return "PfManager: the kill switch rules were loaded but pf is not evaluating them"
        }
    }
}
