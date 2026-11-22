import Foundation
import Security

/// Lets the running helper (root) replace itself with the helper inside an updated app: no password and
/// no reboot. The app asks (RPC `selfUpdate`) after an update; the helper copies the new binary next to
/// itself, checks that the copy is signed by the same team with the same identifier as this running
/// helper, swaps it in atomically and exits; launchd (KeepAlive) starts the new code at once.
///
/// Only while nothing is protecting the user (kill switch off or the Always-On block): a restart during
/// bootstrap/connected would rebuild the firewall from saved state differently. pf rules live in the kernel
/// and are not touched by the restart.
///
/// Industry reference: Mullvad restarts its daemon from its installer after telling it to prepare; IVPN
/// reinstalls its helper with an admin prompt on every version change. This does the same restart without
/// the prompt, because the helper already runs as root.
final class SelfUpdater {
    /// Where install-helper.sh puts the helper (root:wheel 0755) and where the LaunchDaemon runs it from.
    static let installedPath = "/Library/PrivilegedHelperTools/com.wiredog.vpn.helper"

    private let log = HelperLogger.shared

    enum UpdateError: LocalizedError {
        case notInstalledCopy(String)
        case busy(String)
        case sourceMissing(String)
        case copyFailed(String)
        case signature(String)
        case swapFailed(String)

        var errorDescription: String? {
            switch self {
            case .notInstalledCopy(let path):
                return "this helper runs from \(path), not \(SelfUpdater.installedPath); it is replaced by the one-time install instead"
            case .busy(let state):
                return "busy: the kill switch is in state '\(state)'; update after the next disconnect"
            case .sourceMissing(let path):
                return "no helper binary at \(path)"
            case .copyFailed(let reason):
                return "could not copy the new helper: \(reason)"
            case .signature(let reason):
                return "the new helper's signature was refused: \(reason)"
            case .swapFailed(let reason):
                return "could not put the new helper in place: \(reason)"
            }
        }
    }

    /// Returns "updated" (this process exits in a moment and launchd starts the new one) or "unchanged".
    func update(from sourcePath: String, killSwitchState: KillSwitchStateMachine) throws -> String {
        let running = URL(fileURLWithPath: Bundle.main.executablePath ?? CommandLine.arguments[0]).resolvingSymlinksInPath().path
        guard running == Self.installedPath else { throw UpdateError.notInstalledCopy(running) }

        let state = killSwitchState.state
        guard state == .disabled || state == .persistentBlock else { throw UpdateError.busy(state.rawValue) }

        let fm = FileManager.default
        guard sourcePath.hasSuffix("/wiredog-helper"), fm.fileExists(atPath: sourcePath) else {
            throw UpdateError.sourceMissing(sourcePath)
        }

        // Copy first, then check the copy: what is verified is exactly what gets installed (the source sits
        // in a user-writable app bundle and could change between a check and a copy).
        let staging = Self.installedPath + ".new"
        try? fm.removeItem(atPath: staging)
        do {
            try fm.copyItem(atPath: sourcePath, toPath: staging)
        } catch {
            throw UpdateError.copyFailed(error.localizedDescription)
        }
        _ = chown(staging, 0, 0)
        _ = chmod(staging, 0o755)
        _ = removexattr(staging, "com.apple.quarantine", 0)

        do {
            try verifySignature(ofFileAt: staging)
        } catch {
            try? fm.removeItem(atPath: staging)
            throw error
        }

        if fm.contentsEqual(atPath: staging, andPath: Self.installedPath) {
            try? fm.removeItem(atPath: staging)
            return "unchanged"
        }

        guard rename(staging, Self.installedPath) == 0 else {
            let reason = String(cString: strerror(errno))
            try? fm.removeItem(atPath: staging)
            throw UpdateError.swapFailed(reason)
        }

        log.info("Self-update: installed the helper from \(sourcePath); restarting into the new version")
        // Give the reply time to reach the app, then exit; launchd relaunches the new binary.
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.3) { exit(0) }
        return "updated"
    }

    /// The copy must be validly signed (every architecture, strict) by the same team and with the same
    /// signing identifier as this running helper. Nothing is hard-coded: a helper signed by anyone else,
    /// ad-hoc or unsigned is refused.
    private func verifySignature(ofFileAt path: String) throws {
        var selfCode: SecCode?
        guard SecCodeCopySelf([], &selfCode) == errSecSuccess, let me = selfCode else {
            throw UpdateError.signature("could not read this helper's own code")
        }
        var selfStatic: SecStaticCode?
        guard SecCodeCopyStaticCode(me, [], &selfStatic) == errSecSuccess, let meStatic = selfStatic else {
            throw UpdateError.signature("could not read this helper's own signature")
        }
        var infoRef: CFDictionary?
        guard SecCodeCopySigningInformation(meStatic, SecCSFlags(rawValue: kSecCSSigningInformation), &infoRef) == errSecSuccess,
              let info = infoRef as? [String: Any],
              let team = info[kSecCodeInfoTeamIdentifier as String] as? String,
              let identifier = info[kSecCodeInfoIdentifier as String] as? String else {
            throw UpdateError.signature("this helper is not signed with a team identifier (development build?)")
        }

        let requirementText = "anchor apple generic and certificate leaf[subject.OU] = \"\(team)\" and identifier \"\(identifier)\""
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(requirementText as CFString, [], &requirement) == errSecSuccess, let req = requirement else {
            throw UpdateError.signature("could not build the requirement \(requirementText)")
        }

        var candidateRef: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &candidateRef) == errSecSuccess,
              let candidate = candidateRef else {
            throw UpdateError.signature("could not read the new helper's signature")
        }
        let flags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate)
        let status = SecStaticCodeCheckValidity(candidate, flags, req)
        guard status == errSecSuccess else {
            throw UpdateError.signature("OSStatus \(status) against \(requirementText)")
        }
    }
}
