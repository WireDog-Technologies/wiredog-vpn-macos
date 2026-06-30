import Foundation
import SystemExtensions

/// WireDog VPN — System Extension Activation Tool
///
/// Submits an activation request for the WireDogTunnel system extension via
/// OSSystemExtensionManager. Must be called from within the app bundle that
/// contains the extension (macOS verifies the team ID match).
///
/// Exit codes:
///   0 — success (stdout: ACTIVATED, PENDING, or REBOOT_REQUIRED)
///   1 — error   (stdout: ERROR: <message>)
///
/// Electron reads stdout to determine next action:
///   ACTIVATED        → proceed with tunnel connection
///   PENDING          → show "approve in System Settings" message, retry on next connect
///   REBOOT_REQUIRED  → prompt user to reboot (rare)

let extensionIdentifier = "com.wiredog.vpn.macos.tunnel"
var didReceiveResult = false
var exitCode: Int32 = 0

class ActivationDelegate: NSObject, OSSystemExtensionRequestDelegate {

    func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        switch result {
        case .completed:
            print("ACTIVATED")
        case .willCompleteAfterReboot:
            print("REBOOT_REQUIRED")
        @unknown default:
            print("ACTIVATED")
        }
        fflush(stdout)
        didReceiveResult = true
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        let nsError = error as NSError
        // Code 4 = OSSystemExtensionErrorCode.requestSuperseded — another request already in flight;
        // treat as already-active so the user isn't stuck.
        if nsError.domain == OSSystemExtensionErrorDomain && nsError.code == 4 {
            print("ACTIVATED")
        } else {
            fputs("ERROR: \(error.localizedDescription)\n", stderr)
            print("ERROR: \(error.localizedDescription)")
            exitCode = 1
        }
        fflush(stdout)
        didReceiveResult = true
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        // Extension is not yet approved — macOS has shown the Security prompt.
        // Exit immediately so Electron can surface the "go approve in System Settings" message.
        print("PENDING")
        fflush(stdout)
        didReceiveResult = true
    }

    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension replacement: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        // Always replace when a newer version is bundled (handles app updates)
        return .replace
    }
}

let delegate = ActivationDelegate()
let request = OSSystemExtensionRequest.activationRequest(
    forExtensionWithIdentifier: extensionIdentifier,
    queue: .main
)
request.delegate = delegate
OSSystemExtensionManager.shared.submitRequest(request)

// Spin the run loop until the delegate fires or we time out (30 s)
let deadline = Date().addingTimeInterval(30)
while !didReceiveResult && Date() < deadline {
    RunLoop.main.run(until: Date().addingTimeInterval(0.05))
}

if !didReceiveResult {
    fputs("ERROR: Timeout waiting for system extension activation response\n", stderr)
    print("ERROR: Timeout")
    exitCode = 1
}

exit(exitCode)
