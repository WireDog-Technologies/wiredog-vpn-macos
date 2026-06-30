import Foundation
import SystemExtensions

// Unbuffered output so Electron reads lines immediately
setbuf(stdout, nil)

class ActivatorDelegate: NSObject, OSSystemExtensionRequestDelegate {
    func request(_ request: OSSystemExtensionRequest,
                 didFinishWithResult result: OSSystemExtensionRequest.Result) {
        print(result == .willCompleteAfterReboot ? "REBOOT_REQUIRED" : "ACTIVATED")
        exit(0)
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        let e = error as NSError
        // Code 12 = RequestSuperseded — a newer request took over, treat as active
        if e.domain == OSSystemExtensionErrorDomain && e.code == 12 {
            print("ACTIVATED")
            exit(0)
        }
        print("ERROR: [domain=\(e.domain) code=\(e.code)] \(e.localizedDescription)")
        exit(1)
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        // Inform Electron so it can show a notification, then keep running
        // until the user approves (didFinishWithResult) or we timeout.
        print("PENDING")
    }

    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension replacement: OSSystemExtensionProperties)
        -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }
}

let delegate = ActivatorDelegate()
let request = OSSystemExtensionRequest.activationRequest(
    forExtensionWithIdentifier: "com.wiredog.vpn.macos.tunnel",
    queue: .main
)
request.delegate = delegate
OSSystemExtensionManager.shared.submitRequest(request)

// Give the user up to 5 minutes to approve in System Settings
DispatchQueue.main.asyncAfter(deadline: .now() + 300) {
    print("TIMEOUT")
    exit(2)
}

RunLoop.main.run()
