import Foundation
import NetworkExtension

/// Observes NETunnelProviderManager connection status changes via NotificationCenter
/// and forwards them to a callback (which the N-API wrapper bridges to JavaScript).
@objc public class StatusObserver: NSObject {
    private var observer: NSObjectProtocol?
    private var callback: ((String) -> Void)?

    @objc public init(connection: NEVPNConnection?, callback: @escaping (String) -> Void) {
        self.callback = callback
        super.init()

        guard let connection = connection else { return }

        observer = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: connection,
            queue: .main
        ) { [weak self] notification in
            guard let self = self,
                  let conn = notification.object as? NEVPNConnection else { return }

            let status = Self.statusString(from: conn.status)
            NSLog("[WireDog] tunnel status: %@ (connected since %@)", status, conn.connectedDate.map { "\($0)" } ?? "-")
            // Why macOS stopped the tunnel (extension crashed, configuration problem, server unreachable...).
            // Read by Verbose Diagnostic Mode from the system log.
            if conn.status == .disconnected {
                if #available(macOS 13.0, *) {
                    conn.fetchLastDisconnectError { error in
                        if let error = error as NSError? {
                            NSLog("[WireDog] last disconnect error: %@ (domain %@, code %ld)", error.localizedDescription, error.domain, error.code)
                        } else {
                            NSLog("[WireDog] last disconnect error: none")
                        }
                    }
                }
            }
            self.callback?(status)
        }
    }

    deinit {
        if let observer = observer {
            NotificationCenter.default.removeObserver(observer)
        }
    }

    /// Convert NEVPNStatus enum to JavaScript-friendly string
    @objc public static func statusString(from status: NEVPNStatus) -> String {
        switch status {
        case .invalid:
            return "invalid"
        case .disconnected:
            return "disconnected"
        case .connecting:
            return "connecting"
        case .connected:
            return "connected"
        case .reasserting:
            return "reasserting"
        case .disconnecting:
            return "disconnecting"
        @unknown default:
            return "disconnected"
        }
    }
}
