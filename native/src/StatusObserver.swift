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
