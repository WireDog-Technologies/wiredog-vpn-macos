import Foundation
import NetworkExtension

@objc protocol VPNConfigServiceProtocol {
    func createVPNConfiguration(reply: @escaping (Bool, String?) -> Void)
}

class VPNConfigService: NSObject, NSXPCListenerDelegate, VPNConfigServiceProtocol {

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        connection.exportedInterface = NSXPCInterface(with: VPNConfigServiceProtocol.self)
        connection.exportedObject = self
        connection.resume()
        return true
    }

    func createVPNConfiguration(reply: @escaping (Bool, String?) -> Void) {
        Task {
            do {
                let managers = try await NETunnelProviderManager.loadAllFromPreferences()
                let ourBundleId = "com.wiredog.vpn.macos.tunnel"

                // Remove any existing config regardless of pluginType — the NE framework binds
                // pluginType to the calling process's bundle ID at saveToPreferences() time, so
                // any config saved by this XPC service previously has pluginType=com.wiredog.vpn.macos.config
                // instead of com.wiredog.vpn.macos.tunnel. nesessionmanager uses pluginType to select
                // the tunnel plugin, so a stale config causes it to launch the XPC service instead
                // of the system extension. Always recreate to guarantee pluginType is correct.
                for m in managers where (m.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == ourBundleId {
                    try? await m.removeFromPreferences()
                }

                let manager = NETunnelProviderManager()
                manager.localizedDescription = "WireDog VPN"
                manager.isEnabled = true

                let proto = NETunnelProviderProtocol()
                proto.providerBundleIdentifier = ourBundleId
                // Explicitly set pluginType to match providerBundleIdentifier. Without this, the NE
                // framework sets pluginType to the calling process's bundle ID (this XPC service),
                // which causes nesessionmanager to try to launch the XPC service as the tunnel plugin.
                // pluginType is on NEVPNProtocol (grandparent) and not directly accessible in Swift
                // on NETunnelProviderProtocol, so use KVC.
                proto.setValue(ourBundleId, forKey: "pluginType")
                proto.serverAddress = "WireDog VPN"
                manager.protocolConfiguration = proto

                try await manager.saveToPreferences()
                reply(true, nil)
            } catch {
                reply(false, error.localizedDescription)
            }
        }
    }
}

let listener = NSXPCListener.service()
let service = VPNConfigService()
listener.delegate = service
listener.resume()
dispatchMain()
