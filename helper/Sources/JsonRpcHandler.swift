import Foundation

/// Handles JSON-RPC 2.0 messages from the Electron app.
class JsonRpcHandler {
    private let killSwitchState: KillSwitchStateMachine
    private let tunnelManager: TunnelManager
    private let filterManager: FilterManager

    init(killSwitchState: KillSwitchStateMachine, tunnelManager: TunnelManager, filterManager: FilterManager) {
        self.killSwitchState = killSwitchState
        self.tunnelManager = tunnelManager
        self.filterManager = filterManager
    }

    /// Process a JSON-RPC 2.0 message and invoke reply with the response string (or nil for notifications)
    func handleMessage(_ json: String, reply: @escaping (String?) -> Void) {
        guard let data = json.data(using: .utf8),
              let message = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              message["jsonrpc"] as? String == "2.0" else {
            reply(errorResponse(id: nil, code: -32700, message: "Parse error"))
            return
        }

        let id = message["id"]  // Could be string, number, or null
        let method = message["method"] as? String ?? ""
        let params = message["params"] as? [String: Any]

        // Notifications (no id) don't get a response
        guard id != nil else { reply(nil); return }

        switch method {
        case "ping":
            reply(successResponse(id: id, result: [
                "version": HelperVersion.current,
                "uptime": ProcessInfo.processInfo.systemUptime
            ]))

        case "enableAdvancedKillSwitch":
            // Sets the Always-On persistence flag only. State transitions
            // (bootstrap/connected/persistent_block) must go through
            // `updateKillSwitch` so we don't silently flip Always-On on.
            do {
                try killSwitchState.enable()
                reply(successResponse(id: id, result: [
                    "success": true,
                    "advancedKillSwitchEnabled": true
                ]))
            } catch {
                reply(errorResponse(id: id, code: -1, message: error.localizedDescription))
            }

        case "disableAdvancedKillSwitch":
            do {
                try killSwitchState.disable()
                reply(successResponse(id: id, result: [
                    "success": true,
                    "advancedKillSwitchEnabled": false
                ]))
            } catch {
                reply(errorResponse(id: id, code: -1, message: error.localizedDescription))
            }

        case "updateKillSwitch":
            let state = params?["state"] as? String ?? ""
            let serverIp = params?["serverIp"] as? String ?? ""
            let serverPort = UInt16((params?["serverPort"] as? Int) ?? 443)
            let tunnelInterface = params?["tunnelInterface"] as? String ?? ""
            do {
                switch state {
                case "bootstrap":
                    try killSwitchState.transitionToBootstrap(serverIp: serverIp, serverPort: serverPort)
                case "connected":
                    if tunnelInterface.isEmpty {
                        // Caller doesn't know the utun name yet — keep bootstrap
                        // rules in place (they already allow the VPN server endpoint).
                        // Real connected-rules require the interface to pass-quick utunN traffic.
                        reply(successResponse(id: id, result: [
                            "success": true,
                            "note": "connected transition deferred: tunnelInterface not provided"
                        ]))
                        return
                    }
                    try killSwitchState.transitionToConnected(serverIp: serverIp, serverPort: serverPort, tunnelInterface: tunnelInterface)
                case "persistent_block":
                    try killSwitchState.transitionToPersistentBlock()
                case "disabled":
                    try killSwitchState.transitionToDisabled()
                default:
                    reply(errorResponse(id: id, code: -1, message: "Unknown state: \(state)"))
                    return
                }
                reply(successResponse(id: id, result: ["success": true]))
            } catch {
                reply(errorResponse(id: id, code: -1, message: error.localizedDescription))
            }

        case "getKillSwitchState":
            reply(successResponse(id: id, result: [
                "state": killSwitchState.state.rawValue,
                "advancedEnabled": killSwitchState.advancedEnabled,
                "advancedActive": killSwitchState.state != .disabled
            ]))

        case "emergencyReset":
            do {
                try killSwitchState.emergencyReset()
                reply(successResponse(id: id, result: ["success": true]))
            } catch {
                reply(errorResponse(id: id, code: -1, message: error.localizedDescription))
            }

        // MARK: - Tunnel methods (routed through TunnelManager)

        case "activateExtension":
            // System extension activation is handled by the Electron app (via native-sysext addon),
            // not the helper daemon. OSSystemExtensionManager calls from a LaunchDaemon are
            // rejected by macOS since activation requires user-session context.
            reply(successResponse(id: id, result: ["status": "activated"]))

        case "removeVPNConfig":
            Task {
                do {
                    try await tunnelManager.removeAllConfigs()
                    reply(successResponse(id: id, result: ["success": true, "removed": true]))
                } catch {
                    reply(errorResponse(id: id, code: -1, message: error.localizedDescription))
                }
            }

        case "loadTunnelManager":
            Task {
                do {
                    try await tunnelManager.loadManager()
                    reply(successResponse(id: id, result: ["success": true]))
                } catch {
                    reply(errorResponse(id: id, code: -1, message: error.localizedDescription))
                }
            }

        case "startTunnel":
            guard let config = params else {
                reply(errorResponse(id: id, code: -32602, message: "Invalid params: startTunnel requires config object"))
                return
            }
            do {
                try tunnelManager.startTunnel(config: config)
                reply(successResponse(id: id, result: ["success": true]))
            } catch {
                reply(errorResponse(id: id, code: -1, message: error.localizedDescription))
            }

        case "stopTunnel":
            tunnelManager.stopTunnel()
            reply(successResponse(id: id, result: ["success": true]))

        case "getTunnelStatus":
            reply(successResponse(id: id, result: ["status": tunnelManager.status]))

        case "getTunnelStats":
            Task {
                do {
                    let stats = try await tunnelManager.getStats()
                    reply(successResponse(id: id, result: [
                        "bytesIn": stats.bytesIn,
                        "bytesOut": stats.bytesOut
                    ]))
                } catch {
                    reply(errorResponse(id: id, code: -1, message: error.localizedDescription))
                }
            }

        // MARK: - Filter methods (split tunnel app routing)

        case "loadFilterManager":
            Task {
                do {
                    try await filterManager.loadManager()
                    reply(successResponse(id: id, result: ["success": true]))
                } catch {
                    reply(errorResponse(id: id, code: -1, message: error.localizedDescription))
                }
            }

        case "startFilter":
            guard let params = params else {
                reply(errorResponse(id: id, code: -32602, message: "startFilter requires config params"))
                return
            }
            let mode = params["mode"] as? String ?? "exclude"
            let apps = params["apps"] as? [String] ?? []
            let config = SplitTunnelFilterConfig(mode: mode, apps: apps, enabled: true)
            do {
                try filterManager.startFilter(config: config)
                reply(successResponse(id: id, result: ["success": true]))
            } catch {
                reply(errorResponse(id: id, code: -1, message: error.localizedDescription))
            }

        case "stopFilter":
            filterManager.stopFilter()
            reply(successResponse(id: id, result: ["success": true]))

        case "updateSplitTunnelConfig":
            guard let params = params else {
                reply(errorResponse(id: id, code: -32602, message: "updateSplitTunnelConfig requires config params"))
                return
            }
            let mode = params["mode"] as? String ?? "exclude"
            let apps = params["apps"] as? [String] ?? []
            let enabled = params["enabled"] as? Bool ?? true
            let config = SplitTunnelFilterConfig(mode: mode, apps: apps, enabled: enabled)
            do {
                try filterManager.updateConfig(config)
                reply(successResponse(id: id, result: ["success": true]))
            } catch {
                reply(errorResponse(id: id, code: -1, message: error.localizedDescription))
            }

        default:
            reply(errorResponse(id: id, code: -32601, message: "Method not found: \(method)"))
        }
    }

    // MARK: - Response Helpers

    private func successResponse(id: Any?, result: [String: Any]) -> String {
        var response: [String: Any] = [
            "jsonrpc": "2.0",
            "result": result
        ]
        if let id = id { response["id"] = id }
        return toJSON(response)
    }

    private func errorResponse(id: Any?, code: Int, message: String) -> String {
        var response: [String: Any] = [
            "jsonrpc": "2.0",
            "error": ["code": code, "message": message]
        ]
        if let id = id { response["id"] = id }
        return toJSON(response)
    }

    private func toJSON(_ dict: [String: Any]) -> String {
        guard let data = try? JSONSerialization.data(withJSONObject: dict),
              let json = String(data: data, encoding: .utf8) else {
            return "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32603,\"message\":\"Internal error\"}}"
        }
        return json
    }
}
