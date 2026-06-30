import NetworkExtension
import Network
import os.log

/// WireDog split tunnel filter extension.
///
/// Subclasses NETransparentProxyProvider to intercept outbound TCP/UDP flows and
/// route them based on the user's split tunneling configuration:
///
///   Exclude mode: listed apps bypass the VPN; all other apps use the tunnel.
///   Include mode: only listed apps use the VPN; all other apps use physical adapter.
///
/// For flows that should bypass the VPN the extension returns `true` (takes ownership)
/// and relays the data via NWConnection. Connections made from within the extension
/// process are not subject to VPN routing policy — they exit on the physical interface.
///
/// Returning `false` alone is NOT sufficient to bypass the VPN because the socket is
/// already bound to the tunnel interface by the time handleNewFlow is called.
///
/// App matching uses NEFlowMetaData.sourceAppSigningIdentifier with prefix matching so
/// helper processes (e.g. "com.google.chrome.helper") inherit the parent app's rule.
class FilterProvider: NETransparentProxyProvider {

    private let logger = Logger(subsystem: "com.wiredog.vpn.macos.filter", category: "FilterProvider")
    private var config = SplitTunnelFilterConfig(mode: "exclude", apps: [], enabled: false)

    // MARK: - Lifecycle

    override func startProxy(options: [String: Any]?, completionHandler: @escaping (Error?) -> Void) {
        logger.info("FilterProvider: ===== startProxy called =====")

        if let configData = options?["config"] as? Data,
           let decoded = try? JSONDecoder().decode(SplitTunnelFilterConfig.self, from: configData) {
            config = decoded
            logger.info("FilterProvider: initial config — mode=\(decoded.mode, privacy: .public) apps=\(decoded.apps.count) enabled=\(decoded.enabled) appList=\(decoded.apps.joined(separator: ","), privacy: .public)")
        } else {
            logger.warning("FilterProvider: no valid config in launch options — extension will idle until config update")
        }

        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.includedNetworkRules = [
            NENetworkRule(
                remoteNetwork: nil, remotePrefix: 0,
                localNetwork: nil, localPrefix: 0,
                protocol: .TCP, direction: .outbound
            ),
            NENetworkRule(
                remoteNetwork: nil, remotePrefix: 0,
                localNetwork: nil, localPrefix: 0,
                protocol: .UDP, direction: .outbound
            ),
        ]

        setTunnelNetworkSettings(settings) { [weak self] error in
            if let error = error {
                self?.logger.error("FilterProvider: setTunnelNetworkSettings FAILED: \(error.localizedDescription, privacy: .public)")
                completionHandler(error)
            } else {
                self?.logger.info("FilterProvider: ===== network settings applied — READY TO INTERCEPT FLOWS =====")
                completionHandler(nil)
            }
        }
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        logger.info("FilterProvider: stopProxy (reason=\(reason.rawValue))")
        completionHandler()
    }

    // MARK: - Flow routing

    /// Called for every new outbound TCP or UDP flow offered to us.
    ///
    /// Returns true  → we take ownership and relay the flow via physical interface.
    /// Returns false → the OS routes the flow normally (through WireGuard tunnel).
    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        guard config.enabled else { return false }

        let signingId = flow.metaData.sourceAppSigningIdentifier
        let isListed = appIsListed(signingId)

        let shouldBypass: Bool
        switch config.mode {
        case "exclude":
            shouldBypass = isListed      // listed app → bypass VPN
        case "include":
            shouldBypass = !isListed     // unlisted app → bypass VPN
        default:
            return false
        }

        if shouldBypass {
            logger.debug("FilterProvider: bypassing VPN for \(signingId, privacy: .public) (mode=\(self.config.mode, privacy: .public))")
            relayFlow(flow)
            return true  // we own this flow — data will be relayed via physical interface
        }

        return false  // let tunnel routing apply
    }

    // MARK: - Relay via physical adapter

    private func relayFlow(_ flow: NEAppProxyFlow) {
        if let tcpFlow = flow as? NEAppProxyTCPFlow {
            relayTCPFlow(tcpFlow)
        } else if let udpFlow = flow as? NEAppProxyUDPFlow {
            relayUDPFlow(udpFlow)
        } else {
            flow.closeReadWithError(nil)
            flow.closeWriteWithError(nil)
        }
    }

    // MARK: - TCP relay

    private func relayTCPFlow(_ flow: NEAppProxyTCPFlow) {
        guard let neEndpoint = flow.remoteEndpoint as? NWHostEndpoint else {
            flow.closeReadWithError(nil)
            flow.closeWriteWithError(nil)
            return
        }

        let host = Network.NWEndpoint.Host(neEndpoint.hostname)
        guard let port = Network.NWEndpoint.Port(neEndpoint.port) else {
            flow.closeReadWithError(nil)
            flow.closeWriteWithError(nil)
            return
        }

        // NWConnection from the extension process exits on the physical interface,
        // bypassing VPN routing policy entirely.
        let conn = NWConnection(host: host, port: port, using: .tcp)
        let queue = DispatchQueue(label: "com.wiredog.filter.tcp.\(UUID().uuidString)")

        flow.open(withLocalEndpoint: nil) { [weak self] error in
            if let error = error {
                self?.logger.error("FilterProvider: TCP flow open error: \(error.localizedDescription, privacy: .public)")
                conn.cancel()
                return
            }

            conn.stateUpdateHandler = { [weak self] state in
                switch state {
                case .ready:
                    self?.logger.debug("FilterProvider: TCP relay ready for \(neEndpoint.hostname, privacy: .public)")
                    self?.pumpFlowToConn(flow: flow, conn: conn, queue: queue)
                    self?.pumpConnToFlow(flow: flow, conn: conn, queue: queue)
                case .failed(let err):
                    self?.logger.debug("FilterProvider: TCP conn failed: \(err.localizedDescription, privacy: .public)")
                    flow.closeReadWithError(err)
                    flow.closeWriteWithError(err)
                case .cancelled:
                    flow.closeReadWithError(nil)
                    flow.closeWriteWithError(nil)
                default:
                    break
                }
            }
            conn.start(queue: queue)
        }
    }

    /// Pump data: app flow → NWConnection (outbound)
    private func pumpFlowToConn(flow: NEAppProxyTCPFlow, conn: NWConnection, queue: DispatchQueue) {
        flow.readData { [weak self] data, error in
            if let error = error {
                self?.logger.debug("FilterProvider: flow read error: \(error.localizedDescription, privacy: .public)")
                conn.cancel()
                return
            }
            guard let data = data, !data.isEmpty else {
                // EOF from app side
                conn.send(content: nil, contentContext: .finalMessage, isComplete: true, completion: .idempotent)
                return
            }
            conn.send(content: data, completion: .contentProcessed { [weak self] sendError in
                if let sendError = sendError {
                    self?.logger.debug("FilterProvider: conn send error: \(sendError.localizedDescription, privacy: .public)")
                    flow.closeReadWithError(sendError)
                    return
                }
                self?.pumpFlowToConn(flow: flow, conn: conn, queue: queue)
            })
        }
    }

    /// Pump data: NWConnection → app flow (inbound)
    private func pumpConnToFlow(flow: NEAppProxyTCPFlow, conn: NWConnection, queue: DispatchQueue) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            if let error = error {
                self?.logger.debug("FilterProvider: conn receive error: \(error.localizedDescription, privacy: .public)")
                flow.closeWriteWithError(error)
                return
            }
            if let data = data, !data.isEmpty {
                flow.write(data) { [weak self] writeError in
                    if let writeError = writeError {
                        self?.logger.debug("FilterProvider: flow write error: \(writeError.localizedDescription, privacy: .public)")
                        conn.cancel()
                        return
                    }
                    if isComplete {
                        flow.closeWriteWithError(nil)
                    } else {
                        self?.pumpConnToFlow(flow: flow, conn: conn, queue: queue)
                    }
                }
            } else if isComplete {
                flow.closeWriteWithError(nil)
            } else {
                self?.pumpConnToFlow(flow: flow, conn: conn, queue: queue)
            }
        }
    }

    // MARK: - UDP relay

    private func relayUDPFlow(_ flow: NEAppProxyUDPFlow) {
        flow.open(withLocalEndpoint: nil) { [weak self] error in
            if let error = error {
                self?.logger.error("FilterProvider: UDP flow open error: \(error.localizedDescription, privacy: .public)")
                return
            }
            self?.pumpUDPFlow(flow)
        }
    }

    private func pumpUDPFlow(_ flow: NEAppProxyUDPFlow) {
        flow.readDatagrams { [weak self] dataList, endpointList, error in
            if let error = error {
                self?.logger.debug("FilterProvider: UDP read error: \(error.localizedDescription, privacy: .public)")
                return
            }

            guard let dataList = dataList, let endpointList = endpointList, !dataList.isEmpty else {
                return
            }

            for (data, endpoint) in zip(dataList, endpointList) {
                guard let neEndpoint = endpoint as? NWHostEndpoint,
                      let port = Network.NWEndpoint.Port(neEndpoint.port) else { continue }

                let conn = NWConnection(
                    host: Network.NWEndpoint.Host(neEndpoint.hostname),
                    port: port,
                    using: .udp
                )
                let queue = DispatchQueue(label: "com.wiredog.filter.udp.\(UUID().uuidString)")
                conn.stateUpdateHandler = { [weak self] state in
                    if case .ready = state {
                        conn.send(content: data, completion: .contentProcessed { sendError in
                            if let sendError = sendError {
                                self?.logger.debug("FilterProvider: UDP send error: \(sendError.localizedDescription, privacy: .public)")
                            }
                            conn.cancel()
                        })
                    } else if case .failed(let err) = state {
                        self?.logger.debug("FilterProvider: UDP conn failed: \(err.localizedDescription, privacy: .public)")
                    }
                }
                conn.start(queue: queue)
            }

            // Continue reading datagrams
            self?.pumpUDPFlow(flow)
        }
    }

    // MARK: - Config updates (live, no restart)

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        if let decoded = try? JSONDecoder().decode(SplitTunnelFilterConfig.self, from: messageData) {
            config = decoded
            logger.info("FilterProvider: config updated — mode=\(decoded.mode, privacy: .public) apps=\(decoded.apps.count) enabled=\(decoded.enabled)")
        } else {
            logger.warning("FilterProvider: handleAppMessage received unrecognised payload")
        }
        completionHandler?(nil)
    }

    // MARK: - App matching

    private func appIsListed(_ signingId: String) -> Bool {
        guard !signingId.isEmpty else { return false }
        return config.apps.contains { listedId in
            signingId == listedId || signingId.hasPrefix(listedId + ".")
        }
    }
}
