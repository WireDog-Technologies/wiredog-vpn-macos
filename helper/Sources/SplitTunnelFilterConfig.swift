import Foundation

/// Split tunnel filter configuration passed from the helper daemon to the
/// WireDogFilter extension via sendProviderMessage / startVPNTunnel options.
///
/// Defined in both the helper daemon and the filter extension (separate Swift
/// packages/targets) — keep the two definitions in sync.
struct SplitTunnelFilterConfig: Codable {
    /// Routing mode: "exclude" (listed apps bypass VPN) or "include" (only listed apps use VPN).
    let mode: String

    /// Bundle IDs (CFBundleIdentifier) of apps subject to the split tunnel rule.
    /// Matched against NEFlowMetaData.sourceAppSigningIdentifier using prefix logic.
    let apps: [String]

    /// Whether the filter should actively apply routing decisions.
    let enabled: Bool
}
