import Foundation

/// Configuration passed from the helper daemon to the WireDogFilter extension
/// via NETransparentProxyProvider.handleAppMessage / startProxy options.
///
/// Shared struct — must be kept in sync with FilterManager.swift in the helper.
struct SplitTunnelFilterConfig: Codable {
    /// Routing mode: "exclude" (listed apps bypass VPN) or "include" (only listed apps use VPN).
    let mode: String

    /// Bundle IDs (CFBundleIdentifier) of apps subject to the split tunnel rule.
    /// Matched against NEFlowMetaData.sourceAppSigningIdentifier using prefix logic.
    let apps: [String]

    /// Whether the filter should actively apply routing decisions.
    /// Set to false when split tunneling is disabled without stopping the extension.
    let enabled: Bool
}
