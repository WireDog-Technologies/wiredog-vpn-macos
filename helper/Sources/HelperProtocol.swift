// Hand-maintained (unlike GeneratedVersion.swift, which follows package.json).
// Bump this ONLY when the helper's behaviour or RPC surface changes in a way the app depends on.
// The app compares it with its own REQUIRED_HELPER_PROTOCOL and reinstalls a stale helper after an
// update. A version bump with an unchanged helper must not change this number, or every release
// would ask users for an admin password.
//
// 3: getDiagnostics / setDiagnostics for Verbose Diagnostic Mode.
// 4: selfUpdate, and the helper runs from /Library/PrivilegedHelperTools (root-owned) instead of the app
//    bundle. The app requires 4: one admin-prompt reinstall moves every user over (the industry norm,
//    Mullvad and IVPN ask on every update), and every helper update after that is silent (selfUpdate).
enum HelperProtocol {
    static let current = 4
}

/// Verbose Diagnostic Mode: set by the app while VDM is on (setDiagnostics). While on, the helper logs every
/// request it handles and the full pf rules it loads. Starts off at every helper launch.
enum HelperDiagnostics {
    static var verbose = false
}
