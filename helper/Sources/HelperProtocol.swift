// Hand-maintained (unlike GeneratedVersion.swift, which follows package.json).
// Bump this ONLY when the helper's behaviour or RPC surface changes in a way the app depends on.
// The app compares it with its own REQUIRED_HELPER_PROTOCOL and reinstalls a stale helper after an
// update. A version bump with an unchanged helper must not change this number, or every release
// would ask users for an admin password.
enum HelperProtocol {
    static let current = 2
}
