const path = require('path');
const fs = require('fs');
const net = require('net');
const os = require('os');
const dns = require('dns').promises;
const { exec } = require('child_process');
const { app, safeStorage } = require('electron');
const log = require('electron-log');
const serviceClient = require('../ipc/service-client');
const { buildAllowedIPs } = require('../utils/cidrUtils');

// Thrown when a connect() attempt is aborted via cancelConnect() (user tapped Connect again
// while connecting/reconnecting). Distinguished from a real failure so callers can skip
// surfacing an error toast for it — mirrors iOS's VPNError.cancelled.
class ConnectCancelledError extends Error {
  constructor() {
    super('Connection cancelled');
    this.name = 'ConnectCancelledError';
  }
}

// Thrown when /vpn/connect rejects the auth token (expired/invalid). Distinguished by a
// fixed sentinel message so the renderer can detect it across the IPC boundary (only
// message/name/stack survive electron's ipcRenderer.invoke error serialization) and route
// the user back to login instead of leaving them stuck on a raw "Invalid token" toast.
class UnauthorizedError extends Error {
  constructor() {
    super('WIREDOG_UNAUTHORIZED');
    this.name = 'UnauthorizedError';
  }
}

// Extract the UDP port from an endpoint string like "1.2.3.4:443" or "host:443".
function extractEndpointPort(endpoint) {
  const str = (endpoint || '').trim();
  const lastColon = str.lastIndexOf(':');
  if (lastColon === -1) return 443;
  const port = parseInt(str.slice(lastColon + 1), 10);
  return Number.isInteger(port) && port > 0 && port <= 65535 ? port : 443;
}

// pf rules require literal IPv4 addresses — resolve hostnames before passing to the helper.
async function resolveServerIpv4(endpointHost) {
  const host = (endpointHost || '').split(':')[0];
  if (!host) return '';
  if (net.isIPv4(host)) return host;
  try {
    const { address } = await dns.lookup(host, { family: 4 });
    return address;
  } catch (err) {
    log.warn(`VPN: DNS resolve failed for ${host}: ${err.message}`);
    return '';
  }
}

// pf `pass quick on utunN` rules need the exact interface name. The helper runs in a
// separate process from the Network Extension, so it can't observe the tunnel directly —
// we locate the utun whose IPv4 matches the VPN address assigned in the config and pass
// that name down. Retries briefly because the interface may not appear the instant
// startTunnel() returns.
async function findTunnelInterface(vpnAddress, { attempts = 10, delayMs = 200 } = {}) {
  const target = (vpnAddress || '').split('/')[0].trim();
  if (!target) return '';
  for (let i = 0; i < attempts; i++) {
    const interfaces = os.networkInterfaces();
    for (const [name, addrs] of Object.entries(interfaces)) {
      if (!name.startsWith('utun')) continue;
      for (const addr of addrs || []) {
        if (addr.family === 'IPv4' && addr.address === target) {
          return name;
        }
      }
    }
    await new Promise(r => setTimeout(r, delayMs));
  }
  return '';
}

/**
 * VPN Service - Main facade for VPN operations (macOS)
 *
 * Tunnel operations (NETunnelProviderManager) go through the wiredog_native N-API addon
 * running inside the Electron process (user session context). This is required because
 * NETunnelProviderManager.loadAllFromPreferences() hangs indefinitely from a LaunchDaemon
 * (system session) when the extension binary has changed since last NE framework registration.
 *
 * Kill switch operations (pf management) still go through the helper daemon, which needs
 * root access for pfctl.
 */
class VPNService {
  constructor() {
    this.currentSession = null;
    this.settings = { killSwitch: false };
    this.statusCallbacks = [];
    this.apiBaseUrl = process.env.VITE_API_URL || (app.isPackaged ? 'https://api.wiredogvpn.com/api' : 'http://localhost:3001/api');
    this.helperConnected = false;
    this.helperInstalled = false;
    this.tunnelManagerLoaded = false;
    this.lastConnectionConfig = null;
    this.killSwitchState = 'disabled'; // disabled | bootstrap | connected | persistentBlock
    this.configStore = null; // electron-store, injected from main.js
    this._intentionalDisconnect = false; // true while disconnect() is in progress
    this._extensionApprovalCallback = null; // fired when extension is in activated_waiting_for_user
    this._tunnelManagerLoading = false;
    this._getAuthToken = null; // injected from main.js — () => decrypted auth token string

    // --- Connection-counter bookkeeping (mirrors iOS VPNService.swift) ---
    this.currentServerId = null;
    this.userInitiatedDisconnect = false; // persists across the whole disconnected period, unlike _intentionalDisconnect
    this.isReconnecting = false;
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 10;
    this.reconnectBaseDelay = 1.0; // seconds
    this.reconnectMaxDelay = 15.0; // seconds
    this.minimumStableConnectionDuration = 30; // seconds — a connection that drops before this never really established
    this.disconnectNotifyDelayMs = 1500; // time for tunnel to fully stop before notifying backend
    this.connectedSince = null;
    this._reconnectTimer = null;
    // Cooperative cancellation token for whichever connect() call is currently in flight
    // (either a first attempt or an auto-reconnect retry) — set by cancelConnect().
    this._connectAbortToken = null;
    // Guards against firing two concurrent /disconnect calls for the same session (e.g. a
    // crash-recovery retry and a foreground retry landing close together).
    this.sessionsPendingCleanup = new Set();
    this.hasHandledFirstFocusEvent = false;

    log.info('VPN Service initialized (macOS)');
    log.info('API Base URL:', this.apiBaseUrl);
  }

  /**
   * Inject the electron-store instance used for persisting the last known
   * connection config. Called once by main.js after the store is created.
   * Persisting config is what enables cold-start auto-reconnect when the
   * always-on kill switch left persistent_block pf rules in place — the
   * backend /vpn/connect API is unreachable in that state, so we need to
   * bootstrap the tunnel from cached WireGuard parameters instead.
   */
  setConfigStore(store) {
    this.configStore = store;
    try {
      const persisted = store.get('lastConnectionConfig');
      if (persisted && persisted.config && persisted.server) {
        // Reassemble: private key is stored separately, encrypted via OS Keychain
        const encryptedPrivKey = store.get('lastConnectionPrivateKey');
        if (encryptedPrivKey) {
          try {
            persisted.config.privateKey = safeStorage.isEncryptionAvailable()
              ? safeStorage.decryptString(Buffer.from(encryptedPrivKey, 'base64'))
              : encryptedPrivKey; // plaintext migration fallback
          } catch {
            log.warn('VPN: Failed to decrypt cached private key — cold-start reconnect may require manual connect');
          }
        }
        this.lastConnectionConfig = persisted;
        log.info('VPN: Restored lastConnectionConfig from store (server: %s)',
          persisted.server.id || persisted.server.serverId || 'unknown');
      }
    } catch (err) {
      log.warn('VPN: Failed to load persisted connection config:', err.message);
    }
  }

  /**
   * Inject a function that returns the current (decrypted) auth token. Needed because
   * auto-reconnect and pending-disconnect retries originate from inside VPNService itself,
   * not from an IPC call that already carries a token from the renderer.
   */
  setAuthTokenProvider(fn) {
    this._getAuthToken = fn;
  }

  // --- Pending-disconnect ledger (mirrors iOS's UserDefaults-backed pendingDisconnectIds) ---
  // A sessionId is written here *before* the network call is attempted, and only removed on
  // confirmed success, so a disconnect lost to a network blip / offline app survives to be
  // retried on next launch or foreground instead of leaking the backend counter forever.

  _pendingDisconnectIds() {
    if (!this.configStore) return [];
    return this.configStore.get('pendingDisconnectIds', []);
  }

  _addPendingDisconnect(sessionId) {
    if (!this.configStore) return;
    const ids = new Set(this._pendingDisconnectIds());
    ids.add(sessionId);
    this.configStore.set('pendingDisconnectIds', Array.from(ids));
  }

  _removePendingDisconnect(sessionId) {
    if (!this.configStore) return;
    const ids = new Set(this._pendingDisconnectIds());
    ids.delete(sessionId);
    this.configStore.set('pendingDisconnectIds', Array.from(ids));
  }

  /**
   * Best-effort notification to the backend that a session is no longer valid, so its
   * device-count slot is released. This is the single choke point every code path that could
   * leave a claimed-but-unreleased session routes through — mirrors iOS's cleanupOrphanedSession.
   *
   * The sessionId is persisted to the durable pending list *before* the network call, and only
   * removed on confirmed success — if the app has no connectivity right now, the call fails
   * silently, but the record survives so retryPendingDisconnects() can retry it later instead of
   * leaking the counter forever. The backend's /disconnect is NOT idempotent (unconditionally
   * decrements on every valid call), so sessionsPendingCleanup guards against firing two
   * concurrent calls for the same session.
   */
  cleanupOrphanedSession(sessionId, reason) {
    if (this.sessionsPendingCleanup.has(sessionId)) return;
    this.sessionsPendingCleanup.add(sessionId);

    log.info(`VPN: cleaning up orphaned session (${reason})`);
    this._addPendingDisconnect(sessionId);

    setTimeout(async () => {
      try {
        const token = this._getAuthToken ? this._getAuthToken() : '';
        const headers = { 'Content-Type': 'application/json' };
        if (token) headers['Authorization'] = `Bearer ${token}`;
        const response = await fetch(`${this.apiBaseUrl}/vpn/disconnect`, {
          method: 'POST',
          headers,
          credentials: 'include',
          body: JSON.stringify({ sessionId }),
        });
        if (response.ok) {
          this._removePendingDisconnect(sessionId);
        }
        // Non-ok: left in the pending list, retried via retryPendingDisconnects() later.
      } catch (err) {
        log.warn('VPN: cleanupOrphanedSession disconnect failed (will retry):', err.message);
        // Left in the pending list — retried via retryPendingDisconnects() later.
      } finally {
        this.sessionsPendingCleanup.delete(sessionId);
      }
    }, this.disconnectNotifyDelayMs);
  }

  /**
   * Retries any /disconnect calls that were owed but never confirmed — e.g. the app had no
   * connectivity right as cleanupOrphanedSession()'s call went out, so nothing ever reached
   * the backend. Safe to call unconditionally: each retry goes through cleanupOrphanedSession()'s
   * own in-flight guard.
   */
  retryPendingDisconnects() {
    for (const sessionId of this._pendingDisconnectIds()) {
      this.cleanupOrphanedSession(sessionId, 'retrying pending disconnect from previous launch');
    }
  }

  /**
   * Called when the app returns to the foreground (window focus). Mirrors iOS's
   * willEnterForeground handler: its very first firing coincides with the cold-start retry
   * initialize() already performs, so it's skipped there in favor of that one.
   */
  handleAppForeground() {
    if (this.hasHandledFirstFocusEvent) {
      this.retryPendingDisconnects();
    } else {
      this.hasHandledFirstFocusEvent = true;
    }
  }

  _persistLastConnectionConfig() {
    if (!this.configStore) return;
    try {
      if (this.lastConnectionConfig) {
        // Split the private key out — store it encrypted separately via OS Keychain.
        // Everything else (server metadata, endpoint, serverPublicKey, allowedIPs) is non-secret
        // and can safely live in electron-store.
        const { config, ...rest } = this.lastConnectionConfig;
        const { privateKey, ...safeConfig } = config || {};
        this.configStore.set('lastConnectionConfig', { ...rest, config: safeConfig });
        if (privateKey) {
          const encrypted = safeStorage.isEncryptionAvailable()
            ? safeStorage.encryptString(privateKey).toString('base64')
            : privateKey; // fallback: store plaintext if Keychain unavailable
          this.configStore.set('lastConnectionPrivateKey', encrypted);
        }
      } else {
        this.configStore.set('lastConnectionConfig', null);
        this.configStore.delete('lastConnectionPrivateKey');
      }
    } catch (err) {
      log.warn('VPN: Failed to persist connection config:', err.message);
    }
  }

  /**
   * Initialize the VPN service.
   * Connects to the helper daemon, loads the tunnel manager, and registers
   * for tunnel status notifications.
   */
  async initialize() {
    // Retry any /disconnect calls that were owed but never confirmed from a previous launch —
    // independent of helper/tunnel-manager availability below, this is a pure HTTP call against
    // the durable pending-disconnect ledger. Mirrors iOS's loadVPNManager() cold-start retry.
    this.retryPendingDisconnects();

    // Check if helper daemon is installed
    // Helper binary lives inside the app bundle so Bundle.main resolves to the Electron app
    const helperPath = app.isPackaged
      ? path.join(path.dirname(process.resourcesPath), 'MacOS', 'wiredog-helper')
      : path.join(__dirname, '../../helper/.build/release/wiredog-helper');
    this.helperInstalled = fs.existsSync(helperPath);

    if (this.helperInstalled) {
      try {
        await serviceClient.connect();
        const ping = await serviceClient.ping();
        log.info('VPN: Helper daemon connected (version: %s)', ping.version);
        this.helperConnected = true;
        this.helperVersion = ping.version || null;

        await this._checkHelperVersionMismatch();

        // Activate system extension and load tunnel manager.
        // The sysext addon returns PENDING when waiting for user approval in System Settings.
        this._activateSysext();

        // Sync in-memory kill switch state with what the helper actually
        // has applied. Without this the JS side defaults to 'disabled' after
        // an app restart, and the persistent_block → bootstrap fast path in
        // connect() never fires, so we'd try to hit the (blocked) backend
        // API instead of reusing the cached WireGuard config.
        try {
          const ksState = await serviceClient.request('getKillSwitchState');
          if (ksState?.state === 'persistent_block') {
            this.killSwitchState = 'persistentBlock';
            this.settings.permanentKillSwitch = true;
            log.info('VPN: Restored kill switch state: persistentBlock');
          } else if (ksState?.state === 'bootstrap') {
            this.killSwitchState = 'bootstrap';
          } else if (ksState?.state === 'connected') {
            this.killSwitchState = 'connected';
          }
          if (ksState?.advancedEnabled) {
            this.settings.permanentKillSwitch = true;
          }
        } catch (err) {
          log.warn('VPN: getKillSwitchState failed:', err.message);
        }

        // Crash recovery: if we have a persisted sessionId but the tunnel is not
        // currently active, the previous app instance exited without cleanly calling
        // /disconnect. Send a best-effort disconnect now so the backend counter
        // decrements correctly. Keep the WireGuard config intact — the kill-switch
        // reconnect path may still need it.
        if (this.lastConnectionConfig?.sessionId) {
          try {
            const _crashAddon = this._getNativeAddon();
            const tunnelStatusStr = _crashAddon ? _crashAddon.getStatus() : 'disconnected';

            if (tunnelStatusStr === 'disconnected') {
              log.info('VPN: Startup crash recovery — cleaning up stale session %s',
                this.lastConnectionConfig.sessionId);

              // Durable cleanup — if this fails (no connectivity yet at cold start), the
              // sessionId survives in the pending-disconnect ledger and gets retried by
              // retryPendingDisconnects() on a later launch/foreground instead of being
              // forgotten outright.
              this.cleanupOrphanedSession(this.lastConnectionConfig.sessionId, 'crash recovery — stale session');

              // Clear the stale sessionId but preserve the WireGuard config
              // so the kill-switch persistent-block reconnect path can still use it
              this.lastConnectionConfig.sessionId = null;
              this._persistLastConnectionConfig();
            }
          } catch (err) {
            log.warn('VPN: Startup crash recovery check failed:', err.message);
          }
        }
      } catch (error) {
        log.warn('VPN: Helper daemon not available:', error.message);
        this.helperConnected = false;
        // Binary is present but daemon is not running (likely in launchd penalty box
        // from a previous crash loop). Trigger reinstall now so the admin prompt
        // appears on app launch rather than silently failing at connect time.
        log.info('VPN: Helper binary found but daemon unreachable — prompting for reinstall...');
        this.installHelper().catch(err => {
          log.warn('VPN: Startup helper reinstall failed:', err.message);
        });
      }
    } else {
      log.info('VPN: Helper daemon not installed (VPN unavailable until installed)');
    }
  }

  /**
   * Install the helper daemon with admin privileges.
   * Prompts the user for their password via macOS authorization dialog.
   * @returns {Promise<boolean>} true if installation succeeded
   */
  async installHelper() {
    // Helper binary is in Contents/MacOS/ (same bundle as Electron app)
    const helperBin = app.isPackaged
      ? path.join(path.dirname(process.resourcesPath), 'MacOS', 'wiredog-helper')
      : path.join(__dirname, '../../helper/.build/release/wiredog-helper');
    const plistFile = app.isPackaged
      ? path.join(process.resourcesPath, 'helper', 'com.wiredog.vpn.helper.plist')
      : path.join(__dirname, '../../helper/com.wiredog.vpn.helper.plist');
    const installScript = app.isPackaged
      ? path.join(process.resourcesPath, 'helper', 'install-helper.sh')
      : path.join(__dirname, '../../helper/install-helper.sh');

    if (!fs.existsSync(helperBin)) {
      throw new Error('Helper binary not found. Build with: scripts/build-helper.sh');
    }

    log.info('VPN: Installing helper daemon (requesting admin privileges)...');
    log.info('VPN: Install script:', installScript);
    log.info('VPN: Helper binary:', helperBin);

    return new Promise((resolve, reject) => {
      const cmd = `osascript -e 'do shell script "bash \\"${installScript}\\" \\"${helperBin}\\" \\"${plistFile}\\"" with administrator privileges'`;

      exec(cmd, (error, stdout, stderr) => {
        if (error) {
          log.error('VPN: Helper installation failed:', error.message);
          if (error.message.includes('User canceled')) {
            reject(new Error('Installation canceled by user'));
          } else {
            reject(error);
          }
          return;
        }

        log.info('VPN: Helper daemon installed successfully');
        log.info('Install output:', stdout);
        this.helperInstalled = true;

        // Poll for socket availability — the install script already verified the socket
        // exists, but the daemon may still be initializing when we get here.
        const tryConnect = async (attemptsLeft) => {
          try {
            await serviceClient.connect();
            const ping = await serviceClient.ping();
            log.info('VPN: Connected to newly installed helper (version: %s)', ping.version);
            this.helperConnected = true;
            serviceClient.onNotification('tunnelStatusChanged', (params) => {
              this._handleTunnelStatusChange(params?.status ?? 'disconnected');
            });
            // Activate the system extension now that the helper is confirmed running
            this._activateSysext();
            resolve(true);
          } catch (err) {
            if (attemptsLeft > 0) {
              log.info(`VPN: Helper not ready yet, retrying... (${attemptsLeft} attempts left)`);
              setTimeout(() => tryConnect(attemptsLeft - 1), 1000);
            } else {
              log.warn('VPN: Could not connect to helper after install:', err.message);
              resolve(false);
            }
          }
        };
        setTimeout(() => tryConnect(5), 500);
      });
    });
  }

  /**
   * Ensure helper daemon is available, installing if needed.
   * @returns {Promise<boolean>}
   */
  async ensureHelperAvailable() {
    if (this.helperConnected) return true;

    // Always reinstall — launchctl kickstart requires root (we don't have it),
    // and if the socket is dead the daemon is either in launchd penalty box or
    // not registered. osascript runs the install script as admin which does
    // bootout + bootstrap, clearing any penalty-box state.
    try {
      await this.installHelper();
      await serviceClient.connect();
      const ping = await serviceClient.ping();
      this.helperConnected = true;
      return true;
    } catch (error) {
      log.warn('VPN: Helper daemon connection failed after reinstall:', error.message);
      return false;
    }
  }

  /**
   * Load the wiredog_native addon (lazy, cached after first load).
   * This addon runs inside the Electron process and can use APIs that require
   * entitlements on the .app bundle (e.g. app-proxy-provider for NEAppProxyProviderManager).
   */
  _getNativeAddon() {
    if (this._nativeAddon !== undefined) return this._nativeAddon;
    try {
      const addonPath = app.isPackaged
        ? path.join(process.resourcesPath, 'native', 'wiredog_native.node')
        : path.join(__dirname, '../../native/build/Release/wiredog_native.node');
      this._nativeAddon = require(addonPath);
      log.info('VPN: wiredog_native addon loaded');
    } catch (err) {
      log.warn('VPN: wiredog_native addon not available:', err.message);
      this._nativeAddon = null;
    }
    return this._nativeAddon;
  }

  /**
   * Register a callback fired when the system extension needs user approval
   * (OSSystemExtensionManager returns PENDING / activated_waiting_for_user in
   * sysextd). Main process uses this to show a native dialog guiding the user
   * to System Settings → General → Login Items & Extensions.
   */
  onExtensionNeedsApproval(callback) {
    this._extensionApprovalCallback = callback;
  }

  /**
   * Register a callback fired once the extension actually finishes activating
   * — including the delayed completion that follows a prior PENDING, once the
   * user approves it in System Settings. Lets the UI confirm "you're ready to
   * connect" instead of leaving the user to guess whether it worked.
   */
  onExtensionActivated(callback) {
    this._extensionActivatedCallback = callback;
  }

  _notifyExtensionNeedsApproval() {
    if (this._extensionApprovalCallback) {
      this._extensionApprovalCallback();
    }
  }

  _notifyExtensionActivated() {
    if (this._extensionActivatedCallback) {
      this._extensionActivatedCallback();
    }
  }

  /**
   * Activate the system extension via the native sysext addon and eagerly load
   * the tunnel manager (creating the VPN config profile if it doesn't exist yet).
   *
   * The sysext addon calls OSSystemExtensionManager from within the Electron process
   * (which has system-extension.install). The NE entitlement (packet-tunnel-provider-
   * systemextension) in entitlements.mac.plist lets loadManager() call saveToPreferences().
   */
  _activateSysext() {
    const sysextAddonPath = app.isPackaged
      ? path.join(process.resourcesPath, 'sysext', 'wiredog_sysext.node')
      : path.join(__dirname, '../../native-sysext/build/Release/wiredog_sysext.node');

    try {
      const sysextAddon = require(sysextAddonPath);
      let wasPending = false;
      // This callback can fire more than once: PENDING first (interim notice),
      // then a terminal result (ACTIVATED/REBOOT_REQUIRED/ERROR) once the
      // request actually completes — including after the user approves
      // following a PENDING. See native-sysext/src/sysext_activate.mm.
      sysextAddon.activate('com.wiredog.vpn.macos.tunnel', (result) => {
        log.info('VPN: System extension activation result:', result);
        if (result === 'PENDING') {
          wasPending = true;
          this._notifyExtensionNeedsApproval();
        } else if (result === 'ACTIVATED' && wasPending) {
          log.info('VPN: Extension approved by user — now activated');
          this._notifyExtensionActivated();
        }
      });
    } catch (e) {
      log.warn('VPN: native-sysext addon not available:', e.message);
    }

    // Eagerly load (or create) the tunnel manager config. Even if the extension
    // is not yet approved, saveToPreferences() works and the manager will observe
    // status changes via KVO once the extension is eventually approved.
    this._loadTunnelManagerIfNeeded();
  }

  _loadTunnelManagerIfNeeded() {
    if (this.tunnelManagerLoaded || this._tunnelManagerLoading) return;
    this._tunnelManagerLoading = true;
    const addon = this._getNativeAddon();
    if (!addon) { this._tunnelManagerLoading = false; return; }
    addon.loadManager()
      .then(() => {
        this._tunnelManagerLoading = false;
        if (!this.tunnelManagerLoaded) {
          this.tunnelManagerLoaded = true;
          addon.onStatusChange((status) => {
            this._handleTunnelStatusChange(status);
          });
          log.info('VPN: Tunnel manager loaded');
        }
      })
      .catch(err => {
        this._tunnelManagerLoading = false;
        log.warn('VPN: loadManager failed (will retry on connect):', err.message);
      });
  }

  /**
   * Ensure the tunnel manager is loaded. loadManager() creates the VPN config
   * if one doesn't exist (container app now has packet-tunnel-provider-systemextension).
   */
  async ensureExtensionActive() {
    if (!this.tunnelManagerLoaded) {
      const addon = this._getNativeAddon();
      if (!addon) throw new Error('Native addon not available — cannot load tunnel manager');
      try {
        await addon.loadManager();
        this.tunnelManagerLoaded = true;
        addon.onStatusChange((status) => {
          this._handleTunnelStatusChange(status);
        });
        log.info('VPN: Tunnel manager loaded');
      } catch (err) {
        throw new Error(`Failed to initialize VPN tunnel manager: ${err.message}`);
      }
    }
  }

  /**
   * Restore session from persisted data
   */
  restoreSession(savedSession) {
    if (!this.currentSession && savedSession) {
      this.currentSession = savedSession;
      // Needed so an unexpected drop after a restart-while-connected can still auto-reconnect
      // (see _attemptReconnect, which reconnects by currentServerId).
      this.currentServerId = savedSession.server?.id ?? savedSession.server?.serverId ?? null;
      log.info('VPN: Restored session from saved state');
    }
  }

  /**
   * Connect to a VPN server
   */
  async connect(serverId, settings, token = '') {
    log.info(`VPN: Connect request to server ${serverId}`);
    this.settings = settings;

    // Cooperative cancellation token for this specific attempt — cancelConnect() flips
    // .cancelled on whatever token is current; checked at the same two checkpoints iOS uses
    // (right before and right after starting the tunnel).
    const abortToken = { cancelled: false };
    this._connectAbortToken = abortToken;

    // Helper daemon is required for tunnel operations
    const available = await this.ensureHelperAvailable();
    if (!available) {
      throw new Error('Helper daemon is required for VPN. Installation was canceled or failed.');
    }

    // Kill switch and split tunneling are mutually exclusive — enforce at service layer
    if (settings.splitTunneling?.enabled && (settings.killSwitch || settings.permanentKillSwitch)) {
      throw new Error('Split tunneling and kill switch cannot be active simultaneously. Disable one before connecting.');
    }

    // Ensure system extension is activated and tunnel manager is loaded
    await this.ensureExtensionActive();

    this.connectedSince = null;
    if (!this.isReconnecting) {
      this.userInitiatedDisconnect = false;
      this.reconnectAttempts = 0;
    }

    // Declared outside the try block so the catch clause below can see whether a sessionId
    // was already claimed from the backend (and thus already incremented the counter) before
    // something later in this function threw.
    let config, sessionId, server;
    let usedCachedConfig = false;

    try {
      // If we're in persistentBlock with cached config for this same server,
      // skip the API call (it would be blocked by pf rules anyway) and reuse
      // the cached WireGuard config. Matches Windows auto-reconnect behavior.
      const cached = this.lastConnectionConfig;
      const cachedServerId = cached?.server?.serverId ?? cached?.server?.id;
      if (
        this.killSwitchState === 'persistentBlock' &&
        cached &&
        cachedServerId === serverId
      ) {
        log.info('VPN: Reconnecting from persistentBlock with cached config (skipping API fetch)');
        config = { ...cached.config };
        sessionId = cached.sessionId;
        server = cached.server;
        usedCachedConfig = true;
        this.currentServerId = serverId;
      } else {
        // Fetch connection config from backend API
        log.info('VPN: Fetching connection config from backend...');
        const headers = { 'Content-Type': 'application/json' };
        if (token) {
          headers['Authorization'] = `Bearer ${token}`;
        }

        // 5s hard timeout — when persistent_block pf rules are still active
        // (cold-start reconnect without cached config), pf drops SYNs silently
        // and fetch() would otherwise hang ~75s on TCP timeout.
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000);
        let response;
        try {
          response = await fetch(`${this.apiBaseUrl}/vpn/connect`, {
            method: 'POST',
            headers,
            credentials: 'include',
            body: JSON.stringify({
              serverId,
              localMode: settings.localMode || false,
              blockAds: settings.blockAdsEnabled ?? true,
              blockMalware: settings.blockMalwareEnabled ?? true,
            }),
            signal: controller.signal,
          });
        } catch (err) {
          if (err.name === 'AbortError') {
            throw new Error('Backend unreachable — kill switch may be blocking the API. Disable the kill switch or use Emergency Reset.');
          }
          throw err;
        } finally {
          clearTimeout(timeoutId);
        }

        if (!response.ok) {
          const error = await response.json().catch(() => ({ error: 'Unknown error' }));
          // The backend reuses 429 for the 5-device connection cap (the only source of 429 on
          // this endpoint) — surface a clean, actionable message instead of the raw backend text.
          if (response.status === 429 && error.error?.includes('Connection limit exceeded')) {
            throw new Error("You've reached your 5-device limit. Disconnect another device to continue.");
          }
          if (response.status === 401) {
            throw new UnauthorizedError();
          }
          throw new Error(error.error || `API error: ${response.status}`);
        }

        const responseData = await response.json();
        ({ config, sessionId, server } = responseData);
        this.currentServerId = serverId;

        log.info('VPN: Received connection config');
        log.info('VPN: Server location:', server?.city ? `${server.city}, ${server.stateCode || ''}` : 'unknown');

        // Flatten nested peer structure
        if (config.peer) {
          config.endpoint = config.endpoint || config.peer.endpoint;
          config.serverPublicKey = config.serverPublicKey || config.peer.publicKey || config.peer.serverPublicKey;
          config.allowedIPs = config.allowedIPs || config.peer.allowedIPs;
          config.persistentKeepalive = config.persistentKeepalive || config.peer.persistentKeepalive;
        }

        // Cache for potential reconnection (in-memory + persisted to disk
        // so cold-start auto-reconnect from persistent_block can skip the
        // blocked /vpn/connect call).
        this.lastConnectionConfig = { config: { ...config }, sessionId, server };
        this._persistLastConnectionConfig();
      }

      // Resolve the server's IPv4 address once — reused for kill switch rules and publicIp display.
      const resolvedServerIp = await resolveServerIpv4(config.endpoint).catch(() => '');
      const serverPort = extractEndpointPort(config.endpoint);

      // Transition kill switch to bootstrap state before starting tunnel
      if (settings.killSwitch && this.helperConnected) {
        try {
          if (!resolvedServerIp) throw new Error(`could not resolve ${config.endpoint} to IPv4`);
          await this._updateKillSwitchState('bootstrap', { serverIp: resolvedServerIp, serverPort });
        } catch (ksError) {
          log.warn('VPN: Kill switch bootstrap failed:', ksError.message);
        }
      }

      // Start the split tunnel filter extension BEFORE the tunnel so it is ready
      // to intercept flows as soon as the VPN tunnel comes up.  Starting it after
      // the tunnel causes a brief window where excluded-app traffic goes through the
      // tunnel before the transparent proxy provider initialises.
      //
      // The filter extension is managed via NEAppProxyProviderManager, which requires
      // the app-proxy-provider entitlement. This must run in the Electron app process
      // (via the native addon) — the helper daemon cannot hold this entitlement.
      if (settings.splitTunneling?.enabled && settings.splitTunneling.apps?.length > 0) {
        const bundleIds = settings.splitTunneling.apps
          .map(a => a.bundleId)
          .filter(Boolean);
        if (bundleIds.length > 0) {
          try {
            const native = this._getNativeAddon();
            if (native) {
              await native.loadFilterManager();
              await native.startFilter(settings.splitTunneling.mode, bundleIds);
              log.info(`VPN: Split tunnel filter started (${settings.splitTunneling.mode} mode, ${bundleIds.length} app(s)):`, bundleIds);
            } else {
              log.warn('VPN: native addon not available — split tunnel filter not started');
            }
          } catch (filterErr) {
            log.warn('VPN: Failed to start split tunnel filter:', filterErr.message);
          }
        }
      }

      // Start tunnel via native addon (NETunnelProviderManager in user-session context)
      log.info('VPN: Starting tunnel via native addon...');

      // Build allowedIPs: start from server-provided default, apply IPv6 filter,
      // then apply split tunnel IP rules if enabled.
      let allowedIPs = config.allowedIPs || '0.0.0.0/0, ::/0';
      if (!settings.ipv6Enabled) {
        // Remove IPv6 routes if IPv6 is disabled
        allowedIPs = allowedIPs.split(',').map(ip => ip.trim()).filter(ip => !ip.includes(':')).join(', ');
      }

      // Apply IP-based split tunneling rules.
      // buildAllowedIPs handles both include and exclude modes and returns a
      // WireGuard-ready allowedIPs string. Only applied when there are IPs configured;
      // an empty list leaves the full default in place (no IP splitting).
      if (settings.splitTunneling?.enabled && settings.splitTunneling.ips?.length > 0) {
        allowedIPs = buildAllowedIPs(settings.splitTunneling, settings.ipv6Enabled ?? true);
        log.info(`VPN: Split tunnel (${settings.splitTunneling.mode}) — allowedIPs computed from ${settings.splitTunneling.ips.length} rule(s)`);
      }

      const tunnelAddon = this._getNativeAddon();
      if (!tunnelAddon) throw new Error('Native addon not available — cannot start tunnel');
      const awg = config.awg || {};
      log.info('VPN: AWG params — Jc=%s Jmin=%s Jmax=%s S1=%s S2=%s H1=%s H2=%s H3=%s H4=%s',
        awg.Jc ?? 'nil', awg.Jmin ?? 'nil', awg.Jmax ?? 'nil', awg.S1 ?? 'nil', awg.S2 ?? 'nil',
        awg.H1 ?? 'nil', awg.H2 ?? 'nil', awg.H3 ?? 'nil', awg.H4 ?? 'nil');
      log.info('VPN: endpoint=%s dns=%s address=%s allowedIPs=%s', config.endpoint, config.dns, config.address, allowedIPs);

      // A cancel (tap-again-to-cancel) may have arrived while awaiting everything above —
      // check before starting the tunnel, mirroring iOS's Task.checkCancellation().
      if (abortToken.cancelled) throw new ConnectCancelledError();

      await tunnelAddon.startTunnel({
        privateKey: config.privateKey,
        address: config.address,
        dns: config.dns || '10.64.0.1',
        serverPublicKey: config.serverPublicKey,
        endpoint: config.endpoint,
        allowedIPs,
        persistentKeepalive: config.persistentKeepalive || 25,
        includeAllNetworks: settings.killSwitch || false,
        excludeLocalNetworks: true,
        awgJc: awg.Jc,
        awgJmin: awg.Jmin,
        awgJmax: awg.Jmax,
        awgS1: awg.S1,
        awgS2: awg.S2,
        awgH1: awg.H1,
        awgH2: awg.H2,
        awgH3: awg.H3,
        awgH4: awg.H4,
      });

      // The tunnel just started — if a cancel landed in the narrow window right around this
      // call, tear it back down immediately rather than leaving an untracked live tunnel.
      if (abortToken.cancelled) {
        tunnelAddon.stopTunnel();
        throw new ConnectCancelledError();
      }

      // Kill switch connected-state transition (status notification will also trigger this)
      if (settings.killSwitch && this.helperConnected) {
        try {
          if (!resolvedServerIp) throw new Error(`could not resolve ${config.endpoint} to IPv4`);
          const tunnelInterface = await findTunnelInterface(config.address);
          if (!tunnelInterface) {
            log.warn(`VPN: could not find utun interface for ${config.address}; helper will defer connected rules`);
          }
          await this._updateKillSwitchState('connected', { serverIp: resolvedServerIp, serverPort, tunnelInterface });
        } catch (ksError) {
          log.warn('VPN: Kill switch connected-state transition failed:', ksError.message);
        }
      }

      // Store session info
      // publicIp = the backend-assigned per-session SNAT exit IP (server.exitIp) —
      // this is what external services actually see when the tunnel is active.
      // resolvedServerIp (the tunnel endpoint) is only a fallback for sessions
      // where the backend didn't return an exitIp.
      this.currentSession = {
        sessionId,
        server,
        assignedIp: config.address,
        publicIp: server?.exitIp || resolvedServerIp || server?.ipAddress || '',
        connectedAt: new Date().toISOString()
      };

      log.info('VPN: Connected successfully');
      // Do NOT call notifyStatusChange() here — the NE tunnel is still starting at this
      // point and the helper would report 'disconnected' or 'connecting', causing the
      // frontend to flicker. The tunnelStatusChanged notification from the helper daemon
      // will push the authoritative 'connected' status when the tunnel is actually up.

      // If we reconnected from cache, fire-and-forget a fresh /vpn/connect so
      // the backend's session tracking catches up now that HTTPS is unblocked.
      if (usedCachedConfig) {
        const headers = { 'Content-Type': 'application/json' };
        if (token) headers['Authorization'] = `Bearer ${token}`;
        fetch(`${this.apiBaseUrl}/vpn/connect`, {
          method: 'POST',
          headers,
          credentials: 'include',
          body: JSON.stringify({
            serverId,
            localMode: settings.localMode || false,
            blockAds: settings.blockAdsEnabled ?? true,
            blockMalware: settings.blockMalwareEnabled ?? true,
          })
        })
          .then(resp => resp.ok
            ? resp.json().then(data => {
                if (data?.sessionId) {
                  this.currentSession.sessionId = data.sessionId;
                  this.lastConnectionConfig.sessionId = data.sessionId;
                }
              })
            : log.warn(`VPN: Post-reconnect backend sync failed: ${resp.status}`))
          .catch(err => log.warn('VPN: Post-reconnect backend sync failed:', err.message));
      }

      return this.currentSession;

    } catch (error) {
      if (error instanceof ConnectCancelledError) {
        // User-initiated cancel (tap-again-to-cancel) — expected, not a failure.
        log.info('VPN: Connect cancelled');
      } else if (error instanceof UnauthorizedError) {
        log.warn('VPN: Connect failed — auth token rejected by backend (expired or invalid)');
      } else {
        log.error('VPN: Connection failed:', error);
      }
      // If we obtained a sessionId from a *fresh* /vpn/connect call (thus incrementing the
      // backend's device counter) before something later in this function failed, release it —
      // mirrors iOS's cleanupLeakedSessionIfNeeded(). Scoped to the non-cached path only: in the
      // persistentBlock cached-config-reuse path, sessionId came from an already-tracked session
      // rather than a fresh claim, so there is nothing new here to release.
      if (sessionId && !usedCachedConfig) {
        this.cleanupOrphanedSession(sessionId, 'connect() threw after sessionId obtained');
        if (!this.isReconnecting) {
          this.currentServerId = null;
        }
      }
      throw error;
    }
  }

  /**
   * Cancels an in-progress connect() — either a first attempt (still awaiting the backend or
   * the tunnel starting) or an in-progress auto-reconnect loop (backoff wait or an active retry
   * attempt). Mirrors iOS's cancelConnect()/VPNManager.cancelConnect() split, collapsed into one
   * method since macOS has no separate caller-owned Task to cancel independently.
   */
  cancelConnect() {
    log.info('VPN: Cancel connect requested');

    // Flips whichever connect() call is currently in flight (first attempt or an active
    // reconnect retry) — checked cooperatively at the two checkpoints inside connect().
    if (this._connectAbortToken) {
      this._connectAbortToken.cancelled = true;
    }

    if (this.isReconnecting) {
      this.userInitiatedDisconnect = true;
      clearTimeout(this._reconnectTimer);
      this._reconnectTimer = null;
      this.isReconnecting = false;
      this.reconnectAttempts = 0;
      // A previous retry may have already claimed a session (and thus incremented the counter)
      // before this cancel arrived — release it so the counter stays net-zero.
      if (this.currentSession?.sessionId) {
        this.disconnect().catch(err => log.warn('VPN: cancelConnect disconnect failed:', err.message));
      }
    }
  }

  /**
   * Disconnect from VPN
   */
  async disconnect(token = '', disableProtection = true) {
    log.info(`VPN: Disconnect request (disableProtection=${disableProtection})`);

    // Persists across the whole disconnected period (unlike _intentionalDisconnect, which is
    // reset in the finally block below) so a status notification arriving after disconnect()
    // has already returned is still correctly recognized as user-initiated, not an unexpected
    // drop — mirrors iOS's userInitiatedDisconnect, only reset at the start of the next connect().
    this.userInitiatedDisconnect = true;
    clearTimeout(this._reconnectTimer);
    this._reconnectTimer = null;
    this.isReconnecting = false;
    this.reconnectAttempts = 0;
    this.currentServerId = null;
    this.connectedSince = null;

    this._intentionalDisconnect = true;
    try {
      const addon = this._getNativeAddon();
      if (addon) {
        addon.stopTunnel();

        // Stop the split tunnel filter extension if it was running
        try {
          addon.stopFilter();
        } catch (filterErr) {
          log.debug('VPN: stopFilter skipped or failed:', filterErr.message);
        }
      }

      // Transition kill switch state on disconnect
      if (disableProtection) {
        try {
          await this._updateKillSwitchState('disabled');
        } catch (ksError) {
          log.warn('VPN: Kill switch disable failed:', ksError.message);
        }
      } else if (this.settings.permanentKillSwitch) {
        try {
          await this._updateKillSwitchState('persistentBlock');
        } catch (ksError) {
          log.warn('VPN: Kill switch persistent block failed:', ksError.message);
        }
      }

      // Notify backend — durable cleanup (persisted + retried on failure) rather than a bare
      // fire-and-forget fetch, so a disconnect lost to a network blip doesn't leak the counter.
      if (this.currentSession) {
        this.cleanupOrphanedSession(this.currentSession.sessionId, 'user-initiated disconnect');
      }

      this.currentSession = null;
      if (disableProtection) {
        this.lastConnectionConfig = null;
        this._persistLastConnectionConfig();
      }
      log.info('VPN: Disconnected successfully');
      this.notifyStatusChange();

    } catch (error) {
      log.error('VPN: Disconnect error:', error);
      this.currentSession = null;
      this.notifyStatusChange();
      throw error;
    } finally {
      this._intentionalDisconnect = false;
    }
  }

  /**
   * Get full VPN status
   */
  async getFullStatus() {
    try {
      let status = 'disconnected';
      let killSwitchEnabled = false;
      let advancedKillSwitchEnabled = false;
      let advancedKillSwitchActive = false;

      // Get tunnel status from native addon (synchronous, always available if addon loaded)
      const statusAddon = this._getNativeAddon();
      if (statusAddon) {
        try {
          status = statusAddon.getStatus() || 'disconnected';
        } catch (e) {
          status = this.currentSession ? 'connected' : 'disconnected';
        }
      } else if (this.currentSession) {
        status = 'connected'; // Optimistic if native addon unavailable
      }

      // Map intermediate NE states based on whether a session is active:
      // - With session: tunnel is reconnecting internally, keep showing 'connected'
      // - Without session: tunnel is shutting down or never started, show 'disconnected'
      //   (prevents the push from notifyStatusChange() in disconnect() overriding the
      //   IPC return and leaving the UI permanently stuck on 'connecting')
      if (status === 'connecting' || status === 'disconnecting' || status === 'reasserting') {
        status = this.currentSession ? 'connected' : 'disconnected';
      }

      // During an auto-reconnect backoff wait, the tunnel is genuinely down (no session, no
      // native transition) so the mapping above reports 'disconnected' — override so the UI
      // shows the same in-progress affordance (and cancel button) as a first connect attempt.
      if (this.isReconnecting) {
        status = 'connecting';
      }

      // Query helper daemon for kill switch state
      if (this.helperConnected) {
        try {
          const ksState = await serviceClient.request('getKillSwitchState');
          advancedKillSwitchEnabled = ksState.advancedEnabled || false;
          advancedKillSwitchActive = ksState.advancedActive || false;
          killSwitchEnabled = advancedKillSwitchActive;
        } catch (e) {
          // Helper not available
        }
      }

      return {
        status,
        session: this.currentSession,
        killSwitchEnabled,
        advancedKillSwitchEnabled,
        advancedKillSwitchActive,
        isReconnecting: this.isReconnecting
      };
    } catch (error) {
      return {
        status: this.isReconnecting ? 'connecting' : 'disconnected',
        session: this.currentSession,
        killSwitchEnabled: false,
        advancedKillSwitchEnabled: false,
        advancedKillSwitchActive: false,
        isReconnecting: this.isReconnecting
      };
    }
  }

  /**
   * Get connection statistics
   */
  async getStats() {
    try {
      const addon = this._getNativeAddon();
      if (!addon) {
        return null;
      }
      const stats = await addon.getStats();
      return {
        bytesReceived: stats.bytesIn.toString(),
        bytesSent: stats.bytesOut.toString()
      };
    } catch (error) {
      return null;
    }
  }

  /**
   * Enable advanced (permanent) kill switch.
   * If the helper daemon isn't installed yet, prompts for admin install.
   */
  async enableAdvancedKillSwitch() {
    log.info('VPN: Enable advanced kill switch');

    const available = await this.ensureHelperAvailable();
    if (!available) {
      throw new Error('Helper daemon is required for the advanced kill switch. Installation was canceled or failed.');
    }

    await serviceClient.request('enableAdvancedKillSwitch');
    this.settings.permanentKillSwitch = true;
    log.info('VPN: Advanced kill switch enabled');
    this.notifyStatusChange();
  }

  /**
   * Disable advanced (permanent) kill switch
   */
  async disableAdvancedKillSwitch() {
    log.info('VPN: Disable advanced kill switch');
    if (this.helperConnected) {
      await serviceClient.request('disableAdvancedKillSwitch');
    }
    this.settings.permanentKillSwitch = false;
    log.info('VPN: Advanced kill switch disabled');
    this.notifyStatusChange();
  }

  /**
   * Emergency reset: stop tunnel and flush all pf rules
   */
  async emergencyReset() {
    log.info('VPN: Emergency reset requested');
    try {
      const addon = this._getNativeAddon();
      if (addon) addon.stopTunnel();
      if (this.helperConnected) {
        await serviceClient.request('emergencyReset');
      }
      this.settings.killSwitch = false;
      this.settings.permanentKillSwitch = false;
      this.userInitiatedDisconnect = true;
      clearTimeout(this._reconnectTimer);
      this._reconnectTimer = null;
      this.isReconnecting = false;
      this.reconnectAttempts = 0;
      this.currentServerId = null;
      this.connectedSince = null;
      if (this.currentSession) {
        this.cleanupOrphanedSession(this.currentSession.sessionId, 'emergency reset');
      }
      this.currentSession = null;
      this.lastConnectionConfig = null;
      this._persistLastConnectionConfig();
      this.killSwitchState = 'disabled';
      log.info('VPN: Emergency reset complete');
      this.notifyStatusChange();
    } catch (error) {
      log.error('VPN: Emergency reset failed:', error);
      throw error;
    }
  }

  /**
   * Toggle kill switch while connected
   */
  async toggleKillSwitch(enabled) {
    log.info(`VPN: Toggle kill switch: ${enabled}`);

    if (enabled && this.helperConnected) {
      // Apply standard kill switch pf rules using the cached connection config.
      // Must NOT call enableAdvancedKillSwitch here — that flips the Always-On flag
      // and causes the advanced kill switch to appear enabled in the UI.
      const config = this.lastConnectionConfig?.config;
      if (config) {
        try {
          const serverIp = await resolveServerIpv4(config.endpoint);
          const serverPort = extractEndpointPort(config.endpoint);
          const tunnelInterface = await findTunnelInterface(config.address);
          if (serverIp) {
            await this._updateKillSwitchState('connected', { serverIp, serverPort, tunnelInterface });
          } else {
            log.warn('VPN: toggleKillSwitch: could not resolve server IP — pf rules not applied');
          }
        } catch (err) {
          log.warn('VPN: toggleKillSwitch enable failed:', err.message);
        }
      } else {
        log.warn('VPN: toggleKillSwitch: no cached config — pf rules not applied');
      }
    } else if (!enabled && this.helperConnected) {
      // Flush pf rules directly. Do NOT go through _updateKillSwitchState('disabled')
      // because that calls disableAdvancedKillSwitch when permanentKillSwitch is set,
      // which would incorrectly clear the Always-On flag.
      try {
        await serviceClient.request('updateKillSwitch', { state: 'disabled' });
        this.killSwitchState = 'disabled';
      } catch (err) {
        log.warn('VPN: toggleKillSwitch disable failed:', err.message);
      }
    }

    this.settings.killSwitch = enabled;
    this.notifyStatusChange();
  }

  /**
   * Register callback for status changes
   */
  onStatusChange(callback) {
    this.statusCallbacks.push(callback);
  }

  /**
   * Notify all status change listeners
   */
  async notifyStatusChange() {
    const status = await this.getFullStatus();
    this.statusCallbacks.forEach(cb => {
      try {
        cb(status);
      } catch (error) {
        log.error('Status callback error:', error);
      }
    });
  }

  /**
   * Check if the helper daemon version mismatches the app version.
   */
  async _checkHelperVersionMismatch() {
    if (!this.helperVersion) return;

    const appVersion = app.getVersion();
    if (this.helperVersion !== appVersion) {
      log.warn(`VPN: Helper daemon version mismatch — helper: ${this.helperVersion}, app: ${appVersion}`);
      this.helperNeedsUpdate = true;
    } else {
      this.helperNeedsUpdate = false;
    }
  }

  /**
   * Check if the helper daemon needs updating.
   * @returns {{ needsUpdate: boolean, helperVersion: string|null, appVersion: string }}
   */
  getHelperUpdateStatus() {
    return {
      needsUpdate: this.helperNeedsUpdate || false,
      helperVersion: this.helperVersion || null,
      appVersion: app.getVersion(),
      installed: this.helperInstalled,
    };
  }

  /**
   * Update kill switch state machine.
   */
  async _updateKillSwitchState(newState, params = {}) {
    const oldState = this.killSwitchState;
    log.info(`VPN: Kill switch state: ${oldState} → ${newState}`, params);
    this.killSwitchState = newState;

    if (!this.helperConnected) {
      log.warn('VPN: _updateKillSwitchState skipped — helper not connected');
      return;
    }

    // State transitions go through updateKillSwitch; the Always-On persistence
    // flag (enable/disableAdvancedKillSwitch) is controlled separately so that
    // bootstrapping a standard kill switch does not flip Always-On on.
    switch (newState) {
      case 'bootstrap':
        await serviceClient.request('updateKillSwitch', {
          state: 'bootstrap',
          serverIp: params.serverIp,
          serverPort: params.serverPort || 443,
        });
        break;
      case 'connected':
        await serviceClient.request('updateKillSwitch', {
          state: 'connected',
          serverIp: params.serverIp,
          serverPort: params.serverPort || 443,
          tunnelInterface: params.tunnelInterface || '',
        });
        break;
      case 'persistentBlock':
        // Requires Always-On to be enabled on the helper.
        await serviceClient.request('updateKillSwitch', {
          state: 'persistent_block'
        });
        break;
      case 'disabled':
        // Flush bootstrap/connected rules without touching the Always-On flag.
        // If Always-On is on, caller should transition to persistentBlock instead.
        if (this.settings.permanentKillSwitch) {
          await serviceClient.request('disableAdvancedKillSwitch');
        } else {
          await serviceClient.request('updateKillSwitch', { state: 'disabled' });
        }
        break;
    }
  }

  /**
   * Handle tunnel status change notifications pushed from the helper daemon.
   */
  _handleTunnelStatusChange(status) {
    log.info('VPN: Tunnel status changed:', status);

    if (status === 'connected') {
      this.connectedSince = Date.now();
      this.isReconnecting = false;
      this.reconnectAttempts = 0;
    }

    // If the tunnel disconnects while a session is active and we didn't call disconnect()
    // ourselves, the tunnel dropped unexpectedly — mirrors iOS's updateConnectionState().
    if (status === 'disconnected' && this.currentSession && !this._intentionalDisconnect && !this.userInitiatedDisconnect) {
      log.info('VPN: Unexpected tunnel disconnect — clearing stale session');

      const staleSessionId = this.currentSession.sessionId;
      const serverId = this.currentServerId;
      const wasStable = this.connectedSince != null &&
        (Date.now() - this.connectedSince) >= this.minimumStableConnectionDuration * 1000;

      // Connection never proved itself stable — clean up its slot rather than letting the
      // upcoming reconnect attempt leak another increment on top of this orphaned one.
      // (A connection that *was* stable and then drops is not cleaned up here — the reconnect
      // attempt below claims a brand-new session instead. This mirrors iOS exactly, including
      // its own known gap: that old session's slot is only reclaimed via the backend's manual
      // /vpn/reset-connections escape hatch, not automatically.)
      if (!wasStable && staleSessionId) {
        this.cleanupOrphanedSession(
          staleSessionId,
          `dropped before ${this.minimumStableConnectionDuration}s stability threshold`
        );
      }

      this.currentSession = null;
      this.connectedSince = null;

      if (serverId) {
        this._attemptReconnect(serverId);
      }
    }

    // While disconnect() is in progress, suppress NE notifications entirely.
    // The NE 'disconnected' event fires before disconnect() has finished disabling
    // the kill switch, so a premature notifyStatusChange() would push stale state
    // (advancedKillSwitchActive: true) to the frontend. That causes the auto-connect
    // effect to fire as soon as disconnect() sets status to 'disconnected', creating
    // the reconnect loop. disconnect() calls notifyStatusChange() itself when done.
    if (this._intentionalDisconnect) {
      log.info('VPN: Suppressing tunnelStatusChanged during intentional disconnect');
      return;
    }

    if (status === 'connected' && this.killSwitchState === 'bootstrap') {
      const endpoint = this.lastConnectionConfig?.config?.endpoint;
      const vpnAddress = this.lastConnectionConfig?.config?.address;
      if (endpoint) {
        const serverPort = extractEndpointPort(endpoint);
        resolveServerIpv4(endpoint)
          .then(async serverIp => {
            if (!serverIp) throw new Error(`could not resolve ${endpoint} to IPv4`);
            const tunnelInterface = await findTunnelInterface(vpnAddress);
            return this._updateKillSwitchState('connected', { serverIp, serverPort, tunnelInterface });
          })
          .catch(err => log.warn('VPN: Kill switch connected transition failed:', err.message));
      }
    }

    if (status === 'disconnected' && this.settings.permanentKillSwitch) {
      this._updateKillSwitchState('persistentBlock').catch(err =>
        log.warn('VPN: Kill switch persistent block failed:', err.message)
      );
    }

    this.notifyStatusChange();
  }

  /**
   * Auto-reconnect after an unexpected tunnel drop. Mirrors iOS's attemptReconnect(): exponential
   * backoff with jitter (1s, 2s, 4s, 8s, 15s max by default), up to maxReconnectAttempts, using
   * the same server/settings as the connection that just dropped.
   */
  _attemptReconnect(serverId) {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      this.isReconnecting = false;
      log.error(`VPN: Reconnection failed after ${this.maxReconnectAttempts} attempts`);
      if (this.currentSession?.sessionId) {
        this.cleanupOrphanedSession(this.currentSession.sessionId, 'reconnect attempts exhausted');
      }
      this.currentServerId = null;
      this.notifyStatusChange();
      return;
    }

    this.isReconnecting = true;
    this.reconnectAttempts += 1;
    log.warn(`VPN: Auto-reconnect attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts}`);

    const baseDelay = Math.min(
      this.reconnectBaseDelay * Math.pow(2, this.reconnectAttempts - 1),
      this.reconnectMaxDelay
    );
    const jitterFactor = 0.5 + Math.random(); // 0.5..1.5
    const delay = baseDelay * jitterFactor;

    clearTimeout(this._reconnectTimer);
    this._reconnectTimer = setTimeout(async () => {
      if (this.userInitiatedDisconnect) return;
      try {
        const token = this._getAuthToken ? this._getAuthToken() : '';
        await this.connect(serverId, this.settings, token);
      } catch (err) {
        // Will retry via _handleTunnelStatusChange when a further disconnect is detected,
        // same as iOS — connect() above has already released any session it leaked.
        log.warn(`VPN: Reconnect attempt ${this.reconnectAttempts} failed: ${err.message}`);
      }
    }, delay);
  }

  /**
   * Cleanup on shutdown
   */
  async cleanup() {
    log.info('VPN: Cleanup on shutdown');

    // Persist the sessionId to the pending-disconnect ledger so it survives even if the process
    // exits before cleanupOrphanedSession's own delayed network attempt gets to run — the actual
    // decrement then happens via retryPendingDisconnects() on the next launch, same as how iOS
    // relies on next-launch crash recovery for an unclean quit it can't otherwise intercept.
    if (this.currentSession) {
      this.cleanupOrphanedSession(this.currentSession.sessionId, 'app quit');
    }

    try {
      const addon = this._getNativeAddon();
      if (addon) addon.stopTunnel();
    } catch (error) {
      log.warn('VPN: Stop tunnel on cleanup error:', error.message);
    }

    serviceClient.disconnect();
    this.currentSession = null;
    this.lastConnectionConfig = null;
  }
}

module.exports = new VPNService();
