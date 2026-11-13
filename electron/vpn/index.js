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
const health = require('./health');
const apiRelay = require('../apiRelay');

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

// Messages for the 403s /vpn/connect tags with a machine-readable `code`. An untagged 403 falls
// back to the backend's own text.
const CONNECT_FORBIDDEN_MESSAGES = {
  two_factor_setup_required: 'Your organization requires two-factor authentication. Set it up on your dashboard, then try again.',
  server_not_available: 'Your organization does not have access to this location.',
  subscription_required: 'An active subscription is required to connect.',
};

// Failed reconnect attempts on the same server before a user with "reconnect to another server"
// on is moved to a different one.
const FALLBACK_AFTER_ATTEMPTS = 2;
// How long a reconnect attempt waits for the dropped session's release to finish before asking
// for a new one. Only matters at the 5-device limit; a refusal there just retries next attempt.
const RELEASE_WAIT_MS = 2000;

// A sleep at least this long (a little under the backend's idle cleanup) is treated as having lost
// the session on the backend. This is the default for a backend that does not report its lease; a
// backend that does (leaseHours in the /vpn/connect response) sets the limit to the lease minus an hour.
const LONG_SLEEP_MS = 11 * 60 * 60 * 1000;
// Tunnel health monitor. The loop freezes while the machine sleeps, so a gap far longer than the tick
// between two checks means it just woke up: the handshake is stale only because nothing could refresh
// it and the network is usually not back yet, so judging is held off for a grace period.
const MONITOR_INTERVAL_MS = 5000;
const SLEEP_GAP_MS = 30 * 1000;
const RESUME_GRACE_MS = 60 * 1000;
const PROBE_INTERVAL_MS = 10 * 1000;
const PROBE_FAILURE_THRESHOLD = 3;       // about 30-40 s of silence
const STALE_HANDSHAKE_THRESHOLD = 2;     // consecutive checks (10 s)
// After the tunnel starts, how long to wait for the server to answer the handshake.
const HANDSHAKE_WAIT_MS = 10 * 1000;
// The system reports 'disconnected' for a moment while a tunnel is starting; only a status that
// stays there this long means the extension is not coming up.
const TUNNEL_START_GRACE_MS = 2000;
// With the tunnel up but no health snapshot ever readable, stop waiting for one after this long.
const UNREADABLE_SNAPSHOT_GIVEUP_MS = 4000;

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
const NETWORK_ERROR_CODES = new Set([
  'ENETUNREACH', 'EHOSTUNREACH', 'ENOTFOUND', 'EAI_AGAIN', 'ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT',
  'UND_ERR_CONNECT_TIMEOUT', 'UND_ERR_SOCKET',
]);
const NETWORK_UNREACHABLE_MESSAGE = "Can't reach WireDog. Check your internet connection and try again.";

/**
 * A failed network call (Node's fetch throws `TypeError: fetch failed`, with the real reason in `cause`)
 * versus an answer from the backend. Only the former is rewritten for the user.
 */
function isNetworkFailure(error) {
  if (!error || error instanceof ConnectCancelledError || error instanceof UnauthorizedError) return false;
  const code = error.code || error.cause?.code;
  if (code && NETWORK_ERROR_CODES.has(code)) return true;
  return error instanceof TypeError && /fetch failed/i.test(error.message || '');
}

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
    // Single-flight guard for connect(): the promise of the attempt currently running (and the
    // server it is for). connect() does several awaits before it claims a session, so without
    // this two triggers can both call /vpn/connect and orphan the first one's counter increment.
    this._connectPromise = null;
    this._connectingServerId = null;
    this._connectingGatewayId = null;
    // The organization gateway (named Dedicated IP) the current connection uses, if any. Kept so an
    // auto-reconnect goes back through the same gateway instead of the shared network.
    this.currentGatewayId = null;
    // The promise of each /disconnect currently in flight, so a reconnect about to ask for a new
    // session can wait for the old slot to be freed instead of racing it.
    this._cleanupInFlight = new Map();
    // Set when the backend rejected our token during an auto-reconnect (the screen must go to sign-in).
    this.authExpired = false;
    // Set when the auto-reconnect loop used up all its attempts / when the user cancelled it. The
    // screen needs to be told: the tunnel by then simply reports 'disconnected', which the UI ignores
    // while it still shows 'connecting'.
    this.reconnectGaveUp = false;
    this.reconnectCancelled = false;
    // Set when the last reconnect attempt failed because of the SERVER (the backend could not set a
    // session up on the node, or the tunnel could not be established), not the user's own network.
    this._lastAttemptServerSide = false;
    // Servers that already failed during this reconnect, so a later attempt does not pick them again.
    this._reconnectExcluded = new Set();
    this._lastTargetServerId = null;
    // Last IPv4 each server hostname resolved to. Right after the network returns DNS can fail for a
    // while; pf rules need a literal IP, so reuse the known one instead of dropping the kill switch.
    this._resolvedServerIps = new Map();
    // Sleep/wake and tunnel health monitor state.
    this.suspendedAt = null;
    this._monitorTimer = null;
    this._monitorBusy = false;
    this._lastTick = 0;
    this._graceUntil = 0;
    this._lastProbe = 0;
    this._probeFailures = 0;
    this._staleHandshakeChecks = 0;
    // Servers whose tunnel has answered the data-path probe at least once in this app run. A tunnel to
    // one of them that stops answering counts as dead even if it never answered since it was rebuilt.
    this._probeAnsweredServers = new Set();
    this._probeEverAnswered = false;
    this._connectedAtMs = 0;

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

  /** First 8 characters of a session id: enough to correlate log lines without writing the full token. */
  _short(sessionId) {
    return sessionId ? String(sessionId).slice(0, 8) : 'none';
  }

  // --- Released-session ledger ---
  // The backend's /disconnect is NOT idempotent, so a session that was already released must
  // never be released again (several paths can reach the same session: a drop, a supersede, a
  // crash-recovery pass). Confirmed releases are remembered here, capped, across restarts.
  _wasRecentlyReleased(sessionId) {
    if (!this.configStore) return false;
    return (this.configStore.get('releasedSessionIds', []) || []).includes(sessionId);
  }

  _markReleased(sessionId) {
    if (!this.configStore) return;
    const ids = (this.configStore.get('releasedSessionIds', []) || []).filter(id => id !== sessionId);
    ids.push(sessionId);
    this.configStore.set('releasedSessionIds', ids.slice(-50));
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
   * concurrent calls for the same session, and the released-session ledger guards against
   * releasing one that was already confirmed.
   */
  cleanupOrphanedSession(sessionId, reason, { immediate = false } = {}) {
    if (!sessionId) {
      log.warn(`CONN_COUNTER: release requested with no session id (${reason}) — nothing to send`);
      return Promise.resolve();
    }
    if (this._wasRecentlyReleased(sessionId)) {
      log.info(`CONN_COUNTER: session ${this._short(sessionId)} was already released, skipping duplicate /disconnect (${reason})`);
      this._removePendingDisconnect(sessionId);
      return Promise.resolve();
    }
    if (this.sessionsPendingCleanup.has(sessionId)) {
      log.info(`CONN_COUNTER: /disconnect for ${this._short(sessionId)} already in flight, skipping duplicate (${reason})`);
      return this._cleanupInFlight.get(sessionId) || Promise.resolve();
    }
    this.sessionsPendingCleanup.add(sessionId);

    log.info(`CONN_COUNTER: -1 queued /disconnect for session ${this._short(sessionId)} (${reason})`);
    this._addPendingDisconnect(sessionId);

    // `immediate` skips the grace period meant for a tunnel that is still stopping: when the tunnel
    // is already down (an unexpected drop, a quit that has torn it down first) there is nothing to wait for.
    const delay = immediate ? 0 : this.disconnectNotifyDelayMs;
    const releasePromise = new Promise((resolve) => {
      setTimeout(async () => {
        const startedAt = Date.now();
        log.info(`[TEMP] release of ${this._short(sessionId)} starting; previous API request was ${this._lastApiRequestAt ? (startedAt - this._lastApiRequestAt) + 'ms' : 'never'} ago`);
        this._logReleaseNetworkDiag(sessionId);
        try {
          const token = this._getAuthToken ? this._getAuthToken() : '';
          // A fresh connection, never a pooled one: the app's earlier requests went out through the
          // tunnel, and a kept-alive socket bound to a tunnel that has just gone away hangs for about
          // 45 s before the OS gives up on it. No timeout and no retry here, like Windows: the relay is
          // only a fallback for a real network failure, never for a slow answer.
          const headers = { 'Content-Type': 'application/json' };
          if (token) headers['Authorization'] = `Bearer ${token}`;
          const response = await this._fetch(`${this.apiBaseUrl}/vpn/disconnect`, {
            method: 'POST',
            headers,
            credentials: 'include',
            body: JSON.stringify({ sessionId }),
          });
          if (response.ok) {
            this._markReleased(sessionId);
            this._removePendingDisconnect(sessionId);
            log.info(`CONN_COUNTER: -1 /disconnect confirmed for session ${this._short(sessionId)} (${reason})`);
            log.info(`[TEMP] release of ${this._short(sessionId)} took ${Date.now() - startedAt}ms (immediate=${immediate})`);
            this._logConnectionCounter('after disconnect');
          } else if (response.status === 404) {
            // The backend has no such session (a malformed id, or its server record is gone). That
            // answer never changes and /disconnect did not touch the counter, so retrying forever
            // (at every launch and window focus) only noise. Give it up.
            this._markReleased(sessionId);
            this._removePendingDisconnect(sessionId);
            log.warn(`CONN_COUNTER: /disconnect for session ${this._short(sessionId)} (${reason}): backend has no such session (HTTP 404), dropping it from the retry list`);
          } else {
            // Non-ok: left in the pending list, retried via retryPendingDisconnects() later.
            log.error(`CONN_COUNTER: /disconnect FAILED for session ${this._short(sessionId)} (${reason}): HTTP ${response.status} — counter stays incremented until retried`);
          }
        } catch (err) {
          log.error(`CONN_COUNTER: /disconnect FAILED for session ${this._short(sessionId)} (${reason}): ${err.message} — counter stays incremented until retried`);
          // Left in the pending list — retried via retryPendingDisconnects() later.
        } finally {
          this.sessionsPendingCleanup.delete(sessionId);
          this._cleanupInFlight.delete(sessionId);
          resolve();
        }
      }, delay);
    });
    this._cleanupInFlight.set(sessionId, releasePromise);
    return releasePromise;
  }

  /**
   * [TEMP] Why does a release right after the tunnel goes down sometimes stall for seconds on a fresh
   * connection while the Rescue Relay (which dials an IP, no DNS) answers at once? Times a DNS lookup
   * of the API host and a TCP connect to the result, in parallel with the real request, and logs both.
   */
  _logReleaseNetworkDiag(sessionId) {
    let host;
    try { host = new URL(this.apiBaseUrl).hostname; } catch { return; }
    const t0 = Date.now();
    // Which interface the default route points at while the tunnel is going away: a route that still
    // names the dead utun would black-hole the first connection attempts.
    for (const afterMs of [0, 2000, 4000]) {
      setTimeout(() => {
        exec('route -n get default 2>&1 | grep -E "interface|gateway"', { timeout: 3000 }, (err, out) => {
          log.info(`[TEMP] release net diag (${this._short(sessionId)}): +${Date.now() - t0}ms default route: ${(out || String(err || 'none')).replace(/\s+/g, ' ').trim()}`);
        });
      }, afterMs);
    }
    dns.lookup(host, { all: true }).then((addrs) => {
      log.info(`[TEMP] release net diag (${this._short(sessionId)}): DNS ${host} -> ${addrs.map(a => a.address).join(',')} in ${Date.now() - t0}ms`);
      const v4 = addrs.find(a => a.family === 4);
      if (!v4) return;
      const t1 = Date.now();
      const sock = net.connect({ host: v4.address, port: 443, timeout: 8000 });
      sock.on('connect', () => { log.info(`[TEMP] release net diag (${this._short(sessionId)}): TCP ${v4.address}:443 connected in ${Date.now() - t1}ms`); sock.destroy(); });
      sock.on('timeout', () => { log.info(`[TEMP] release net diag (${this._short(sessionId)}): TCP ${v4.address}:443 TIMED OUT after ${Date.now() - t1}ms`); sock.destroy(); });
      sock.on('error', (e) => { log.info(`[TEMP] release net diag (${this._short(sessionId)}): TCP ${v4.address}:443 error ${e.code} after ${Date.now() - t1}ms`); });
    }).catch((e) => {
      log.info(`[TEMP] release net diag (${this._short(sessionId)}): DNS ${host} FAILED (${e.code || e.message}) after ${Date.now() - t0}ms`);
    });
  }

  /** All backend calls go through here so the Rescue Relay can be slotted in (see apiRelay). */
  _fetch(url, options = {}) {
    // `Connection: close` on EVERY request the main process makes, so no idle keep-alive socket is left
    // behind. The app's requests while connected go out through the tunnel; undici keeps such a socket
    // for 4 s, and a release sent right after the tunnel is torn down picked it up and sat on a
    // black-holed connection for ~47 s (every slow release in the first test run followed a status
    // request by less than 4 s; the fast ones did not). Header only: relay behavior is unchanged.
    this._lastApiRequestAt = Date.now();
    return apiRelay.apiFetch(url, { ...options, headers: { ...(options.headers || {}), Connection: 'close' } });
  }

  /**
   * True only when the tunnel is genuinely idle: no session, no connect in flight and no reconnect
   * loop. Latency probes made at any other time are routed through the connected server and come
   * back inflated.
   */
  async isIdleForLatency() {
    if (this.currentSession || this.isReconnecting || this._connectPromise) return false;
    try {
      const addon = this._getNativeAddon();
      return !addon || (addon.getStatus() || 'disconnected') === 'disconnected';
    } catch {
      return true;
    }
  }

  /**
   * Asks the backend what its active_connection_counter currently says and logs it next to what
   * this app believes it holds. A counter that rises with no matching local event shows up as a
   * `localSession=none` with backend>0 mismatch (another device, or a leaked session). Purely
   * diagnostic: never throws, never blocks the caller, skipped when there is no auth token.
   * Mirrors iOS's logConnectionCounter.
   */
  async _logConnectionCounter(context) {
    try {
      const token = this._getAuthToken ? this._getAuthToken() : '';
      if (!token) return;
      const response = await this._fetch(`${this.apiBaseUrl}/vpn/status`, {
        method: 'GET',
        headers: { Authorization: `Bearer ${token}` },
        credentials: 'include',
      });
      if (!response.ok) {
        log.warn(`CONN_COUNTER [${context}]: status check failed: HTTP ${response.status}`);
        return;
      }
      const status = await response.json();
      const pending = this._pendingDisconnectIds().map(id => this._short(id)).join(',');
      log.info(
        `CONN_COUNTER [${context}]: backend=${status.activeConnections}/${status.maxConnections} ` +
        `localSession=${this._short(this.currentSession?.sessionId)} ` +
        `configSession=${this._short(this.lastConnectionConfig?.sessionId)} ` +
        `reconnecting=${this.isReconnecting} pendingDisconnects=[${pending}]`
      );
    } catch (err) {
      log.warn(`CONN_COUNTER [${context}]: status check failed: ${err.message}`);
    }
  }

  /**
   * Retries any /disconnect calls that were owed but never confirmed — e.g. the app had no
   * connectivity right as cleanupOrphanedSession()'s call went out, so nothing ever reached
   * the backend. Safe to call unconditionally: each retry goes through cleanupOrphanedSession()'s
   * own in-flight guard.
   */
  retryPendingDisconnects({ immediate = false } = {}) {
    const owed = this._pendingDisconnectIds();
    if (owed.length > 0) {
      log.info(`[TEMP] retrying ${owed.length} owed /disconnect: ${owed.map(id => this._short(id)).join(',')}`);
    }
    return Promise.all(owed.map(sessionId =>
      this.cleanupOrphanedSession(sessionId, 'retrying pending disconnect', { immediate })
    ));
  }

  /**
   * Called when the app returns to the foreground (window focus). Mirrors iOS's
   * willEnterForeground handler: its very first firing coincides with the cold-start retry
   * initialize() already performs, so it's skipped there in favor of that one.
   */
  handleAppForeground() {
    this._logConnectionCounter('app foreground');
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
        apiRelay.resend();

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
            apiRelay.setBlockedHint(true);
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

        // Crash recovery: release a session the previous app instance never released.
        this._recoverStaleSession('helper connected');
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

    log.info(`CONN_COUNTER: startup — restored session=${this._short(this.currentSession?.sessionId)} configSession=${this._short(this.lastConnectionConfig?.sessionId)} pendingDisconnects=${this._pendingDisconnectIds().length}`);
    // The auth token is stored a moment after launch, so give it time before asking the backend.
    setTimeout(() => this._logConnectionCounter('app launch'), 3000);
  }

  /**
   * Crash recovery: if we have a persisted sessionId but the tunnel is not currently active, the
   * previous app instance exited without cleanly calling /disconnect. Send a best-effort
   * disconnect now so the backend counter decrements correctly. Keeps the WireGuard config
   * intact — the kill-switch reconnect path may still need it.
   *
   * Called from every startup path that ends with a usable tunnel manager, not only the one where
   * the helper daemon was already running. When the daemon had to be reinstalled (it was missing
   * on both relaunches in the customer log) this used to be skipped, and the old session was
   * lost the moment the next connect() overwrote lastConnectionConfig.
   */
  _recoverStaleSession(source) {
    // Both copies: the one in the saved connection config and the one restored from lastSession.
    const held = new Set([this.lastConnectionConfig?.sessionId, this.currentSession?.sessionId].filter(Boolean));
    if (held.size === 0) return;
    try {
      const addon = this._getNativeAddon();
      const tunnelStatusStr = addon ? addon.getStatus() : 'disconnected';
      if (tunnelStatusStr !== 'disconnected') {
        log.info(`CONN_COUNTER: startup — session(s) ${[...held].map(id => this._short(id)).join(',')} left in place, tunnel status is ${tunnelStatusStr} (${source})`);
        return;
      }
      // Unlike Windows (whose service replays the saved session itself at boot), nothing on macOS
      // resumes a session after a restart, even with Always-On: the old session is dead weight, so
      // it is released whether or not a persistent block is up.
      for (const sessionId of held) {
        log.info('VPN: Startup crash recovery — cleaning up stale session %s (%s)', this._short(sessionId), source);
        // Durable cleanup — if this fails (no connectivity yet at cold start), the sessionId
        // survives in the pending-disconnect ledger and gets retried by retryPendingDisconnects()
        // on a later launch/foreground instead of being forgotten outright.
        this.cleanupOrphanedSession(sessionId, 'crash recovery — stale session', { immediate: true });
      }

      // Clear the stale session ids but preserve the WireGuard config so the persistent-block
      // reconnect fallback can still use it.
      if (this.lastConnectionConfig) {
        this.lastConnectionConfig.sessionId = null;
        this._persistLastConnectionConfig();
      }
      this.currentSession = null;
      try { this.configStore?.delete('lastSession'); } catch { /* best effort */ }
    } catch (err) {
      log.warn('VPN: Startup crash recovery check failed:', err.message);
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
            apiRelay.resend();
            serviceClient.onNotification('tunnelStatusChanged', (params) => {
              this._handleTunnelStatusChange(params?.status ?? 'disconnected');
            });
            // Activate the system extension now that the helper is confirmed running
            this._activateSysext();
            // Crash recovery used to run only when the daemon was already up at launch. Give the
            // tunnel manager a moment to load so the status check below is meaningful.
            setTimeout(() => this._recoverStaleSession('helper reinstalled'), 3000);
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
  async connect(serverId, settings, token = '', gatewayId = null) {
    // An attempt that was just cancelled may still be unwinding; let it finish so a switch to a
    // different server is not refused for a connect nobody wants any more.
    if (this._connectPromise && this._connectAbortToken?.cancelled) {
      try { await this._connectPromise; } catch { /* the cancelled attempt's own error */ }
    }

    // Single-flight. connect() awaits the helper, the extension and the backend before it claims
    // a session, so two triggers (auto-connect, a retry timer, a click) can both get this far and
    // each call /vpn/connect; the second session overwrites the first and its counter increment
    // is orphaned. A duplicate for the same server joins the attempt already running.
    if (this._connectPromise) {
      if (this._connectingServerId === serverId && (this._connectingGatewayId ?? null) === (gatewayId ?? null)) {
        log.warn(`CONN_COUNTER: duplicate connect to ${serverId} joined the attempt already in flight`);
        return this._connectPromise;
      }
      log.warn(`CONN_COUNTER: connect to ${serverId} rejected — a connect to ${this._connectingServerId} is already in flight`);
      throw new Error('VPN is already connecting');
    }

    this._connectingServerId = serverId;
    this._connectingGatewayId = gatewayId;
    const attempt = this._connect(serverId, settings, token, gatewayId);
    this._connectPromise = attempt;
    try {
      return await attempt;
    } finally {
      if (this._connectPromise === attempt) {
        this._connectPromise = null;
        this._connectingServerId = null;
        this._connectingGatewayId = null;
      }
    }
  }

  /**
   * Whether the backend answers from here. Cheap, short-timeout probe; any non-5xx reply counts.
   * Used to decide between fresh credentials and the cached config when a block is up.
   */
  async _backendReachable() {
    try {
      const response = await this._fetch(`${this.apiBaseUrl}/app/config`, { signal: AbortSignal.timeout(4000) });
      return response.status < 500;
    } catch {
      return false;
    }
  }

  async _connect(serverId, settings, token = '', gatewayId = null) {
    log.info(`VPN: Connect request to server ${serverId}${gatewayId ? ` (gateway ${gatewayId})` : ''} (heldSession=${this._short(this.currentSession?.sessionId)}, configSession=${this._short(this.lastConnectionConfig?.sessionId)}, reconnecting=${this.isReconnecting})`);
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
    this.authExpired = false;
    this.reconnectGaveUp = false;
    this.reconnectCancelled = false;
    if (!this.isReconnecting) {
      this.userInitiatedDisconnect = false;
      this.reconnectAttempts = 0;
    }
    // Remembered so a failed attempt can put the block back the way it found it.
    const wasPersistentBlock = this.killSwitchState === 'persistentBlock';
    // A block is holding the network: send backend requests through the Rescue Relay first instead of
    // waiting out a direct attempt that cannot succeed.
    apiRelay.setBlockedHint(wasPersistentBlock || this.killSwitchState === 'bootstrap');

    // Declared outside the try block so the catch clause below can see whether a sessionId
    // was already claimed from the backend (and thus already incremented the counter) before
    // something later in this function threw.
    let config, sessionId, server, leaseHours;
    let usedCachedConfig = false;

    try {
      // Under a persistent block the saved config is only a fallback: it points at a peer the backend
      // may have removed (idle cleanup, a node rebuild) and can never work again then. Prefer fresh
      // credentials; use the saved ones only when the backend cannot be reached from here (and,
      // through the Rescue Relay, that is rare). Matches the Windows app.
      const cached = this.lastConnectionConfig;
      const cachedServerId = cached?.server?.serverId ?? cached?.server?.id;
      if (
        this.killSwitchState === 'persistentBlock' &&
        cached &&
        cachedServerId === serverId &&
        !(await this._backendReachable())
      ) {
        log.info('VPN: Backend unreachable under persistentBlock — using cached connection config');
        config = { ...cached.config };
        sessionId = cached.sessionId;
        server = cached.server;
        usedCachedConfig = true;
        this.currentServerId = serverId;
      } else {
        // Fetch connection config from backend API
        log.info('VPN: Fetching connection config from backend...');
        // A fresh connection, not a pooled one bound to a tunnel that may just have gone away.
        const headers = { 'Content-Type': 'application/json' };
        if (token) {
          headers['Authorization'] = `Bearer ${token}`;
        }

        // No timeout, like Windows: under a block the Rescue Relay is tried first (see setBlockedHint),
        // and a slow answer (the backend waits ~15 s on a node that is down) is a real answer, not a
        // failure to retry through the relay: /vpn/connect adds a device to the counter and must not
        // be sent twice.
        let response;
        const requestPayload = {
          serverId,
          localMode: settings.localMode || false,
          blockAds: settings.blockAdsEnabled ?? true,
          blockMalware: settings.blockMalwareEnabled ?? true,
        };
        if (gatewayId) requestPayload.dedicatedIpId = gatewayId;
        response = await this._fetch(`${this.apiBaseUrl}/vpn/connect`, {
          method: 'POST',
          headers,
          credentials: 'include',
          body: JSON.stringify(requestPayload),
        });

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
          // 403s the backend tags with a machine-readable `code` get a specific message. Plain
          // 403s fall through to the backend's own text.
          if (response.status === 403 && CONNECT_FORBIDDEN_MESSAGES[error.code]) {
            const forbidden = new Error(CONNECT_FORBIDDEN_MESSAGES[error.code]);
            forbidden.code = error.code;
            throw forbidden;
          }
          const failure = new Error(error.error || `API error: ${response.status}`);
          // A 5xx here means the backend could not set the session up on the node: that server is the problem.
          failure.serverSide = response.status >= 500;
          throw failure;
        }

        const responseData = await response.json();
        ({ config, sessionId, server } = responseData);
        leaseHours = responseData.leaseHours;
        this.currentServerId = serverId;
        this.currentGatewayId = gatewayId;
        log.info(`CONN_COUNTER: +1 /connect granted session ${this._short(sessionId)} server=${serverId} reconnect=${this.isReconnecting}`);

        // The new session is about to overwrite whatever this app still holds. Anything held that
        // was never released (a stable drop, a session restored after an unclean quit that crash
        // recovery missed) would otherwise keep its counter increment forever.
        this._releaseSupersededSessions(sessionId);

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

      // Resolve the server's IPv4 address once — reused for the kill switch rules. Falls back to the
      // last address this host resolved to: right after the network returns DNS can fail for a while.
      const resolvedServerIp = await this._resolveServerIp(config.endpoint);
      const serverPort = extractEndpointPort(config.endpoint);

      // Transition kill switch to bootstrap state before starting tunnel. Fail closed: a connect that
      // was asked to run behind a kill switch must not carry on without one.
      if (settings.killSwitch && this.helperConnected) {
        if (!resolvedServerIp) throw new Error(`Could not resolve the server address (${(config.endpoint || '').split(':')[0]})`);
        await this._updateKillSwitchState('bootstrap', { serverIp: resolvedServerIp, serverPort });
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

      const tunnelStartedMs = Date.now();
      try {
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
      } catch (tunnelErr) {
        // The tunnel could not be brought up with this server: the server is the problem.
        if (!(tunnelErr instanceof ConnectCancelledError)) tunnelErr.serverSide = true;
        throw tunnelErr;
      }

      // The tunnel just started — if a cancel landed in the narrow window right around this
      // call, tear it back down immediately rather than leaving an untracked live tunnel.
      if (abortToken.cancelled) {
        tunnelAddon.stopTunnel();
        throw new ConnectCancelledError();
      }

      // A tunnel that never completed a handshake is not connected, whatever the system says. Declaring
      // success here would hide a dead tunnel and move the kill switch on to Connected.
      await this._verifyHandshake(tunnelStartedMs, abortToken, tunnelAddon);

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
      // publicIp = the backend-assigned per-session SNAT exit IP (server.exitIp, shared pool or
      // Dedicated IP) — what external services actually see when the tunnel is active. No fallback to
      // the VPN server's own address: that is not an exit IP. Empty when the backend doesn't provide
      // one; the UI then shows "Unknown".
      this.currentSession = {
        sessionId,
        server,
        gatewayId,
        assignedIp: config.address,
        publicIp: server?.exitIp || '',
        // The backend's idle limit for this session (hours); drives the long-sleep rule.
        leaseHours,
        connectedAt: new Date().toISOString()
      };
      // Persist for app restart recovery here, not only in the vpn:connect IPC handler: an
      // auto-reconnect succeeds through this method too, and a stale lastSession made a relaunched app
      // restore (and later skip releasing) an already-released session while the live one kept its slot.
      try { this.configStore?.set('lastSession', this.currentSession); } catch { /* best effort */ }
      this.connectedSince = Date.now();
      this.isReconnecting = false;
      this.reconnectAttempts = 0;
      this._lastAttemptServerSide = false;
      this._reconnectExcluded.clear();

      apiRelay.setBlockedHint(false);
      log.info(`VPN: Connected successfully (session=${this._short(sessionId)}, lease=${leaseHours ?? 'unreported'}h)`);
      this._startHealthMonitor(config);
      this._logConnectionCounter('after connect');
      // Do NOT call notifyStatusChange() here — the NE tunnel is still starting at this
      // point and the helper would report 'disconnected' or 'connecting', causing the
      // frontend to flicker. The tunnelStatusChanged notification from the helper daemon
      // will push the authoritative 'connected' status when the tunnel is actually up.

      // If we reconnected from cache, fire-and-forget a fresh /vpn/connect so
      // the backend's session tracking catches up now that HTTPS is unblocked.
      if (usedCachedConfig) {
        const headers = { 'Content-Type': 'application/json' };
        if (token) headers['Authorization'] = `Bearer ${token}`;
        this._fetch(`${this.apiBaseUrl}/vpn/connect`, {
          method: 'POST',
          headers,
          credentials: 'include',
          body: JSON.stringify({
            serverId,
            localMode: settings.localMode || false,
            blockAds: settings.blockAdsEnabled ?? true,
            blockMalware: settings.blockMalwareEnabled ?? true,
            ...(gatewayId ? { dedicatedIpId: gatewayId } : {}),
          })
        })
          .then(resp => resp.ok
            ? resp.json().then(data => {
                if (data?.sessionId) {
                  // The session that was running on the cached config is being replaced: release the
                  // old one (a no-op if it was already released), or its slot is lost for good.
                  const previousId = this.currentSession?.sessionId;
                  if (previousId && previousId !== data.sessionId) {
                    log.warn(`CONN_COUNTER: post-reconnect sync granted ${this._short(data.sessionId)}, replacing ${this._short(previousId)}`);
                    this.cleanupOrphanedSession(previousId, 'replaced by the post-reconnect backend sync', { immediate: true });
                  }
                  log.info(`CONN_COUNTER: +1 /connect granted session ${this._short(data.sessionId)} (post-reconnect sync)`);
                  if (this.currentSession) this.currentSession.sessionId = data.sessionId;
                  if (this.lastConnectionConfig) this.lastConnectionConfig.sessionId = data.sessionId;
                  try { this.configStore?.set('lastSession', this.currentSession); } catch { /* best effort */ }
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
      // Put the block back the way it was found. A failed RETRY inside the auto-reconnect loop must not
      // lift a kill switch: that would open the internet for the whole wait before the next attempt.
      // The block stays until the reconnect succeeds, gives up, or the user clicks Disconnect.
      const holdBlock = this.isReconnecting && !(error instanceof ConnectCancelledError) &&
        (settings.killSwitch || settings.permanentKillSwitch);
      if (holdBlock) {
        log.info('VPN: Reconnect attempt failed, leaving the kill switch block in place');
        try { this._getNativeAddon()?.stopTunnel(); } catch { /* nothing running */ }
      } else {
        await this._abortFailedConnect(wasPersistentBlock);
      }

      if (sessionId && !usedCachedConfig) {
        log.warn(`CONN_COUNTER: connect failed after /connect granted session ${this._short(sessionId)} — releasing`);
        this.cleanupOrphanedSession(sessionId, 'connect() threw after sessionId obtained');
        if (!this.isReconnecting) {
          this.currentServerId = null;
          this.currentGatewayId = null;
        }
      }
      if (isNetworkFailure(error)) {
        // The raw error is already in the log. The screen gets a sentence a person can act on.
        const friendly = new Error(NETWORK_UNREACHABLE_MESSAGE, { cause: error });
        friendly.networkUnreachable = true;
        throw friendly;
      }
      throw error;
    }
  }

  /**
   * Resolves the tunnel endpoint to an IPv4 literal for the pf rules, remembering the answer per
   * host so a later lookup that fails (DNS not back yet after a network drop) can reuse it.
   */
  async _resolveServerIp(endpoint) {
    const host = (endpoint || '').split(':')[0];
    const ip = await resolveServerIpv4(endpoint).catch(() => '');
    if (ip) {
      if (host && !net.isIPv4(host)) this._resolvedServerIps.set(host, ip);
      return ip;
    }
    const known = this._resolvedServerIps.get(host);
    if (known) {
      log.warn(`VPN: DNS failed for ${host}, using the last known address ${known}`);
      return known;
    }
    return '';
  }

  /**
   * A connect failed and nothing is holding the block on purpose: stop whatever half-started and put
   * the kill switch back the way it was before the attempt (back to the persistent block if that is
   * what it was, or fully off). Without this a failed first connect left the Bootstrap rules in place
   * and the machine with no internet and no tunnel.
   */
  async _abortFailedConnect(wasPersistentBlock) {
    try {
      const addon = this._getNativeAddon();
      if (addon) {
        addon.stopTunnel();
        try { addon.stopFilter(); } catch { /* not running */ }
      }
    } catch (cleanupError) {
      log.warn('VPN: Cleanup after failed connect: stopTunnel failed:', cleanupError.message);
    }
    if (!this.helperConnected) return;
    try {
      if (this.settings?.permanentKillSwitch || wasPersistentBlock) {
        await this._updateKillSwitchState('persistentBlock');
      } else if (this.killSwitchState !== 'disabled') {
        await this._updateKillSwitchState('disabled');
      }
    } catch (ksError) {
      log.warn('VPN: Restoring the kill switch after a failed connect failed:', ksError.message);
    }
  }

  /**
   * Releases any session this app still holds (in memory or in the persisted connection config)
   * other than the one that was just claimed. Safe to call when nothing is held, and safe if a
   * session was already released: cleanupOrphanedSession() refuses to release one twice.
   */
  _releaseSupersededSessions(newSessionId) {
    let savedSessionId = null;
    try { savedSessionId = this.configStore?.get('lastSession')?.sessionId ?? null; } catch { /* best effort */ }
    // Sessions already confirmed released are skipped, so the warning below only fires for a real
    // leak risk (a drop releases the old session a moment before the reconnect claims a new one).
    const held = new Set(
      [this.currentSession?.sessionId, this.lastConnectionConfig?.sessionId, savedSessionId]
        .filter(id => id && id !== newSessionId && !this._wasRecentlyReleased(id))
    );
    for (const priorSessionId of held) {
      log.warn(`CONN_COUNTER: new session ${this._short(newSessionId)} replaces unreleased ${this._short(priorSessionId)} — releasing the old one`);
      this.cleanupOrphanedSession(priorSessionId, 'superseded by a new connect', { immediate: true });
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
      this.reconnectCancelled = true;
      clearTimeout(this._reconnectTimer);
      this._reconnectTimer = null;
      this.isReconnecting = false;
      this.reconnectAttempts = 0;
      // Always tear down now: it lifts the block the loop was holding, releases a session an earlier
      // retry may have claimed (so the counter stays net-zero) and tells the screen at once. Waiting
      // for an in-flight attempt to fail on its own took 10 to 15 s, or never happened between attempts.
      this.disconnect().catch(err => log.warn('VPN: cancelConnect disconnect failed:', err.message));
    } else {
      // Nothing to cancel: the screen is showing a stale 'connecting'. Send the real status so it corrects itself.
      this.notifyStatusChange();
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
    this.reconnectGaveUp = false;
    this._stopHealthMonitor();
    clearTimeout(this._reconnectTimer);
    this._reconnectTimer = null;
    this.isReconnecting = false;
    this.reconnectAttempts = 0;
    this.currentServerId = null;
    this.currentGatewayId = null;
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
        log.info(`CONN_COUNTER: disconnect() releasing session ${this._short(this.currentSession.sessionId)}`);
        this.cleanupOrphanedSession(this.currentSession.sessionId, 'user-initiated disconnect');
      } else if (disableProtection && this.lastConnectionConfig?.sessionId) {
        // Disconnected during the gap between a drop and the reconnect claiming a new session:
        // the dropped session is still held in the cached config and nothing else will release it.
        this.cleanupOrphanedSession(this.lastConnectionConfig.sessionId, 'user-initiated disconnect (held from a dropped connection)');
      } else {
        log.warn('CONN_COUNTER: disconnect() had no session to release — nothing sent to backend');
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

      // The reconnect gave up but a kill switch is still holding the block: the machine is cut off with
      // no tunnel. Report it as an error (CONNECTION LOST) so the screen explains it and offers the
      // way out (Disconnect, or turning Always-On off); 'disconnected' would show an idle,
      // unprotected-looking state while the internet is in fact blocked.
      if (this.reconnectGaveUp && advancedKillSwitchActive && !this.currentSession) {
        status = 'error';
      }

      return {
        status,
        session: this.currentSession,
        killSwitchEnabled,
        advancedKillSwitchEnabled,
        advancedKillSwitchActive,
        isReconnecting: this.isReconnecting,
        authExpired: this.authExpired,
        reconnectGaveUp: this.reconnectGaveUp,
        reconnectCancelled: this.reconnectCancelled
      };
    } catch (error) {
      return {
        status: this.isReconnecting ? 'connecting' : 'disconnected',
        session: this.currentSession,
        killSwitchEnabled: false,
        advancedKillSwitchEnabled: false,
        advancedKillSwitchActive: false,
        isReconnecting: this.isReconnecting,
        authExpired: this.authExpired,
        reconnectGaveUp: this.reconnectGaveUp,
        reconnectCancelled: this.reconnectCancelled
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
      this._stopHealthMonitor();
      clearTimeout(this._reconnectTimer);
      this._reconnectTimer = null;
      this.isReconnecting = false;
      this.reconnectAttempts = 0;
      this.currentServerId = null;
      this.currentGatewayId = null;
      this.reconnectGaveUp = false;
      this.connectedSince = null;
      if (this.currentSession) {
        this.cleanupOrphanedSession(this.currentSession.sessionId, 'emergency reset');
      } else if (this.lastConnectionConfig?.sessionId) {
        this.cleanupOrphanedSession(this.lastConnectionConfig.sessionId, 'emergency reset (held from a dropped connection)');
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

  /** [TEMP] One line of what pf is doing, from the helper's reply. */
  _logPfDiag(label, result) {
    const pf = result && result.pf;
    if (!pf) { log.info(`[TEMP] [PF] ${label}: helper gave no pf status`); return; }
    log.info(`[TEMP] [PF] ${label}: pfEnabled=${pf.pfEnabled} anchorHooked=${pf.anchorHooked} blockAllInAnchor=${pf.blockAllInAnchor} anchorRules=${pf.anchorRules} mainRules=${pf.mainRules} relays=${pf.relayIps}`);
  }

  /** [TEMP] Starts the 10 s pf watch (idempotent). */
  _startPfWatch() {
    if (this._pfWatchTimer) return;
    this._pfWatchTimer = setInterval(() => { this._pfWatchTick().catch(() => {}); }, 10000);
    if (this._pfWatchTimer.unref) this._pfWatchTimer.unref();
  }

  _stopPfWatch() {
    if (!this._pfWatchTimer) return;
    clearInterval(this._pfWatchTimer);
    this._pfWatchTimer = null;
  }

  /**
   * [TEMP] Every 10 s while a block is up: ask the helper what pf is doing, and, when the block is meant
   * to stop everything (no tunnel carrying traffic), try to open a TCP connection straight out to a
   * public IPv4 and a public IPv6 address. 'REACHED' there means traffic is getting out under the block.
   * Nothing is sent but a TCP SYN.
   */
  async _pfWatchTick() {
    if (this._pfWatchBusy) return;
    this._pfWatchBusy = true;
    try {
      let pfLine = 'pf status unavailable';
      try {
        const r = await serviceClient.request('getPfDiag');
        const pf = r && r.pf;
        if (pf) pfLine = `helperState=${r.state} pfEnabled=${pf.pfEnabled} anchorHooked=${pf.anchorHooked} blockAllInAnchor=${pf.blockAllInAnchor} anchorRules=${pf.anchorRules}`;
      } catch (err) { pfLine = `pf status failed: ${err.message}`; }

      const blocking = this.killSwitchState === 'bootstrap' || this.killSwitchState === 'persistentBlock';
      let probeLine = 'direct-probe=skipped(tunnel state)';
      if (blocking) {
        const tryConnect = (host, family) => new Promise((resolve) => {
          const sock = net.connect({ host, port: 443, family });
          const done = (result) => { sock.destroy(); resolve(result); };
          sock.setTimeout(1500, () => done('blocked'));
          sock.once('connect', () => done('REACHED'));
          sock.once('error', (e) => done(e.code === 'ENETUNREACH' || e.code === 'EHOSTUNREACH' ? 'no-route' : 'blocked'));
        });
        const [v4, v6] = await Promise.all([tryConnect('1.1.1.1', 4), tryConnect('2606:4700:4700::1111', 6)]);
        probeLine = `direct-probe v4=${v4} v6=${v6}`;
      }
      log.info(`[TEMP] [PF] watch appState=${this.killSwitchState} reconnecting=${!!this.isReconnecting} ${pfLine} ${probeLine}`);
    } finally {
      this._pfWatchBusy = false;
    }
  }

  /**
   * Update kill switch state machine.
   */
  async _updateKillSwitchState(newState, params = {}) {
    const oldState = this.killSwitchState;
    log.info(`VPN: Kill switch state: ${oldState} → ${newState}`, params);
    this.killSwitchState = newState;
    // While a block is up the backend is reached through the Rescue Relay first.
    apiRelay.setBlockedHint(newState === 'persistentBlock' || newState === 'bootstrap');

    if (!this.helperConnected) {
      log.warn('VPN: _updateKillSwitchState skipped — helper not connected');
      return;
    }

    // [TEMP] While any block is meant to be up, report what pf is really doing and try to reach the
    // internet directly (see _pfWatchTick).
    if (newState === 'disabled' && !this.settings.permanentKillSwitch) this._stopPfWatch();
    else this._startPfWatch();

    // State transitions go through updateKillSwitch; the Always-On persistence
    // flag (enable/disableAdvancedKillSwitch) is controlled separately so that
    // bootstrapping a standard kill switch does not flip Always-On on.
    switch (newState) {
      case 'bootstrap':
        this._logPfDiag(newState, await serviceClient.request('updateKillSwitch', {
          state: 'bootstrap',
          serverIp: params.serverIp,
          serverPort: params.serverPort || 443,
        }));
        break;
      case 'connected':
        this._logPfDiag(newState, await serviceClient.request('updateKillSwitch', {
          state: 'connected',
          serverIp: params.serverIp,
          serverPort: params.serverPort || 443,
          tunnelInterface: params.tunnelInterface || '',
        }));
        break;
      case 'persistentBlock':
        // Requires Always-On to be enabled on the helper.
        this._logPfDiag(newState, await serviceClient.request('updateKillSwitch', {
          state: 'persistent_block'
        }));
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
      this._handleUnexpectedDrop();
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
            // The lookup can take seconds when the tunnel's resolver is not answering yet. If the user
            // disconnected (or the connect already moved the block on) meanwhile, a late transition
            // here would re-arm a block nobody is going to lift.
            if (this.killSwitchState !== 'bootstrap' || this._intentionalDisconnect) {
              log.info(`[TEMP] late bootstrap->connected transition skipped (state is now ${this.killSwitchState})`);
              return undefined;
            }
            return this._updateKillSwitchState('connected', { serverIp, serverPort, tunnelInterface });
          })
          .catch(err => log.warn('VPN: Kill switch connected transition failed:', err.message));
      }
    }

    // While an auto-reconnect is running the block must stay in Bootstrap (it permits the server, DNS
    // and the relay the reconnect needs); the persistent block is where it lands only if the
    // reconnect gives up, or after a plain disconnect.
    if (status === 'disconnected' && this.settings.permanentKillSwitch && !this.isReconnecting) {
      this._updateKillSwitchState('persistentBlock').catch(err =>
        log.warn('VPN: Kill switch persistent block failed:', err.message)
      );
    }

    this.notifyStatusChange();
  }

  /**
   * The tunnel is gone and the user did not ask for that. Release the dropped session, then start
   * the reconnect loop with a brand-new one.
   */
  _handleUnexpectedDrop() {
    log.info('VPN: Unexpected tunnel disconnect — clearing stale session');
    this._lastAttemptServerSide = false;
    this._reconnectExcluded.clear();
    this._stopHealthMonitor();

    const staleSessionId = this.currentSession?.sessionId;
    const serverId = this.currentServerId;
    const gatewayId = this.currentGatewayId;
    const wasStable = this.connectedSince != null &&
      (Date.now() - this.connectedSince) >= this.minimumStableConnectionDuration * 1000;

    // Release the dropped session whether or not it was stable. The reconnect below claims a
    // brand-new session (+1); without a /disconnect for this one its slot is lost for good, since
    // neither stale-session cleanup nor subscription expiry ever lowers the backend's counter.
    // The tunnel is already down, so nothing needs to settle first: release right away, which also
    // keeps the replacement /connect from tripping the device limit at 5/5.
    log.warn(`CONN_COUNTER: unexpected drop, session=${this._short(staleSessionId)} stable=${wasStable} — releasing it, then reconnecting`);
    if (staleSessionId) {
      this.cleanupOrphanedSession(
        staleSessionId,
        wasStable
          ? 'unexpected drop of a stable connection'
          : `dropped before ${this.minimumStableConnectionDuration}s stability threshold`,
        { immediate: true }
      );
    }

    this.currentSession = null;
    this.connectedSince = null;
    // The saved copy goes too, so a relaunch cannot restore a session that was just released. The
    // in-memory config stays: it is the fallback when the backend cannot be reached.
    try { this.configStore?.delete('lastSession'); } catch { /* best effort */ }

    if (serverId) {
      // Standard kill switch: the Connected rules pass the (now gone) tunnel interface. Fall back to
      // Bootstrap, which permits only the server, DNS and the relay, so the reconnect can work and
      // nothing else gets out. Always-On takes the same route; it reaches the persistent block only
      // if the reconnect gives up.
      this._holdBlockForReconnect().catch(err => log.warn('VPN: Could not move the block to Bootstrap:', err.message));
      this._attemptReconnect(serverId, gatewayId);
    }
  }

  /** Moves a Connected kill switch back to Bootstrap after the tunnel dropped. */
  async _holdBlockForReconnect() {
    if (!this.helperConnected) return;
    if (!(this.settings?.killSwitch || this.settings?.permanentKillSwitch)) return;
    if (this.killSwitchState !== 'connected') return;
    const endpoint = this.lastConnectionConfig?.config?.endpoint;
    if (!endpoint) return;
    const serverIp = await this._resolveServerIp(endpoint);
    if (!serverIp) return;
    log.info('[TEMP] drop: moving kill switch Connected -> Bootstrap while the reconnect runs');
    await this._updateKillSwitchState('bootstrap', { serverIp, serverPort: extractEndpointPort(endpoint) });
  }

  /**
   * Auto-reconnect after an unexpected tunnel drop. Mirrors iOS's attemptReconnect(): exponential
   * backoff with jitter (1s, 2s, 4s, 8s, 15s max by default), up to maxReconnectAttempts, using
   * the same server/settings as the connection that just dropped.
   */
  _attemptReconnect(serverId, gatewayId = this.currentGatewayId) {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      this.isReconnecting = false;
      this.reconnectGaveUp = true;
      log.error(`VPN: Reconnection failed after ${this.maxReconnectAttempts} attempts`);
      // currentSession was cleared when the tunnel dropped; release whichever is still held.
      const held = this.currentSession?.sessionId || this.lastConnectionConfig?.sessionId;
      if (held) {
        this.cleanupOrphanedSession(held, 'reconnect attempts exhausted');
      }
      this.currentServerId = null;
      this.currentGatewayId = null;
      this._finishGiveUp();
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
    const delay = baseDelay * jitterFactor * 1000; // the base/max delays are in seconds; setTimeout wants ms

    clearTimeout(this._reconnectTimer);
    this._reconnectTimer = setTimeout(async () => {
      if (this.userInitiatedDisconnect) return;
      try {
        // Free the old slot first. At 5 of 5 devices, asking for a new session before the old one is
        // released is refused as "device limit"; the release may have been waiting for the network.
        await Promise.race([
          this.retryPendingDisconnects({ immediate: true }),
          new Promise((resolve) => setTimeout(resolve, RELEASE_WAIT_MS)),
        ]);
        const token = this._getAuthToken ? this._getAuthToken() : '';

        // The same server keeps failing (rebuilt, down, or removed): with "reconnect to another
        // server" on, try the lowest-latency other server instead. Skipped for organization gateways
        // (a Dedicated IP is tied to its server). Later attempts re-check, so a recovered server is
        // not abandoned for good by one bad moment.
        let targetServerId = serverId;
        // Read the saved choice, not the settings captured at connect time: the user may have flipped it since.
        let switchServers = this.settings?.reconnectToAnotherServer ?? true;
        try { switchServers = this.configStore?.get('reconnectToAnotherServer', switchServers); } catch { /* keep the captured value */ }
        // Switch right after the first failure that was the SERVER's fault (retrying it would get the same
        // answer); for other failures wait until it has failed FALLBACK_AFTER_ATTEMPTS times.
        const shouldSwitch = this._lastAttemptServerSide || this.reconnectAttempts > FALLBACK_AFTER_ATTEMPTS;
        if (shouldSwitch && switchServers && !gatewayId) {
          try {
            this._reconnectExcluded.add(serverId);
            const alternative = await this._pickFallbackServerId(this._reconnectExcluded, token);
            if (alternative) {
              log.warn(`VPN: ${serverId} failed (${this._lastAttemptServerSide ? 'server error' : `${this.reconnectAttempts - 1} attempts`}), trying ${alternative} instead`);
              targetServerId = alternative;
            }
          } catch (pickError) {
            log.warn(`VPN: Could not choose a fallback server: ${pickError.message}`);
          }
        }

        // The user may have cancelled during the waits above. Without this check the cancelled attempt
        // carried on into connect(), which reset the cancel flags and ended up connecting anyway.
        if (this.userInitiatedDisconnect) return;

        this._lastTargetServerId = targetServerId;
        await this.connect(targetServerId, this.settings, token, gatewayId);
        // Success: _connect() already reset isReconnecting/reconnectAttempts/connectedSince.
        // Tell the screen. The tunnel's own 'connected' push arrives while isReconnecting is still true
        // (the status then reads 'connecting'), and connect() sends nothing at the end, so without this
        // the screen stays on "connecting" although the tunnel is up.
        this.notifyStatusChange();
      } catch (err) {
        log.warn(`VPN: Reconnect attempt ${this.reconnectAttempts} failed: ${err.message}`);
        this._lastAttemptServerSide = !!(err && err.serverSide);
        // A server that failed on its own is not tried again during this reconnect.
        if (this._lastAttemptServerSide && this._lastTargetServerId) this._reconnectExcluded.add(this._lastTargetServerId);
        if (err instanceof UnauthorizedError) {
          // The login expired while away. Retrying cannot fix that: stop, and let the app send the
          // user back to sign-in (see authExpired in the status).
          log.warn('VPN: Reconnect stopped, the login expired');
          this.isReconnecting = false;
          this.reconnectAttempts = 0;
          this.currentServerId = null;
          this.currentGatewayId = null;
          this.authExpired = true;
          this.notifyStatusChange();
          return;
        }
        if (err instanceof ConnectCancelledError) return;
        if (!this.userInitiatedDisconnect) {
          this._attemptReconnect(serverId, gatewayId);
        }
      }
    }, delay);
  }

  /**
   * The reconnect loop used up its attempts. Always-On lands in the persistent block (protected, the
   * user reconnects by hand). A standard kill switch STAYS blocked: opening the internet here, unasked,
   * would break the promise that a dropped VPN never leaks. The user restores it with Disconnect.
   */
  _finishGiveUp() {
    if (!this.helperConnected) return;
    if (this.settings?.permanentKillSwitch) {
      log.info('VPN: Reconnect gave up, Always-On keeps the internet blocked (persistent block)');
      this._updateKillSwitchState('persistentBlock').catch(err =>
        log.warn('VPN: Kill switch persistent block failed:', err.message));
    } else if (this.settings?.killSwitch) {
      log.info('VPN: Reconnect gave up, standard kill switch stays blocked until the user disconnects');
    }
  }

  /**
   * The lowest-latency active server other than the ones that keep failing, or null when none can be
   * reached. Needs the backend (the server list), so it only helps while the network is open.
   */
  async _pickFallbackServerId(excludedServerIds, token) {
    const response = await this._fetch(`${this.apiBaseUrl}/vpn/servers`, {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok) return null;

    const list = await response.json();
    // Plain servers only: organization gateway entries repeat a node's id with a gatewayId.
    const candidates = (Array.isArray(list) ? list : [])
      .filter(sv => sv && sv.id && sv.host && !sv.gatewayId && !excludedServerIds.has(sv.id))
      .map(sv => ({ id: sv.id, host: sv.host }));
    if (candidates.length === 0) return null;

    const latencies = await require('../latency').measureAll(candidates);
    let best = null;
    for (const c of candidates) {
      const ms = latencies[c.id];
      if (ms !== undefined && (best === null || ms < best.ms)) best = { id: c.id, ms };
    }
    return best ? best.id : null;
  }

  // --- Sleep / wake -------------------------------------------------------------------------

  /**
   * The machine is going to sleep (lid closed). Nothing to do: the tunnel cannot be serviced while
   * asleep. Logged so a bad wake-up can be read against the sleep that caused it.
   */
  handleSuspend() {
    this.suspendedAt = Date.now();
    log.info(`POWER: suspend (connected=${!!this.currentSession}, session=${this._short(this.currentSession?.sessionId)})`);
  }

  /**
   * The machine woke up. A short sleep is left to recover by itself: the health monitor holds off
   * judging the tunnel for a grace period, then reconnects through the usual drop path if the tunnel
   * really is gone. A sleep as long as the backend's idle limit has lost the session on the server,
   * so the saved credentials can no longer work: skip the retry that is bound to fail and ask for a
   * new session now.
   */
  handleResume() {
    const asleepMs = this.suspendedAt ? Date.now() - this.suspendedAt : null;
    this.suspendedAt = null;
    const asleepFor = asleepMs === null ? 'unknown' : `${Math.round(asleepMs / 1000)}s`;
    log.info(`POWER: resume after ${asleepFor} (connected=${!!this.currentSession}, reconnecting=${this.isReconnecting}, session=${this._short(this.currentSession?.sessionId)})`);
    this._graceUntil = Date.now() + RESUME_GRACE_MS;
    this._probeFailures = 0;
    this._staleHandshakeChecks = 0;
    if (this.currentSession) this._logConnectionCounter('after resume');

    if (asleepMs !== null && asleepMs >= this._longSleepMs() && this.currentSession &&
        !this.userInitiatedDisconnect && !this.isReconnecting) {
      this._rebuildAfterLongSleep().catch(err => log.error('POWER: rebuild after long sleep failed:', err.message));
    }
  }

  /** How long a sleep must be to assume the backend dropped the session: the lease minus an hour. */
  _longSleepMs() {
    const lease = this.currentSession?.leaseHours;
    return Number.isFinite(lease) && lease > 1 ? (lease - 1) * 60 * 60 * 1000 : LONG_SLEEP_MS;
  }

  /** Tear down the stale tunnel and reconnect through the normal drop path (new session, with backoff). */
  async _rebuildAfterLongSleep() {
    log.info('POWER: long sleep, rebuilding the connection with a new session');
    this._tearDownDeadTunnel();
    this._handleUnexpectedDrop();
  }

  /** Stops the tunnel without the status handler mistaking the resulting event for a user action. */
  _tearDownDeadTunnel() {
    try {
      this._getNativeAddon()?.stopTunnel();
    } catch (err) {
      log.warn('VPN: Teardown of the dead tunnel failed:', err.message);
    }
  }

  // --- Tunnel health --------------------------------------------------------------------------

  /**
   * After the tunnel starts, confirm it really came up. Two checks, both needed:
   *  - the system's tunnel status must not sit at 'disconnected': when the extension cannot start (not
   *    approved, bad signature, crash) the start request still "succeeds" and the status flips to
   *    disconnected a moment later, so without this the app reports Connected with no tunnel at all and
   *    the user's real IP showing;
   *  - the server must answer the handshake. Unknown (the extension's snapshot cannot be read) lets the
   *    connect proceed once the tunnel is up: only a snapshot that is readable AND says no handshake
   *    happened fails the attempt.
   */
  async _verifyHandshake(sinceMs, abortToken, addon) {
    const deadline = Date.now() + HANDSHAKE_WAIT_MS;
    let sawReadable = false;
    let disconnectedSince = null;
    let lastStatus = 'unknown';
    let lastWaitLog = 0;
    while (Date.now() < deadline) {
      if (abortToken.cancelled) {
        this._tearDownDeadTunnel();
        throw new ConnectCancelledError();
      }

      try { lastStatus = addon?.getStatus?.() || 'unknown'; } catch { lastStatus = 'unknown'; }
      if (lastStatus === 'disconnected') {
        if (disconnectedSince === null) disconnectedSince = Date.now();
        if (Date.now() - disconnectedSince >= TUNNEL_START_GRACE_MS) {
          log.error(`VPN: The tunnel did not come up (system status stayed '${lastStatus}' ${Date.now() - disconnectedSince}ms after start)`);
          throw new Error('The VPN tunnel failed to start. Check that the WireDog network extension is approved in System Settings, then try again.');
        }
      } else {
        disconnectedSince = null;
      }

      if (Date.now() - lastWaitLog >= 1000) {
        lastWaitLog = Date.now();
        const snap = await health.readTunnelHealth();
        log.info(`[TEMP] handshake wait +${Date.now() - sinceMs}ms status=${lastStatus} ${snap ? `rx=${snap.rxBytes} tx=${snap.txBytes} lastHandshake=${snap.lastHandshake}` : 'snapshot not reachable'}`);
      }
      const result = await health.hasRecentHandshake(sinceMs);
      if (result === true) {
        log.info(`[TEMP] Handshake confirmed ${Date.now() - sinceMs}ms after the tunnel started (status=${lastStatus})`);
        return;
      }
      if (result === false) sawReadable = true;

      // The tunnel is up but the snapshot has never been readable: nothing more to learn by waiting.
      if (!sawReadable && lastStatus === 'connected' && Date.now() - sinceMs >= UNREADABLE_SNAPSHOT_GIVEUP_MS) {
        log.warn('[TEMP] Handshake state unknown (tunnel health snapshot not reachable from the app) — not failing the connect');
        return;
      }
      await new Promise(r => setTimeout(r, 250));
    }
    if (!sawReadable && lastStatus === 'connected') {
      log.warn('[TEMP] Handshake state unknown (tunnel health snapshot not reachable from the app) — not failing the connect');
      return;
    }
    const err = new Error(sawReadable ? 'The server did not answer the tunnel handshake' : 'The VPN tunnel did not come up in time');
    err.serverSide = sawReadable;
    throw err;
  }

  _startHealthMonitor(config) {
    this._stopHealthMonitor();
    const now = Date.now();
    this._connectedAtMs = now;
    this._lastTick = now;
    this._lastProbe = now;
    this._graceUntil = 0;
    this._probeFailures = 0;
    this._staleHandshakeChecks = 0;
    this._probeTarget = health.getProbeTarget(config?.dns);
    this._probeServerKey = (config?.endpoint || '').split(':')[0];
    this._probeEverAnswered = !!this._probeServerKey && this._probeAnsweredServers.has(this._probeServerKey);
    this._noAnswerWarned = false;
    if (!this._probeTarget) log.info('[HEALTH] No IPv4 resolver in the tunnel config, data-path probe disabled');
    this._monitorTimer = setInterval(() => {
      this._monitorTick().catch(err => log.warn('[HEALTH] check failed:', err.message));
    }, MONITOR_INTERVAL_MS);
    if (this._monitorTimer.unref) this._monitorTimer.unref();
  }

  _stopHealthMonitor() {
    if (this._monitorTimer) {
      clearInterval(this._monitorTimer);
      this._monitorTimer = null;
    }
  }

  async _monitorTick() {
    if (this._monitorBusy) return;
    if (!this.currentSession || this.isReconnecting || this.userInitiatedDisconnect) return;
    this._monitorBusy = true;
    try {
      const now = Date.now();
      if (now - this._lastTick > SLEEP_GAP_MS) {
        this._graceUntil = now + RESUME_GRACE_MS;
        this._probeFailures = 0;
        this._staleHandshakeChecks = 0;
        log.info(`[HEALTH] Resume from sleep detected (gap ${Math.round((now - this._lastTick) / 1000)}s) — holding off health checks for ${RESUME_GRACE_MS / 1000}s`);
      }
      this._lastTick = now;
      const inGrace = now < this._graceUntil;

      // Data-path probe. Only counts once it has been answered at least once on this tunnel (or this
      // server in this run), so a node that does not answer it can never tear down a healthy connection.
      if (this._probeTarget && !inGrace && now - this._lastProbe >= PROBE_INTERVAL_MS) {
        this._lastProbe = now;
        const answered = await health.probeTunnel(this._probeTarget);
        if (!this.currentSession) return; // went away while probing
        if (answered) {
          if (!this._probeEverAnswered) log.info(`[HEALTH] Data-path probe answered by ${this._probeTarget}, now watching the tunnel with it`);
          this._probeEverAnswered = true;
          if (this._probeServerKey) this._probeAnsweredServers.add(this._probeServerKey);
          this._probeFailures = 0;
        } else if (!this._probeEverAnswered) {
          if (!this._noAnswerWarned && now - this._connectedAtMs > 30000) {
            this._noAnswerWarned = true;
            log.warn(`[HEALTH] Data-path probe has not been answered ${Math.round((now - this._connectedAtMs) / 1000)}s after connecting (${await this._describeHealth()})`);
          }
        } else {
          this._probeFailures += 1;
          log.warn(`[HEALTH] Data-path probe got no answer (failure ${this._probeFailures}/${PROBE_FAILURE_THRESHOLD}; ${await this._describeHealth()})`);
          if (this._probeFailures >= PROBE_FAILURE_THRESHOLD) {
            this._onTunnelDead('data-path probe unanswered');
            return;
          }
        }
      }

      // Handshake freshness (WireGuard re-handshakes about every 2 minutes while data flows).
      if (!inGrace) {
        const fresh = await health.hasRecentHandshake(this._connectedAtMs);
        if (fresh === false) {
          this._staleHandshakeChecks += 1;
          log.warn(`[HEALTH] Handshake stale (check ${this._staleHandshakeChecks}/${STALE_HANDSHAKE_THRESHOLD}; ${await this._describeHealth()})`);
          if (this._staleHandshakeChecks >= STALE_HANDSHAKE_THRESHOLD) {
            this._onTunnelDead('handshake stale');
            return;
          }
        } else if (fresh === true) {
          this._staleHandshakeChecks = 0;
        }
      }
    } finally {
      this._monitorBusy = false;
    }
  }

  async _describeHealth() {
    const h = await health.readTunnelHealth();
    if (!h) return 'snapshot unavailable';
    const hs = h.lastHandshake ? `${Math.round(Date.now() / 1000 - h.lastHandshake)}s ago` : 'never';
    return `rx ${h.rxBytes}, tx ${h.txBytes}, last handshake ${hs}`;
  }

  /** The monitor decided the tunnel stopped carrying data: same path as an unexpected drop. */
  _onTunnelDead(reason) {
    log.error(`[HEALTH] Tunnel stopped carrying data (${reason}) — treating as an unexpected drop`);
    if (!this.currentSession || this.userInitiatedDisconnect) return;
    this._tearDownDeadTunnel();
    this._handleUnexpectedDrop();
  }

  /**
   * Cleanup on shutdown. The release is awaited: the process may exit right after this returns, and a
   * release left to a timer would only happen at the next launch (days later, for someone who doesn't
   * reopen the app), leaving the counter one too high. If the call can't complete, the pending-
   * disconnect ledger still retries it on the next launch.
   */
  async cleanup() {
    log.info('VPN: Cleanup on shutdown');

    // Quitting is the user's choice: nothing below may be mistaken for a drop and start a reconnect.
    this.userInitiatedDisconnect = true;
    this._stopHealthMonitor();
    clearTimeout(this._reconnectTimer);
    this._reconnectTimer = null;
    this.isReconnecting = false;

    const session = this.currentSession;
    const heldFromDrop = session ? null : this.lastConnectionConfig?.sessionId;
    this.currentSession = null;

    try {
      const addon = this._getNativeAddon();
      if (addon) addon.stopTunnel();
    } catch (error) {
      log.warn('VPN: Stop tunnel on cleanup error:', error.message);
    }

    const sessionId = session?.sessionId || heldFromDrop;
    if (sessionId) {
      await this.cleanupOrphanedSession(sessionId, 'app quit', { immediate: true });
    }
    // Quit means the session was released: it must not be restored (and released again) next launch.
    try { this.configStore?.delete('lastSession'); } catch { /* best effort */ }

    serviceClient.disconnect();
    this.lastConnectionConfig = null;
  }
}

module.exports = new VPNService();
