/**
 * Tunnel health helpers: the extension's health snapshot and the data-path probe.
 *
 * Two independent signals about a tunnel that claims to be up:
 *  - the WireGuard handshake time, which the extension serves on loopback, refreshed every few seconds
 *    (see PacketTunnelProvider, "Tunnel health"). A handshake goes stale about two minutes after
 *    the tunnel stops carrying data.
 *  - a data-path probe: one tiny DNS question sent through the tunnel to the node's own resolver. An
 *    answer proves the path works both ways, and a few misses in a row notice a dead tunnel in about
 *    half a minute instead of two.
 */
const dgram = require('dgram');
const log = require('electron-log');

// The extension is sandboxed and runs as root, so it cannot write a file the user's app can read. It
// serves its snapshot on 127.0.0.1 instead (see PacketTunnelProvider, "Tunnel health").
const HEALTH_URL = 'http://127.0.0.1:51873/';
const HEALTH_FETCH_TIMEOUT_MS = 1500;

// A snapshot older than this is not trusted (the extension refreshes it every 3 s).
const HEALTH_MAX_AGE_S = 15;
// A handshake older than this means the tunnel stopped carrying data (WireGuard re-keys about every 2 min).
const HANDSHAKE_FRESH_S = 3 * 60;

let wasReachable = null;

/**
 * The newest snapshot the extension is serving, or null when it cannot be read (not running, stale).
 * @returns {Promise<{updatedAt:number,lastHandshake:number,rxBytes:number,txBytes:number}|null>}
 */
async function readTunnelHealth() {
  try {
    const response = await fetch(HEALTH_URL, {
      // A fresh connection every time: this must never ride a pooled socket.
      headers: { Connection: 'close' },
      signal: AbortSignal.timeout(HEALTH_FETCH_TIMEOUT_MS),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const parsed = await response.json();
    if (!Number.isFinite(parsed.updatedAt)) throw new Error('no snapshot yet');
    if (Date.now() / 1000 - parsed.updatedAt > HEALTH_MAX_AGE_S) throw new Error('snapshot is stale');
    if (wasReachable !== true) {
      wasReachable = true;
      log.info('[TEMP] Health: tunnel snapshot is reachable on loopback');
    }
    return parsed;
  } catch (err) {
    if (wasReachable !== false) {
      wasReachable = false;
      log.info(`[TEMP] Health: tunnel snapshot not available (${err.message})`);
    }
    return null;
  }
}

/**
 * True when the node completed a handshake within the last 3 minutes, false when the snapshot is
 * readable and says it did not, null when it cannot be read (unknown: callers must NOT treat that as
 * a failure, or a snapshot the app cannot reach would break every connect).
 * @param {number} [sinceMs] only trust a snapshot written after this time
 */
async function hasRecentHandshake(sinceMs = 0) {
  const health = await readTunnelHealth();
  if (!health) return null;
  if (health.updatedAt * 1000 < sinceMs) return null;
  if (!health.lastHandshake) return false;
  return Date.now() / 1000 - health.lastHandshake < HANDSHAKE_FRESH_S;
}

/** First IPv4 address in the tunnel's DNS list: the node's own resolver, reached through the tunnel. */
function getProbeTarget(dnsConfig) {
  if (typeof dnsConfig !== 'string') return null;
  for (const part of dnsConfig.split(',').map(p => p.trim())) {
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(part)) return part;
  }
  return null;
}

/**
 * Sends one DNS question (a made-up name under .invalid, which the resolver answers on its own with no
 * upstream lookup) to the node's resolver and waits up to 3 s for ANY reply. Nothing the user browsed
 * is involved. Any send or receive error counts as no answer.
 * @returns {Promise<boolean>}
 */
function probeTunnel(target) {
  return new Promise((resolve) => {
    const socket = dgram.createSocket('udp4');
    const id = Math.floor(Math.random() * 65534) + 1;
    const header = Buffer.from([id >> 8, id & 0xff, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    const labels = ['wiredog', 'invalid'].map(l => Buffer.concat([Buffer.from([l.length]), Buffer.from(l, 'ascii')]));
    const query = Buffer.concat([header, ...labels, Buffer.from([0x00, 0x00, 0x01, 0x00, 0x01])]);

    let done = false;
    const finish = (ok) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { socket.close(); } catch { /* already closed */ }
      resolve(ok);
    };
    const timer = setTimeout(() => finish(false), 3000);
    socket.on('error', () => finish(false));
    socket.on('message', (msg) => {
      finish(msg.length >= 12 && msg[0] === (id >> 8) && msg[1] === (id & 0xff) && (msg[2] & 0x80) !== 0);
    });
    socket.send(query, 53, target, (err) => { if (err) finish(false); });
  });
}

module.exports = { readTunnelHealth, hasRecentHandshake, getProbeTarget, probeTunnel, HANDSHAKE_FRESH_S };
