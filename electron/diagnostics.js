/**
 * Verbose Diagnostic Mode (VDM).
 *
 * An opt-in support tool: a customer turns it on (Account > Debug Logs), reproduces a problem, then sends the
 * log folder to support. While on, it writes WireDog-VDM.log next to main.log with everything needed to
 * diagnose a connect, disconnect, switch or drop without a one-off build:
 *   - an environment snapshot (macOS, Mac model, app/helper/extension versions, other system extensions
 *     and VPN configurations, network service order, DNS and proxy configuration);
 *   - a timeline per connect/disconnect attempt with the time spent in every stage;
 *   - a 1 s sampler while an attempt or teardown is in progress (system tunnel status, scutil status, the
 *     extension's health snapshot, the extension and Network Extension daemons, utun interfaces, the
 *     default route) and a 15 s sampler otherwise;
 *   - preflight checks per attempt (DNS timings, ping to the server, backend HTTPS timings);
 *   - macOS unified-log captures for our extension and Apple's Network Extension daemons around attempts
 *     that are slow, failed, or dropped;
 *   - a mirror of every main.log line, so it all reads as one timeline.
 *
 * Privacy: nothing leaves the Mac unless the customer sends the file. Nothing about browsing is
 * recorded (no visited addresses, no DNS questions other than our own server names). Output is redacted
 * (home folder, user name in paths, MAC addresses, WireGuard keys, auth tokens). It turns itself off 24 h
 * after it was turned on, so it cannot be left running by accident.
 */
const fs = require('fs');
const path = require('path');
const os = require('os');
const util = require('util');
const { execFile } = require('child_process');
const dnsPromises = require('dns').promises;
const log = require('electron-log');
const { app } = require('electron');

const STORE_KEY = 'verboseDiagnostics';
const AUTO_OFF_MS = 24 * 60 * 60 * 1000;
const FILE_NAME = 'WireDog-VDM.log';
const MAX_FILE_BYTES = 25 * 1024 * 1024;
const FAST_SAMPLE_MS = 1000;
const SLOW_SAMPLE_MS = 15000;
// After an attempt or teardown ends, keep sampling this long to see what the system does next.
const FAST_TAIL_MS = 20000;
// A connect still in progress after this long gets a unified-log capture (the slow-start case).
const MID_CAPTURE_MS = 15000;
const AFTER_TEARDOWN_CAPTURE_MS = 30000;
const MAX_UNIFIED_CHARS = 3 * 1024 * 1024;
const MAX_CMD_CHARS = 40000;
const CMD_TIMEOUT_MS = 4000;

// Our extension, our app, and the Apple daemons that start and stop it.
const UNIFIED_PREDICATE = [
  'subsystem == "com.wiredog.vpn.macos.tunnel"',
  'process == "com.wiredog.vpn.macos.tunnel"',
  'process == "WireDog VPN"',
  'process == "nesessionmanager"',
  'process == "neagent"',
  'process == "sysextd"',
].join(' OR ');

// ---- redaction ---------------------------------------------------------------------------------

const HOME = os.homedir();
const REDACTIONS = [
  [/\/Users\/[^/\s"']+/g, '/Users/<user>'],
  [/\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b/gi, '<mac>'],
  [/eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, '<token>'],
  [/Bearer\s+[^\s"']+/gi, 'Bearer <token>'],
  // WireGuard keys (32 bytes, base64): never needed to diagnose anything.
  [/\b[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=/g, '<key>'],
];

function redact(text) {
  let out = String(text);
  if (HOME && HOME.length > 1) out = out.split(HOME).join('~');
  for (const [pattern, replacement] of REDACTIONS) out = out.replace(pattern, replacement);
  return out;
}

// ---- small helpers -----------------------------------------------------------------------------

function run(cmd, args, { timeout = CMD_TIMEOUT_MS, maxChars = MAX_CMD_CHARS } = {}) {
  const started = Date.now();
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout, maxBuffer: 64 * 1024 * 1024 }, (error, stdout, stderr) => {
      let out = String(stdout || '') + (stderr ? String(stderr) : '');
      if (out.length > maxChars) out = `${out.slice(0, maxChars)}\n...[truncated ${out.length - maxChars} chars]`;
      resolve({ ok: !error, ms: Date.now() - started, out: out.trim(), error: error ? error.message : null });
    });
  });
}

function localStamp(ms) {
  const d = new Date(ms);
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function oneLine(text, max = 400) {
  const flat = String(text || '').replace(/\s+/g, ' ').trim();
  return flat.length > max ? `${flat.slice(0, max)}...` : flat;
}

function interfaceSummary() {
  const result = [];
  for (const [name, addrs] of Object.entries(os.networkInterfaces())) {
    const list = (addrs || []).filter(a => !a.internal).map(a => `${a.address}/${a.cidr ? a.cidr.split('/')[1] : '?'}`);
    if (list.length) result.push(`${name}=[${list.join(', ')}]`);
  }
  return result.join(' ');
}

// ---- the module --------------------------------------------------------------------------------

class VerboseDiagnostics {
  constructor() {
    this.enabled = false;
    this.enabledAt = null;
    this.store = null;
    this.providers = {};
    this.filePath = null;
    this._queue = [];
    this._writing = false;
    this._attempt = null;
    this._attemptSeq = 0;
    this._fastUntil = 0;
    this._fastTimer = null;
    this._slowTimer = null;
    this._autoOffTimer = null;
    this._sampling = false;
    this._hookInstalled = false;
  }

  /** Called once the settings store exists. Restores the saved state (and turns off an expired one). */
  init({ store }) {
    this.store = store;
    try {
      const logDir = path.dirname(log.transports.file.getFile().path);
      this.filePath = path.join(logDir, FILE_NAME);
    } catch {
      this.filePath = path.join(app.getPath('logs'), FILE_NAME);
    }
    this._installLogMirror();
    const saved = store?.get(STORE_KEY) || {};
    if (saved.enabled && Number.isFinite(saved.enabledAt)) {
      if (Date.now() - saved.enabledAt >= AUTO_OFF_MS) {
        log.info('[VDM] Verbose Diagnostic Mode expired (24 h), turning it off');
        this._persist(false, null);
      } else {
        this._activate(saved.enabledAt, 'restored at app launch');
      }
    }
  }

  /** Functions the module calls to read live state; supplied by the VPN service and main.js. */
  setProviders(providers) {
    this.providers = { ...this.providers, ...providers };
  }

  isEnabled() {
    return this.enabled;
  }

  getState() {
    return {
      enabled: this.enabled,
      enabledAt: this.enabledAt,
      autoOffAt: this.enabled && this.enabledAt ? this.enabledAt + AUTO_OFF_MS : null,
      filePath: this.filePath ? redact(this.filePath) : null,
    };
  }

  setEnabled(on) {
    if (on && !this.enabled) {
      const now = Date.now();
      this._persist(true, now);
      this._activate(now, 'turned on by the user');
    } else if (!on && this.enabled) {
      this._deactivate('turned off by the user');
    }
    return this.getState();
  }

  // ---- logging ---------------------------------------------------------------------------------

  /** One line in the VDM file. No-op when VDM is off. */
  log(category, message, data) {
    if (!this.enabled) return;
    const rel = this._attempt ? ` ${this._attempt.label} +${((Date.now() - this._attempt.startMs) / 1000).toFixed(3)}s |` : '';
    let line = `[${new Date().toISOString()}]${rel} [${category}] ${message}`;
    if (data !== undefined) {
      try {
        line += ` ${typeof data === 'string' ? data : JSON.stringify(data)}`;
      } catch {
        line += ` ${util.inspect(data, { depth: 3 })}`;
      }
    }
    this._write(`${redact(line)}\n`);
  }

  /** A multi-line block (command output, unified log). */
  block(title, text) {
    if (!this.enabled) return;
    const body = redact(text || '(empty)');
    this._write(`[${new Date().toISOString()}] ===== BEGIN ${title} (${body.length} chars) =====\n${body}\n===== END ${title} =====\n`);
  }

  // ---- attempts --------------------------------------------------------------------------------

  /**
   * Starts tracking a connect or disconnect. Returns an id to pass to stage()/endAttempt(); the calls are
   * safe (and do nothing) when VDM is off.
   */
  beginAttempt(kind, info = {}) {
    if (!this.enabled) return null;
    this._attemptSeq += 1;
    const id = this._attemptSeq;
    const startMs = Date.now();
    this._attempt = { id, kind, label: `${kind === 'connect' ? 'c' : 'd'}${id}`, startMs, stages: [], firsts: new Set(), lastStatus: null };
    this.log('ATTEMPT', `BEGIN ${kind} #${id}`, { ...info, app: app.getVersion() });
    this.log('ATTEMPT', 'state', this._safe(() => this.providers.describeState?.()));
    this._extendFastSampling(startMs + 10 * 60 * 1000);
    if (kind === 'connect') {
      const attempt = this._attempt;
      attempt.midTimer = setTimeout(() => {
        if (this._attempt === attempt && !attempt.ended) {
          this.captureUnifiedLog(`MID +${MID_CAPTURE_MS / 1000}s (still not connected)`, startMs - 20000);
        }
      }, MID_CAPTURE_MS);
    }
    return id;
  }

  stage(id, name, data) {
    if (!this.enabled || !this._attempt || this._attempt.id !== id) return;
    const elapsed = Date.now() - this._attempt.startMs;
    this._attempt.stages.push(`${name}=+${(elapsed / 1000).toFixed(3)}s`);
    this.log('STAGE', name, data);
  }

  /** Logs a "first time seen" milestone once per attempt (first status, first handshake, and so on). */
  first(id, what, data) {
    if (!this.enabled || !this._attempt || this._attempt.id !== id || this._attempt.firsts.has(what)) return;
    this._attempt.firsts.add(what);
    this._attempt.stages.push(`${what}=+${((Date.now() - this._attempt.startMs) / 1000).toFixed(3)}s`);
    this.log('FIRST', what, data);
  }

  endAttempt(id, outcome, error) {
    if (!this.enabled || !this._attempt || this._attempt.id !== id) return;
    const attempt = this._attempt;
    attempt.ended = true;
    clearTimeout(attempt.midTimer);
    const total = ((Date.now() - attempt.startMs) / 1000).toFixed(3);
    this.log('ATTEMPT', `END ${attempt.kind} #${id}: ${outcome} after ${total}s`, error ? { error: error.message, serverSide: error.serverSide, retryable: error.retryable } : undefined);
    this.log('SUMMARY', attempt.stages.join('; ') || '(no stages)');
    this._extendFastSampling(Date.now() + FAST_TAIL_MS);
    if (outcome !== 'ok') {
      const since = attempt.startMs - 20000;
      this.captureUnifiedLog(`FINAL ${attempt.kind} #${id} (${outcome})`, since);
      setTimeout(() => this.captureUnifiedLog(`AFTER-TEARDOWN ${attempt.kind} #${id} (+${AFTER_TEARDOWN_CAPTURE_MS / 1000}s)`, since), AFTER_TEARDOWN_CAPTURE_MS);
    }
    if (this._attempt === attempt) this._attempt = null;
  }

  /** Every system tunnel status notification, with the attempt-relative time. */
  noteTunnelStatus(status) {
    if (!this.enabled) return;
    this.log('NE-STATUS', `notification: ${status}`);
    if (this._attempt) this.first(this._attempt.id, `notification ${status}`);
  }

  /** An unexpected drop or health-monitor failure: worth a unified-log capture on its own. */
  noteDrop(reason) {
    if (!this.enabled) return;
    this.log('DROP', reason, this._safe(() => this.providers.describeState?.()));
    this._extendFastSampling(Date.now() + 60000);
    this.captureUnifiedLog(`DROP (${reason})`, Date.now() - 120000);
  }

  // ---- preflight -------------------------------------------------------------------------------

  /** Checks the path to the server outside the tunnel, in the background. */
  preflight(id, endpoint) {
    if (!this.enabled) return;
    const host = String(endpoint || '').split(':')[0];
    if (!host) return;
    (async () => {
      for (let i = 1; i <= 3; i++) {
        const started = Date.now();
        try {
          const res = await dnsPromises.lookup(host, { family: 4 });
          this.log('PREFLIGHT', `getaddrinfo(${host}) #${i}: ${Date.now() - started}ms -> ${res.address}`);
        } catch (err) {
          this.log('PREFLIGHT', `getaddrinfo(${host}) #${i}: FAILED after ${Date.now() - started}ms (${err.code || err.message})`);
        }
      }
      const control = Date.now();
      try {
        await dnsPromises.lookup('www.apple.com', { family: 4 });
        this.log('PREFLIGHT', `control getaddrinfo(www.apple.com): ${Date.now() - control}ms`);
      } catch (err) {
        this.log('PREFLIGHT', `control getaddrinfo(www.apple.com): FAILED (${err.code || err.message})`);
      }
      const ping = await run('/sbin/ping', ['-c', '4', '-t', '6', host], { timeout: 8000 });
      this.log('PREFLIGHT', `ping ${host} (outside the tunnel, 4 packets): ${oneLine(ping.out.split('\n').slice(-2).join(' | '))}`);
      const base = this._safe(() => this.providers.apiBaseUrl?.());
      if (base) {
        const curl = await run('/usr/bin/curl', ['-s', '-o', '/dev/null', '-m', '8', '-w',
          'dns=%{time_namelookup}s connect=%{time_connect}s tls=%{time_appconnect}s ttfb=%{time_starttransfer}s total=%{time_total}s http=%{http_code}',
          `${base}/app/config`], { timeout: 10000 });
        this.log('PREFLIGHT', `backend HTTPS timing: ${oneLine(curl.out)}${curl.error ? ` (${curl.error})` : ''}`);
      }
      if (this._attempt?.id === id) this.first(id, 'preflight done');
    })().catch(err => this.log('PREFLIGHT', `failed: ${err.message}`));
  }

  // ---- unified log -----------------------------------------------------------------------------

  captureUnifiedLog(label, sinceMs) {
    if (!this.enabled) return;
    const start = localStamp(sinceMs);
    this.log('UNIFIED', `capturing "${label}" since ${start} local`);
    run('/usr/bin/log', ['show', '--style', 'compact', '--info', '--debug', '--start', start, '--predicate', UNIFIED_PREDICATE],
      { timeout: 60000, maxChars: MAX_UNIFIED_CHARS })
      .then(res => this.block(`UNIFIED LOG ${label} (${res.ms}ms${res.error ? `, ${res.error}` : ''})`, res.out))
      .catch(err => this.log('UNIFIED', `capture failed: ${err.message}`));
  }

  // ---- environment -----------------------------------------------------------------------------

  async snapshotEnvironment(reason) {
    if (!this.enabled) return;
    this.log('ENV', `environment snapshot (${reason})`);
    const versions = this._safe(() => this.providers.versions?.()) || {};
    this.log('ENV', 'app', {
      app: app.getVersion(),
      electron: process.versions.electron,
      packaged: app.isPackaged,
      appPath: app.getAppPath(),
      ...versions,
    });
    this.log('ENV', 'machine', {
      platform: process.platform,
      arch: process.arch,
      osRelease: os.release(),
      cpus: os.cpus().length,
      cpuModel: os.cpus()[0]?.model,
      memGB: Math.round(os.totalmem() / 1e9),
      freeMemGB: Math.round(os.freemem() / 1e9),
      uptimeHours: Math.round(os.uptime() / 360) / 10,
      locale: app.getLocale?.(),
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    });
    this.log('ENV', 'interfaces', interfaceSummary());
    const commands = [
      ['sw_vers', '/usr/bin/sw_vers', []],
      ['hw.model', '/usr/sbin/sysctl', ['-n', 'hw.model']],
      ['system extensions', '/usr/bin/systemextensionsctl', ['list']],
      ['VPN configurations (scutil --nc list)', '/usr/sbin/scutil', ['--nc', 'list']],
      ['network service order', '/usr/sbin/networksetup', ['-listnetworkserviceorder']],
      ['DNS configuration (scutil --dns)', '/usr/sbin/scutil', ['--dns']],
      ['proxy configuration (scutil --proxy)', '/usr/sbin/scutil', ['--proxy']],
      ['routing table (IPv4)', '/usr/sbin/netstat', ['-rn', '-f', 'inet']],
      ['power (pmset -g)', '/usr/bin/pmset', ['-g']],
    ];
    for (const [title, cmd, args] of commands) {
      const res = await run(cmd, args);
      this.block(`ENV ${title} (${res.ms}ms${res.error ? `, ${res.error}` : ''})`, res.out);
    }
    const extLog = await run('/usr/bin/tail', ['-n', '200', '/private/tmp/wiredog-ext.log']);
    if (extLog.ok && extLog.out) this.block('ENV extension diag file (last 200 lines)', extLog.out);
  }

  // ---- internals -------------------------------------------------------------------------------

  _activate(enabledAt, reason) {
    this.enabled = true;
    this.enabledAt = enabledAt;
    log.info(`[VDM] Verbose Diagnostic Mode ON (${reason}); auto-off at ${new Date(enabledAt + AUTO_OFF_MS).toISOString()}`);
    this._write(`\n[${new Date().toISOString()}] ================ VDM ON (${reason}) app ${app.getVersion()} ================\n`);
    clearTimeout(this._autoOffTimer);
    this._autoOffTimer = setTimeout(() => this._deactivate('24 h limit reached'), Math.max(0, enabledAt + AUTO_OFF_MS - Date.now()));
    if (this._autoOffTimer.unref) this._autoOffTimer.unref();
    clearInterval(this._slowTimer);
    this._slowTimer = setInterval(() => {
      if (Date.now() >= this._fastUntil) this._sample('slow').catch(() => {});
    }, SLOW_SAMPLE_MS);
    if (this._slowTimer.unref) this._slowTimer.unref();
    this.snapshotEnvironment(reason).catch(err => this.log('ENV', `snapshot failed: ${err.message}`));
  }

  _deactivate(reason) {
    log.info(`[VDM] Verbose Diagnostic Mode OFF (${reason})`);
    this._write(`[${new Date().toISOString()}] ================ VDM OFF (${reason}) ================\n`);
    this.enabled = false;
    this.enabledAt = null;
    this._attempt = null;
    clearTimeout(this._autoOffTimer);
    clearInterval(this._slowTimer);
    clearInterval(this._fastTimer);
    this._fastTimer = null;
    this._fastUntil = 0;
    this._persist(false, null);
  }

  _persist(enabled, enabledAt) {
    try { this.store?.set(STORE_KEY, { enabled, enabledAt }); } catch (err) { log.warn('[VDM] could not save the setting:', err.message); }
  }

  /** Mirrors every line written to main.log into the VDM file while VDM is on. */
  _installLogMirror() {
    if (this._hookInstalled || !Array.isArray(log.hooks)) return;
    this._hookInstalled = true;
    log.hooks.push((message, _transport, transportName) => {
      if (this.enabled && transportName === 'file') {
        try {
          const text = util.format(...(message.data || []));
          this._write(redact(`[${(message.date || new Date()).toISOString()}] [main.log ${message.level}] ${text}\n`));
        } catch { /* never break logging */ }
      }
      return message;
    });
  }

  _extendFastSampling(untilMs) {
    if (!this.enabled) return;
    this._fastUntil = Math.max(this._fastUntil, untilMs);
    if (this._fastTimer) return;
    this._fastTimer = setInterval(() => {
      if (!this.enabled || Date.now() >= this._fastUntil) {
        clearInterval(this._fastTimer);
        this._fastTimer = null;
        return;
      }
      this._sample('fast').catch(() => {});
    }, FAST_SAMPLE_MS);
    if (this._fastTimer.unref) this._fastTimer.unref();
  }

  async _sample(mode) {
    if (!this.enabled || this._sampling) return;
    this._sampling = true;
    try {
      const status = this._safe(() => this.providers.getTunnelStatus?.()) ?? 'unknown';
      let healthText = 'unreadable';
      const h = await this._safeAsync(() => this.providers.readHealth?.());
      if (h) {
        const age = Math.round(Date.now() / 1000 - h.updatedAt);
        const hs = h.lastHandshake ? `${Math.round(Date.now() / 1000 - h.lastHandshake)}s ago` : 'NEVER';
        healthText = `handshake=${hs} rx=${h.rxBytes} tx=${h.txBytes} snapshotAge=${age}s`;
      }
      if (mode === 'slow') {
        this.log('SAMPLE-SLOW', `status=${status} health[${healthText}]`);
        return;
      }
      const [nc, ps, route] = await Promise.all([
        run('/usr/sbin/scutil', ['--nc', 'status', 'WireDog VPN'], { timeout: 2000 }),
        run('/bin/ps', ['-axo', 'pid,etime,pcpu,rss,stat,comm'], { timeout: 2000, maxChars: 400000 }),
        run('/sbin/route', ['-n', 'get', 'default'], { timeout: 2000 }),
      ]);
      const procs = ps.out.split('\n')
        .filter(l => /wiredog|nesessionmanager|neagent|sysextd/i.test(l))
        .map(l => l.trim().replace(/\s+/g, ' ').replace(/\/\S*\/([^/\s]+)$/, '$1'))
        .join(' ; ');
      const routeText = route.out.split('\n').filter(l => /gateway|interface/.test(l)).map(l => l.trim()).join(' ');
      const utuns = interfaceSummary().split(' ').filter(s => s.startsWith('utun')).join(' ') || 'none';
      if (this._attempt) {
        if (status !== this._attempt.lastStatus) this.first(this._attempt.id, `system status ${status}`);
        this._attempt.lastStatus = status;
        if (h && h.lastHandshake) this.first(this._attempt.id, 'handshake seen in snapshot');
        if (h && h.rxBytes > 0) this.first(this._attempt.id, 'tunnel received bytes');
      }
      this.log('SAMPLE', `status=${status} nc="${oneLine(nc.out.split('\n')[0], 60)}" health[${healthText}] utun[${utuns}] route[${routeText}] procs[${procs}]`);
    } finally {
      this._sampling = false;
    }
  }

  _safe(fn) {
    try { return fn(); } catch { return undefined; }
  }

  async _safeAsync(fn) {
    try { return await fn(); } catch { return undefined; }
  }

  _write(text) {
    if (!this.filePath) return;
    this._queue.push(text);
    if (this._writing) return;
    this._writing = true;
    const flush = () => {
      const chunk = this._queue.join('');
      this._queue = [];
      if (!chunk) { this._writing = false; return; }
      try {
        const size = fs.existsSync(this.filePath) ? fs.statSync(this.filePath).size : 0;
        if (size > MAX_FILE_BYTES) fs.renameSync(this.filePath, `${this.filePath}.1`);
      } catch { /* rotation is best effort */ }
      fs.appendFile(this.filePath, chunk, () => {
        if (this._queue.length) flush(); else this._writing = false;
      });
    };
    flush();
  }
}

module.exports = new VerboseDiagnostics();
module.exports.redact = redact;
