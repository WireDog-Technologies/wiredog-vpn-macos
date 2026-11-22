/**
 * Verbose Diagnostic Mode (VDM).
 *
 * An opt-in support tool: a customer turns it on (Account > Debug Logs), reproduces a problem, then sends the
 * log folder to support. While on, it writes WireDog-VDM.log next to main.log with everything needed to
 * diagnose a connect, disconnect, switch or drop without a one-off build:
 *   - an environment snapshot: macOS version and build, SIP/Gatekeeper, Mac hardware, disk, the app's
 *     install location and code signature, app/helper/extension versions, every system extension and NE
 *     configuration (other VPNs, content filters, DNS proxies), the app firewall, the process list,
 *     network hardware/services/interfaces/Wi-Fi, routes, DNS, proxies, power settings and sleep/wake
 *     history, recent crash reports for our processes, the helper daemon's log and kill switch state, the
 *     app's own settings, and the backend's /app/config with the clock difference;
 *   - a timeline per connect/disconnect attempt with the time spent in every stage;
 *   - a 1 s sampler while an attempt or teardown is in progress (system tunnel status, scutil status, the
 *     extension's health snapshot, the extension and Network Extension daemons, utun interfaces, the
 *     default route) and a 15 s sampler otherwise, with network changes (Wi-Fi switch, new address) noted;
 *   - preflight checks per attempt (DNS timings, ping to the server, backend HTTPS timings);
 *   - a network snapshot when each attempt ends and on a drop (the tunnel interface, which way the server
 *     and the internet are routed, DNS as the system sees it), to spot routing loops and DNS leaks;
 *   - macOS unified-log captures for our extension, our app and Apple's Network Extension and network
 *     configuration daemons around attempts that are slow, failed, or dropped;
 *   - the screen: every click (connect, disconnect, switch, cancel, settings), each status it received
 *     and what it showed (label, progress text, error), console output, screen navigation, freezes,
 *     window show/hide/focus, and every backend request (method, path, status, time) from the screen
 *     and from the main process;
 *   - power and system events (lock/unlock, battery/AC, thermal), crashes of any app process, and the
 *     app's own CPU/memory per process;
 *   - the helper (protocol 3+): it logs every request it handles and the full pf rules it loads, and
 *     reports the firewall's live state (pf status, rules with packet counters, anchors) on demand;
 *   - the extension and the in-app tunnel controller log, to the system log captured here: time since
 *     startTunnel on every line, start/stop durations, the cost of each extension log line, and
 *     macOS's reason for each disconnect (macOS 13+);
 *   - a mirror of every main.log line, so it all reads as one timeline.
 *
 * Nothing leaves the Mac unless the customer sends the file. Everything is written as is, so support can
 * read it, except secrets that never help a diagnosis and would let a reader take over the account or the
 * tunnel (WireGuard keys, login tokens, the anonymous account number). Browsing is never recorded: no
 * visited addresses, and no DNS lookups other than our own server names (mDNSResponder is deliberately
 * not captured). macOS itself hides some fields of Apple's own log lines as <private>; support can lift
 * that with the logging profile in tasks/support/ when it is needed. VDM turns itself off 24 h after it
 * was turned on, so it cannot be left running by accident.
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

// Our extension, our app, the Apple daemons that start, stop and configure it, and the daemon that applies
// network configuration changes. mDNSResponder (every DNS lookup the Mac makes) is left out on purpose.
const UNIFIED_PREDICATE = [
  'subsystem == "com.wiredog.vpn.macos.tunnel"',
  'process == "com.wiredog.vpn.macos.tunnel"',
  'process == "WireDog VPN"',
  'process == "wiredog-helper"',
  'process == "nesessionmanager"',
  'process == "neagent"',
  'process == "nehelper"',
  'process == "sysextd"',
  'process == "configd"',
  'subsystem == "com.apple.networkextension"',
].join(' OR ');

// ---- secrets -----------------------------------------------------------------------------------

// Only secrets are masked: they never help a diagnosis, and a log sent by e-mail must not hand over the
// account or the tunnel. Everything else stays readable.
const SECRETS = [
  [/eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, '<token>'],
  [/Bearer\s+[^\s"']+/gi, 'Bearer <token>'],
  // WireGuard keys (32 bytes, base64).
  [/\b[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=/g, '<key>'],
];

function redact(text) {
  let out = String(text);
  for (const [pattern, replacement] of SECRETS) out = out.replace(pattern, replacement);
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
    // The helper forgets verbose mode when it restarts (reinstall, crash); remind it at every attempt.
    this._safeAsync(() => this.providers.setHelperVerbose?.(true));
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
    // How the system routes and resolves right now: a connected tunnel that never gets an answer is often
    // the server's own address being routed into the tunnel, or DNS not switched over.
    if (attempt.kind === 'connect') {
      this.networkSnapshot(`after ${attempt.kind} #${id} (${outcome})`, attempt.target).catch(() => {});
    }
    if (outcome !== 'ok') {
      const since = attempt.startMs - 20000;
      this.captureUnifiedLog(`FINAL ${attempt.kind} #${id} (${outcome})`, since);
      this.helperLogTail(`after ${attempt.kind} #${id} (${outcome})`).catch(() => {});
      this.helperFirewallSnapshot(`after ${attempt.kind} #${id} (${outcome})`).catch(() => {});
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
    this.networkSnapshot(`DROP (${reason})`, this._lastTarget).catch(() => {});
    this.helperLogTail(`DROP (${reason})`).catch(() => {});
    this.helperFirewallSnapshot(`DROP (${reason})`).catch(() => {});
  }

  // ---- preflight -------------------------------------------------------------------------------

  /**
   * Checks the path to the server outside the tunnel, in the background, and remembers the server for the
   * network snapshot taken when the attempt ends.
   */
  preflight(id, endpoint, { serverIp, address } = {}) {
    if (!this.enabled) return;
    const host = String(endpoint || '').split(':')[0];
    if (!host) return;
    const target = { host, serverIp: serverIp || null, address: address || null };
    this._lastTarget = target;
    if (this._attempt?.id === id) this._attempt.target = target;
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
      const routeToServer = await run('/sbin/route', ['-n', 'get', serverIp || host], { timeout: 3000 });
      this.log('PREFLIGHT', `route to the server before the tunnel: ${oneLine(routeToServer.out.split('\n').filter(l => /gateway|interface|flags/.test(l)).join(' '))}`);
      if (this._attempt?.id === id) this.first(id, 'preflight done');
    })().catch(err => this.log('PREFLIGHT', `failed: ${err.message}`));
  }

  // ---- network, helper, crash reports ------------------------------------------------------------

  /**
   * The tunnel interface, which way the server's address and the internet are routed, and DNS as the
   * system sees it. Shows a routing loop (server routed into the tunnel), a tunnel that never got its
   * address, DNS still on the LAN resolver (a leak), or IPv6 bypassing the tunnel.
   */
  async networkSnapshot(label, target) {
    if (!this.enabled) return;
    const utun = (() => {
      if (!target?.address) return null;
      const ip = String(target.address).split(',')[0].split('/')[0].trim();
      for (const [name, addrs] of Object.entries(os.networkInterfaces())) {
        if ((addrs || []).some(a => a.address === ip)) return name;
      }
      return null;
    })();
    const parts = [
      ['tunnel interface', utun ? ['/sbin/ifconfig', [utun]] : null],
      ['route to the server', target?.serverIp || target?.host ? ['/sbin/route', ['-n', 'get', target.serverIp || target.host]] : null],
      ['route to the internet (1.1.1.1)', ['/sbin/route', ['-n', 'get', '1.1.1.1']]],
      ['route to the internet over IPv6', ['/sbin/route', ['-n', 'get', '-inet6', '2606:4700:4700::1111']]],
      ['network reachability (scutil --nwi)', ['/usr/sbin/scutil', ['--nwi']]],
      ['DNS configuration (scutil --dns)', ['/usr/sbin/scutil', ['--dns']]],
      ['VPN configuration (scutil --nc show)', ['/usr/sbin/scutil', ['--nc', 'show', 'WireDog VPN']]],
      ['routing table (IPv4)', ['/usr/sbin/netstat', ['-rn', '-f', 'inet']]],
      ['routing table (IPv6)', ['/usr/sbin/netstat', ['-rn', '-f', 'inet6']]],
    ];
    const lines = [`tunnel interface: ${utun || 'not found'} (address ${target?.address || 'unknown'}), server ${target?.host || '?'} = ${target?.serverIp || '?'}`];
    for (const [title, cmd] of parts) {
      if (!cmd) continue;
      const res = await run(cmd[0], cmd[1], { timeout: 4000 });
      lines.push(`--- ${title} (${res.ms}ms${res.error ? `, ${res.error}` : ''})\n${res.out}`);
    }
    this.block(`NETWORK SNAPSHOT ${label}`, lines.join('\n'));
  }

  /**
   * The firewall as the helper (root) sees it: pf status, the main ruleset, our anchor's rules, anchors,
   * state count, /etc/pf.conf. Needs helper protocol 3; an older helper is reported once, not as an error.
   */
  async helperFirewallSnapshot(label) {
    if (!this.enabled) return;
    let report;
    try {
      report = await this.providers.helperDiagnostics?.();
    } catch (err) {
      if (/Method not found/i.test(err?.message || '')) {
        if (!this._helperTooOldNoted) {
          this._helperTooOldNoted = true;
          this.log('HELPER', 'the helper is too old to report firewall state (needs protocol 3); turn VDM off and on while disconnected to update it');
        }
        return;
      }
      this.log('HELPER', `firewall snapshot failed: ${err?.message || err}`);
      return;
    }
    if (!report) return;
    const parts = Object.entries(report).map(([key, value]) => `--- ${key}\n${typeof value === 'string' ? value : JSON.stringify(value, null, 2)}`);
    this.block(`HELPER FIREWALL ${label}`, parts.join('\n'));
  }

  /**
   * The helper daemon's own log (pf rules, kill switch states), which this app can read but not write. The
   * helper rotates it at 2 MB, so right after a rotation the earlier lines are in the .1 file: read both.
   */
  async helperLogTail(label, lines = 300) {
    if (!this.enabled) return;
    const files = ['/var/log/wiredog-helper.log.1', '/var/log/wiredog-helper.log'].filter(f => fs.existsSync(f));
    if (!files.length) {
      this.log('HELPER', `no helper log found (${label})`);
      return;
    }
    const res = await run('/usr/bin/tail', ['-n', String(lines), ...files], { maxChars: 120000 });
    this.block(`HELPER LOG last ${lines} lines per file (${label})${res.error ? ` ${res.error}` : ''}`, res.out);
  }

  /** Crash reports from the last 14 days for our app, helper and extension (they explain a tunnel that just stops). */
  async crashReports() {
    if (!this.enabled) return;
    const dirs = [path.join(os.homedir(), 'Library/Logs/DiagnosticReports'), '/Library/Logs/DiagnosticReports'];
    const since = Date.now() - 14 * 24 * 60 * 60 * 1000;
    const found = [];
    for (const dir of dirs) {
      let names = [];
      try { names = fs.readdirSync(dir); } catch { continue; }
      for (const name of names) {
        if (!/wiredog|WireDog/i.test(name)) continue;
        const full = path.join(dir, name);
        try {
          const st = fs.statSync(full);
          if (st.isFile() && st.mtimeMs >= since) found.push({ full, mtimeMs: st.mtimeMs, size: st.size });
        } catch { /* unreadable */ }
      }
    }
    found.sort((a, b) => b.mtimeMs - a.mtimeMs);
    this.log('ENV', `crash reports (last 14 days): ${found.length ? found.map(f => `${f.full} (${new Date(f.mtimeMs).toISOString()}, ${f.size} B)`).join('; ') : 'none'}`);
    for (const f of found.slice(0, 5)) {
      try {
        const text = fs.readFileSync(f.full, 'utf8');
        this.block(`CRASH REPORT ${f.full}`, text.length > 120000 ? `${text.slice(0, 120000)}\n...[truncated]` : text);
      } catch (err) {
        this.log('ENV', `could not read ${f.full}: ${err.message}`);
      }
    }
  }

  /** The backend's /app/config as this Mac sees it, and how far the Mac's clock is from the server's. */
  async backendCheck() {
    const base = this._safe(() => this.providers.apiBaseUrl?.());
    if (!this.enabled || !base) return;
    const started = Date.now();
    try {
      const res = await fetch(`${base}/app/config`, { headers: { Connection: 'close' }, signal: AbortSignal.timeout(10000) });
      const body = await res.text();
      const serverDate = Date.parse(res.headers.get('date') || '');
      const skew = Number.isFinite(serverDate) ? Math.round((Date.now() - serverDate) / 1000) : null;
      this.log('ENV', `backend /app/config: HTTP ${res.status} in ${Date.now() - started}ms; Mac clock is ${skew === null ? 'unknown' : `${skew}s ${skew >= 0 ? 'ahead of' : 'behind'}`} the server`, {
        cfRay: res.headers.get('cf-ray'), server: res.headers.get('server'),
      });
      this.block('ENV backend /app/config body', body.length > 20000 ? `${body.slice(0, 20000)}...[truncated]` : body);
    } catch (err) {
      this.log('ENV', `backend /app/config FAILED after ${Date.now() - started}ms: ${err.cause?.code || err.message}`);
    }
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
    this.log('ENV', 'app settings', this._safe(() => this.providers.settingsSnapshot?.()));
    this.log('ENV', 'helper daemon', await this._safeAsync(() => this.providers.helperState?.()));

    // The .app bundle this process runs from (a copy run from the DMG shows up under AppTranslocation).
    const bundle = path.resolve(app.getPath('exe'), '../../..');
    const sh = (script) => ['/bin/sh', ['-c', script]];
    const commands = [
      // macOS and the Mac
      ['macOS version (sw_vers)', '/usr/bin/sw_vers', []],
      ['kernel and boot (sysctl)', '/usr/sbin/sysctl', ['kern.osversion', 'kern.osproductversion', 'kern.boottime', 'hw.model', 'hw.memsize', 'machdep.cpu.brand_string', 'hw.optional.arm64']],
      ['software and hardware (system_profiler)', '/usr/sbin/system_profiler', ['SPSoftwareDataType', 'SPHardwareDataType'], { timeout: 30000 }],
      ['System Integrity Protection (csrutil status)', '/usr/bin/csrutil', ['status']],
      ['Gatekeeper (spctl --status)', '/usr/sbin/spctl', ['--status']],
      ['uptime and load', '/usr/bin/uptime', []],
      ['disk space (df -h /)', '/bin/df', ['-h', '/']],
      ['device management enrollment (profiles status)', '/usr/bin/profiles', ['status', '-type', 'enrollment']],
      // This app: where it runs from and whether macOS trusts it
      ['app bundle path', '/bin/echo', [bundle]],
      ['app code signature (codesign -dv)', '/usr/bin/codesign', ['-dv', '--verbose=4', bundle], { timeout: 15000 }],
      ['app signature check (codesign --verify)', '/usr/bin/codesign', ['--verify', '--deep', '--strict', '--verbose=2', bundle], { timeout: 60000 }],
      ['app Gatekeeper assessment (spctl -a)', '/usr/sbin/spctl', ['-a', '-vv', bundle], { timeout: 15000 }],
      ['app extended attributes (quarantine)', '/usr/bin/xattr', ['-l', bundle]],
      // The helper as installed: root-owned copy, its signature, and the LaunchDaemon that runs it (with the
      // launch constraint on macOS 13+). An old install still points into the app bundle.
      ['helper launch daemon (launchctl print)', '/bin/launchctl', ['print', 'system/com.wiredog.vpn.helper']],
      ['helper files (ls -l)', '/bin/ls', ['-l', '/Library/PrivilegedHelperTools/com.wiredog.vpn.helper', '/Library/LaunchDaemons/com.wiredog.vpn.helper.plist']],
      ['helper LaunchDaemon plist', '/usr/bin/plutil', ['-p', '/Library/LaunchDaemons/com.wiredog.vpn.helper.plist']],
      ['installed helper signature (codesign -dv)', '/usr/bin/codesign', ['-dv', '--verbose=2', '/Library/PrivilegedHelperTools/com.wiredog.vpn.helper']],
      // Extensions, VPNs, filters and firewalls that could interfere
      ['system extensions (systemextensionsctl list)', '/usr/bin/systemextensionsctl', ['list']],
      ['VPN configurations (scutil --nc list)', '/usr/sbin/scutil', ['--nc', 'list']],
      ['WireDog VPN configuration (scutil --nc show)', '/usr/sbin/scutil', ['--nc', 'show', 'WireDog VPN']],
      ['Network Extension configurations (all apps)', '/usr/bin/plutil', ['-p', '/Library/Preferences/com.apple.networkextension.plist'], { maxChars: 200000 }],
      ['application firewall', '/usr/libexec/ApplicationFirewall/socketfilterfw', ['--getglobalstate', '--getblockall', '--getstealthmode']],
      ['running processes', '/bin/ps', ['-axo', 'pid,ppid,user,etime,pcpu,rss,comm'], { maxChars: 300000 }],
      // The network
      ['network hardware ports', '/usr/sbin/networksetup', ['-listallhardwareports']],
      ['network service order', '/usr/sbin/networksetup', ['-listnetworkserviceorder']],
      ['interfaces (ifconfig -a)', '/sbin/ifconfig', ['-a'], { maxChars: 100000 }],
      ['network reachability (scutil --nwi)', '/usr/sbin/scutil', ['--nwi']],
      ['DHCP lease on en0 (ipconfig getpacket)', '/usr/sbin/ipconfig', ['getpacket', 'en0']],
      ['Wi-Fi (system_profiler SPAirPortDataType)', '/usr/sbin/system_profiler', ['SPAirPortDataType'], { timeout: 30000 }],
      ['DNS configuration (scutil --dns)', '/usr/sbin/scutil', ['--dns']],
      ['proxy configuration (scutil --proxy)', '/usr/sbin/scutil', ['--proxy']],
      ['routing table (IPv4)', '/usr/sbin/netstat', ['-rn', '-f', 'inet']],
      ['routing table (IPv6)', '/usr/sbin/netstat', ['-rn', '-f', 'inet6']],
      // Power and sleep (drops after sleep are a common report)
      ['power settings (pmset -g)', '/usr/bin/pmset', ['-g']],
      ['power assertions (pmset -g assertions)', '/usr/bin/pmset', ['-g', 'assertions']],
      ['sleep/wake history (last 200)', ...sh("/usr/bin/pmset -g log | /usr/bin/grep -E ' (Sleep|Wake|DarkWake|Start) ' | /usr/bin/tail -n 200"), { timeout: 30000 }],
    ];
    for (const [title, cmd, args, opts] of commands) {
      const res = await run(cmd, args, opts || {});
      this.block(`ENV ${title} (${res.ms}ms${res.error ? `, ${res.error}` : ''})`, res.out);
    }
    const extLog = await run('/usr/bin/tail', ['-n', '300', '/private/tmp/wiredog-ext.log']);
    if (extLog.ok && extLog.out) this.block('ENV extension diag file (last 300 lines)', extLog.out);
    await this.helperLogTail('environment snapshot');
    await this.helperFirewallSnapshot('environment snapshot');
    await this.crashReports();
    await this.backendCheck();
    // The last hour of our own and the Network Extension daemons' system log, for what led up to this.
    this.captureUnifiedLog(`ENV last hour (${reason})`, Date.now() - 60 * 60 * 1000);
    this.log('ENV', 'environment snapshot done');
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
    this._safeAsync(() => this.providers.setHelperVerbose?.(true));
    this.snapshotEnvironment(reason).catch(err => this.log('ENV', `snapshot failed: ${err.message}`));
  }

  _deactivate(reason) {
    this._safeAsync(() => this.providers.setHelperVerbose?.(false));
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
      // A network change (Wi-Fi to Ethernet, a new address after a DHCP renew, another VPN's interface)
      // often explains a drop that the tunnel alone does not.
      const ifaces = interfaceSummary();
      if (this._lastIfaces !== undefined && ifaces !== this._lastIfaces) {
        this.log('NETWORK-CHANGE', `interfaces changed`, { before: this._lastIfaces, after: ifaces });
        run('/usr/sbin/scutil', ['--nwi']).then(res => this.block('NETWORK-CHANGE scutil --nwi', res.out)).catch(() => {});
      }
      this._lastIfaces = ifaces;
      const status = this._safe(() => this.providers.getTunnelStatus?.()) ?? 'unknown';
      let healthText = 'unreadable';
      const h = await this._safeAsync(() => this.providers.readHealth?.());
      if (h) {
        const age = Math.round(Date.now() / 1000 - h.updatedAt);
        const hs = h.lastHandshake ? `${Math.round(Date.now() / 1000 - h.lastHandshake)}s ago` : 'NEVER';
        healthText = `handshake=${hs} rx=${h.rxBytes} tx=${h.txBytes} snapshotAge=${age}s`;
        // Extension-side extras (extension 1.0.14+): its own uptime, how long the last start took, and
        // what one of its log lines costs (the old UserDefaults store was a suspect for slow starts).
        const extras = ['extUptimeSec', 'lastStartMs', 'lastStopMs', 'diagFileBytes', 'diagWriteAvgMs', 'diagWriteMaxMs', 'diagWrites']
          .filter(k => h[k] !== undefined).map(k => `${k}=${h[k]}`).join(' ');
        if (extras) healthText += ` ${extras}`;
      }
      const stats = await this._safeAsync(() => this.providers.getStats?.());
      const statsText = stats ? `bytes[in=${stats.bytesReceived ?? stats.bytesIn ?? '?'} out=${stats.bytesSent ?? stats.bytesOut ?? '?'}]` : '';
      if (mode === 'slow') {
        // Electron's own processes: a renderer pegging the CPU or leaking memory shows up here.
        const metrics = this._safe(() => app.getAppMetrics().map(m => `${m.type}:${m.pid} cpu=${m.cpu?.percentCPUUsage?.toFixed(1)}% mem=${Math.round((m.memory?.workingSetSize || 0) / 1024)}MB`).join(' ; '));
        this.log('SAMPLE-SLOW', `status=${status} health[${healthText}] ${statsText} app[${metrics || '?'}]`);
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
      this.log('SAMPLE', `status=${status} nc="${oneLine(nc.out.split('\n')[0], 60)}" health[${healthText}] ${statsText} utun[${utuns}] route[${routeText}] procs[${procs}]`);
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
