/**
 * Unix Domain Socket client for communicating with the WireDog VPN Helper Daemon
 * Uses JSON-RPC 2.0 protocol over Unix domain socket (same protocol as Windows named pipe)
 */

const net = require('net');
const log = require('electron-log');
const { createRequest, parseResponse, parseNotification } = require('./json-rpc');

const SOCKET_PATH = process.env.NODE_ENV === 'development'
  ? '/tmp/wiredog-dev.sock'
  : '/var/run/wiredog.sock';
const CONNECT_TIMEOUT = 5000;
const REQUEST_TIMEOUT = 30000;

/**
 * ServiceClient - Connects to the WireDog VPN Helper Daemon via Unix socket
 */
class ServiceClient {
  constructor() {
    this.socket = null;
    this.connected = false;
    this.pendingRequests = new Map();
    this.notificationHandlers = new Map();
    this.buffer = '';
    this.reconnectTimer = null;
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 5;
  }

  /**
   * Connect to the helper daemon
   */
  async connect() {
    if (this.connected) {
      return;
    }

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error('Connection timeout'));
      }, CONNECT_TIMEOUT);

      this.socket = net.createConnection(SOCKET_PATH, () => {
        clearTimeout(timeout);
        this.connected = true;
        this.reconnectAttempts = 0;
        log.info(`Connected to helper daemon at ${SOCKET_PATH}`);
        resolve();
      });

      this.socket.on('data', (data) => this.handleData(data));

      this.socket.on('error', (err) => {
        clearTimeout(timeout);
        log.error('Helper daemon connection error:', err.message);
        this.handleDisconnect();
        reject(err);
      });

      this.socket.on('close', () => {
        log.info('Helper daemon connection closed');
        this.handleDisconnect();
      });
    });
  }

  /**
   * Disconnect from the helper daemon
   */
  disconnect() {
    this.clearReconnectTimer();
    if (this.socket) {
      this.socket.destroy();
      this.socket = null;
    }
    this.connected = false;
    this.rejectPendingRequests(new Error('Disconnected'));
  }

  /**
   * Send a request and wait for response
   */
  async request(method, params = null) {
    if (!this.connected) {
      await this.connect();
    }

    const message = createRequest(method, params);
    const id = JSON.parse(message).id;

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pendingRequests.delete(id);
        reject(new Error(`Request timeout: ${method}`));
      }, REQUEST_TIMEOUT);

      this.pendingRequests.set(id, {
        resolve: (result) => {
          clearTimeout(timeout);
          resolve(result);
        },
        reject: (error) => {
          clearTimeout(timeout);
          reject(error);
        }
      });

      this.send(message);
    });
  }

  /**
   * Register a handler for notifications
   */
  onNotification(method, handler) {
    this.notificationHandlers.set(method, handler);
  }

  /**
   * Send raw message
   */
  send(message) {
    if (!this.socket || !this.connected) {
      throw new Error('Not connected to helper daemon');
    }
    this.socket.write(message + '\n');
    // Do not log full message — may contain sensitive WireGuard key material
    log.debug('Sent IPC message (method hidden)');
  }

  /**
   * Handle incoming data
   */
  handleData(data) {
    this.buffer += data.toString('utf-8');

    let newlineIndex;
    while ((newlineIndex = this.buffer.indexOf('\n')) !== -1) {
      const line = this.buffer.slice(0, newlineIndex);
      this.buffer = this.buffer.slice(newlineIndex + 1);

      if (line.trim()) {
        this.handleMessage(line.trim());
      }
    }
  }

  /**
   * Handle a complete message
   */
  handleMessage(json) {
    // Do not log full message — responses may contain sensitive key material
    log.debug('Received IPC response');

    const notification = parseNotification(json);
    if (notification) {
      const handler = this.notificationHandlers.get(notification.method);
      if (handler) {
        try {
          handler(notification.params);
        } catch (err) {
          log.error('Notification handler error:', err);
        }
      }
      return;
    }

    try {
      const parsed = JSON.parse(json);
      const pending = this.pendingRequests.get(parsed.id);

      if (pending) {
        this.pendingRequests.delete(parsed.id);

        if (parsed.error) {
          const error = new Error(parsed.error.message);
          error.code = parsed.error.code;
          error.data = parsed.error.data;
          pending.reject(error);
        } else {
          pending.resolve(parsed.result);
        }
      }
    } catch (err) {
      log.error('Failed to parse message:', err);
    }
  }

  handleDisconnect() {
    this.connected = false;
    this.socket = null;
    this.rejectPendingRequests(new Error('Connection lost'));
    this.scheduleReconnect();
  }

  rejectPendingRequests(error) {
    for (const [id, pending] of this.pendingRequests) {
      pending.reject(error);
    }
    this.pendingRequests.clear();
  }

  scheduleReconnect() {
    if (this.reconnectTimer) return;
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      log.warn('Max reconnect attempts reached');
      return;
    }

    const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 30000);
    this.reconnectAttempts++;

    log.info(`Scheduling reconnect in ${delay}ms (attempt ${this.reconnectAttempts})`);

    this.reconnectTimer = setTimeout(async () => {
      this.reconnectTimer = null;
      try {
        await this.connect();
      } catch (err) {
        log.warn('Reconnect failed:', err.message);
      }
    }, delay);
  }

  clearReconnectTimer() {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }

  // ============ High-level API methods ============

  async ping() {
    return this.request('ping');
  }

  async enableAdvancedKillSwitch(serverIp) {
    return this.request('enableAdvancedKillSwitch', { serverIp });
  }

  async disableAdvancedKillSwitch() {
    return this.request('disableAdvancedKillSwitch');
  }

  async getKillSwitchState() {
    return this.request('getKillSwitchState');
  }

  async emergencyReset() {
    return this.request('emergencyReset');
  }

  async updateKillSwitch(state, serverIp, tunnelInterface) {
    return this.request('updateKillSwitch', { state, serverIp, tunnelInterface });
  }

  // ============ Tunnel methods (NETunnelProviderManager in helper) ============

  async loadTunnelManager() {
    return this.request('loadTunnelManager');
  }

  async startTunnel(config) {
    return this.request('startTunnel', config);
  }

  async stopTunnel() {
    return this.request('stopTunnel');
  }

  async getTunnelStatus() {
    return this.request('getTunnelStatus');
  }

  async getTunnelStats() {
    return this.request('getTunnelStats');
  }
}

const serviceClient = new ServiceClient();
module.exports = serviceClient;
