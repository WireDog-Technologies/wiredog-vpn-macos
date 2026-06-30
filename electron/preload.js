const { contextBridge, ipcRenderer } = require('electron');

/**
 * Secure preload script for WireDog VPN (macOS)
 *
 * Same electronAPI surface as Windows to maximize frontend code sharing.
 * Platform detection returns 'darwin' for macOS-specific UI logic.
 */

contextBridge.exposeInMainWorld('electronAPI', {
  // Window controls
  minimizeWindow: () => ipcRenderer.invoke('app:minimize'),
  maximizeWindow: () => ipcRenderer.invoke('app:maximize'),
  closeWindow: () => ipcRenderer.invoke('app:close'),
  quitApp: () => ipcRenderer.invoke('app:quit'),
  getAppVersion: () => ipcRenderer.invoke('app:get-version'),
  getBuildNumber: () => ipcRenderer.invoke('app:get-build-number'),
  isWindowMaximized: () => ipcRenderer.invoke('app:is-maximized'),
  safeReload: () => ipcRenderer.invoke('app:safe-reload'),

  // System info
  getOsVersion: () => ipcRenderer.invoke('system:get-os-version'),
  getGeolocation: () => ipcRenderer.invoke('system:get-geolocation'),

  // System operations
  openExternal: (url) => ipcRenderer.invoke('system:open-external', url),

  // Split tunneling (UI-only stub for macOS v1)
  getInstalledApps: () => ipcRenderer.invoke('split-tunnel:get-installed-apps'),
  browseForApp: () => ipcRenderer.invoke('split-tunnel:browse-for-app'),

  // Latency measurement
  measureLatency: (servers) => ipcRenderer.invoke('latency:measure-servers', servers),

  // VPN operations
  vpn: {
    connect: (serverId, settings) => ipcRenderer.invoke('vpn:connect', { serverId, settings }),
    disconnect: (options) => ipcRenderer.invoke('vpn:disconnect', options),
    getStatus: () => ipcRenderer.invoke('vpn:get-status'),
    getStats: () => ipcRenderer.invoke('vpn:get-stats'),
    toggleKillSwitch: (enabled) => ipcRenderer.invoke('vpn:toggle-killswitch', { enabled }),
    enableAdvancedKillSwitch: () => ipcRenderer.invoke('vpn:enable-advanced-killswitch'),
    disableAdvancedKillSwitch: () => ipcRenderer.invoke('vpn:disable-advanced-killswitch'),
    emergencyReset: () => ipcRenderer.invoke('vpn:emergency-reset'),
    installHelper: () => ipcRenderer.invoke('vpn:install-helper'),
    isHelperInstalled: () => ipcRenderer.invoke('vpn:is-helper-installed'),
    getHelperUpdateStatus: () => ipcRenderer.invoke('vpn:helper-update-status'),
    onHelperUpdateNeeded: (callback) => {
      const handler = (_, data) => callback(data);
      ipcRenderer.on('helper:update-needed', handler);
      return () => ipcRenderer.removeListener('helper:update-needed', handler);
    },
    onStatusChange: (callback) => {
      const handler = (_, status) => callback(status);
      ipcRenderer.on('vpn:status-changed', handler);
      return () => ipcRenderer.removeListener('vpn:status-changed', handler);
    }
  },

  // Network extension one-time approval flow
  extension: {
    onNeedsApproval: (callback) => {
      const handler = () => callback();
      ipcRenderer.on('extension:needs-approval', handler);
      return () => ipcRenderer.removeListener('extension:needs-approval', handler);
    },
    onActivated: (callback) => {
      const handler = () => callback();
      ipcRenderer.on('extension:activated', handler);
      return () => ipcRenderer.removeListener('extension:activated', handler);
    },
  },

  // Log operations
  logs: {
    openAppLogs: () => ipcRenderer.invoke('logs:open-app-logs'),
    openServiceLogs: () => ipcRenderer.invoke('logs:open-service-logs'),
  },

  // Compact window operations
  compact: {
    showMain: () => ipcRenderer.invoke('compact:show-main'),
    exit: () => ipcRenderer.invoke('compact:exit'),
  },

  // Event listeners
  on: (channel, callback) => {
    const handler = (_, ...args) => callback(...args);
    ipcRenderer.on(channel, handler);
    return handler;
  },

  off: (channel, handler) => {
    ipcRenderer.removeListener(channel, handler);
  },

  // Legacy VPN operations (for backwards compatibility)
  connectVPN: (serverId) => ipcRenderer.invoke('vpn:connect', { serverId, settings: {} }),
  disconnectVPN: () => ipcRenderer.invoke('vpn:disconnect'),

  // Settings
  getSettings: () => ipcRenderer.invoke('settings:get'),
  setSettings: (settings) => ipcRenderer.invoke('settings:set', settings),
  setAutoLaunch: (enabled, mode) => ipcRenderer.invoke('app:set-auto-launch', { enabled, mode }),

  // Auth token management
  auth: {
    setToken: (token) => ipcRenderer.invoke('auth:set-token', token),
    getToken: () => ipcRenderer.invoke('auth:get-token'),
    clearToken: () => ipcRenderer.invoke('auth:clear-token'),
    setUser: (user) => ipcRenderer.invoke('auth:set-user', user),
    getUser: () => ipcRenderer.invoke('auth:get-user'),
    clearUser: () => ipcRenderer.invoke('auth:clear-user'),
  },

  // Update operations
  update: {
    signalReady: () => ipcRenderer.invoke('update:renderer-ready'),
    checkForUpdates: () => ipcRenderer.invoke('update:check-now'),
    downloadUpdate: () => ipcRenderer.invoke('update:download-now'),
    installUpdate: () => ipcRenderer.invoke('update:install-now'),
    onAvailable: (callback) => {
      const handler = (_, data) => callback(data);
      ipcRenderer.on('update:available', handler);
      return () => ipcRenderer.removeListener('update:available', handler);
    },
    onDownloaded: (callback) => {
      const handler = (_, data) => callback(data);
      ipcRenderer.on('update:downloaded', handler);
      return () => ipcRenderer.removeListener('update:downloaded', handler);
    },
    onForceRequired: (callback) => {
      const handler = (_, data) => callback(data);
      ipcRenderer.on('update:force-required', handler);
      return () => ipcRenderer.removeListener('update:force-required', handler);
    },
    onMaintenance: (callback) => {
      const handler = (_, data) => callback(data);
      ipcRenderer.on('update:maintenance', handler);
      return () => ipcRenderer.removeListener('update:maintenance', handler);
    },
    onDownloadProgress: (callback) => {
      const handler = (_, data) => callback(data);
      ipcRenderer.on('update:download-progress', handler);
      return () => ipcRenderer.removeListener('update:download-progress', handler);
    },
  },

  // Legacy update listeners (backwards compatibility)
  onUpdateAvailable: (callback) => {
    ipcRenderer.on('update:available', callback);
    return () => ipcRenderer.removeListener('update:available', callback);
  },

  onUpdateDownloaded: (callback) => {
    ipcRenderer.on('update:downloaded', callback);
    return () => ipcRenderer.removeListener('update:downloaded', callback);
  },

  // Logging (goes to main.log)
  log: {
    debug: (message) => ipcRenderer.send('renderer:log', { level: 'debug', message }),
    info: (message) => ipcRenderer.send('renderer:log', { level: 'info', message }),
    warn: (message) => ipcRenderer.send('renderer:log', { level: 'warn', message }),
    error: (message) => ipcRenderer.send('renderer:log', { level: 'error', message }),
  },

  // Platform detection
  platform: process.platform,
  isMac: process.platform === 'darwin',
  isWindows: process.platform === 'win32',
  isLinux: process.platform === 'linux',

  // Environment detection
  nodeEnv: process.env.NODE_ENV || 'production',
  isDev: process.env.NODE_ENV === 'development'
});

/**
 * Additional security measures
 */
if (window.electron) {
  delete window.electron;
}

if (window.require) {
  delete window.require;
}

// Prevent prototype pollution
Object.freeze(Object.prototype);
Object.freeze(Array.prototype);
Object.freeze(Function.prototype);

// Preload script initialised — environment details intentionally not logged to console
