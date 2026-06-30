// ================================
// Load environment variables FIRST (dev only)
// ================================
const path = require('path');
const fs = require('fs');
const dotenv = require('dotenv');
const { app } = require('electron');
const log = require('electron-log');

// Load .env only in development — production config is baked in at build time via Vite
if (!app.isPackaged) {
  const devEnvPath = path.join(__dirname, '../.env');
  if (fs.existsSync(devEnvPath)) {
    dotenv.config({ path: devEnvPath });
    log.info('Loaded .env from', devEnvPath);
  }
}

// ================================
// Import Electron and other modules
// ================================
const { BrowserWindow, ipcMain, Menu, Tray, shell, dialog, nativeImage, safeStorage, Notification } = require('electron');
const vpnService = require('./vpn');
const { getInstalledApps, readPlist, extractAppIcon } = require('./utils/appDiscovery');

// Configure logging
log.transports.file.level = 'debug';

// Log environment for debugging
log.info('=== Environment Configuration ===');
log.info('NODE_ENV:', process.env.NODE_ENV);
log.info('VITE_API_URL:', process.env.VITE_API_URL);
log.info('App path:', __dirname);

// Settings store - will be initialized in app.whenReady()
let settingsStore;

// Encrypt a secret string using the OS Keychain (macOS Keychain, via Electron safeStorage).
// Falls back to plaintext only if the Keychain is unavailable (shouldn't happen on macOS).
function encryptSecret(value) {
  if (safeStorage.isEncryptionAvailable()) {
    return safeStorage.encryptString(value).toString('base64');
  }
  log.warn('safeStorage: Keychain unavailable, storing secret without encryption');
  return value;
}

// Decrypt a secret previously stored with encryptSecret.
// Handles migration: if the stored value isn't valid base64-encrypted data,
// returns it as-is so old plaintext tokens keep working on first run after upgrade.
function decryptSecret(stored) {
  if (!stored) return null;
  if (safeStorage.isEncryptionAvailable()) {
    try {
      return safeStorage.decryptString(Buffer.from(stored, 'base64'));
    } catch {
      return stored; // plaintext migration fallback
    }
  }
  return stored;
}

// Keep a global reference of the window object
let mainWindow;
let compactWindow;
let tray;

// Application configuration
if (!process.env.NODE_ENV) {
  process.env.NODE_ENV = app.isPackaged ? 'production' : 'development';
}
const isDev = process.env.NODE_ENV === 'development';
const isMac = process.platform === 'darwin';
const connectSrc = isDev
  ? "'self' https: http://localhost:3001 http://localhost:3003 http://localhost:5173"
  : "'self' https:";

// Track whether app is quitting to distinguish from hide-to-menu-bar
let isQuitting = false;

/**
 * Create the main application window
 * macOS: Uses hiddenInset titlebar with native traffic lights
 */
function createMainWindow() {
  mainWindow = new BrowserWindow({
    width: 1500,
    height: 900,
    minWidth: 1350,
    minHeight: 800,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      enableRemoteModule: false,
      preload: path.join(__dirname, 'preload.js'),
      webSecurity: true,
    },
    icon: app.isPackaged
      ? path.join(process.resourcesPath, 'icon.png')
      : path.join(__dirname, '../build/icon.png'),
    show: false,
    frame: false,
    titleBarStyle: 'hiddenInset',
    trafficLightPosition: { x: 12, y: 10 },
  });

  // Load the app
  if (isDev) {
    mainWindow.loadURL('http://localhost:5173');
    mainWindow.webContents.openDevTools();
  } else {
    mainWindow.loadFile(path.join(__dirname, '../dist/index.html'));
  }

  // Show window when ready to prevent visual flash
  mainWindow.once('ready-to-show', () => {
    if (process.argv.includes('--hidden')) {
      log.info('Main window ready but started hidden');
    } else {
      mainWindow.show();
      log.info('Main window ready and shown');
    }
  });

  // macOS: Hide window instead of quitting when user clicks close (red traffic light)
  // Cmd+Q sets isQuitting=true first, so the app actually quits then.
  mainWindow.on('close', (event) => {
    if (!isQuitting) {
      event.preventDefault();
      mainWindow.hide();
      log.info('Window hidden to menu bar');
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  // Prevent new window creation
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: 'deny' };
  });

  // Handle renderer process crashes
  mainWindow.webContents.on('render-process-gone', async (event, details) => {
    log.error('Renderer process crashed:', details);
    try {
      await vpnService.cleanup();
    } catch (error) {
      log.error('VPN cleanup failed after crash:', error);
    }
  });

  mainWindow.webContents.on('unresponsive', () => {
    log.warn('Renderer process became unresponsive');
  });

  // Intercept keyboard shortcuts for reload (Cmd+R on macOS)
  mainWindow.webContents.on('before-input-event', async (event, input) => {
    const isReload = (input.meta && input.key === 'r') || input.key === 'F5';

    if (isReload && input.type === 'keyDown') {
      event.preventDefault();
      log.info('Manual reload detected (Cmd+R/F5) - cleaning up VPN');
      try {
        await vpnService.cleanup();
      } catch (error) {
        log.error('VPN cleanup failed during reload:', error);
      }
      mainWindow.reload();
    }
  });

  // Set Content Security Policy
  mainWindow.webContents.session.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': [
          "default-src 'self'; " +
          "script-src 'self' 'unsafe-inline'; " +
          "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
          "img-src 'self' data: https:; " +
          "font-src 'self' https://fonts.gstatic.com; " +
          `connect-src ${connectSrc}; ` +
          "object-src 'none';"
        ]
      }
    });
  });

  log.info('Main window created');
}

/**
 * Update tray menu with current VPN status
 */
async function updateTrayMenu() {
  if (!tray) return;

  try {
    const vpnStatus = await vpnService.getFullStatus();
    const { status, session } = vpnStatus;

    // Update tray icon based on status
    let trayIconPath;
    if (status === 'connected') {
      trayIconPath = app.isPackaged
        ? path.join(process.resourcesPath, 'tray-connected.png')
        : path.join(__dirname, '../build/tray-connected.png');
    } else {
      trayIconPath = app.isPackaged
        ? path.join(process.resourcesPath, 'tray-disconnected.png')
        : path.join(__dirname, '../build/tray-disconnected.png');
    }
    if (fs.existsSync(trayIconPath)) {
      const img = nativeImage.createFromPath(trayIconPath);
      const sized = img.resize({ width: 16, height: 16, quality: 'good' });
      tray.setImage(sized);
    }

    // Build status label
    let statusLabel = 'Status: Disconnected';
    if (status === 'connecting') {
      statusLabel = 'Status: Connecting...';
    } else if (status === 'connected' && session?.server) {
      const server = session.server;
      const location = server.city ? `${server.city}, ${server.stateCode || ''}` : 'Connected';
      statusLabel = `Status: Connected to ${location}`;
    }

    // Build and set context menu
    const contextMenu = Menu.buildFromTemplate([
      { label: statusLabel, enabled: false },
      { type: 'separator' },
      { label: 'Show WireDog VPN', click: () => { mainWindow.show(); mainWindow.focus(); } },
      { type: 'separator' },
      { label: 'Quit WireDog VPN', click: () => { isQuitting = true; app.quit(); } }
    ]);

    tray.setContextMenu(contextMenu);
  } catch (error) {
    log.error('Failed to update tray menu:', error);
    const fallbackMenu = Menu.buildFromTemplate([
      { label: 'Status: Unknown', enabled: false },
      { type: 'separator' },
      { label: 'Show WireDog VPN', click: () => { mainWindow.show(); mainWindow.focus(); } },
      { type: 'separator' },
      { label: 'Quit WireDog VPN', click: () => { isQuitting = true; app.quit(); } }
    ]);
    tray.setContextMenu(fallbackMenu);
  }
}

/**
 * Create macOS menu bar (status bar) icon
 */
function createTray() {
  const trayIconPath = app.isPackaged
    ? path.join(process.resourcesPath, 'tray-icon.png')
    : path.join(__dirname, '../build/tray-icon.png');

  // Create a small template image for the menu bar (macOS convention)
  let trayImage;
  if (fs.existsSync(trayIconPath)) {
    trayImage = nativeImage.createFromPath(trayIconPath);
    // Mark as template image so macOS handles dark/light mode automatically
    trayImage.setTemplateImage(true);
  } else {
    // Fallback: create a simple 16x16 icon
    trayImage = nativeImage.createEmpty();
    log.warn('Tray icon not found at:', trayIconPath);
  }

  tray = new Tray(trayImage);
  tray.setToolTip('WireDog VPN');

  // Set initial menu
  updateTrayMenu();

  // Click on tray icon: show/hide compact window or toggle main window
  tray.on('click', (event, bounds) => {
    if (compactWindow && compactWindow.isVisible()) {
      compactWindow.hide();
    } else {
      showCompactWindow(bounds);
    }
  });

  log.info('Menu bar tray created');
}

/**
 * Create compact window for menu bar popover
 */
function createCompactWindow() {
  compactWindow = new BrowserWindow({
    width: 350,
    height: 480,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      enableRemoteModule: false,
      preload: path.join(__dirname, 'preload.js'),
      webSecurity: true,
    },
    show: false,
    frame: false,
    resizable: false,
    alwaysOnTop: true,
    skipTaskbar: true,
    // No titlebar style needed for compact window
  });

  // Load the compact window route
  if (isDev) {
    const url = 'http://localhost:5173/#/compact';
    log.info('Loading compact window URL:', url);
    compactWindow.loadURL(url);
  } else {
    const indexPath = path.join(__dirname, '../dist/index.html');
    compactWindow.loadFile(indexPath, { hash: 'compact' });
  }

  compactWindow.webContents.on('did-finish-load', () => {
    log.info('Compact window content loaded successfully');
  });

  compactWindow.on('closed', () => {
    compactWindow = null;
  });

  // Hide compact window when clicking outside (blur)
  compactWindow.on('blur', () => {
    if (compactWindow && !compactWindow.isDestroyed()) {
      compactWindow.hide();
    }
  });

  // Prevent new window creation
  compactWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: 'deny' };
  });

  // Handle renderer process crashes
  compactWindow.webContents.on('render-process-gone', async (event, details) => {
    log.error('Compact window renderer crashed:', details);
    try {
      await vpnService.cleanup();
    } catch (error) {
      log.error('VPN cleanup failed after crash:', error);
    }
  });

  // Intercept reload shortcuts in compact window
  compactWindow.webContents.on('before-input-event', async (event, input) => {
    const isReload = (input.meta && input.key === 'r') || input.key === 'F5';

    if (isReload && input.type === 'keyDown') {
      event.preventDefault();
      log.info('Manual reload detected in compact window - cleaning up VPN');
      try {
        await vpnService.cleanup();
      } catch (error) {
        log.error('VPN cleanup failed during reload:', error);
      }
      compactWindow.reload();
    }
  });

  // Set Content Security Policy (matches main window policy)
  compactWindow.webContents.session.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': [
          "default-src 'self'; " +
          "script-src 'self' 'unsafe-inline'; " +
          "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
          "img-src 'self' data: https:; " +
          "font-src 'self' https://fonts.gstatic.com; " +
          `connect-src ${connectSrc}; ` +
          "object-src 'none';"
        ]
      }
    });
  });

  log.info('Compact window created');
}

/**
 * Show compact window positioned below the menu bar icon
 */
function showCompactWindow(bounds) {
  if (!compactWindow) {
    createCompactWindow();
  }

  if (bounds) {
    // Position compact window below the menu bar icon (macOS convention)
    const windowBounds = compactWindow.getBounds();
    const x = Math.round(bounds.x - windowBounds.width / 2);
    const y = bounds.y;
    compactWindow.setPosition(x, y);
  }

  if (mainWindow && mainWindow.isVisible()) {
    mainWindow.hide();
  }

  compactWindow.show();
  compactWindow.focus();
  log.info('Compact window shown');
}

/**
 * Hide compact window and show main window
 */
function hideCompactWindow() {
  if (!compactWindow || compactWindow.isDestroyed()) return;

  compactWindow.hide();

  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.show();
    mainWindow.focus();
  }

  log.info('Compact window hidden');
}

/**
 * Create macOS application menu
 */
function createMenu() {
  const template = [
    {
      label: app.getName(),
      submenu: [
        { role: 'about' },
        { type: 'separator' },
        {
          label: 'Preferences…',
          accelerator: 'Cmd+,',
          click: () => {
            if (mainWindow) {
              mainWindow.show();
              mainWindow.webContents.send('navigate', '/settings');
            }
          }
        },
        { type: 'separator' },
        { role: 'services' },
        { type: 'separator' },
        { role: 'hide' },
        { role: 'hideOthers' },
        { role: 'unhide' },
        { type: 'separator' },
        { role: 'quit' }
      ]
    },
    {
      label: 'Edit',
      submenu: [
        { role: 'undo' },
        { role: 'redo' },
        { type: 'separator' },
        { role: 'cut' },
        { role: 'copy' },
        { role: 'paste' },
        { role: 'selectAll' }
      ]
    },
    {
      label: 'View',
      submenu: [
        ...(isDev ? [
          { role: 'reload' },
          { role: 'forceReload' },
          { role: 'toggleDevTools' },
          { type: 'separator' },
        ] : []),
        { role: 'resetZoom' },
        { role: 'zoomIn' },
        { role: 'zoomOut' },
        { type: 'separator' },
        { role: 'togglefullscreen' }
      ]
    },
    {
      label: 'Window',
      submenu: [
        { role: 'minimize' },
        { role: 'close' },
        { type: 'separator' },
        { role: 'front' }
      ]
    }
  ];

  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

/**
 * IPC event handlers
 */
function setupIpcHandlers() {
  // Window controls
  ipcMain.handle('app:minimize', () => {
    if (mainWindow) mainWindow.minimize();
  });

  ipcMain.handle('app:maximize', () => {
    if (mainWindow) {
      mainWindow.isMaximized() ? mainWindow.unmaximize() : mainWindow.maximize();
    }
  });

  ipcMain.handle('app:close', () => {
    if (mainWindow) mainWindow.close();
  });

  ipcMain.handle('app:quit', () => {
    isQuitting = true;
    app.quit();
  });

  ipcMain.handle('app:get-version', () => {
    return app.getVersion();
  });

  ipcMain.handle('app:get-build-number', () => {
    const pkg = require('../package.json');
    return pkg.buildNumber || 0;
  });

  ipcMain.handle('app:is-maximized', () => {
    return mainWindow ? mainWindow.isMaximized() : false;
  });

  // System operations
  ipcMain.handle('system:open-external', async (event, url) => {
    try {
      await shell.openExternal(url);
      return true;
    } catch (error) {
      log.error('Failed to open external URL:', error);
      return false;
    }
  });

  // Helper daemon installation (for advanced kill switch)
  ipcMain.handle('vpn:install-helper', async () => {
    log.info('Helper daemon install requested');
    try {
      await vpnService.installHelper();
      return { success: true };
    } catch (error) {
      log.error('Helper install failed:', error);
      throw error;
    }
  });

  ipcMain.handle('vpn:is-helper-installed', () => {
    return vpnService.helperInstalled;
  });

  ipcMain.handle('vpn:helper-update-status', () => {
    return vpnService.getHelperUpdateStatus();
  });

  // VPN operations
  ipcMain.handle('vpn:connect', async (event, { serverId, settings }) => {
    log.info(`VPN connect request: ${serverId}`);

    // Skip the pre-connect policy check when reconnecting from persistentBlock —
    // HTTPS is guaranteed blocked by pf rules, so the fetch would just time out.
    if (vpnService.killSwitchState === 'persistentBlock') {
      log.info('[Update] Pre-connect: skipped (persistentBlock — HTTPS blocked by kill switch)');
    } else {
    // Pre-connect policy check
    log.info('[Update] Pre-connect policy check before VPN connection');
    try {
      const policy = await checkUpdatePolicy();
      if (policy) {
        const buildNumber = getBuildNumber();
        if (policy.maintenanceMode) {
          log.warn('[Update] Pre-connect: BLOCKED — maintenance mode active');
          evaluateUpdatePolicy(policy);
          throw new Error('WireDog VPN is currently under maintenance. Please try again later.');
        }
        if (buildNumber < policy.minSupportedVersion || policy.forceUpdate) {
          log.warn(`[Update] Pre-connect: BLOCKED — force update required (build ${buildNumber} < min ${policy.minSupportedVersion})`);
          evaluateUpdatePolicy(policy);
          throw new Error('A required update is available. Please update WireDog VPN before connecting.');
        }
        log.info('[Update] Pre-connect: policy check passed, allowing connection');
      } else {
        log.info('[Update] Pre-connect: no policy returned, allowing connection');
      }
    } catch (error) {
      if (error.message.includes('maintenance') || error.message.includes('required update')) {
        throw error;
      }
      log.warn(`[Update] Pre-connect: policy fetch failed (${error.message}), allowing connection (fail-open)`);
    }
    }

    try {
      const token = decryptSecret(settingsStore.get('authToken'));
      const result = await vpnService.connect(serverId, settings, token);
      settingsStore.set('lastServerId', serverId);
      settingsStore.set('lastSession', result);
      return result;
    } catch (error) {
      log.error('VPN connect failed:', error);
      throw error;
    }
  });

  ipcMain.handle('vpn:disconnect', async (_, options = {}) => {
    const disableProtection = options?.disableProtection !== false;
    log.info(`VPN disconnect request (disableProtection=${disableProtection})`);
    try {
      const token = decryptSecret(settingsStore.get('authToken'));
      await vpnService.disconnect(token, disableProtection);
      if (disableProtection) {
        settingsStore.delete('lastSession');
      }
      return { success: true };
    } catch (error) {
      log.error('VPN disconnect failed:', error);
      throw error;
    }
  });

  ipcMain.handle('vpn:get-status', async () => {
    const status = await vpnService.getFullStatus();
    if (status.status === 'connected') {
      const lastSession = settingsStore.get('lastSession');
      if (lastSession) {
        if (!status.session) {
          status.session = lastSession;
        } else if (!status.session.server?.city) {
          status.session = lastSession;
        }
      }
    }
    return status;
  });

  ipcMain.handle('vpn:get-stats', async () => {
    try {
      return await vpnService.getStats();
    } catch (error) {
      log.error('Failed to get VPN stats:', error);
      return null;
    }
  });

  ipcMain.handle('vpn:toggle-killswitch', async (_, { enabled }) => {
    log.info(`VPN toggle kill switch: ${enabled}`);
    try {
      await vpnService.toggleKillSwitch(enabled);
      return { success: true };
    } catch (error) {
      log.error('VPN toggle kill switch failed:', error);
      throw error;
    }
  });

  ipcMain.handle('vpn:enable-advanced-killswitch', async () => {
    log.info('VPN enable advanced kill switch');
    try {
      await vpnService.enableAdvancedKillSwitch();
      return { success: true };
    } catch (error) {
      log.error('VPN enable advanced kill switch failed:', error);
      throw error;
    }
  });

  ipcMain.handle('vpn:disable-advanced-killswitch', async () => {
    log.info('VPN disable advanced kill switch');
    try {
      await vpnService.disableAdvancedKillSwitch();
      return { success: true };
    } catch (error) {
      log.error('VPN disable advanced kill switch failed:', error);
      throw error;
    }
  });

  ipcMain.handle('vpn:emergency-reset', async () => {
    log.info('VPN emergency reset requested');
    try {
      await vpnService.emergencyReset();
      settingsStore.delete('lastSession');
      return { success: true };
    } catch (error) {
      log.error('VPN emergency reset failed:', error);
      throw error;
    }
  });

  // Forward VPN status changes to renderer and update tray
  vpnService.onStatusChange((status) => {
    if (status.status === 'connected' && (!status.session || !status.session.server?.city)) {
      const saved = settingsStore.get('lastSession');
      if (saved) status.session = saved;
    }
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('vpn:status-changed', status);
    }
    if (compactWindow && !compactWindow.isDestroyed()) {
      compactWindow.webContents.send('vpn:status-changed', status);
    }
    updateTrayMenu();
  });

  // Renderer process logging
  ipcMain.on('renderer:log', (event, { level, message }) => {
    const prefix = '[Renderer]';
    if (level === 'debug') {
      log.debug(prefix, message);
    } else if (level === 'info') {
      log.info(prefix, message);
    } else if (level === 'warn') {
      log.warn(prefix, message);
    } else if (level === 'error') {
      log.error(prefix, message);
    }
  });

  // Settings
  ipcMain.handle('settings:get', () => {
    return settingsStore.store;
  });

  ipcMain.handle('settings:set', (event, newSettings) => {
    try {
      const currentSettings = settingsStore.store;
      const merged = { ...currentSettings, ...newSettings };
      settingsStore.store = merged;
      const { authToken, authUser, ...safeSettings } = merged;
      log.info('Settings updated:', safeSettings);
      return { success: true, settings: merged };
    } catch (error) {
      log.error('Failed to update settings:', error);
      return { success: false, error: error.message };
    }
  });

  // Auth token management — stored encrypted via OS Keychain (safeStorage)
  ipcMain.handle('auth:set-token', (event, token) => {
    try {
      settingsStore.set('authToken', encryptSecret(token));
      log.info('Auth token stored (Keychain-encrypted)');
      return { success: true };
    } catch (error) {
      log.error('Failed to store auth token:', error);
      return { success: false, error: error.message };
    }
  });

  ipcMain.handle('auth:get-token', () => {
    return decryptSecret(settingsStore.get('authToken'));
  });

  ipcMain.handle('auth:clear-token', () => {
    try {
      settingsStore.delete('authToken');
      log.info('Auth token cleared');
      return { success: true };
    } catch (error) {
      log.error('Failed to clear auth token:', error);
      return { success: false, error: error.message };
    }
  });

  // Cached user profile — used to hydrate the UI when the kill switch is
  // blocking internet and the auth API is unreachable (otherwise the app
  // gets stuck on the login screen forever, unable to call /auth/me).
  ipcMain.handle('auth:set-user', (event, user) => {
    try {
      settingsStore.set('authUser', user);
      return { success: true };
    } catch (error) {
      log.error('Failed to store cached user:', error);
      return { success: false, error: error.message };
    }
  });

  ipcMain.handle('auth:get-user', () => {
    return settingsStore.get('authUser') || null;
  });

  ipcMain.handle('auth:clear-user', () => {
    try {
      settingsStore.set('authUser', null);
      return { success: true };
    } catch (error) {
      log.error('Failed to clear cached user:', error);
      return { success: false, error: error.message };
    }
  });

  // Compact window operations
  ipcMain.handle('compact:show-main', () => {
    hideCompactWindow();
  });

  ipcMain.handle('compact:exit', () => {
    isQuitting = true;
    app.quit();
  });

  // Auto-launch settings (macOS uses Login Items)
  ipcMain.handle('app:set-auto-launch', async (event, { enabled, mode }) => {
    try {
      app.setLoginItemSettings({
        openAtLogin: enabled,
        args: mode === 'minimize' ? ['--hidden'] : []
      });
      log.info(`Auto-launch ${enabled ? 'enabled' : 'disabled'} with mode: ${mode}`);
      return { success: true };
    } catch (error) {
      log.error('Failed to set auto-launch:', error);
      return { success: false, error: error.message };
    }
  });

  // System info
  ipcMain.handle('system:get-os-version', () => {
    const os = require('os');
    return `macOS ${os.release()}`;
  });

  ipcMain.handle('system:get-geolocation', async () => {
    const http = require('http');
    const https = require('https');

    const get = (url) => new Promise((resolve, reject) => {
      const client = url.startsWith('https') ? https : http;
      client.get(url, (res) => {
        let data = '';
        res.on('data', (chunk) => data += chunk);
        res.on('end', () => {
          try { resolve(JSON.parse(data)); }
          catch { reject(new Error(`Invalid JSON from ${url}`)); }
        });
      }).on('error', reject);
    });

    try {
      const data = await get('http://ip-api.com/json/?fields=query,city,region,regionName,country');
      if (data.city) {
        return { ip: data.query, city: data.city, region: data.region || data.regionName, country: data.country };
      }
    } catch (err) {
      log.warn('Primary geolocation failed:', err.message);
    }

    try {
      const ipData = await get('https://api.ipify.org?format=json');
      const geoData = await get(`https://ipapi.co/${ipData.ip}/json/`);
      return { ip: ipData.ip, city: geoData.city, region: geoData.region, country: geoData.country_name };
    } catch (err) {
      log.error('Geolocation fetch failed:', err.message);
      return { ip: 'Redacted', city: 'Redacted', region: '', country: 'US' };
    }
  });

  // Log operations (macOS paths)
  ipcMain.handle('logs:open-app-logs', () => {
    const logPath = log.transports.file.getFile().path;
    const logDir = path.dirname(logPath);
    shell.openPath(logDir);
  });

  ipcMain.handle('logs:open-service-logs', () => {
    // macOS helper daemon logs
    const serviceLogPath = '/var/log/wiredog-helper.log';
    if (fs.existsSync(serviceLogPath)) {
      shell.openPath(path.dirname(serviceLogPath));
    } else {
      // Fallback to app logs
      const logPath = log.transports.file.getFile().path;
      shell.openPath(path.dirname(logPath));
    }
  });

  // Split tunneling — enumerate installed apps from /Applications and ~/Applications
  ipcMain.handle('split-tunnel:get-installed-apps', async () => {
    try {
      return await getInstalledApps();
    } catch (error) {
      log.error('Failed to enumerate installed apps:', error);
      return [];
    }
  });

  ipcMain.handle('split-tunnel:browse-for-app', async () => {
    try {
      const result = await dialog.showOpenDialog(mainWindow, {
        title: 'Select Application',
        filters: [{ name: 'Applications', extensions: ['app'] }],
        properties: ['openFile'],
        defaultPath: '/Applications'
      });
      if (result.canceled || !result.filePaths.length) return null;
      const appPath = result.filePaths[0];
      const displayName = path.basename(appPath, '.app');

      // Read bundleId from the app's Info.plist — required for filter extension matching
      const plistPath = path.join(appPath, 'Contents', 'Info.plist');
      const plist = await readPlist(plistPath);
      const bundleId = plist?.CFBundleIdentifier || null;
      const name = (plist?.CFBundleDisplayName || plist?.CFBundleName || displayName).trim();
      const icon = plist ? extractAppIcon(appPath, plist) : null;

      return { name, exePath: appPath, bundleId, icon };
    } catch (error) {
      log.error('Failed to browse for app:', error);
      return null;
    }
  });

  // Latency measurement
  ipcMain.handle('latency:measure-servers', async (_, servers) => {
    try {
      const latency = require('./latency');
      return await latency.measureAll(servers);
    } catch (error) {
      log.error('Latency measurement failed:', error);
      return {};
    }
  });

  // Safe reload
  ipcMain.handle('app:safe-reload', async () => {
    log.info('Safe reload requested - cleaning up VPN');
    try {
      await vpnService.cleanup();
    } catch (error) {
      log.error('VPN cleanup failed during reload:', error);
    }

    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.reload();
    }
    if (compactWindow && !compactWindow.isDestroyed()) {
      compactWindow.reload();
    }
  });

  log.info('IPC handlers registered');
}

/**
 * Initialize settings store
 */
async function initializeSettingsStore() {
  try {
    const Store = (await import('electron-store')).default;
    settingsStore = new Store({
      name: 'vpn-settings',
      defaults: {
        protocol: 'wireguard',
        killSwitch: false,
        autoConnect: false,
        automaticUpdates: true,
        splitTunneling: {
          enabled: false,
          mode: 'exclude',
          apps: [],
          ips: []
        },
        lastServerId: null,
        authToken: null
      }
    });
    // Wire the VPN service to the store so it can persist lastConnectionConfig
    // (required for cold-start auto-reconnect when persistent_block is active)
    try { vpnService.setConfigStore(settingsStore); } catch (err) {
      log.warn('VPN: setConfigStore failed:', err.message);
    }
    log.info('Settings store initialized');
  } catch (error) {
    log.error('Failed to initialize settings store:', error);
    throw error;
  }
}

/**
 * App update system
 */
const https = require('https');
const http = require('http');
const { spawn } = require('child_process');

function getApiBaseUrl() {
  return process.env.VITE_API_URL
    || (isDev ? 'http://localhost:3001/api' : 'https://api.wiredogvpn.com/api');
}

function fetchJson(url, { timeoutMs = 5000 } = {}) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith('https') ? https : http;
    const req = client.get(url, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch { reject(new Error('Invalid JSON')); }
      });
    });
    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error(`fetchJson timeout after ${timeoutMs}ms`));
    });
    req.on('error', reject);
  });
}

async function checkUpdatePolicy() {
  const url = `${getApiBaseUrl()}/app/config`;
  log.info(`[Update] Fetching app config from ${url}`);
  try {
    // 10s timeout — kill switch can block all traffic and a shorter timeout causes false negatives
    const config = await fetchJson(url, { timeoutMs: 10000 });
    const platformKeys = Object.keys(config.platforms || {});
    log.info(`[Update] app/config response — top-level maintenanceMode:${config.maintenanceMode} platformKeys:[${platformKeys.join(', ')}]`);

    let policy = config.platforms?.['macos-universal'] || config.platforms?.['macos-arm64'];

    if (!policy) {
      log.warn(`[Update] No macOS platform policy found (checked macos-universal, macos-arm64). Available keys: [${platformKeys.join(', ')}]`);

      // Top-level maintenanceMode with no matching platform key — still block the app
      if (config.maintenanceMode) {
        log.warn('[Update] Top-level maintenanceMode=true with no platform key — synthesizing maintenance policy');
        return {
          maintenanceMode: true,
          updateMessage: config.updateMessage || null,
          minSupportedVersion: 0,
          latestVersion: 0,
          forceUpdate: false,
          downloadUrl: null,
        };
      }

      return null;
    }

    // Top-level maintenanceMode overrides the platform-level flag (either location can trigger it)
    if (config.maintenanceMode && !policy.maintenanceMode) {
      log.info('[Update] Merging top-level maintenanceMode=true into platform policy');
      policy = { ...policy, maintenanceMode: true };
    }

    log.info(`[Update] Policy found — minSupported:${policy.minSupportedVersion} latest:${policy.latestVersion} forceUpdate:${policy.forceUpdate} maintenance:${policy.maintenanceMode}`);
    return policy;
  } catch (error) {
    log.error(`[Update] Failed to fetch app config from ${url}: ${error.message}`);
    return null;
  }
}

function getBuildNumber() {
  const pkg = require('../package.json');
  return pkg.buildNumber || 0;
}

function sendToAllWindows(channel, data) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send(channel, data);
  }
  if (compactWindow && !compactWindow.isDestroyed()) {
    compactWindow.webContents.send(channel, data);
  }
}

let lastDownloadedDmgPath = null;

function downloadDmgFile(url) {
  return new Promise((resolve, reject) => {
    if (!url) {
      reject(new Error('No download URL provided'));
      return;
    }

    log.info(`[Update] Starting download: ${url}`);
    const client = url.startsWith('https') ? https : http;

    const handleRes = (currentUrl) => (res) => {
      log.info(`[Update] Response from ${currentUrl} — HTTP ${res.statusCode} content-type:${res.headers['content-type'] || 'unknown'} content-length:${res.headers['content-length'] || 'unknown'}`);

      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        const redirectUrl = res.headers.location;
        log.info(`[Update] Redirect ${res.statusCode} → ${redirectUrl}`);
        const redirectClient = redirectUrl.startsWith('https') ? https : http;
        redirectClient.get(redirectUrl, handleRes(redirectUrl)).on('error', (err) => {
          log.error(`[Update] Network error fetching ${redirectUrl}: ${err.message}`);
          reject(err);
        });
        return;
      }

      if (res.statusCode !== 200) {
        const err = new Error(`HTTP ${res.statusCode} at ${currentUrl}`);
        log.error(`[Update] Download failed — ${err.message}`);
        reject(err);
        return;
      }

      const total = parseInt(res.headers['content-length'], 10) || 0;
      const fileName = `wiredog-vpn-update-${Date.now()}.dmg`;
      const filePath = path.join(app.getPath('temp'), fileName);
      const fileStream = fs.createWriteStream(filePath);
      log.info(`[Update] Saving to ${filePath} (${total > 0 ? `${(total / 1024 / 1024).toFixed(1)} MB` : 'unknown size'})`);

      let transferred = 0;
      let lastProgressReport = 0;

      res.on('data', (chunk) => {
        transferred += chunk.length;
        fileStream.write(chunk);
        const now = Date.now();
        if (now - lastProgressReport > 200 || transferred === total) {
          lastProgressReport = now;
          const percent = total > 0 ? Math.round((transferred / total) * 100) : 0;
          sendToAllWindows('update:download-progress', { percent, bytesPerSecond: 0, transferred, total });
        }
      });

      res.on('end', () => {
        fileStream.end(() => {
          lastDownloadedDmgPath = filePath;
          log.info(`[Update] Download complete: ${filePath}`);
          sendToAllWindows('update:downloaded', {});
          resolve(filePath);
        });
      });

      res.on('error', (error) => {
        log.error(`[Update] Stream error while downloading from ${currentUrl}: ${error.message}`);
        fileStream.close();
        fs.unlink(filePath, () => {});
        reject(error);
      });
    };

    client.get(url, handleRes(url)).on('error', (err) => {
      log.error(`[Update] Network error fetching ${url}: ${err.message}`);
      reject(err);
    });
  });
}

async function evaluateUpdatePolicy(policy) {
  const buildNumber = getBuildNumber();
  log.info(`[Update] Evaluating policy — buildNumber:${buildNumber} minSupported:${policy.minSupportedVersion} latest:${policy.latestVersion} forceUpdate:${policy.forceUpdate}`);

  if (policy.maintenanceMode) {
    log.warn('[Update] MAINTENANCE MODE active — blocking app usage');
    sendToAllWindows('update:maintenance', {
      message: policy.updateMessage,
    });
    return;
  }

  if (buildNumber < policy.minSupportedVersion || policy.forceUpdate) {
    log.warn('[Update] Force update required');
    sendToAllWindows('update:force-required', {
      message: policy.updateMessage,
      downloadUrl: policy.downloadUrl,
    });
    return;
  }

  if (buildNumber < policy.latestVersion) {
    const automaticUpdates = settingsStore ? settingsStore.get('automaticUpdates', true) : true;
    log.info('[Update] Optional update available');

    if (automaticUpdates) {
      log.info(`[Update] Auto-updates ON — initiating silent background download from: ${policy.downloadUrl}`);
      try {
        await downloadDmgFile(policy.downloadUrl);
      } catch (error) {
        log.error(`[Update] Background download failed: ${error.message} — falling back to manual update notification`);
        sendToAllWindows('update:available', {
          message: policy.updateMessage,
          downloadUrl: policy.downloadUrl,
          latestVersion: policy.latestVersion,
        });
      }
    } else {
      log.info('[Update] Auto-updates OFF — notifying user of available update');
      sendToAllWindows('update:available', {
        message: policy.updateMessage,
        downloadUrl: policy.downloadUrl,
        latestVersion: policy.latestVersion,
      });
    }
    return;
  }

  log.info('[Update] App is up to date');
}

function setupUpdateSystem() {
  ipcMain.handle('update:check-now', async () => {
    log.info('[Update] Manual update check requested by user');
    const policy = await checkUpdatePolicy();
    if (!policy) {
      return { upToDate: true };
    }

    const buildNumber = getBuildNumber();
    if (buildNumber < policy.latestVersion || buildNumber < policy.minSupportedVersion || policy.forceUpdate) {
      await evaluateUpdatePolicy(policy);
      return { upToDate: false };
    }
    return { upToDate: true };
  });

  ipcMain.handle('update:download-now', async () => {
    log.info('[Update] User-initiated download requested');
    try {
      const policy = await checkUpdatePolicy();
      if (policy?.downloadUrl) {
        await downloadDmgFile(policy.downloadUrl);
        log.info('[Update] User-initiated download complete');
      } else {
        throw new Error('No download URL available');
      }
    } catch (error) {
      log.error(`[Update] User-initiated download failed: ${error.message}`);
      throw error;
    }
  });

  ipcMain.handle('update:install-now', () => {
    if (!lastDownloadedDmgPath || !fs.existsSync(lastDownloadedDmgPath)) {
      log.error('[Update] Install requested but no downloaded DMG found');
      return { success: false, error: 'Update file not found' };
    }

    const scriptPath = app.isPackaged
      ? path.join(process.resourcesPath, 'install-update.sh')
      : path.join(__dirname, '../scripts/install-update.sh');

    log.info(`[Update] Spawning installer: ${scriptPath} ${lastDownloadedDmgPath}`);

    const child = spawn('bash', [scriptPath, lastDownloadedDmgPath], {
      detached: true,
      stdio: 'ignore',
    });
    child.unref();

    // Quit after a short delay so IPC reply reaches the renderer first
    setTimeout(() => app.quit(), 500);
    return { success: true };
  });

  let initialCheckDone = false;
  ipcMain.handle('update:renderer-ready', async () => {
    if (initialCheckDone) {
      log.info('[Update] renderer-ready received but initial check already done — skipping');
      return;
    }
    initialCheckDone = true;
    log.info('[Update] renderer-ready — triggering initial policy check');
    const policy = await checkUpdatePolicy();
    if (policy) evaluateUpdatePolicy(policy);
  });

  // Periodic policy check every 30 minutes
  setInterval(async () => {
    log.info('[Update] Periodic check triggered (30-min interval)');
    const policy = await checkUpdatePolicy();
    if (policy) evaluateUpdatePolicy(policy);
  }, 30 * 60 * 1000);

  log.info('[Update] Update system initialized — initial check fires on renderer-ready, then every 30 minutes');
}

// ================================
// App lifecycle
// ================================
app.whenReady().then(async () => {
  log.info('Electron app ready (macOS)');
  await initializeSettingsStore();
  setupIpcHandlers();

  // Restore last session for boot auto-reconnect
  const lastSession = settingsStore.get('lastSession');
  if (lastSession) {
    vpnService.restoreSession(lastSession);
  }

  createMainWindow();
  createTray();
  createMenu();

  // Tell the renderer when the system extension needs one-time user approval.
  // macOS Security requires this for all Network Extensions distributed via Developer ID
  // — this step can't be skipped or automated by the app, only guided well. The renderer
  // (see ExtensionApprovalDialog.tsx) shows a blocking in-app card, matching how other
  // VPN apps (e.g. Proton) handle this same unavoidable macOS requirement — a plain
  // native dialog.showMessageBox proved too easy to miss (it can render unfocused/behind
  // the app window with no parent set), so this is rendered in-app instead where it's
  // impossible to lose behind other windows.
  vpnService.onExtensionNeedsApproval(() => {
    log.info('VPN: Extension needs user approval — notifying renderer');
    app.focus({ steal: true });
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.show();
      mainWindow.focus();
      mainWindow.webContents.send('extension:needs-approval');
    }
  });

  // Fires once the user actually approves the extension in System Settings
  // following the notice above — confirms the one-time setup is genuinely done
  // instead of leaving the user to guess. Dismisses the blocking card in the
  // renderer and lets a system notification confirm it too.
  vpnService.onExtensionActivated(() => {
    log.info('VPN: Extension activated after user approval — notifying renderer');
    if (mainWindow) {
      mainWindow.webContents.send('extension:activated');
    }
    new Notification({
      title: 'WireDog VPN is ready',
      body: 'Network extension approved — you can connect now.',
    }).show();
  });

  // Initialize VPN service (native addon + helper daemon)
  try {
    log.info('Initializing VPN service...');
    await vpnService.initialize();
    log.info('VPN service initialized');

    // Check if helper daemon needs updating after an app update
    const helperStatus = vpnService.getHelperUpdateStatus();
    if (helperStatus.needsUpdate) {
      log.warn(`Helper daemon version mismatch (helper: ${helperStatus.helperVersion}, app: ${helperStatus.appVersion})`);
      // Notify the renderer so it can prompt the user
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.once('did-finish-load', () => {
          mainWindow.webContents.send('helper:update-needed', helperStatus);
        });
      }
    }
  } catch (error) {
    log.warn('VPN service initialization:', error.message);
  }

  // Auto-launch settings
  try {
    const savedAutoStart = settingsStore.get('autoStart', false);
    const savedAutoStartMode = settingsStore.get('autoStartMode', 'open');
    app.setLoginItemSettings({
      openAtLogin: savedAutoStart,
      args: savedAutoStartMode === 'minimize' ? ['--hidden'] : []
    });
    log.info(`Auto-launch initialized: enabled=${savedAutoStart}, mode=${savedAutoStartMode}`);
  } catch (error) {
    log.warn('Failed to initialize auto-launch:', error.message);
  }

  setupUpdateSystem();

  // macOS: Re-create window when dock icon is clicked
  app.on('activate', () => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.show();
      mainWindow.focus();
    } else {
      createMainWindow();
    }
  });
});

// macOS: Don't quit when all windows closed (keep running in menu bar)
app.on('window-all-closed', () => {
  // On macOS, apps stay active until Cmd+Q
  // Do nothing - tray keeps the app alive
});

app.on('before-quit', async () => {
  isQuitting = true;
  log.info('Application quitting - cleaning up VPN');
  try {
    await vpnService.cleanup();
  } catch (error) {
    log.error('VPN cleanup failed:', error);
  }
});

// Handle app being opened again (e.g., from Dock)
app.on('second-instance', () => {
  if (mainWindow) {
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.show();
    mainWindow.focus();
  }
});

// Security: Prevent navigation to external websites
app.on('web-contents-created', (event, contents) => {
  contents.on('will-navigate', (event, navigationUrl) => {
    const parsedUrl = new URL(navigationUrl);
    if (parsedUrl.origin !== 'http://localhost:5173' && !navigationUrl.startsWith('file://')) {
      event.preventDefault();
    }
  });
});

log.info('Electron main process started (macOS)');
