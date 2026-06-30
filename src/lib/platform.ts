/**
 * Platform detection utilities for WireDog VPN.
 *
 * Uses the electronAPI bridge when available, falls back to
 * navigator.userAgent for web/dev mode.
 */

export const isMac =
  window.electronAPI?.isMac ?? navigator.userAgent.includes('Macintosh');

export const isWindows =
  window.electronAPI?.isWindows ?? navigator.userAgent.includes('Windows');

export const isLinux =
  window.electronAPI?.isLinux ??
  (navigator.userAgent.includes('Linux') && !navigator.userAgent.includes('Android'));

/** Human-readable OS label for UI strings */
export const platformLabel = isMac ? 'macOS' : isWindows ? 'Windows' : 'Linux';

/** Human-readable term for the system tray / menu bar area */
export const trayLabel = isMac ? 'Menu Bar' : 'System Tray';
