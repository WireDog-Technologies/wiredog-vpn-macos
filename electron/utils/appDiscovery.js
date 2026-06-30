'use strict';

/**
 * App Discovery — macOS
 *
 * Scans /Applications and ~/Applications for installed .app bundles and returns
 * a list of { name, exePath, bundleId, icon } objects sorted alphabetically.
 *
 * bundleId = CFBundleIdentifier from the app's Info.plist. This is the identifier
 * used by the WireDogFilter NETransparentProxyProvider to match flows via
 * NEFlowMetaData.sourceAppSigningIdentifier (which equals the bundle ID for
 * all properly code-signed macOS apps).
 *
 * icon = base64 PNG data URL (32×32) extracted from the app's .icns resource,
 * or null if the icon cannot be found/read.
 */

const path = require('path');
const fs = require('fs');
const os = require('os');
const { execFile } = require('child_process');
const { nativeImage } = require('electron');

/**
 * Read and parse an Info.plist file as JSON using plutil.
 * Returns a plain object, or null if the file can't be read/parsed.
 */
function readPlist(plistPath) {
  return new Promise((resolve) => {
    execFile(
      'plutil',
      ['-convert', 'json', '-o', '-', plistPath],
      { timeout: 3000 },
      (err, stdout) => {
        if (err) { resolve(null); return; }
        try {
          resolve(JSON.parse(stdout));
        } catch (_) {
          resolve(null);
        }
      }
    );
  });
}

/**
 * Extract a 32×32 PNG data URL from an app bundle's .icns resource.
 * Uses Electron's nativeImage which natively reads ICNS on macOS.
 * Returns a data URL string or null on any failure.
 */
function extractAppIcon(appPath, plist) {
  try {
    // CFBundleIconFile (classic) or CFBundleIcons.CFBundlePrimaryIcon (modern)
    let iconFileName =
      plist.CFBundleIconFile ||
      plist.CFBundleIcons?.CFBundlePrimaryIcon?.CFBundleIconName ||
      (plist.CFBundleIcons?.CFBundlePrimaryIcon?.CFBundleIconFiles || []).slice(-1)[0] ||
      '';

    if (!iconFileName) return null;

    const iconName = iconFileName.endsWith('.icns') ? iconFileName : `${iconFileName}.icns`;
    const iconPath = path.join(appPath, 'Contents', 'Resources', iconName);
    if (!fs.existsSync(iconPath)) return null;

    const img = nativeImage.createFromPath(iconPath);
    if (img.isEmpty()) return null;

    return img.resize({ width: 32, height: 32 }).toDataURL();
  } catch (_) {
    return null;
  }
}

/**
 * Discover installed apps in a single directory.
 * Returns an array of { name, exePath, bundleId, icon } for each valid .app bundle found.
 */
async function discoverAppsInDir(dir) {
  if (!fs.existsSync(dir)) return [];

  let entries;
  try {
    entries = fs.readdirSync(dir);
  } catch (_) {
    return [];
  }

  const apps = [];

  for (const entry of entries) {
    if (!entry.endsWith('.app')) continue;

    const appPath = path.join(dir, entry);
    const plistPath = path.join(appPath, 'Contents', 'Info.plist');

    if (!fs.existsSync(plistPath)) continue;

    const plist = await readPlist(plistPath);
    if (!plist) continue;

    const bundleId = plist.CFBundleIdentifier;
    if (!bundleId || typeof bundleId !== 'string') continue;

    const displayName =
      plist.CFBundleDisplayName ||
      plist.CFBundleName ||
      entry.replace(/\.app$/, '');

    apps.push({
      name: String(displayName).trim(),
      exePath: appPath,                      // Full .app bundle path
      bundleId: bundleId,                    // CFBundleIdentifier — primary key for filter extension matching
      icon: extractAppIcon(appPath, plist),  // 32×32 PNG data URL, or null
    });
  }

  return apps;
}

/**
 * Return all installed macOS applications visible to the current user.
 * Scans /Applications and ~/Applications; deduplicates by bundle ID.
 * Results are sorted alphabetically by app name.
 *
 * @returns {Promise<Array<{ name: string, exePath: string, bundleId: string }>>}
 */
async function getInstalledApps() {
  const searchDirs = [
    '/Applications',
    path.join(os.homedir(), 'Applications'),
  ];

  const seen = new Set();
  const all = [];

  for (const dir of searchDirs) {
    const apps = await discoverAppsInDir(dir);
    for (const app of apps) {
      if (seen.has(app.bundleId)) continue;
      seen.add(app.bundleId);
      all.push(app);
    }
  }

  return all.sort((a, b) => a.name.localeCompare(b.name));
}

module.exports = { getInstalledApps, readPlist, extractAppIcon };
