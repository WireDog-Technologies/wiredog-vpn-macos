/**
 * Post-build notarization script for macOS
 * Called by electron-builder via afterSign hook
 *
 * Requires environment variables:
 *   APPLE_ID - Apple Developer account email
 *   APPLE_APP_SPECIFIC_PASSWORD - App-specific password for notarization
 *   APPLE_TEAM_ID - Apple Developer Team ID
 */
const { notarize } = require('@electron/notarize');
const path = require('path');

exports.default = async function notarizing(context) {
  const { electronPlatformName, appOutDir } = context;

  // Only notarize macOS builds
  if (electronPlatformName !== 'darwin') {
    return;
  }

  // Skip notarization in development
  if (process.env.NODE_ENV === 'development' || !process.env.APPLE_ID) {
    console.log('Skipping notarization (development mode or APPLE_ID not set)');
    return;
  }

  const appName = context.packager.appInfo.productFilename;
  const appPath = path.join(appOutDir, `${appName}.app`);
  const appBundleId = context.packager.appInfo.macBundleIdentifier;

  console.log(`Notarizing ${appPath} (${appBundleId})...`);

  try {
    await notarize({
      tool: 'notarytool',
      appPath,
      appBundleId,
      appleId: process.env.APPLE_ID,
      appleIdPassword: process.env.APPLE_APP_SPECIFIC_PASSWORD,
      teamId: process.env.APPLE_TEAM_ID,
    });
    console.log('Notarization complete');
  } catch (error) {
    console.error('Notarization failed:', error);
    throw error;
  }
};
