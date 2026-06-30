const { execSync } = require('child_process');
const path = require('path');
const fs = require('fs');

exports.default = async function afterPack(context) {
  const appOutDir = context.appOutDir;
  const appName = context.packager.appInfo.productFilename;
  const appPath = path.join(appOutDir, `${appName}.app`);

  console.log('afterPack: stripping xattrs from', appPath);
  execSync(`find "${appPath}" -exec xattr -c {} \\;`, { stdio: 'inherit' });

  // --- Embed provisioning profiles ---
  const profilesDir = path.join(require('os').homedir(), 'Documents', 'wiredog');
  const certsDir = path.join(profilesDir, 'certs');

  // Main app profile (Developer ID) — embed as Contents/embedded.provisionprofile
  const mainProfile = path.join(certsDir, 'WireDog_macOS_Main.provisionprofile');
  if (fs.existsSync(mainProfile)) {
    const dest = path.join(appPath, 'Contents', 'embedded.provisionprofile');
    fs.copyFileSync(mainProfile, dest);
    console.log('afterPack: Embedded main provisioning profile');
  } else {
    console.warn('afterPack: Main Developer ID profile not found at', mainProfile);
  }

  const plugInsDir = path.join(appPath, 'Contents', 'PlugIns');

  // --- Ensure tunnel system extension is in Contents/Library/SystemExtensions ---
  const sysextName = 'com.wiredog.vpn.macos.tunnel.systemextension';
  const sysextDir = path.join(appPath, 'Contents', 'Library', 'SystemExtensions');
  let appexPath = path.join(sysextDir, sysextName);

  if (!fs.existsSync(appexPath)) {
    console.warn('afterPack: System extension not found at', appexPath);
    const fallbackPaths = [
      path.join(appPath, 'Contents', 'PlugIns', sysextName),
      path.join(appPath, 'Contents', 'Resources', sysextName),
    ];
    const fallback = fallbackPaths.find(p => fs.existsSync(p));
    if (fallback) {
      console.log('afterPack: Found system extension at', fallback, '— moving to', sysextDir);
      fs.mkdirSync(sysextDir, { recursive: true });
      execSync(`cp -R "${fallback}" "${appexPath}"`, { stdio: 'inherit' });
      execSync(`rm -rf "${fallback}"`, { stdio: 'inherit' });
    } else {
      console.error('afterPack: System extension not found. VPN tunnel will not work.');
      return;
    }
  }

  // Tunnel profile — embed inside the system extension as Contents/embedded.provisionprofile
  const tunnelProfile = path.join(certsDir, 'WireDog_macOS_Tunnel.provisionprofile');
  if (fs.existsSync(tunnelProfile)) {
    const dest = path.join(appexPath, 'Contents', 'embedded.provisionprofile');
    fs.copyFileSync(tunnelProfile, dest);
    console.log('afterPack: Embedded tunnel provisioning profile');
  } else {
    console.warn('afterPack: Tunnel Developer ID profile not found at', tunnelProfile);
    console.warn('afterPack: Ensure a Developer ID profile for com.wiredog.vpn.macos.tunnel exists');
  }

  const signingIdentity = process.env.DEVELOPER_ID_APPLICATION
    || process.env.CSC_NAME
    || 'Developer ID Application';

  const expectedTeamId = process.env.APPLE_TEAM_ID;

  // --- Move helper binary into Contents/MacOS/ so Bundle.main = the Electron app ---
  // NETunnelProviderManager looks for extensions in the calling process's Bundle.main.
  // Placing the helper in Contents/MacOS/ makes Bundle.main resolve to WireDog VPN.app.
  const helperSrc = path.join(appPath, 'Contents', 'Resources', 'helper', 'wiredog-helper');
  const helperDest = path.join(appPath, 'Contents', 'MacOS', 'wiredog-helper');
  const helperEntitlements = path.join(__dirname, 'entitlements.helper.plist');

  if (fs.existsSync(helperSrc)) {
    fs.copyFileSync(helperSrc, helperDest);
    fs.chmodSync(helperDest, 0o755);
    fs.unlinkSync(helperSrc);
    console.log('afterPack: Moved helper binary to Contents/MacOS/');

    console.log('afterPack: Signing helper daemon with identity:', signingIdentity);
    try {
      execSync(
        `codesign --force --options runtime --timestamp ` +
        `--sign "${signingIdentity}" ` +
        `--entitlements "${helperEntitlements}" ` +
        `"${helperDest}"`,
        { stdio: 'inherit' }
      );
      console.log('afterPack: Helper daemon signed successfully');

      const entCheck = execSync(
        `codesign -d --entitlements - "${helperDest}" 2>/dev/null || true`
      ).toString();
      console.log('afterPack: Helper entitlements:', entCheck.substring(0, 200));
    } catch (error) {
      console.error('afterPack: Failed to sign helper daemon:', error.message);
      throw error;
    }
  } else {
    console.warn('afterPack: Helper binary not found at', helperSrc, '— skipping helper signing');
  }

  // --- Embed and sign the VPN config XPC service ---
  // This service holds packet-tunnel-provider-systemextension (no JIT) and calls
  // saveToPreferences() on behalf of the Electron process, which cannot hold both
  // the NE entitlement and JIT simultaneously (RunningBoard blocks launch).
  const xpcBundleName = 'com.wiredog.vpn.macos.config.xpc';
  const xpcServicesDir = path.join(appPath, 'Contents', 'XPCServices');
  const xpcDest = path.join(xpcServicesDir, xpcBundleName);
  const xpcSrc = path.join(__dirname, 'xpc-config', 'build', xpcBundleName);

  if (fs.existsSync(xpcSrc)) {
    fs.mkdirSync(xpcServicesDir, { recursive: true });
    if (fs.existsSync(xpcDest)) execSync(`rm -rf "${xpcDest}"`, { stdio: 'inherit' });
    execSync(`cp -R "${xpcSrc}" "${xpcDest}"`, { stdio: 'inherit' });

    const xpcProfile = path.join(certsDir, 'WireDog_macOS_Config.provisionprofile');
    if (fs.existsSync(xpcProfile)) {
      fs.copyFileSync(xpcProfile, path.join(xpcDest, 'Contents', 'embedded.provisionprofile'));
      console.log('afterPack: Embedded config XPC provisioning profile');
    } else {
      console.warn('afterPack: Config XPC provisioning profile not found at', xpcProfile);
      console.warn('afterPack: Create a Developer ID profile for com.wiredog.vpn.macos.config');
    }

    const xpcEntitlements = path.join(__dirname, 'xpc-config', 'entitlements.plist');
    try {
      execSync(
        `codesign --force --options runtime --timestamp ` +
        `--sign "${signingIdentity}" ` +
        `--entitlements "${xpcEntitlements}" ` +
        `"${xpcDest}"`,
        { stdio: 'inherit' }
      );
      console.log('afterPack: ✅ VPN config XPC service signed');
    } catch (error) {
      console.error('afterPack: Failed to sign XPC service:', error.message);
      throw error;
    }
  } else {
    console.error('afterPack: XPC config service not built. Run: scripts/build-xpc-config.sh');
    throw new Error('Missing XPC config service — build it before packaging');
  }

  // --- Sign native modules and dylibs if present ---
  // Unsigned Mach-O files anywhere in the bundle will block notarization.
  const nativeFiles = [
    path.join(appPath, 'Contents', 'Resources', 'native', 'wiredog_native.node'),
    path.join(appPath, 'Contents', 'Resources', 'native', 'libWireDogNative.dylib'),
    path.join(appPath, 'Contents', 'Resources', 'sysext', 'wiredog_sysext.node'),
  ];
  for (const nativeFile of nativeFiles) {
    if (fs.existsSync(nativeFile)) {
      try {
        execSync(
          `codesign --force --options runtime --timestamp ` +
          `--sign "${signingIdentity}" ` +
          `"${nativeFile}"`,
          { stdio: 'inherit' }
        );
        console.log('afterPack: Signed native file:', path.basename(nativeFile));
      } catch (error) {
        console.warn('afterPack: Could not sign native file (may not be a valid Mach-O):', path.basename(nativeFile), error.message);
      }
    }
  }

  // --- Sign the Network System Extension (.systemextension) with Developer ID ---
  // System extensions MUST be signed with Developer ID Application (unlike legacy .appex
  // which required team certs). This is correct and expected for Developer ID distribution.
  const sysextEntitlements = path.join(__dirname, 'extension', 'WireDogTunnel', 'WireDogTunnel.entitlements');

  console.log('afterPack: Signing tunnel system extension with Developer ID:', signingIdentity);
  console.log('afterPack: Using entitlements:', sysextEntitlements);

  try {
    if (!fs.existsSync(sysextEntitlements)) {
      throw new Error(`Entitlements file not found: ${sysextEntitlements}`);
    }

    execSync(
      `codesign --force --options runtime --timestamp ` +
      `--sign "${signingIdentity}" ` +
      `--entitlements "${sysextEntitlements}" ` +
      `"${appexPath}"`,
      { stdio: 'inherit' }
    );
    console.log('afterPack: Tunnel system extension signed successfully');

    const sigCheck = execSync(`codesign -dvvv "${appexPath}" 2>&1`).toString();

    if (!sigCheck.includes('Authority=Developer ID Application')) {
      throw new Error('Tunnel system extension not signed with Developer ID Application');
    }
    if (expectedTeamId && !sigCheck.includes(`TeamIdentifier=${expectedTeamId}`)) {
      console.warn('afterPack: WARNING - Tunnel system extension Team ID mismatch');
    }

    console.log('afterPack: ✅ Tunnel system extension signature verified: Developer ID Application');
    console.log(sigCheck.split('\n').filter(l => l.includes('Authority') || l.includes('Team')).join('\n'));
  } catch (error) {
    console.error('afterPack: Failed to sign tunnel system extension:', error.message);
    throw error;
  }

  // --- Sign the sysext activator binary ---
  // WireDogActivator is a standalone Swift binary at Contents/MacOS/WireDogActivator.
  // Signed with NO entitlements (hardened runtime only) — privileged entitlements on
  // non-main-executable binaries are rejected by AMFI at launch. OSSystemExtensionManager
  // validates against Bundle.main (WireDog VPN.app), not the calling binary's own entitlements.
  const activatorPath = path.join(appPath, 'Contents', 'MacOS', 'WireDogActivator');

  if (fs.existsSync(activatorPath)) {
    const activatorEntitlements = path.join(__dirname, 'sysext-activator', 'WireDogActivator.entitlements');
    console.log('afterPack: Signing WireDogActivator (system-extension.install only)...');
    try {
      execSync(
        `codesign --force --options runtime --timestamp ` +
        `--sign "${signingIdentity}" ` +
        `--entitlements "${activatorEntitlements}" ` +
        `"${activatorPath}"`,
        { stdio: 'inherit' }
      );
      const actSigCheck = execSync(`codesign -dvvv "${activatorPath}" 2>&1`).toString();
      if (!actSigCheck.includes('Authority=Developer ID Application')) {
        throw new Error('WireDogActivator not signed with Developer ID Application');
      }
      console.log('afterPack: ✅ WireDogActivator signed with Developer ID Application');
    } catch (error) {
      console.error('afterPack: Failed to sign WireDogActivator:', error.message);
      throw error;
    }
  } else {
    console.warn('afterPack: WireDogActivator not found at', activatorPath);
  }

  // --- Ensure Filter extension is in Contents/PlugIns ---
  const filterAppexName = 'WireDogFilter.appex';
  let filterAppexPath = path.join(plugInsDir, filterAppexName);

  if (!fs.existsSync(filterAppexPath)) {
    console.warn('afterPack: Filter extension not found at', filterAppexPath);
    const fallbackPaths = [
      path.join(appPath, 'Contents', 'Resources', 'PlugIns', filterAppexName),
      path.join(appPath, 'Contents', 'Resources', filterAppexName),
    ];
    const fallback = fallbackPaths.find(p => fs.existsSync(p));
    if (fallback) {
      console.log('afterPack: Found filter extension at', fallback, '— moving to', plugInsDir);
      fs.mkdirSync(plugInsDir, { recursive: true });
      execSync(`cp -R "${fallback}" "${filterAppexPath}"`, { stdio: 'inherit' });
      execSync(`rm -rf "${fallback}"`, { stdio: 'inherit' });
    } else {
      console.warn('afterPack: Filter extension not found. Split tunneling will not work.');
    }
  }

  if (fs.existsSync(filterAppexPath)) {
    const filterProfile = path.join(certsDir, 'WireDog_macOS_Filter.provisionprofile');
    if (fs.existsSync(filterProfile)) {
      const dest = path.join(filterAppexPath, 'Contents', 'embedded.provisionprofile');
      fs.copyFileSync(filterProfile, dest);
      console.log('afterPack: Embedded filter provisioning profile');
    } else {
      console.warn('afterPack: Filter profile not found at', filterProfile);
      console.warn('afterPack: Create a Developer ID profile for com.wiredog.vpn.macos.filter');
    }

    const filterAppexEntitlements = path.join(__dirname, 'extension', 'WireDogFilter', 'WireDogFilter.entitlements');

    console.log('afterPack: Signing filter extension with Developer ID:', signingIdentity);

    try {
      if (!fs.existsSync(filterAppexEntitlements)) {
        console.warn(`afterPack: Filter entitlements file not found: ${filterAppexEntitlements} — skipping`);
      } else {
        execSync(
          `codesign --force --options runtime --timestamp ` +
          `--sign "${signingIdentity}" ` +
          `--entitlements "${filterAppexEntitlements}" ` +
          `"${filterAppexPath}"`,
          { stdio: 'inherit' }
        );
        console.log('afterPack: Filter extension signed successfully');

        const filterSigCheck = execSync(`codesign -dvvv "${filterAppexPath}" 2>&1`).toString();

        if (!filterSigCheck.includes('Authority=Developer ID Application')) {
          throw new Error('Filter extension not signed with Developer ID Application');
        }

        console.log('afterPack: ✅ Filter extension signature verified: Developer ID Application');
      }
    } catch (error) {
      console.error('afterPack: Failed to sign filter extension:', error.message);
      throw error;
    }
  }
};
