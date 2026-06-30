import { useEffect, useState, useCallback } from 'react';

export type ExtensionApprovalStatus = 'idle' | 'pending' | 'activated';

export const useExtensionApproval = () => {
  const [status, setStatus] = useState<ExtensionApprovalStatus>('idle');

  const isElectron = !!window.electronAPI?.extension;

  useEffect(() => {
    if (!isElectron) return;

    const api = window.electronAPI.extension;

    const cleanupPending = api.onNeedsApproval(() => {
      setStatus('pending');
    });

    const cleanupActivated = api.onActivated(() => {
      setStatus('activated');
    });

    return () => {
      cleanupPending();
      cleanupActivated();
    };
  }, [isElectron]);

  const openNetworkExtensions = useCallback(async () => {
    if (!window.electronAPI?.openExternal) return;
    // Deep-links straight to the Network Extensions list (just the toggle),
    // not the "By Category" overview — confirmed against the
    // com.apple.LoginItems-Settings.extension?ExtensionItems variant, which
    // lands one level too high and makes the user find Network Extensions
    // themselves.
    await window.electronAPI.openExternal(
      'x-apple.systempreferences:com.apple.ExtensionsPreferences?extensionPointIdentifier=com.apple.system_extension.network_extension.extension-point'
    );
  }, []);

  // Once activated, briefly show the confirmation state, then clear — the card
  // itself handles displaying success before disappearing (see
  // ExtensionApprovalDialog.tsx), this just resets the underlying status after.
  const clearActivated = useCallback(() => {
    setStatus('idle');
  }, []);

  return {
    status,
    openNetworkExtensions,
    clearActivated,
  };
};
