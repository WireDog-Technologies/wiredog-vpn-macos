import { useElectron } from '@/context/ElectronContext';
import { useVPN } from '@/context/VPNContext';
import { useEffect } from 'react';

/**
 * Hook that bridges the VPN context with Electron IPC
 * Provides real VPN operations when running in Electron
 */
export const useElectronVPN = () => {
  const { connectVPN: electronConnect, disconnectVPN: electronDisconnect } = useElectron();
  const { connect, disconnect, connection } = useVPN();

  const enhancedConnect = async (serverId: string) => {
    try {
      // Call Electron IPC first (for real VPN operations)
      const electronResult = await electronConnect(serverId);

      if (electronResult.success) {
        // Update React context with the result
        await connect({ id: serverId } as any); // Simplified for demo
        return { success: true };
      } else {
        throw new Error('Electron VPN connection failed');
      }
    } catch (error) {
      console.error('VPN connection failed:', error);
      // Fallback to mock implementation
      await connect({ id: serverId } as any);
      return { success: false, error: error.message };
    }
  };

  const enhancedDisconnect = async () => {
    try {
      // Call Electron IPC first
      const electronResult = await electronDisconnect();

      if (electronResult.success) {
        // Update React context
        await disconnect();
        return { success: true };
      } else {
        throw new Error('Electron VPN disconnection failed');
      }
    } catch (error) {
      console.error('VPN disconnection failed:', error);
      // Fallback to mock implementation
      await disconnect();
      return { success: false, error: error.message };
    }
  };

  // Sync connection status with Electron (if available)
  useEffect(() => {
    // In a real implementation, you would listen to Electron events
    // for connection status changes and update the React context accordingly
  }, []);

  return {
    connect: enhancedConnect,
    disconnect: enhancedDisconnect,
    connection
  };
};