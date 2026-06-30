import React, { useState, useEffect, useRef } from 'react';
import { ChevronLeft, Power, Lock, AlertTriangle, Download } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { Switch } from '@/components/ui/switch';
import { Card } from '@/components/ui/card';
import { useVPN } from '@/context/VPNContext';
import { isMac } from '@/lib/platform';

const SettingsKillSwitch: React.FC = () => {
  const navigate = useNavigate();
  const { settings, updateSettings } = useVPN();
  const [resetting, setResetting] = useState(false);
  const [installingHelper, setInstallingHelper] = useState(false);
  const [splitTunnelConflict, setSplitTunnelConflict] = useState(false);
  const conflictTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const splitTunnelingActive = settings.splitTunneling?.enabled ?? false;

  useEffect(() => {
    if (splitTunnelConflict) {
      conflictTimerRef.current = setTimeout(() => setSplitTunnelConflict(false), 5000);
    }
    return () => {
      if (conflictTimerRef.current) clearTimeout(conflictTimerRef.current);
    };
  }, [splitTunnelConflict]);

  const handleKillSwitchToggle = (checked: boolean) => {
    if (checked && splitTunnelingActive) {
      // Split tunneling and kill switch are mutually exclusive — disable split tunneling first
      updateSettings({
        killSwitch: true,
        splitTunneling: { ...settings.splitTunneling, enabled: false },
      });
      setSplitTunnelConflict(true);
    } else {
      updateSettings({ killSwitch: checked });
    }
  };

  return (
    <div className="h-full p-6 star-pattern overflow-auto">
      {/* Back Button */}
      <button
        onClick={() => navigate('/settings')}
        className="text-muted-foreground hover:text-foreground transition-colors mb-4 p-0"
      >
        <ChevronLeft className="w-8 h-8" />
      </button>

      <div className="max-w-2xl mx-auto">
        {/* Header */}
        <div className="mb-6">
          <h1 className="font-display text-4xl tracking-wider text-foreground mb-2">
            KILL SWITCH
          </h1>
          <p className="text-muted-foreground">
            Protect your privacy with automatic network protection
          </p>
        </div>

        {/* Description Card */}
        <Card className="p-4 mb-4 bg-muted/50">
          <div className="space-y-2">
            <p className="font-medium text-foreground">What is Kill Switch?</p>
            <p className="text-sm text-muted-foreground leading-snug">
              The Kill Switch is a critical security feature that protects your privacy by blocking all internet traffic if your VPN connection drops unexpectedly. This ensures your true IP address and online activity are never exposed through an unprotected connection.
            </p>
            <p className="text-sm text-muted-foreground leading-snug">
              When enabled, if the VPN connection is interrupted, your device's internet access will be cut off until the VPN connection is re-established. This prevents any data leaks that could compromise your privacy.
            </p>
          </div>
        </Card>

        {/* Split tunnel conflict banner */}
        {splitTunnelConflict && (
          <div className="flex items-start gap-2 p-3 mb-4 rounded-lg bg-amber-500/10 border border-amber-500/20">
            <AlertTriangle className="w-4 h-4 text-amber-500 flex-shrink-0 mt-0.5" />
            <p className="text-xs text-amber-500 leading-snug">
              Split tunneling has been disabled. Kill switch and split tunneling cannot be active simultaneously.
            </p>
          </div>
        )}

        {/* Kill Switch Toggle Card */}
        <Card className="p-4 mb-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-muted flex items-center justify-center">
                <Power className="w-5 h-5 text-muted-foreground" />
              </div>
              <div>
                <p className="font-medium leading-tight">Kill Switch Protection</p>
                <p className="text-sm text-muted-foreground leading-tight">
                  {splitTunnelingActive
                    ? 'Unavailable while split tunneling is active'
                    : settings.killSwitch
                      ? 'Enabled - Your connection is protected'
                      : 'Disabled - Enable for maximum protection'
                  }
                </p>
              </div>
            </div>
            <Switch
              checked={settings.killSwitch}
              disabled={splitTunnelingActive}
              onCheckedChange={handleKillSwitchToggle}
            />
          </div>
          {splitTunnelingActive && (
            <p className="mt-2 text-xs text-muted-foreground leading-snug">
              Disable split tunneling to use the kill switch.
            </p>
          )}
        </Card>

        {/* Always-On Kill Switch Toggle Card */}
        <Card className="p-4 mb-4">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-muted flex items-center justify-center">
                <Lock className="w-5 h-5 text-muted-foreground" />
              </div>
              <div>
                <p className="font-medium leading-tight">Always-On Kill Switch</p>
                <p className="text-sm text-muted-foreground leading-tight">
                  {settings.permanentKillSwitch ? 'Enabled - Blocks internet when not connected' : 'Disabled'}
                </p>
              </div>
            </div>
            <Switch
              checked={settings.permanentKillSwitch}
              disabled={!settings.killSwitch}
              onCheckedChange={async (checked) => {
                if (checked && isMac && window.electronAPI?.vpn?.isHelperInstalled) {
                  const installed = await window.electronAPI.vpn.isHelperInstalled();
                  if (!installed) {
                    setInstallingHelper(true);
                    try {
                      await window.electronAPI.vpn.installHelper();
                    } catch (err) {
                      console.error('Helper install failed:', err);
                      setInstallingHelper(false);
                      return;
                    }
                    setInstallingHelper(false);
                  }
                }
                updateSettings({ permanentKillSwitch: checked });
              }}
            />
          </div>
          <p className="text-xs text-muted-foreground leading-snug">
            Block all internet whenever the VPN is not connected. Protection persists across disconnect and restart. Requires Kill Switch to be enabled.
          </p>
          {isMac && (
            <p className="text-xs text-muted-foreground mt-2 leading-snug">
              On macOS, this requires a helper daemon to manage firewall rules. You will be prompted for your password when enabling.
            </p>
          )}
          {installingHelper && (
            <div className="mt-2 flex items-center gap-2">
              <Download className="w-4 h-4 text-muted-foreground animate-pulse" />
              <p className="text-xs text-muted-foreground">Installing helper daemon...</p>
            </div>
          )}
          {settings.permanentKillSwitch && (
            <p className="text-xs text-amber-500 mt-2 leading-snug">
              Internet requires an active VPN connection. Explicitly disable to restore normal internet access.
            </p>
          )}
        </Card>

        {/* Emergency Reset */}
        {window.electronAPI?.vpn && (
          <Card className="p-4 mt-4 border-red-500/30 bg-red-500/5">
            <div className="flex items-center gap-3 mb-3">
              <div className="w-10 h-10 rounded-lg bg-red-500/10 flex items-center justify-center">
                <AlertTriangle className="w-5 h-5 text-red-400" />
              </div>
              <div>
                <p className="font-medium leading-tight text-red-400">Emergency Reset</p>
                <p className="text-sm text-muted-foreground leading-tight">
                  Flush all firewall rules and restore internet access
                </p>
              </div>
            </div>
            <p className="text-xs text-muted-foreground leading-snug mb-3">
              Clears all kill switch firewall rules, removes persistent block, and disconnects VPN. Use this if you are unable to access the internet after a VPN failure.
            </p>
            <button
              onClick={async () => {
                setResetting(true);
                try {
                  await window.electronAPI!.vpn.emergencyReset();
                  alert('Emergency reset complete. All firewall rules have been cleared.');
                } catch (err) {
                  alert('Emergency reset failed: ' + err);
                } finally {
                  setResetting(false);
                }
              }}
              disabled={resetting}
              className="w-full py-2 px-4 rounded-lg border border-red-500/50 bg-red-500/10 text-red-400 hover:bg-red-500/20 transition-colors text-sm font-medium"
            >
              {resetting ? 'Resetting...' : 'Emergency Reset'}
            </button>
          </Card>
        )}
      </div>
    </div>
  );
};

export default SettingsKillSwitch;