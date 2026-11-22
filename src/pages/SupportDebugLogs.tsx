import React, { useCallback, useEffect, useState } from 'react';
import { ChevronLeft, FileText, Server, Activity } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { Card } from '@/components/ui/card';
import { Switch } from '@/components/ui/switch';
import { useElectron } from '@/context/ElectronContext';
import { isMac } from '@/lib/platform';
import { diagnosticsApi, DiagnosticsState } from '@/lib/diagnostics';

function formatTime(ms: number | null): string {
  if (!ms) return '';
  return new Date(ms).toLocaleString(undefined, { weekday: 'short', hour: 'numeric', minute: '2-digit' });
}

const SupportDebugLogs: React.FC = () => {
  const navigate = useNavigate();
  const { openAppLogs, openServiceLogs } = useElectron();
  const diagnostics = diagnosticsApi();
  const [vdm, setVdm] = useState<DiagnosticsState | null>(null);
  const [vdmBusy, setVdmBusy] = useState(false);

  const refreshVdm = useCallback(() => {
    diagnostics?.getState().then(setVdm).catch(() => setVdm(null));
  }, [diagnostics]);

  useEffect(() => {
    refreshVdm();
    // VDM turns itself off after 24 h; keep the shown state honest while this screen stays open.
    const timer = setInterval(refreshVdm, 60_000);
    return () => clearInterval(timer);
  }, [refreshVdm]);

  const toggleVdm = async (enabled: boolean) => {
    if (!diagnostics) return;
    setVdmBusy(true);
    try {
      setVdm(await diagnostics.setEnabled(enabled));
    } catch (error) {
      console.error('Failed to change Verbose Diagnostic Mode:', error);
    } finally {
      setVdmBusy(false);
    }
  };

  return (
    <div className="h-full p-6 star-pattern overflow-auto">
      {/* Back Button */}
      <button
        onClick={() => navigate(-1)}
        className="text-muted-foreground hover:text-foreground transition-colors mb-4 p-0"
      >
        <ChevronLeft className="w-8 h-8" />
      </button>

      <div className="max-w-2xl mx-auto">
        {/* Header */}
        <div className="mb-6">
          <h1 className="font-display text-4xl tracking-wider text-foreground mb-2">
            DEBUG LOGS
          </h1>
          <p className="text-muted-foreground">
            View diagnostic information to help troubleshoot issues
          </p>
        </div>

        <div className="space-y-4">
          <Card
            className="p-6 cursor-pointer hover:bg-muted/50 transition-colors"
            onClick={openAppLogs}
          >
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 rounded-lg bg-muted flex items-center justify-center flex-shrink-0">
                <FileText className="w-6 h-6 text-muted-foreground" />
              </div>
              <div>
                <p className="font-medium text-lg">Application Logs</p>
                <p className="text-sm text-muted-foreground">
                  {isMac
                    ? 'Open ~/Library/Logs/wiredog-vpn-macos/ in Finder'
                    : 'Open the application log directory in your file explorer'
                  }
                </p>
              </div>
            </div>
          </Card>

          <Card
            className="p-6 cursor-pointer hover:bg-muted/50 transition-colors"
            onClick={openServiceLogs}
          >
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 rounded-lg bg-muted flex items-center justify-center flex-shrink-0">
                <Server className="w-6 h-6 text-muted-foreground" />
              </div>
              <div>
                <p className="font-medium text-lg">{isMac ? 'Helper Daemon Logs' : 'Service Logs'}</p>
                <p className="text-sm text-muted-foreground">
                  {isMac
                    ? 'Open /var/log/wiredog-helper.log in Console'
                    : 'Open the VPN service log directory in your file explorer'
                  }
                </p>
              </div>
            </div>
          </Card>

          {/* Verbose Diagnostic Mode */}
          {diagnostics && (
            <Card className="p-6">
              <div className="flex items-start gap-4">
                <div className="w-12 h-12 rounded-lg bg-muted flex items-center justify-center flex-shrink-0">
                  <Activity className="w-6 h-6 text-muted-foreground" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between gap-4">
                    <p className="font-medium text-lg">Verbose Diagnostic Mode (VDM)</p>
                    <Switch
                      checked={!!vdm?.enabled}
                      disabled={vdmBusy || !vdm}
                      onCheckedChange={toggleVdm}
                      aria-label="Verbose Diagnostic Mode"
                    />
                  </div>
                  <p className="text-sm text-muted-foreground mt-1">
                    Records detailed technical information about each connect, disconnect, and your
                    system/application behavior. Recommended only for advanced debugging/troubleshooting,
                    especially when in communications with the support team.
                  </p>
                  <p className="text-sm text-muted-foreground mt-2">
                    Your VDM log file can be found in the ~/Library/Logs/wiredog-vpn-macos/ folder.
                  </p>
                  {vdm?.enabled && (
                    <p className="text-sm text-amber-500 mt-2">
                      On since {formatTime(vdm.enabledAt)}. Turns off automatically {formatTime(vdm.autoOffAt)}.
                    </p>
                  )}
                </div>
              </div>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
};

export default SupportDebugLogs;
