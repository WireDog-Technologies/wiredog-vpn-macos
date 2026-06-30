import React, { useState, useEffect, useMemo } from 'react';
import { ChevronLeft, Search, Plus, Info } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { Card } from '@/components/ui/card';
import { useVPN } from '@/context/VPNContext';
import { SplitTunnelApp } from '@/types/vpn';
import { cn } from '@/lib/utils';
import ReconnectDialog from '@/components/ReconnectDialog';

const SplitTunnelApps: React.FC = () => {
  const navigate = useNavigate();
  const { settings, updateSettings, connection, reconnect } = useVPN();
  const splitTunneling = settings.splitTunneling;
  const isConnected = connection.status === 'connected';

  const [installedApps, setInstalledApps] = useState<SplitTunnelApp[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [showReconnectDialog, setShowReconnectDialog] = useState(false);

  // Load installed apps on mount
  useEffect(() => {
    const load = async () => {
      if (window.electronAPI?.getInstalledApps) {
        try {
          const apps = await window.electronAPI.getInstalledApps();
          setInstalledApps(apps);
        } catch (err) {
          console.error('Failed to load installed apps:', err);
        }
      }
      setIsLoading(false);
    };
    load();
  }, []);

  const selectedPaths = useMemo(
    () => new Set(splitTunneling.apps.map(a => a.exePath.toLowerCase())),
    [splitTunneling.apps]
  );

  const isSelected = (app: SplitTunnelApp) => selectedPaths.has(app.exePath.toLowerCase());

  const toggleApp = (app: SplitTunnelApp) => {
    const path = app.exePath.toLowerCase();
    let newApps: SplitTunnelApp[];
    if (selectedPaths.has(path)) {
      newApps = splitTunneling.apps.filter(a => a.exePath.toLowerCase() !== path);
    } else {
      newApps = [...splitTunneling.apps, app];
    }
    updateSettings({
      splitTunneling: { ...splitTunneling, apps: newApps },
    });
    if (isConnected && splitTunneling.enabled) setShowReconnectDialog(true);
  };

  const handleBrowse = async () => {
    if (!window.electronAPI?.browseForApp) return;
    const app = await window.electronAPI.browseForApp();
    if (app && !selectedPaths.has(app.exePath.toLowerCase())) {
      updateSettings({
        splitTunneling: {
          ...splitTunneling,
          apps: [...splitTunneling.apps, app],
        },
      });
      if (isConnected && splitTunneling.enabled) setShowReconnectDialog(true);
    }
  };

  // Filter and sort: selected apps first, then alphabetical
  const filteredApps = useMemo(() => {
    const query = searchQuery.toLowerCase();

    // Merge installed apps with any manually-added selected apps not in the installed list
    const installedPaths = new Set(installedApps.map(a => a.exePath.toLowerCase()));
    const manualApps = splitTunneling.apps.filter(a => !installedPaths.has(a.exePath.toLowerCase()));
    const allApps = [...installedApps, ...manualApps];

    const filtered = query
      ? allApps.filter(a =>
          a.name.toLowerCase().includes(query) ||
          (a.bundleId ?? '').toLowerCase().includes(query) ||
          a.exePath.toLowerCase().includes(query)
        )
      : allApps;

    // Sort: selected first, then alphabetical
    return filtered.sort((a, b) => {
      const aSelected = selectedPaths.has(a.exePath.toLowerCase());
      const bSelected = selectedPaths.has(b.exePath.toLowerCase());
      if (aSelected && !bSelected) return -1;
      if (!aSelected && bSelected) return 1;
      return a.name.localeCompare(b.name);
    });
  }, [installedApps, splitTunneling.apps, selectedPaths, searchQuery]);

  return (
    <div className="h-full p-6 star-pattern overflow-auto">
      {/* Back Button */}
      <button
        onClick={() => navigate('/settings/split-tunneling')}
        className="text-muted-foreground hover:text-foreground transition-colors mb-4 p-0"
      >
        <ChevronLeft className="w-8 h-8" />
      </button>

      <div className="max-w-2xl mx-auto">
        {/* Header */}
        <div className="mb-4">
          <h1 className="font-display text-4xl tracking-wider text-foreground mb-1">
            APPLICATIONS
          </h1>
          <p className="text-muted-foreground text-sm">
            {splitTunneling.mode === 'exclude'
              ? 'Selected apps will bypass the VPN'
              : 'Only selected apps will use the VPN'
            }
          </p>
        </div>

        <>
        {/* Search + Custom App */}
        <div className="flex gap-2 mb-4">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <input
              type="text"
              placeholder="Search applications..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-2 bg-muted/50 border border-border rounded-lg text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-connection-active"
            />
          </div>
          <button
            onClick={handleBrowse}
            title="Browse for an application not listed below"
            className="flex items-center gap-1.5 px-3 py-2 bg-muted/50 border border-border rounded-lg text-sm text-muted-foreground hover:bg-muted transition-colors whitespace-nowrap"
          >
            <Plus className="w-4 h-4" />
            <span>Custom App</span>
          </button>
        </div>

        {/* Selected count */}
        {splitTunneling.apps.length > 0 && (
          <p className="text-xs text-muted-foreground mb-2">
            {splitTunneling.apps.length} app{splitTunneling.apps.length !== 1 ? 's' : ''} selected
          </p>
        )}

        {/* App List */}
        <Card className="p-2 mb-4">
          {isLoading ? (
            <div className="flex items-center justify-center py-8">
              <p className="text-sm text-muted-foreground">Loading applications...</p>
            </div>
          ) : filteredApps.length === 0 ? (
            <div className="flex items-center justify-center py-8">
              <p className="text-sm text-muted-foreground">
                {searchQuery ? 'No apps match your search' : 'No applications found'}
              </p>
            </div>
          ) : (
            <div className="max-h-[400px] overflow-y-auto space-y-0.5">
              {filteredApps.map((app) => {
                const selected = isSelected(app);
                return (
                  <button
                    key={app.exePath}
                    onClick={() => toggleApp(app)}
                    className={cn(
                      "w-full flex items-center gap-3 px-3 py-2 rounded-lg transition-colors text-left",
                      selected
                        ? "bg-connection-active/10 border border-connection-active/30"
                        : "hover:bg-muted/50 border border-transparent"
                    )}
                  >
                    {/* App icon with letter fallback */}
                    <div className="w-8 h-8 flex-shrink-0 rounded-lg overflow-hidden flex items-center justify-center">
                      {app.icon ? (
                        <img src={app.icon} alt="" className="w-8 h-8 object-contain" />
                      ) : (
                        <div className="w-8 h-8 rounded-lg bg-muted flex items-center justify-center">
                          <span className="text-xs font-semibold text-muted-foreground uppercase">
                            {app.name.charAt(0)}
                          </span>
                        </div>
                      )}
                    </div>

                    {/* App name */}
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium truncate">{app.name}</p>
                    </div>

                    {/* Checkmark indicator */}
                    {selected && (
                      <div className="w-5 h-5 rounded-full bg-connection-active flex items-center justify-center flex-shrink-0">
                        <svg className="w-3 h-3 text-background" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                        </svg>
                      </div>
                    )}

                  </button>
                );
              })}
            </div>
          )}
        </Card>

        {/* WebKit incompatibility notice — shown when a WebKit-based app is selected */}
        {splitTunneling.apps.some(a =>
          a.bundleId === 'com.apple.Safari' || a.bundleId === 'com.apple.SafariTechnologyPreview'
        ) && (
          <div className="flex items-start gap-2 p-3 rounded-lg bg-amber-500/10 border border-amber-500/20">
            <Info className="w-4 h-4 text-amber-500 flex-shrink-0 mt-0.5" />
            <p className="text-xs text-amber-500 leading-snug">
              Safari cannot be split tunneled due to macOS system restrictions. WebKit-based apps bypass per-app network filtering at the OS level.
            </p>
          </div>
        )}
        </>
      </div>

      <ReconnectDialog
        open={showReconnectDialog}
        onReconnect={() => {
          setShowReconnectDialog(false);
          reconnect();
        }}
        onDismiss={() => setShowReconnectDialog(false)}
      />
    </div>
  );
};

export default SplitTunnelApps;
