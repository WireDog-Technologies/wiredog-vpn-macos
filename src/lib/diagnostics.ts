// Verbose Diagnostic Mode (VDM): typed access to the main process's diagnostics IPC (electron/diagnostics.js).

export interface DiagnosticsState {
  enabled: boolean;
  enabledAt: number | null;
  autoOffAt: number | null;
  filePath: string | null;
}

interface DiagnosticsApi {
  getState: () => Promise<DiagnosticsState>;
  setEnabled: (enabled: boolean) => Promise<DiagnosticsState>;
}

/** The diagnostics API, or null outside the Electron app. */
export function diagnosticsApi(): DiagnosticsApi | null {
  return (window as unknown as { electronAPI?: { diagnostics?: DiagnosticsApi } }).electronAPI?.diagnostics ?? null;
}
