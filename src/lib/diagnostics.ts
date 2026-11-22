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
  event: (name: string, data?: unknown) => void;
}

/** The diagnostics API, or null outside the Electron app. */
export function diagnosticsApi(): DiagnosticsApi | null {
  return (window as unknown as { electronAPI?: { diagnostics?: DiagnosticsApi } }).electronAPI?.diagnostics ?? null;
}

/**
 * Records what the screen did or showed (a click, a status it displayed, an error it put up, a backend
 * request). Fire-and-forget; the main process drops it unless VDM is on. Never pass passwords, codes,
 * tokens or account numbers.
 */
export function vdmEvent(name: string, data?: unknown): void {
  try {
    diagnosticsApi()?.event(name, data);
  } catch {
    // diagnostics must never break the screen
  }
}
