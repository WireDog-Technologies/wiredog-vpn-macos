// What the tunnel is in the middle of doing, and the progress text shown under the status while it does.
// The main process reports each step (see electron/vpn/index.js, _emitStage); the screen turns them into
// plain words so a slow connect never looks like a frozen one.

export type ConnectionTransition = 'connecting' | 'reconnecting' | 'switching' | 'disconnecting' | null;

export type ConnectStage =
  | 'waiting-for-previous'
  | 'preparing'
  | 'starting-tunnel'
  | 'waiting-for-server'
  | 'retrying'
  | 'disconnecting';

const TRANSITION_LABELS: Record<Exclude<ConnectionTransition, null>, string> = {
  connecting: 'CONNECTING...',
  reconnecting: 'RECONNECTING...',
  switching: 'SWITCHING...',
  disconnecting: 'DISCONNECTING...',
};

const STAGE_TEXT: Record<ConnectStage, string> = {
  'waiting-for-previous': 'Finishing the previous disconnect',
  preparing: 'Preparing a secure connection',
  'starting-tunnel': 'Starting the secure tunnel',
  'waiting-for-server': 'Waiting for the server to respond',
  retrying: 'No response yet, trying again',
  disconnecting: 'Closing the secure tunnel',
};

export function transitionLabel(transition: Exclude<ConnectionTransition, null>): string {
  return TRANSITION_LABELS[transition];
}

export function stageText(stage: ConnectStage | null): string | null {
  return stage ? STAGE_TEXT[stage] ?? null : null;
}

type ConnectStageListener = (data: { stage: ConnectStage | 'idle'; detail?: Record<string, unknown> }) => void;

/** Subscribes to the main process's progress events. Returns an unsubscribe function (a no-op outside Electron). */
export function onConnectStage(listener: ConnectStageListener): () => void {
  const vpn = (window as unknown as {
    electronAPI?: { vpn?: { onConnectStage?: (cb: ConnectStageListener) => () => void } };
  }).electronAPI?.vpn;
  return vpn?.onConnectStage ? vpn.onConnectStage(listener) : () => {};
}
