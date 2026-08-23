import React from 'react';
import { ShieldAlert } from 'lucide-react';

interface BlockedActionDialogProps {
  open: boolean;
  title: string;
  message: string;
  onDismiss: () => void;
}

/** Modal shown when an account action (sign out, delete account) is blocked because the VPN is connected. */
const BlockedActionDialog: React.FC<BlockedActionDialogProps> = ({ open, title, message, onDismiss }) => {
  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div className="bg-card border border-border rounded-xl p-6 max-w-sm mx-4 shadow-lg">
        <div className="flex items-center gap-3 mb-3">
          <ShieldAlert className="w-5 h-5 text-amber-500" />
          <h3 className="font-display text-lg tracking-wide text-foreground">{title}</h3>
        </div>
        <p className="text-sm text-muted-foreground mb-4">{message}</p>
        <button
          onClick={onDismiss}
          className="w-full px-4 py-2 bg-muted text-muted-foreground rounded-lg text-sm font-medium hover:bg-muted/80 transition-colors"
        >
          OK
        </button>
      </div>
    </div>
  );
};

export default BlockedActionDialog;
