import React, { useEffect, useState } from 'react';
import { ExternalLink, CheckCircle2, ChevronDown } from 'lucide-react';
import { useExtensionApproval } from '@/hooks/useExtensionApproval';
import wireDogMark from '@/assets/logos/wiredog-minimal-navy_1024x1024.png';

/**
 * Blocking in-app card guiding the user through the one-time macOS Network
 * Extension approval step (System Settings → General → Login Items &
 * Extensions → Network Extensions). This step is a hard macOS requirement —
 * see VPN_CONNECTION_DEBUG.md — the app cannot skip or automate it, only make
 * it unmissable and confirm completion instead of leaving the user to guess.
 */
const ExtensionApprovalDialog: React.FC = () => {
  const { status, openNetworkExtensions, clearActivated } = useExtensionApproval();
  const [showTrouble, setShowTrouble] = useState(false);

  // Auto-dismiss the success state a couple seconds after it appears.
  useEffect(() => {
    if (status !== 'activated') return;
    const timer = setTimeout(clearActivated, 2500);
    return () => clearTimeout(timer);
  }, [status, clearActivated]);

  if (status === 'idle') return null;

  const activated = status === 'activated';

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/70 backdrop-blur-sm">
      <div className="w-[440px] rounded-xl border bg-card text-card-foreground shadow-2xl p-8">
        <div className="flex flex-col items-center text-center gap-5">
          <div
            className={`w-14 h-14 rounded-full flex items-center justify-center transition-colors ${
              activated ? 'bg-green-500/10' : 'bg-primary/10'
            }`}
          >
            {activated ? (
              <CheckCircle2 className="w-7 h-7 text-green-500" />
            ) : (
              <img src={wireDogMark} alt="" className="w-8 h-8 object-contain" />
            )}
          </div>

          {activated ? (
            <>
              <h2 className="font-display text-xl tracking-wide text-foreground">
                You're all set
              </h2>
              <p className="text-muted-foreground text-sm max-w-sm">
                Network extension approved — you can connect now.
              </p>
            </>
          ) : (
            <>
              <h2 className="font-display text-xl tracking-wide text-foreground">
                Enable Network Extension to Continue
              </h2>
              <p className="text-muted-foreground text-sm max-w-sm">
                macOS requires a one-time approval before WireDog VPN can connect. This
                only needs to be done once.
              </p>

              <div className="w-full rounded-lg border bg-muted/30 p-4 text-left">
                <ol className="space-y-3">
                  <Step n={1}>
                    Click <span className="font-medium text-foreground">Open Network Extensions</span> below.
                  </Step>
                  <Step n={2}>
                    Turn on the <span className="font-medium text-foreground">WireDog Tunnel</span> switch.
                  </Step>
                  <Step n={3}>
                    Authenticate with your password or Touch ID if asked.
                  </Step>
                </ol>
              </div>

              <button
                onClick={openNetworkExtensions}
                className="w-full px-6 py-2.5 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors font-medium flex items-center justify-center gap-2"
              >
                <ExternalLink className="w-4 h-4" />
                Open Network Extensions
              </button>

              <div className="w-full text-left">
                <button
                  onClick={() => setShowTrouble(!showTrouble)}
                  className="flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground transition-colors mx-auto"
                >
                  Didn't work?
                  <ChevronDown className={`w-4 h-4 transition-transform duration-200 ${showTrouble ? 'rotate-180' : ''}`} />
                </button>
                {showTrouble && (
                  <div className="mt-2 p-3 rounded-lg bg-muted/50 text-sm text-muted-foreground text-center">
                    Open System Settings manually, go to General → Login Items &amp;
                    Extensions → Network Extensions, and turn on WireDog Tunnel there.
                    Then come back here — WireDog will detect it automatically.
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

const Step: React.FC<{ n: number; children: React.ReactNode }> = ({ n, children }) => (
  <li className="flex items-start gap-3">
    <span className="flex-shrink-0 w-5 h-5 rounded-full bg-primary/15 text-primary text-xs font-semibold flex items-center justify-center mt-0.5">
      {n}
    </span>
    <span className="text-sm text-foreground/90">{children}</span>
  </li>
);

export default ExtensionApprovalDialog;
