import React from 'react';
import { Minus, X, Maximize2, Minimize2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useElectron } from '@/context/ElectronContext';
import Logo from "../../assets/logos/wiredog-minimal-navy_1024x1024.png";
import TextLogo from "../../assets/logos/wiredog_text_logo_1024.png";

const TitleBar: React.FC = () => {
  const {
    minimizeWindow,
    maximizeWindow,
    closeWindow,
    isWindowMaximized,
    isMac,
    isElectron
  } = useElectron();

  const [isMaximized, setIsMaximized] = React.useState(false);

  React.useEffect(() => {
    const checkMaximized = async () => {
      if (isElectron && !isMac) {
        const maximized = await isWindowMaximized();
        setIsMaximized(maximized);
      }
    };
    checkMaximized();
  }, [isElectron, isMac, isWindowMaximized]);

  // Don't render title bar in web mode
  if (!isElectron) {
    return null;
  }

  // macOS: Render a drag region with centered title only.
  // Native traffic lights are positioned by Electron's titleBarStyle: 'hiddenInset'.
  if (isMac) {
    return (
      <div
        className="flex items-center justify-center h-7 bg-background border-b border-border select-none"
        style={{ WebkitAppRegion: 'drag' } as React.CSSProperties}
      >
        <div className="flex items-center justify-center gap-1">
          <div className="w-5 h-5 rounded flex items-center justify-center">
            <img
              src={Logo}
              alt="WireDog VPN Logo"
              className="w-4 h-4 object-contain"
            />
          </div>
          <img
            src={TextLogo}
            alt="WireDog VPN"
            className="w-20 h-auto"
          />
        </div>
      </div>
    );
  }

  // Windows: Custom window controls
  const handleMinimize = async () => {
    try {
      await minimizeWindow();
    } catch (error) {
      console.error('Failed to minimize window:', error);
    }
  };

  const handleMaximize = async () => {
    try {
      await maximizeWindow();
      setIsMaximized(!isMaximized);
    } catch (error) {
      console.error('Failed to maximize window:', error);
    }
  };

  const handleClose = async () => {
    try {
      await closeWindow();
    } catch (error) {
      console.error('Failed to close window:', error);
    }
  };

  return (
    <div className="relative flex items-center justify-center h-8 bg-background border-b border-border select-none" style={{ WebkitAppRegion: 'drag' } as React.CSSProperties}>
      {/* App title with logo - centered */}
      <div className="flex items-center justify-center gap-1">
        <div className="w-6 h-6 rounded flex items-center justify-center">
            <img
              src={Logo}
              alt="WireDog VPN Logo"
              className="w-5 h-5 object-contain"
            />
        </div>
            <img
              src={TextLogo}
              alt="WireDog VPN Logo"
              className="w-20 h-auto"
            />
      </div>

      {/* Window controls */}
      <div className="absolute right-0 flex items-center" style={{ WebkitAppRegion: 'no-drag' } as React.CSSProperties}>
        <Button
          variant="ghost"
          size="sm"
          onClick={handleMinimize}
          className="h-8 w-10 rounded-none hover:bg-accent/50 focus-visible:ring-0 focus-visible:ring-offset-0"
        >
          <Minus className="h-3 w-3" />
        </Button>

        <Button
          variant="ghost"
          size="sm"
          onClick={handleMaximize}
          className="h-8 w-10 rounded-none hover:bg-accent/50 focus-visible:ring-0 focus-visible:ring-offset-0"
        >
          {isMaximized ? (
            <Minimize2 className="h-3 w-3" />
          ) : (
            <Maximize2 className="h-3 w-3" />
          )}
        </Button>

        <Button
          variant="ghost"
          size="sm"
          onClick={handleClose}
          className="h-8 w-10 rounded-none hover:bg-red-500/20 hover:text-red-600 focus-visible:ring-0 focus-visible:ring-offset-0"
        >
          <X className="h-3 w-3" />
        </Button>
      </div>
    </div>
  );
};

export default TitleBar;