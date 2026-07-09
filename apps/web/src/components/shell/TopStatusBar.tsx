import { Menu } from "lucide-react";
import type { RefObject } from "react";

import type { ProviderCapabilities } from "../../api/types";
import { DEV_DISCLOSURE, ENVIRONMENT_LABEL } from "./nav";

export interface TopStatusBarProps {
  /** Backend-reported capabilities; the milestone chip renders only when this
   *  real state is present — never a fabricated status. */
  capabilities: ProviderCapabilities | null;
  onMenuClick: () => void;
  drawerOpen: boolean;
  menuButtonRef: RefObject<HTMLButtonElement>;
}

export function TopStatusBar({
  capabilities,
  onMenuClick,
  drawerOpen,
  menuButtonRef,
}: TopStatusBarProps) {
  return (
    <header className="shell-topbar">
      <button
        type="button"
        ref={menuButtonRef}
        className="shell-topbar__menu"
        onClick={onMenuClick}
        aria-label="Open navigation"
        aria-expanded={drawerOpen}
        aria-controls="shell-sidebar"
      >
        <Menu size={18} aria-hidden />
      </button>
      <div className="shell-topbar__disclosure" role="note">
        <span className="shell-topbar__env">{ENVIRONMENT_LABEL}</span>
        <span className="shell-topbar__sep" aria-hidden>
          ·
        </span>
        <span className="shell-topbar__text" title={DEV_DISCLOSURE}>
          {DEV_DISCLOSURE}
        </span>
      </div>
      {capabilities && (
        <span className="shell-topbar__milestone mono">
          {capabilities.milestone}
          <span className="shell-topbar__sep" aria-hidden>
            ·
          </span>
          {capabilities.provisioning_enabled
            ? "provisioning enabled"
            : "provisioning disabled"}
        </span>
      )}
    </header>
  );
}
