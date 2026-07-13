import "./shell.css";

import clsx from "clsx";
import { ChevronsLeft, ChevronsRight } from "lucide-react";
import { useEffect, useRef, useState, type ReactNode } from "react";

import type { Principal, ProviderCapabilities } from "../../api/types";
import { Sidebar } from "./Sidebar";
import { TopStatusBar } from "./TopStatusBar";

export interface AppShellProps {
  principal: Principal | null;
  capabilities: ProviderCapabilities | null;
  children: ReactNode;
  /** Sign out of the current session (ADR-018). */
  onLogout?: () => void;
}

/** Cyber command application shell: persistent sidebar (collapsible on
 *  desktop, overlay drawer on small screens), top status bar with the
 *  development disclosure, and the main content viewport. */
export function AppShell({ principal, capabilities, children, onLogout }: AppShellProps) {
  const [collapsed, setCollapsed] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const sidebarRef = useRef<HTMLElement>(null);
  const menuButtonRef = useRef<HTMLButtonElement>(null);
  const drawerWasOpen = useRef(false);

  useEffect(() => {
    if (!drawerOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setDrawerOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [drawerOpen]);

  // Focus management + background scroll lock for the mobile drawer: focus
  // moves into the drawer on open and back to the menu button on close.
  useEffect(() => {
    if (drawerOpen) {
      drawerWasOpen.current = true;
      document.body.style.overflow = "hidden";
      sidebarRef.current?.focus();
    } else {
      document.body.style.overflow = "";
      if (drawerWasOpen.current) {
        drawerWasOpen.current = false;
        menuButtonRef.current?.focus();
      }
    }
    return () => {
      document.body.style.overflow = "";
    };
  }, [drawerOpen]);

  return (
    <div
      className={clsx(
        "shell",
        collapsed && "shell--collapsed",
        drawerOpen && "shell--drawer-open",
      )}
    >
      <a className="shell-skip" href="#shell-main">
        Skip to content
      </a>
      <aside
        id="shell-sidebar"
        className="shell-sidebar"
        ref={sidebarRef}
        tabIndex={-1}
      >
        <Sidebar
          principal={principal}
          collapsed={drawerOpen ? false : collapsed}
          onNavigate={() => setDrawerOpen(false)}
          onLogout={onLogout}
        />
        <button
          type="button"
          className="shell-collapse"
          onClick={() => setCollapsed((c) => !c)}
          aria-label={collapsed ? "Expand navigation" : "Collapse navigation"}
          aria-expanded={!collapsed}
          aria-controls="shell-sidebar"
        >
          {collapsed ? (
            <ChevronsRight size={16} aria-hidden />
          ) : (
            <ChevronsLeft size={16} aria-hidden />
          )}
        </button>
      </aside>
      {drawerOpen && (
        <div
          className="shell-backdrop"
          aria-hidden
          onClick={() => setDrawerOpen(false)}
        />
      )}
      <div className="shell-body">
        <TopStatusBar
          capabilities={capabilities}
          onMenuClick={() => setDrawerOpen(true)}
          drawerOpen={drawerOpen}
          menuButtonRef={menuButtonRef}
        />
        <main id="shell-main" className="content shell-main" tabIndex={-1}>
          {children}
        </main>
      </div>
    </div>
  );
}
