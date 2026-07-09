import clsx from "clsx";
import {
  BookOpen,
  Boxes,
  CalendarClock,
  ClipboardList,
  FileCode,
  FlaskConical,
  Gauge,
  KeyRound,
  ListChecks,
  Lock,
  Puzzle,
  Rocket,
  ScrollText,
  Search,
  Settings,
  ShieldCheck,
  Target,
  Terminal,
  type LucideIcon,
} from "lucide-react";
import { NavLink } from "react-router-dom";

import type { Principal } from "../../api/types";
import { principalDisplay } from "./identity";
import { NAV_GROUPS, type NavItem } from "./nav";
import { SecpMark } from "./SecpMark";

const ICONS: Record<string, LucideIcon> = {
  overview: Gauge,
  library: BookOpen,
  "definition-editor": FileCode,
  exercises: FlaskConical,
  targets: Target,
  onboarding: ClipboardList,
  discovery: Search,
  "staging-labs": Boxes,
  "staging-deployments": Rocket,
  approvals: ShieldCheck,
  "readonly-preflight": KeyRound,
  "resolver-activation": Lock,
  "ro-bootstrap": Terminal,
  audit: ScrollText,
  jobs: ListChecks,
  schedules: CalendarClock,
  settings: Settings,
  plugins: Puzzle,
};

function NavEntry({
  item,
  collapsed,
  onNavigate,
}: {
  item: NavItem;
  collapsed: boolean;
  onNavigate?: () => void;
}) {
  const Icon = ICONS[item.id];
  // The label is always real text — visually hidden when collapsed — so
  // every entry keeps an accessible name without relying on aria-label.
  const label = (
    <span className={collapsed ? "shell-sr-only" : undefined}>{item.label}</span>
  );
  if (!item.href) {
    return (
      <span
        className="shell-nav__item shell-nav__item--unavailable"
        title={item.unavailableReason}
      >
        {Icon && <Icon size={16} aria-hidden />}
        {label}
        <span className="shell-sr-only"> — {item.unavailableReason}</span>
      </span>
    );
  }
  return (
    <NavLink
      to={item.href}
      end={item.end}
      onClick={onNavigate}
      title={collapsed ? item.label : undefined}
      className={({ isActive }) =>
        clsx("shell-nav__item", isActive && "shell-nav__item--active")
      }
    >
      {Icon && <Icon size={16} aria-hidden />}
      {label}
    </NavLink>
  );
}

export interface SidebarProps {
  principal: Principal | null;
  collapsed: boolean;
  /** Called when a nav link is followed (closes the mobile drawer). */
  onNavigate?: () => void;
}

export function Sidebar({ principal, collapsed, onNavigate }: SidebarProps) {
  const display = principal ? principalDisplay(principal) : null;
  return (
    <div className="shell-sidebar__inner">
      <div className="shell-brand">
        <SecpMark />
        {!collapsed && (
          <div>
            <div className="shell-brand__title">SECP</div>
            <div className="shell-brand__sub">
              Security Environment Control Plane
            </div>
          </div>
        )}
      </div>
      <nav className="shell-nav" aria-label="Primary">
        {NAV_GROUPS.map((group) => (
          <div className="shell-nav__group" key={group.id}>
            {group.label && !collapsed && (
              <div className="shell-nav__group-label">{group.label}</div>
            )}
            {group.items.map((item) => (
              <NavEntry
                key={item.id}
                item={item}
                collapsed={collapsed}
                onNavigate={onNavigate}
              />
            ))}
          </div>
        ))}
      </nav>
      <div className="shell-sidebar__spacer" />
      {display && (
        <div
          className="shell-user"
          title={collapsed ? `${display.name} · ${display.detail}` : undefined}
        >
          <span className="shell-user__avatar" aria-hidden>
            {display.initials}
          </span>
          <div className={clsx("shell-user__meta", collapsed && "shell-sr-only")}>
            <div className="shell-user__name">{display.name}</div>
            <div className="shell-user__detail mono">{display.detail}</div>
          </div>
        </div>
      )}
    </div>
  );
}
