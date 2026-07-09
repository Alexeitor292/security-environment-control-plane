import { NavLink, Outlet } from "react-router-dom";

import { api } from "./api/client";
import { useAsync } from "./hooks";

const NAV = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/templates", label: "Environment Library" },
  { to: "/templates/new", label: "Definition Editor" },
  { to: "/provider-targets", label: "Provider Targets" },
  { to: "/onboarding", label: "Target Onboarding" },
  { to: "/staging-labs", label: "Staging Labs" },
  { to: "/staging-deployments", label: "Staging Deployments" },
  { to: "/read-only-bootstrap", label: "RO Discovery Bootstrap" },
  { to: "/target-discovery", label: "Target Discovery" },
  { to: "/readonly-preflight", label: "Read-Only Preflight" },
  { to: "/resolver-activation", label: "Resolver Activation" },
  { to: "/audit", label: "Audit Log" },
];

export function App() {
  const me = useAsync(() => api.me(), []);

  return (
    <div className="layout">
      <aside className="sidebar">
        <h1>SECP</h1>
        <div className="sub">Security Environment Control Platform</div>
        <nav>
          {NAV.map((n) => (
            <NavLink key={n.to} to={n.to} end={n.end}>
              {n.label}
            </NavLink>
          ))}
        </nav>
        <div className="spacer" />
        {me.data && (
          <div className="muted mono" style={{ fontSize: 11 }}>
            {me.data.email}
          </div>
        )}
        <div className="dev-banner">
          Local development. Simulated execution only — no real infrastructure.
        </div>
      </aside>
      <main className="content">
        <Outlet />
      </main>
    </div>
  );
}
