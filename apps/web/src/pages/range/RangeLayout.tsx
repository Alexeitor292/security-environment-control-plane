import "./range.css";

import { Link, Outlet, useLocation, useNavigate, useOutletContext, useParams } from "react-router-dom";

import { api } from "../../api/client";
import { CyberGridBackground } from "../../components/backgrounds";
import {
  CyberCard,
  EmptyState,
  SafetyNotice,
  Skeleton,
  StatusBadge,
  TabRail,
  shortId,
  type TabItem,
} from "../../components/ui";
import {
  RANGE_PHASE_HELP,
  RANGE_PHASE_LABEL,
  isInFlight,
  rangeLifecycle,
  type RangeLifecycle,
} from "./range-lifecycle";
import { RECOVERY_REQUIRED_NOTE, operationInFlight } from "./range-view";
import { usePolledAsync } from "./use-range-polling";
import type { Range } from "../../api/range-types";

export interface RangeContext {
  range: Range;
  lifecycle: RangeLifecycle;
  /** Refetch the range. Every mutating child calls this so the header advances too. */
  reloadRange: () => Promise<Range | null>;
  /** True while the layout is polling because an operation is in flight. */
  polling: boolean;
}

/** Typed access to the loaded range from any child route. */
export function useRange(): RangeContext {
  return useOutletContext<RangeContext>();
}

/**
 * The seven original tabs, then the four Proxmox provider surfaces.
 *
 * The Proxmox tabs sit after the lifecycle tab and follow the flow order — placement, then the
 * compiled topology, then plan and apply, then verification, with teardown last. They are present
 * on every range rather than gated on `range.provider`, because no range template on main declares
 * a Proxmox provider (the shipped catalog is `local_docker` only), and a tab that can never appear
 * is a surface nobody can review. Each Proxmox page opens by stating the range's recorded provider
 * and whether the page applies to it — see `ProxmoxSection`.
 */
const TABS: readonly { id: string; label: string; segment: string }[] = [
  { id: "overview", label: "Overview", segment: "" },
  { id: "deployment", label: "Deployment", segment: "deployment" },
  { id: "competition", label: "Competition", segment: "competition" },
  { id: "teams", label: "Teams", segment: "teams" },
  { id: "scoreboard", label: "Scoreboard", segment: "scoreboard" },
  { id: "timeline", label: "Timeline", segment: "timeline" },
  { id: "lifecycle", label: "Reset & destroy", segment: "lifecycle" },
  { id: "placement", label: "Placement", segment: "placement" },
  { id: "topology", label: "Topology", segment: "topology" },
  { id: "plan", label: "Plan & apply", segment: "plan" },
  { id: "verification", label: "Verification", segment: "verification" },
  { id: "teardown", label: "Teardown", segment: "teardown" },
];

/**
 * Shell for every single-range surface: loads the range once for all tabs, renders the identity
 * header, and owns the poll.
 *
 * Polling is decided from the RANGE ITSELF — an in-flight operation, or a transitional state — so
 * a destroy started on the lifecycle tab keeps advancing while the operator reads the overview.
 * `GET /ranges/{id}` is the contract's designated polling endpoint and the only thing polled here.
 */
export function RangeLayout() {
  const { rangeId = "" } = useParams();
  const navigate = useNavigate();
  const location = useLocation();

  const state = usePolledAsync(() => api.getRange(rangeId), [rangeId], {
    intervalMs: 2000,
    shouldPoll: (range) =>
      range !== null &&
      (operationInFlight(range.current_operation) ||
        isInFlight(rangeLifecycle(range.state).phase)),
  });

  const range = state.data;

  // The active tab comes from the URL, so a deep link and a click select identically.
  const tail = location.pathname.split(`/ranges/${rangeId}`)[1] ?? "";
  const segment = tail.replace(/^\//, "").split("/")[0] ?? "";
  const active = TABS.find((t) => t.segment === segment)?.id ?? "overview";

  if (state.loading && range === null) {
    return (
      <div className="rng">
        <CyberCard>
          <Skeleton lines={5} />
        </CyberCard>
      </div>
    );
  }

  if (range === null) {
    return (
      <div className="rng">
        <CyberCard>
          <EmptyState title="Range unavailable">
            This range could not be loaded. It may have been destroyed, or you may not have access
            to it. <Link to="/ranges">Back to the catalog</Link>.
          </EmptyState>
        </CyberCard>
      </div>
    );
  }

  const lifecycle = rangeLifecycle(range.state);
  const tabs: TabItem[] = TABS.map((t) => ({ id: t.id, label: t.label }));

  const context: RangeContext = {
    range,
    lifecycle,
    reloadRange: state.reload,
    polling: state.polling,
  };

  return (
    <div className="rng">
      <CyberGridBackground intensity="subtle" className="rng-bg" />

      <div className="rng-head">
        <div>
          <h1>{range.name}</h1>
          <div className="rng-identity">
            <StatusBadge state={lifecycle.phase} domain="range" />
            <span>{RANGE_PHASE_LABEL[lifecycle.phase]}</span>
            {/* The raw server-recorded state, always beside the label. The range API emits these
                natively so this is not a projection today — it stays because the untranslated
                value next to the rendered one is what makes the rendering checkable. */}
            <span className="rng-recorded" title="State recorded by the control plane">
              recorded: {lifecycle.recorded}
            </span>
            {state.polling && (
              <span className="rng-live" role="status">
                <span className="rng-live-dot" aria-hidden="true" />
                Live — {state.refreshCount} server update
                {state.refreshCount === 1 ? "" : "s"}
              </span>
            )}
          </div>
          <p className="rng-sub">{RANGE_PHASE_HELP[lifecycle.phase]}</p>
          {/* The server's own explanation of the state, when it gave one. */}
          {range.state_reason !== null && range.state_reason !== "" && (
            <p className="rng-sub">{range.state_reason}</p>
          )}
          {!lifecycle.known && (
            <p className="rng-sub" role="alert">
              This build does not recognize the recorded state <code>{lifecycle.recorded}</code>.
              No lifecycle actions are offered until it is understood.
            </p>
          )}
        </div>
        <div className="rng-meta">
          <span title={range.id}>range {shortId(range.id)}</span>
          <span>{range.template_name}</span>
          <span className="mono">{range.provider}</span>
        </div>
      </div>

      {/* Rendered above the tabs, so it is present on EVERY range surface rather than only the one
          that happened to trigger it. An unprovable outcome visible on one tab is one an operator
          can navigate away from. */}
      {lifecycle.phase === "recovery_required" && lifecycle.known && (
        <SafetyNotice role="alert" tone="warn">
          {RECOVERY_REQUIRED_NOTE}
        </SafetyNotice>
      )}

      <TabRail
        tabs={tabs}
        active={active}
        idBase="range"
        aria-label="Range sections"
        onSelect={(id) => {
          const tab = TABS.find((t) => t.id === id);
          if (tab) navigate(`/ranges/${rangeId}${tab.segment ? `/${tab.segment}` : ""}`);
        }}
      />

      <Outlet context={context} />
    </div>
  );
}
