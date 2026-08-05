import "./range.css";

import { Link, Outlet, useLocation, useNavigate, useOutletContext, useParams } from "react-router-dom";

import { api } from "../../api/client";
import { CyberGridBackground } from "../../components/backgrounds";
import {
  CyberCard,
  EmptyState,
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
import { usePolledAsync } from "./use-range-polling";
import type { Exercise } from "../../api/types";

export interface RangeContext {
  range: Exercise;
  lifecycle: RangeLifecycle;
  /** Refetch the range. Every mutating child calls this so the header advances too. */
  reloadRange: () => Promise<Exercise | null>;
  /** True while the layout is polling because the server is mid-operation. */
  polling: boolean;
}

/** Typed access to the loaded range from any child route. */
export function useRange(): RangeContext {
  return useOutletContext<RangeContext>();
}

const TABS: readonly { id: string; label: string; segment: string }[] = [
  { id: "overview", label: "Overview", segment: "" },
  { id: "deployment", label: "Deployment", segment: "deployment" },
  { id: "competition", label: "Competition", segment: "competition" },
  { id: "teams", label: "Teams", segment: "teams" },
  { id: "scoreboard", label: "Scoreboard", segment: "scoreboard" },
  { id: "timeline", label: "Timeline", segment: "timeline" },
  { id: "lifecycle", label: "Reset & destroy", segment: "lifecycle" },
];

/**
 * Shell for every single-range surface: loads the range ONCE for all seven tabs, renders the
 * identity header, and owns the lifecycle poll.
 *
 * Polling lives here rather than on the deployment page so the phase badge advances no matter which
 * tab the operator is on — a destroy started from the lifecycle tab must be visible from the
 * overview without a manual refresh.
 */
export function RangeLayout() {
  const { rangeId = "" } = useParams();
  const navigate = useNavigate();
  const location = useLocation();

  const state = usePolledAsync(() => api.getExercise(rangeId), [rangeId], {
    shouldPoll: (range) =>
      range !== null && isInFlight(rangeLifecycle(range.lifecycle_state).phase),
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

  const lifecycle = rangeLifecycle(range.lifecycle_state);
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
            {/* The precise server-recorded state, always shown next to the product phase so the
                projection in range-lifecycle.ts is never something the operator has to take on
                trust. */}
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
          {!lifecycle.known && (
            <p className="rng-sub" role="alert">
              This build does not recognize the recorded state{" "}
              <code>{lifecycle.recorded}</code>. No lifecycle actions are offered until it is
              understood.
            </p>
          )}
        </div>
        <div className="rng-meta">
          <span title={range.id}>range {shortId(range.id)}</span>
          <span title={range.environment_version_id}>
            version {shortId(range.environment_version_id)}
          </span>
          <span>
            {range.team_count} team{range.team_count === 1 ? "" : "s"}
          </span>
        </div>
      </div>

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
