import "./dashboard.css";

import { ScrollText, Search, Target, Terminal } from "lucide-react";
import { Link } from "react-router-dom";

import { ApiClientError, api } from "../api/client";
import type {
  DiscoveryEnrollment,
  ExecutionTarget,
  Onboarding,
  ReadonlyPreflight,
  StagingDeployment,
  StagingLab,
} from "../api/types";
import { principalDisplay } from "../components/shell/identity";
import {
  ActionTile,
  CyberCard,
  CyberHeroPanel,
  DecisionCard,
  EmptyState,
  MetricTile,
  Skeleton,
  StatusBadge,
  resolveStatusTone,
} from "../components/ui";
import { useAsync, type AsyncState } from "../hooks";
import {
  NO_ACTIVITY_BODY,
  NO_ACTIVITY_TITLE,
  NO_DECISIONS_BODY,
  NO_DECISIONS_PARTIAL_TITLE,
  NO_DECISIONS_TITLE,
  activityRows,
  apiReachabilityView,
  boundariesMetric,
  decisionCountValue,
  deriveDecisionItems,
  labsMetric,
  latestPreflightView,
  targetsMetric,
  unavailableSourceCount,
  type SourceStatus,
} from "./overview";

/** A source's failure kind is preserved so the reachability tile can tell a
 *  responding-but-erroring API apart from a true network failure. */
type Failure = "none" | "http" | "network";
interface Tagged<T> {
  value: T | null;
  failure: Failure;
}

const tag = <T,>(p: Promise<T>): Promise<Tagged<T>> =>
  p
    .then((value) => ({ value, failure: "none" as const }))
    .catch((e) => ({
      value: null,
      failure:
        e instanceof ApiClientError && e.status === 0
          ? ("network" as const)
          : ("http" as const),
    }));

function hookStatus<T>(state: AsyncState<Tagged<T>>): SourceStatus {
  if (!state.data) return "loading";
  if (state.data.failure === "none") return "loaded";
  return state.data.failure === "network" ? "network_error" : "http_error";
}

function taggedStatus<T>(t: Tagged<T>): SourceStatus {
  if (t.failure === "none") return "loaded";
  return t.failure === "network" ? "network_error" : "http_error";
}

interface Fanout<T> {
  value: T[] | null;
  partial: boolean;
}

/** Per-target fan-out keeping fulfilled results: one unreachable target
 *  degrades that target only (partial flag), not the whole metric. */
function settleFanout<T>(results: PromiseSettledResult<T[]>[]): Fanout<T> {
  const fulfilled = results
    .filter((r): r is PromiseFulfilledResult<T[]> => r.status === "fulfilled")
    .flatMap((r) => r.value);
  const rejected = results.length - results.filter((r) => r.status === "fulfilled").length;
  if (rejected > 0 && rejected === results.length && results.length > 0) {
    return { value: null, partial: false };
  }
  return { value: fulfilled, partial: rejected > 0 };
}

interface InfraSummary {
  targets: Tagged<ExecutionTarget[]>;
  labs: Tagged<StagingLab[]>;
  deployments: Tagged<StagingDeployment[]>;
  discovery: Tagged<DiscoveryEnrollment[]>;
  onboardings: Fanout<Onboarding>;
  preflights: Fanout<ReadonlyPreflight>;
}

async function loadInfraSummary(): Promise<InfraSummary> {
  const [targets, labs, deployments, discovery] = await Promise.all([
    tag(api.listTargets()),
    tag(api.listStagingLabs()),
    tag(api.listStagingDeployments()),
    tag(api.listDiscoveryEnrollments()),
  ]);
  let onboardings: Fanout<Onboarding> = { value: null, partial: false };
  let preflights: Fanout<ReadonlyPreflight> = { value: null, partial: false };
  if (targets.value) {
    const [onbSettled, preSettled] = await Promise.all([
      Promise.allSettled(targets.value.map((t) => api.listOnboardings(t.id))),
      Promise.allSettled(
        targets.value.map((t) => api.listReadonlyPreflights(t.id)),
      ),
    ]);
    onboardings = settleFanout(onbSettled);
    preflights = settleFanout(preSettled);
  }
  return { targets, labs, deployments, discovery, onboardings, preflights };
}

function preflightTone(
  outcome: string | null,
  status: string | null,
): "default" | "ok" | "warn" | "danger" {
  const resolved = outcome
    ? resolveStatusTone(outcome, "preflight-outcome")
    : status
      ? resolveStatusTone(status, "preflight")
      : null;
  const tone = resolved?.tone;
  return tone === "ok" || tone === "warn" || tone === "danger" ? tone : "default";
}

export function Dashboard() {
  const me = useAsync(() => tag(api.me()), []);
  const capabilities = useAsync(() => tag(api.providerCapabilities()), []);
  const plugins = useAsync(() => tag(api.plugins()), []);
  const exercises = useAsync(() => tag(api.listExercises()), []);
  const auditEvents = useAsync(() => tag(api.audit()), []);
  const infra = useAsync(loadInfraSummary, []);

  const caps = capabilities.data?.value ?? null;
  const exerciseList = exercises.data?.value ?? null;
  const pluginList = plugins.data?.value ?? null;
  const auditList = auditEvents.data?.value ?? null;

  const decisionSources = {
    exercises: exerciseList,
    onboardings: infra.data?.onboardings.value ?? null,
    stagingLabs: infra.data?.labs.value ?? null,
    stagingDeployments: infra.data?.deployments.value ?? null,
    discoveryEnrollments: infra.data?.discovery.value ?? null,
  };
  const decisionsLoading =
    (exercises.loading && !exercises.data) || (infra.loading && !infra.data);
  const decisions = deriveDecisionItems(decisionSources);
  const unavailableSources = decisionsLoading
    ? 0
    : unavailableSourceCount(decisionSources);

  // Observed reachability across every request group this page issued.
  const infraStatuses: SourceStatus[] = infra.data
    ? [
        taggedStatus(infra.data.targets),
        taggedStatus(infra.data.labs),
        taggedStatus(infra.data.deployments),
        taggedStatus(infra.data.discovery),
      ]
    : ["loading", "loading", "loading", "loading"];
  const reach = apiReachabilityView([
    hookStatus(me),
    hookStatus(capabilities),
    hookStatus(plugins),
    hookStatus(exercises),
    hookStatus(auditEvents),
    ...infraStatuses,
  ]);

  const targetsView = targetsMetric(infra.data?.targets.value ?? null);
  const boundariesView = boundariesMetric(
    infra.data?.onboardings.value ?? null,
    infra.data?.onboardings.partial ?? false,
  );
  const labsView = labsMetric(infra.data?.labs.value ?? null);
  const preflightView = latestPreflightView(
    infra.data?.preflights.value ?? null,
    infra.data?.preflights.partial ?? false,
  );
  const feed = activityRows(auditList, 8);

  const heroName = me.data?.value ? principalDisplay(me.data.value).name : null;
  const today = new Date().toLocaleDateString(undefined, {
    weekday: "long",
    year: "numeric",
    month: "long",
    day: "numeric",
  });

  return (
    <div className="dash">
      <h1 className="ui-sr-only">Overview</h1>
      <div className="dash-hero-band">
        <CyberHeroPanel
          heading={heroName ? `Welcome back, ${heroName}` : "Overview"}
          subheading={today}
        >
          <div className="dash-hero-chips">
            {caps ? (
              <>
                <span className="dash-chip mono">{caps.milestone}</span>
                <span className="dash-chip">
                  {caps.provisioning_enabled
                    ? "provisioning enabled"
                    : "provisioning disabled"}
                </span>
                <span className="dash-chip">discovery: {caps.discovery}</span>
              </>
            ) : (
              <span className="dash-chip">
                {capabilities.loading
                  ? "checking provider capabilities…"
                  : "provider capabilities unavailable — no infrastructure claims are made"}
              </span>
            )}
          </div>
          {caps?.note && <p className="dash-hero-note">{caps.note}</p>}
        </CyberHeroPanel>
        <div className="dash-hero-side">
          <MetricTile
            label="Pending decisions"
            value={
              decisionsLoading
                ? "—"
                : decisionCountValue(decisions.length, unavailableSources)
            }
            detail={
              decisionsLoading
                ? "checking review queues…"
                : unavailableSources > 0
                  ? `${unavailableSources} decision sources unavailable`
                  : "across plans, onboardings, labs, and discovery"
            }
            tone={!decisionsLoading && decisions.length > 0 ? "warn" : "default"}
          />
          <MetricTile
            label="Control-plane API"
            value={reach.value}
            detail={reach.detail}
            tone={reach.tone}
          />
        </div>
      </div>

      <div className="dash-metrics">
        <MetricTile
          label="Targets"
          value={targetsView.value}
          detail={targetsView.detail}
        />
        <MetricTile
          label="Onboarded boundaries"
          value={boundariesView.value}
          detail={boundariesView.detail}
        />
        <MetricTile
          label="Staging labs"
          value={labsView.value}
          detail={labsView.detail}
        />
        <MetricTile
          label="Last preflight"
          value={preflightView.value}
          detail={preflightView.detail}
          tone={preflightTone(preflightView.outcome, preflightView.status)}
        />
      </div>

      <div className="dash-columns">
        <div className="dash-col">
          <CyberCard>
            <div className="dash-card-head">
              <h3>Needs your decision</h3>
              {unavailableSources > 0 && (
                <span className="dash-caveat">
                  {unavailableSources} sources unavailable
                </span>
              )}
            </div>
            {decisionsLoading ? (
              <Skeleton lines={3} />
            ) : decisions.length > 0 ? (
              <ul className="dash-decisions">
                {decisions.map((d) => (
                  <li key={d.id}>
                    <DecisionCard
                      chip={d.chip}
                      title={d.title}
                      meta={d.meta}
                      href={d.href}
                    />
                  </li>
                ))}
              </ul>
            ) : (
              <EmptyState
                title={
                  unavailableSources > 0
                    ? NO_DECISIONS_PARTIAL_TITLE
                    : NO_DECISIONS_TITLE
                }
              >
                {NO_DECISIONS_BODY}
              </EmptyState>
            )}
          </CyberCard>

          <CyberCard>
            <div className="dash-card-head">
              <h3>Recent activity</h3>
              <Link to="/audit">Audit log →</Link>
            </div>
            {auditEvents.loading && !auditEvents.data ? (
              <Skeleton lines={4} />
            ) : feed.length > 0 ? (
              <ul className="dash-feed">
                {feed.map((row) => (
                  <li className="dash-feed__row" key={row.id}>
                    <span className="dash-feed__time mono" title={row.createdAt}>
                      {row.time} UTC
                    </span>
                    <span className="dash-feed__action mono">{row.action}</span>
                    <span className="dash-feed__resource mono">
                      {row.resource} · {row.actor}
                    </span>
                    <StatusBadge state={row.outcome} domain="audit" />
                  </li>
                ))}
              </ul>
            ) : auditList === null && !auditEvents.loading ? (
              <p className="muted">Audit log unavailable.</p>
            ) : (
              <EmptyState title={NO_ACTIVITY_TITLE}>{NO_ACTIVITY_BODY}</EmptyState>
            )}
          </CyberCard>
        </div>

        <div className="dash-col">
          <CyberCard>
            <div className="dash-card-head">
              <h3>Exercises</h3>
              <Link to="/templates">Open library →</Link>
            </div>
            {exercises.loading && !exercises.data ? (
              <Skeleton lines={3} />
            ) : exerciseList && exerciseList.length > 0 ? (
              <ul className="dash-list">
                {exerciseList.map((e) => (
                  <li className="dash-exercise" key={e.id}>
                    <Link className="dash-exercise__name" to={`/exercises/${e.id}`}>
                      {e.name}
                    </Link>
                    <span className="dash-exercise__teams">
                      {e.team_count} teams
                    </span>
                    <StatusBadge state={e.lifecycle_state} domain="lifecycle" />
                  </li>
                ))}
              </ul>
            ) : exerciseList === null && !exercises.loading ? (
              <p className="muted">Exercises unavailable.</p>
            ) : (
              <EmptyState title="No exercises yet">
                Create an environment definition, then start an exercise.
              </EmptyState>
            )}
          </CyberCard>

          <CyberCard>
            <div className="dash-card-head">
              <h3>System posture</h3>
            </div>
            {plugins.loading && !plugins.data ? (
              <Skeleton lines={2} />
            ) : pluginList && pluginList.length > 0 ? (
              <ul className="dash-list">
                {pluginList.map((p) => (
                  <li className="dash-plugin" key={p.name}>
                    <span className="dash-plugin__name mono">
                      {p.name} v{p.version} · contract v{p.contract_version}
                      <span className="muted"> · {p.capabilities.join(", ")}</span>
                    </span>
                    {p.simulated && <span className="badge accent">simulated</span>}
                    <span className={`badge ${p.healthy ? "ok" : "danger"}`}>
                      {p.healthy ? "healthy" : "down"}
                    </span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="muted">
                {pluginList === null && !plugins.loading
                  ? "Plugin status unavailable."
                  : "No plugins registered."}
              </p>
            )}
          </CyberCard>
        </div>
      </div>

      <div className="dash-actions">
        <ActionTile
          icon={<Target size={16} />}
          title="Register target"
          description="Non-secret configuration only — no endpoint is contacted."
          href="/provider-targets"
        />
        <ActionTile
          icon={<Search size={16} />}
          title="Target discovery"
          description="Worker-owned read-only discovery enrollment."
          href="/target-discovery"
        />
        <ActionTile
          icon={<Terminal size={16} />}
          title="RO discovery bootstrap"
          description="Public-key bootstrap for read-only discovery."
          href="/read-only-bootstrap"
        />
        <ActionTile
          icon={<ScrollText size={16} />}
          title="Audit log"
          description="Append-only record of every decision and refusal."
          href="/audit"
        />
      </div>
    </div>
  );
}
