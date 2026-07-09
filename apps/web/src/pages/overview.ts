// Overview command center — pure presentation logic.
//
// Every value shown on the dashboard derives from real backend responses.
// A failed source renders as an explicit unavailable state ("—" +
// truthful detail), never as a fabricated number or status.

import type {
  AuditEvent,
  DiscoveryEnrollment,
  ExecutionTarget,
  Exercise,
  Onboarding,
  ReadonlyPreflight,
  StagingDeployment,
  StagingLab,
} from "../api/types";

/** Truthful copy constants (rendered verbatim by the page). */
export const NO_DECISIONS_TITLE = "No pending decisions";
/** Scoped title when one or more decision sources failed to load. */
export const NO_DECISIONS_PARTIAL_TITLE =
  "No pending decisions in available sources";
export const NO_DECISIONS_BODY =
  "Items appear here when a deployment plan, onboarding, staging lab, deployment, or discovery plan is submitted for review. Approval never executes anything by itself.";
export const NO_ACTIVITY_TITLE = "No audit events recorded";
export const NO_ACTIVITY_BODY =
  "Every mutation and authorization decision — including refusals — is recorded to the append-only audit log.";
export const SOURCE_UNAVAILABLE_DETAIL = "source unavailable";
export const NOT_RECORDED = "Not recorded";

export interface MetricView {
  value: string;
  detail: string;
  unavailable?: boolean;
}

export function targetsMetric(targets: ExecutionTarget[] | null): MetricView {
  if (targets === null) {
    return { value: "—", detail: SOURCE_UNAVAILABLE_DETAIL, unavailable: true };
  }
  const active = targets.filter((t) => t.status === "active").length;
  const disabled = targets.length - active;
  const detail =
    disabled > 0 ? `${active} active · ${disabled} disabled` : `${active} active`;
  return { value: String(targets.length), detail: `registered · ${detail}` };
}

export const PARTIAL_DETAIL_SUFFIX = " · some targets unreachable";

export function boundariesMetric(
  onboardings: Onboarding[] | null,
  partial = false,
): MetricView {
  if (onboardings === null) {
    return { value: "—", detail: SOURCE_UNAVAILABLE_DETAIL, unavailable: true };
  }
  const active = onboardings.filter((o) => o.status === "active").length;
  return {
    value: String(active),
    detail: `active of ${onboardings.length} declared${partial ? PARTIAL_DETAIL_SUFFIX : ""}`,
  };
}

export function labsMetric(labs: StagingLab[] | null): MetricView {
  if (labs === null) {
    return { value: "—", detail: SOURCE_UNAVAILABLE_DETAIL, unavailable: true };
  }
  const approved = labs.filter((l) => l.status === "approved").length;
  const ready = labs.filter((l) => l.status === "simulated_ready").length;
  return {
    value: String(labs.length),
    detail: `${approved} approved · ${ready} simulated-ready`,
  };
}

export interface PreflightView {
  value: string;
  detail: string;
  outcome: string | null;
  /** The preflight's status — used for tone when no outcome exists yet. */
  status: string | null;
  unavailable?: boolean;
}

/** Latest preflight by created_at; outcome codes render via the closed
 *  preflight-outcome tone map, never re-worded. An outcome is dated by
 *  completed_at (when it was recorded); a pending preflight is dated by
 *  created_at and labeled "requested". */
export function latestPreflightView(
  preflights: ReadonlyPreflight[] | null,
  partial = false,
): PreflightView {
  if (preflights === null) {
    return {
      value: "—",
      detail: SOURCE_UNAVAILABLE_DETAIL,
      outcome: null,
      status: null,
      unavailable: true,
    };
  }
  if (preflights.length === 0) {
    return {
      value: NOT_RECORDED,
      detail: `no preflights queued yet${partial ? PARTIAL_DETAIL_SUFFIX : ""}`,
      outcome: null,
      status: null,
    };
  }
  const latest = [...preflights].sort((a, b) =>
    b.created_at.localeCompare(a.created_at),
  )[0];
  const outcome = latest.outcome_code;
  const detail = outcome
    ? `recorded ${(latest.completed_at ?? latest.created_at).slice(0, 10)}`
    : `requested ${latest.created_at.slice(0, 10)}`;
  return {
    value: outcome ? outcome.replace(/_/g, " ") : latest.status.replace(/_/g, " "),
    detail: `${detail}${partial ? PARTIAL_DETAIL_SUFFIX : ""}`,
    outcome: outcome ?? null,
    status: latest.status,
  };
}

export interface DecisionItem {
  id: string;
  chip: string;
  title: string;
  meta: string;
  href: string;
  createdAt: string;
}

export interface DecisionSources {
  exercises: Exercise[] | null;
  onboardings: Onboarding[] | null;
  stagingLabs: StagingLab[] | null;
  stagingDeployments: StagingDeployment[] | null;
  discoveryEnrollments: DiscoveryEnrollment[] | null;
}

/** Pending decisions, derived from the exact states each surface's own
 *  approval predicates use. Null sources contribute nothing (the page shows
 *  a separate truthful sources-unavailable caveat). */
export function deriveDecisionItems(sources: DecisionSources): DecisionItem[] {
  const items: DecisionItem[] = [];
  for (const e of sources.exercises ?? []) {
    if (e.lifecycle_state === "awaiting_approval") {
      items.push({
        id: `exercise:${e.id}`,
        chip: "PLAN",
        title: `Deployment plan — ${e.name}`,
        meta: `${e.team_count} teams · awaiting approval`,
        href: `/exercises/${e.id}/plan`,
        createdAt: e.created_at,
      });
    }
  }
  for (const o of sources.onboardings ?? []) {
    if (o.status === "ready_for_review") {
      items.push({
        id: `onboarding:${o.id}`,
        chip: "ONBOARDING",
        title: "Onboarding boundary — ready for review",
        meta: `${o.onboarding_mode.replace(/_/g, " ")} · ${o.isolation_model}`,
        href: "/onboarding",
        createdAt: o.created_at,
      });
    }
  }
  for (const l of sources.stagingLabs ?? []) {
    if (l.status === "awaiting_approval") {
      items.push({
        id: `staging-lab:${l.id}`,
        chip: "LAB",
        title: `Staging-lab plan v${l.plan_version} — ${l.display_name}`,
        meta: "simulation only · awaiting approval",
        href: "/staging-labs",
        createdAt: l.created_at,
      });
    }
  }
  for (const d of sources.stagingDeployments ?? []) {
    if (d.status === "awaiting_approval") {
      items.push({
        id: `staging-deployment:${d.id}`,
        chip: "DEPLOYMENT",
        title: `Deployment plan v${d.plan_version} — ${d.display_name}`,
        meta: "awaiting approval",
        href: "/staging-deployments",
        createdAt: d.created_at,
      });
    }
  }
  for (const de of sources.discoveryEnrollments ?? []) {
    if (de.status === "plan_ready") {
      items.push({
        id: `discovery:${de.id}`,
        chip: "DISCOVERY",
        title: `Candidate plan — ${de.display_name}`,
        meta: "read-only discovery · plan ready",
        href: "/target-discovery",
        createdAt: de.created_at,
      });
    }
  }
  return items.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

/** Count sources that failed to load (for the truthful caveat line). */
export function unavailableSourceCount(sources: DecisionSources): number {
  return [
    sources.exercises,
    sources.onboardings,
    sources.stagingLabs,
    sources.stagingDeployments,
    sources.discoveryEnrollments,
  ].filter((s) => s === null).length;
}

export const DECISION_SOURCE_TOTAL = 5;

/** A zero is a claim that every review queue was checked and found empty —
 *  it may only render when every source loaded. With any source unavailable,
 *  a zero count renders as "—"; a positive count is real regardless. */
export function decisionCountValue(
  count: number,
  unavailableSources: number,
): string {
  if (count > 0) return String(count);
  return unavailableSources > 0 ? "—" : "0";
}

export interface ActivityRow {
  id: string;
  /** HH:MM:SS in UTC, derived from the recorded ISO timestamp. */
  time: string;
  /** Full recorded ISO timestamp (for tooltips/disambiguation). */
  createdAt: string;
  action: string;
  resource: string;
  actor: string;
  outcome: string;
}

/** Per-source request result used by the reachability view. */
export type SourceStatus = "loading" | "loaded" | "http_error" | "network_error";

export interface ReachabilityView {
  value: string;
  detail: string;
  tone: "default" | "ok" | "danger";
}

/** Observed control-plane reachability, computed from what THIS page's
 *  request groups actually did. "Unreachable" is a network-level claim and
 *  renders only when every settled failure was network-level; a server
 *  answering with errors renders as "Requests failing". */
export function apiReachabilityView(statuses: SourceStatus[]): ReachabilityView {
  const total = statuses.length;
  const loaded = statuses.filter((s) => s === "loaded").length;
  const failed = statuses.filter(
    (s) => s === "http_error" || s === "network_error",
  ).length;
  if (loaded > 0) {
    return {
      value: "Responding",
      tone: "ok",
      detail:
        failed > 0
          ? `${failed} of ${total} request groups failed`
          : `all ${total} request groups answered`,
    };
  }
  if (total === 0 || statuses.some((s) => s === "loading")) {
    return { value: "—", tone: "default", detail: "checking…" };
  }
  if (statuses.some((s) => s === "http_error")) {
    return {
      value: "Requests failing",
      tone: "danger",
      detail: "the API is responding, but with errors",
    };
  }
  return {
    value: "Unreachable",
    tone: "danger",
    detail: "no response — network-level failure",
  };
}

export function activityRows(
  events: AuditEvent[] | null,
  limit: number,
): ActivityRow[] {
  if (events === null) return [];
  return [...events]
    .sort((a, b) => b.created_at.localeCompare(a.created_at))
    .slice(0, limit)
    .map((e) => ({
      id: e.id,
      time: e.created_at.slice(11, 19),
      createdAt: e.created_at,
      action: e.action,
      resource: e.resource_id
        ? `${e.resource_type}/${e.resource_id.slice(0, 8)}`
        : e.resource_type,
      actor: e.actor,
      outcome: e.outcome,
    }));
}
