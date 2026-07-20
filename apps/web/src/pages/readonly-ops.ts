// Presentation view-models shared by the read-only operational surfaces
// (Read-Only Preflight, Resolver Activation, RO Discovery Bootstrap).
//
// This module composes the pinned per-surface contracts (readonly-preflight.ts,
// resolver-activation.ts, read-only-bootstrap.ts) — it never reinterprets a
// lifecycle predicate, authorization rule, or safety constant, and it renders
// no endpoint, host, key, or secret material. The cumulative gates are
// independent: an earlier gate passing never implies a later one passed.

import type {
  BootstrapSession,
  PreflightAuthorization,
  ReadonlyPreflight,
  ResolverActivation,
} from "../api/types";
import type { AccessChainLink } from "../components/ui/AccessChain";
import type { StepRailItem } from "../components/ui/StepRail";
import {
  authorizationIsApprovedAndCurrent,
  isQueuedOrRunning as preflightQueuedOrRunning,
  outcomeLabel,
} from "./readonly-preflight";
import { currentStep, type BootstrapStep } from "./read-only-bootstrap";
import { evidenceSummary } from "./resolver-activation";

/**
 * Generic closed codes these services actually raise (verified against
 * apps/api/secp_api/errors.py: services here raise DomainError / NotFoundError /
 * ValidationFailedError / ForbiddenError). Merge under a surface's own map so
 * namespaced codes win; the shared resolveClosedCodeCopy guards malformed and
 * prototype-key codes and falls back to generic copy for anything unlisted.
 * A backend message/detail is never used as display text.
 */
export const READONLY_COMMON_CODES: Record<string, string> = {
  api_unreachable:
    "Cannot reach the control-plane API. Check that the backend is running.",
  domain_error: "That action is not allowed in the current state.",
  invalid_transition: "That action is not allowed in the current lifecycle state.",
  approval_required: "That action requires an approval that has not been recorded.",
  immutable_resource: "That record is immutable and cannot be changed.",
  validation_failed: "The request was rejected by the server's validation.",
  forbidden: "You are not permitted to perform this action.",
  unauthenticated: "Your session is not authenticated.",
  not_found: "The requested record was not found.",
};

/** Bootstrap/discovery surface: generic codes plus the permission-gated grant
 *  and the create endpoint's input-validation code. */
export const BOOTSTRAP_ERROR_TEXT: Record<string, string> = {
  ...READONLY_COMMON_CODES,
  invalid_bootstrap_input:
    "The submitted bootstrap values were rejected. Provide a valid worker SSH PUBLIC key (never a private key).",
  invalid_worker_node_publication:
    "The worker node identity review was refused. Reload the published node and review every required field again.",
  forbidden:
    "You are not permitted to perform this action (granting staging-substrate eligibility requires the staging_substrate:manage capability).",
};

/** Responsibility for a step — who owns the action, never conflating App/Worker. */
export type Responsibility = "App" | "Human operator" | "Worker" | "Proxmox host";

// ------------------------------------------------------- preflight authz

export interface AuthorizationView {
  versionLabel: string;
  /** approved | draft | expired | revoked | unknown */
  state: "approved" | "draft" | "expired" | "revoked" | "unknown";
  stateLabel: string;
  /** ISO expiry, shown as an absolute timestamp. */
  expiry: string;
  /** Whole minutes remaining (0 when expired). */
  remainingMinutes: number;
  /** GET-only scope statement — fixed. */
  scope: string;
}

export function preflightAuthorizationView(
  auth: PreflightAuthorization,
  now: Date = new Date(),
): AuthorizationView {
  const expiryDate = new Date(auth.authorization_expiry);
  const remainingMinutes = Math.max(
    0,
    Math.round((expiryDate.getTime() - now.getTime()) / 60000),
  );
  let state: AuthorizationView["state"];
  let stateLabel: string;
  if (auth.status === "revoked") {
    state = "revoked";
    stateLabel = "Revoked";
  } else if (auth.status === "approved") {
    if (authorizationIsApprovedAndCurrent(auth, now)) {
      state = "approved";
      stateLabel = "Approved";
    } else {
      state = "expired";
      stateLabel = "Expired";
    }
  } else if (auth.status === "draft") {
    state = "draft";
    stateLabel = "Draft — not yet approved";
  } else {
    state = "unknown";
    stateLabel = auth.status.replace(/_/g, " ");
  }
  return {
    versionLabel: `v${auth.authorization_version}`,
    state,
    stateLabel,
    expiry: auth.authorization_expiry,
    remainingMinutes,
    scope: "GET-only readiness reads",
  };
}

export interface PreflightRow {
  id: string;
  status: string;
  outcome: string;
  /** A worker still owes the outcome — never present results as ready. */
  workerOwned: boolean;
  /** The one expected-while-sealed fail-closed outcome. */
  expectedSealed: boolean;
  ready: boolean;
  createdAt: string;
}

export function preflightHistoryRows(
  preflights: ReadonlyPreflight[] | null,
): PreflightRow[] {
  if (preflights === null) return [];
  return [...preflights]
    .sort((a, b) => b.created_at.localeCompare(a.created_at))
    .map((pf) => ({
      id: pf.id,
      status: pf.status,
      outcome: outcomeLabel(pf.outcome_code),
      workerOwned: preflightQueuedOrRunning(pf.status),
      expectedSealed: pf.outcome_code === "credential_unavailable",
      ready: pf.outcome_code === "ready",
      createdAt: pf.created_at,
    }));
}

export const CREDENTIAL_UNAVAILABLE_NOTICE =
  "credential_unavailable is the expected fail-closed result while the resolver is sealed: the worker verified the authorization, then refused secret resolution before any transport was constructed. No endpoint was contacted and nothing about the host was read or changed.";

export const QUEUE_CREATES_NO_EVIDENCE_NOTICE =
  "Queueing creates no readiness evidence. A worker owns execution; results appear only when it durably records an outcome.";

// ------------------------------------------------------ resolver gates

export interface ResolverGate {
  id: string;
  title: string;
  state: AccessChainLink["state"];
  status: string;
  body?: string;
}

/** Effective badge state for a resolver-activation authorization: an approved
 *  authorization past its expiry reads "expired", never a green "approved".
 *  The visible label still comes from the pinned statusLabel(). */
export function resolverAuthBadgeState(
  auth: ResolverActivation,
  now: Date = new Date(),
): string {
  if (auth.status === "approved" && new Date(auth.authorization_expiry) <= now) {
    return "expired";
  }
  return auth.status;
}

export const RESOLVER_INTRO =
  "These gates are cumulative and independent. Each is established separately; an earlier gate does not activate a later one. This interface performs no activation.";

/**
 * Independent resolver-posture gates derived from the real authorization plus
 * fixed contract language for the sealed shipped default. Authorization being
 * approved never renders the resolver, worker activation, or collector as
 * anything but sealed/not-established (matches resolver-activation.ts isSealed).
 */
export function resolverGates(auth: ResolverActivation | null): ResolverGate[] {
  let authorization: ResolverGate;
  if (!auth) {
    authorization = {
      id: "authorization",
      title: "Activation authorization",
      state: "pending",
      status: "None for this target",
    };
  } else if (auth.status === "approved") {
    authorization = {
      id: "authorization",
      title: "Activation authorization",
      state: "active",
      status: `Approved (sealed, not active) · v${auth.authorization_version}`,
    };
  } else if (auth.status === "revoked") {
    authorization = {
      id: "authorization",
      title: "Activation authorization",
      state: "pending",
      status: "Revoked",
    };
  } else {
    authorization = {
      id: "authorization",
      title: "Activation authorization",
      state: "pending",
      status: auth.status.replace(/_/g, " "),
    };
  }

  const evidence = auth ? evidenceSummary(auth) : { verified: 0, total: 0 };
  const trust: ResolverGate = {
    id: "trust",
    title: "Trust evidence",
    state: evidence.total > 0 && evidence.verified === evidence.total ? "active" : "pending",
    status:
      evidence.total > 0
        ? `${evidence.verified}/${evidence.total} verified`
        : "Not established",
    body: "Every activation-evidence item must be independently verified before approval; none of this activates resolution.",
  };

  // The following three are the sealed shipped default — contract language,
  // never observed worker state. They stay sealed even for an approved authz.
  const workerActivation: ResolverGate = {
    id: "worker-activation",
    title: "Worker admission / activation",
    state: "sealed",
    status: "Sealed",
    body: "Worker-side activation is completed out of band and is never performed from this interface.",
  };
  const resolverBackend: ResolverGate = {
    id: "resolver-backend",
    title: "Resolver backend / configuration",
    state: "sealed",
    status: "Not configured",
    body: "The SealedUnavailableResolver ships by default. No backend is configured or contacted here; every resolution fails closed as credential unavailable.",
  };
  const collector: ResolverGate = {
    id: "collector",
    title: "Collector construction",
    state: "sealed",
    status: "Never constructed",
    body: "No transport or collector is constructed until every gate above is independently satisfied out of band. Resolver availability would still not authorize collection.",
  };

  return [authorization, trust, workerActivation, resolverBackend, collector];
}

export const RESOLVER_KILL_SWITCH_STEPS: string[] = [
  "Revoke the out-of-band activation configuration — the resolver can no longer authenticate.",
  "Revoke the authorization — re-verification fails closed and no lease is issued.",
  "Disable the activation gate — reverts to the sealed default resolver.",
];

// -------------------------------------------------------- bootstrap gates

export interface BootstrapStepView {
  id: BootstrapStep;
  responsibility: Responsibility;
}

/** Responsibility owner per bootstrap step (App / Human operator / Worker /
 *  Proxmox host). The generated script is the ONLY host-side manual action. */
export const BOOTSTRAP_RESPONSIBILITY: Record<BootstrapStep, Responsibility> = {
  create: "App",
  "run-script": "Human operator",
  complete: "Human operator",
  bind: "App",
  "run-discovery": "Worker",
  refused: "Human operator",
};

/** StepRail items for the bootstrap sequence. States derive from the pinned
 *  currentStep(session): steps before current are complete, current is current,
 *  later steps blocked. Completed never implies discovery ran. */
export function bootstrapStepItems(
  labels: Record<BootstrapStep, string>,
  session: BootstrapSession | null,
): StepRailItem[] {
  const order: BootstrapStep[] = [
    "create",
    "run-script",
    "complete",
    "bind",
    "run-discovery",
  ];
  const step = currentStep(session);
  const currentIdx = order.indexOf(step);
  return order.map((id, i) => ({
    id,
    label: `${labels[id]} · ${BOOTSTRAP_RESPONSIBILITY[id]}`,
    state:
      currentIdx === -1
        ? "blocked"
        : i < currentIdx
          ? "complete"
          : i === currentIdx
            ? "current"
            : "blocked",
  }));
}

export const READY_TO_QUEUE_NOTICE =
  "Ready means read-only discovery may now be queued — not that discovery ran or completed.";

export const WORKER_BUNDLE_OWNERSHIP_NOTICE =
  "The worker prepares and owns its discovery bundle automatically once this target is bound and the host key is captured. The app never assembles bundle files and never handles worker private material.";
