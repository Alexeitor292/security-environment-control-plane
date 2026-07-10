// Targets hub — pure presentation logic for the target inventory and the
// per-target detail composition (boundary, evidence, access chain).
//
// Truth rules: every rendered state derives from real backend records or is
// explicit contract language for the sealed shipped default. Unavailable
// sources render "—", never a fabricated state. Secret references are opaque
// pointers; nothing here ever holds or renders a secret.

import type {
  Onboarding,
  PreflightAuthorization,
  ResolverActivation,
  TargetEvidence,
} from "../api/types";
import type { AccessChainLink } from "../components/ui/AccessChain";
import { truncateHash } from "../components/ui/hash-chip";
import { usableAuthorization } from "./readonly-preflight";
import {
  RESOLVER_ACTIVATION_SEALED_NOTICE,
  evidenceSummary,
  statusLabel as resolverStatusLabel,
} from "./resolver-activation";

/** Verbatim carry-over of the milestone banner from the previous page. */
export const MILESTONE_NOTICE =
  "SECP-002A — read-only. Proxmox provisioning is NOT enabled. Discovery is " +
  "read-only and runs only through the Temporal worker; provisioning is " +
  "deferred to SECP-002B. No real endpoint is contacted in this milestone.";

export const INVENTORY_TAGLINE =
  "Execution targets reached only through versioned plugins — never directly.";

export const SECRET_REF_CAPTION =
  "Secret references are opaque pointers — this interface never holds a secret.";

/** Verbatim carry-over of the inline-dev discovery refusal hint. */
export const DISCOVERY_REFUSED_HINT =
  "discovery requires the Temporal worker path; it is refused in inline dev mode";

export const CHAIN_INTRO =
  "Each link is gated separately. No earlier link activates a later one.";

export const CHAIN_FOOTER =
  "Approval on any surface never activates live access.";

/** Contract language for the sealed shipped default (enforced server-side;
 *  this describes the contract, not an observed worker state). */
export const COLLECTOR_GATE_STATEMENT =
  "No transport is constructed until every link above passes, in order — " +
  "the sealed shipped default.";

// ---------------------------------------------------------------- boundary

export interface BoundaryRow {
  key: string;
  value: string;
  mono?: boolean;
}

export interface BoundarySummary {
  /** Inventory cell line: "2 nodes · 1 segment". */
  counts: string;
  /** Inventory cell mono line: cidrs + VMID range. */
  detail: string;
  /** Detail-tab rows for KeyValueList. */
  rows: BoundaryRow[];
}

function asStrings(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((v): v is string => typeof v === "string")
    : [];
}

function asNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

export function boundarySummaryFromScope(
  scopePolicy: Record<string, unknown> | null | undefined,
): BoundarySummary | null {
  const provisioning = (scopePolicy as { provisioning?: unknown } | null | undefined)
    ?.provisioning;
  if (!provisioning || typeof provisioning !== "object") return null;
  const p = provisioning as Record<string, unknown>;
  const nodes = asStrings(p.allowed_nodes);
  const storage = asStrings(p.allowed_storage);
  const segments = asStrings(p.allowed_bridges);
  const cidrs = asStrings(p.allowed_cidr_reservations);
  const vmid = (p.vmid_range ?? {}) as Record<string, unknown>;
  const vmidStart = asNumber(vmid.start);
  const vmidEnd = asNumber(vmid.end);
  const quota = (label: unknown, unit: string) => {
    const n = asNumber(label);
    return n === null ? null : `${n} ${unit}`;
  };
  const quotas = [
    quota(p.max_teams, "teams"),
    quota(p.max_vms, "VMs"),
    quota(p.max_containers, "CT"),
    quota(p.max_total_vcpu, "vCPU"),
    quota(p.max_total_memory_mb, "MB"),
    quota(p.max_total_disk_gb, "GB"),
  ]
    .filter((q): q is string => q !== null)
    .join(" · ");

  const counts = `${nodes.length} node${nodes.length === 1 ? "" : "s"} · ${segments.length} segment${segments.length === 1 ? "" : "s"}`;
  const vmidText =
    vmidStart !== null && vmidEnd !== null ? `VMID ${vmidStart}–${vmidEnd}` : null;
  const detail = [cidrs.join(", ") || null, vmidText]
    .filter((s): s is string => s !== null)
    .join(" · ");

  const rows: BoundaryRow[] = [
    { key: "Nodes", value: nodes.join(", ") || "—", mono: true },
    { key: "Storage", value: storage.join(", ") || "—", mono: true },
    { key: "Network segments", value: segments.join(", ") || "—", mono: true },
    { key: "CIDR reservations", value: cidrs.join(", ") || "—", mono: true },
    { key: "VM-ID range", value: vmidText ?? "—", mono: true },
  ];
  if (quotas) rows.push({ key: "Quotas", value: quotas });
  rows.push({
    key: "External connectivity",
    value: "deny (fixed) — cannot be changed by any role",
  });
  return { counts, detail, rows };
}

// ------------------------------------------------------- inventory cells

export interface CellView {
  label: string;
  tone: "ok" | "warn" | "danger" | "pending" | "none";
  meta?: string;
}

export const UNAVAILABLE_CELL: CellView = {
  label: "—",
  tone: "none",
  meta: "unavailable",
};

export function latestEvidence(evidence: TargetEvidence[]): TargetEvidence | null {
  if (evidence.length === 0) return null;
  return [...evidence].sort((a, b) =>
    b.collected_at.localeCompare(a.collected_at),
  )[0];
}

const EVIDENCE_CELL_TONE: Record<string, CellView["tone"]> = {
  pass: "ok",
  fail: "danger",
  unverifiable: "pending",
};

export function evidenceCellView(evidence: TargetEvidence[] | null): CellView {
  if (evidence === null) return UNAVAILABLE_CELL;
  const latest = latestEvidence(evidence);
  if (!latest) return { label: "none recorded", tone: "none" };
  return {
    label: latest.status,
    tone: EVIDENCE_CELL_TONE[latest.status] ?? "pending",
    meta: `${latest.evidence_source} · ${latest.collected_at.slice(0, 10)}`,
  };
}

export function liveAccessCellView(
  authorizations: PreflightAuthorization[] | null,
  now: Date = new Date(),
): CellView {
  if (authorizations === null) return UNAVAILABLE_CELL;
  const usable = usableAuthorization(authorizations, now);
  if (usable) {
    return { label: "Authorized", tone: "ok", meta: "GET-only · resolver sealed" };
  }
  return { label: "Sealed", tone: "pending" };
}

// ---------------------------------------------------------- access chain

export interface AccessChainInput {
  onboardings: Onboarding[] | null;
  authorizations: PreflightAuthorization[] | null;
  resolverActivations: ResolverActivation[] | null;
  now?: Date;
}

function minutesUntil(iso: string, now: Date): number {
  return Math.max(0, Math.round((new Date(iso).getTime() - now.getTime()) / 60000));
}

function newestBy<T>(items: T[], key: (item: T) => string): T | null {
  if (items.length === 0) return null;
  return [...items].sort((a, b) => key(b).localeCompare(key(a)))[0];
}

/** Derive the four-link access chain from real records. Link states never
 *  exceed what the records prove; the collector link is contract language
 *  for the sealed shipped default and is always sealed here. */
export function buildAccessChain(input: AccessChainInput): AccessChainLink[] {
  const now = input.now ?? new Date();

  // 1 — Declared boundary (onboarding lifecycle).
  let boundary: AccessChainLink;
  if (input.onboardings === null) {
    boundary = {
      id: "boundary",
      title: "Boundary approved",
      state: "pending",
      status: "unavailable — onboardings could not be loaded",
    };
  } else {
    const active = input.onboardings.find((o) => o.status === "active");
    const approved = input.onboardings.find((o) => o.status === "approved");
    const inReview = input.onboardings.find(
      (o) => o.status === "ready_for_review" || o.status === "preflight_pending",
    );
    if (active) {
      boundary = {
        id: "boundary",
        title: "Boundary approved",
        state: "complete",
        status: `active · boundary ${truncateHash(active.boundary_hash, { prefix: "strip", digits: 8, ellipsis: false })}`,
      };
    } else if (approved) {
      boundary = {
        id: "boundary",
        title: "Boundary approved",
        state: "active",
        status: `approved · not yet activated · boundary ${truncateHash(approved.boundary_hash, { prefix: "strip", digits: 8, ellipsis: false })}`,
      };
    } else if (inReview) {
      boundary = {
        id: "boundary",
        title: "Boundary approved",
        state: "pending",
        status: inReview.status.replace(/_/g, " "),
      };
    } else {
      boundary = {
        id: "boundary",
        title: "Boundary approved",
        state: "pending",
        status: "not established",
      };
    }
  }

  // 2 — Read-only authorization (approved + unexpired only counts).
  let authorization: AccessChainLink;
  if (input.authorizations === null) {
    authorization = {
      id: "authorization",
      title: "Read-only authorization",
      state: "pending",
      status: "unavailable — authorizations could not be loaded",
    };
  } else {
    const usable = usableAuthorization(input.authorizations, now);
    if (usable) {
      authorization = {
        id: "authorization",
        title: "Read-only authorization",
        state: "active",
        status: `v${usable.authorization_version} · approved · expires in ${minutesUntil(usable.authorization_expiry, now)}m`,
        body: "Permits queueing GET-only readiness preflights. Nothing else.",
      };
    } else {
      const latest = newestBy(input.authorizations, (a) => a.created_at);
      authorization = {
        id: "authorization",
        title: "Read-only authorization",
        state: "pending",
        status: latest
          ? `${latest.status}${latest.status === "approved" ? " · expired" : ""}`
          : "not granted",
      };
    }
  }

  // 3 — Resolver activation (always sealed from this interface).
  let resolver: AccessChainLink;
  if (input.resolverActivations === null) {
    resolver = {
      id: "resolver",
      title: "Resolver activation",
      state: "pending",
      status: "unavailable — activations could not be loaded",
    };
  } else {
    const latest = newestBy(input.resolverActivations, (a) => a.created_at);
    if (latest) {
      const evidence = evidenceSummary(latest);
      resolver = {
        id: "resolver",
        title: "Resolver activation",
        state: "sealed",
        status: `${resolverStatusLabel(latest.status)} · evidence ${evidence.verified}/${evidence.total}`,
        body: RESOLVER_ACTIVATION_SEALED_NOTICE,
      };
    } else {
      resolver = {
        id: "resolver",
        title: "Resolver activation",
        state: "sealed",
        status: "not established — sealed shipped default",
        body: RESOLVER_ACTIVATION_SEALED_NOTICE,
      };
    }
  }

  // 4 — Live collector: sealed by contract; never presented as observed state.
  const collector: AccessChainLink = {
    id: "collector",
    title: "Live collector",
    state: "sealed",
    status: "not constructed — sealed shipped default",
    body: COLLECTOR_GATE_STATEMENT,
  };

  return [boundary, authorization, resolver, collector];
}
