// Pure, framework-free logic for the Target Onboarding wizard (SECP-002B-1B-0.1).
//
// Kept separate from the React component so it is unit-testable and free of DOM concerns.
// Provider-neutral; contains no real infrastructure values. The server re-validates and
// re-hashes everything — this only guides the operator and mirrors the server contract.

import type {
  IsolationModelName,
  IsolationProfile,
  NetworkApproach,
  OnboardingBoundary,
  OnboardingMode,
  OnboardingStatus,
} from "../api/types";

/** Exact review-screen statement mandated by the onboarding contract (ADR-014). */
export const REVIEW_STATEMENT =
  "SECP will automatically allocate IDs and addresses and create scenario resources inside " +
  "this boundary. Manual per-scenario VM, container, network, disk, or address creation is " +
  "not required.";

export const DEFAULT_NETWORK_APPROACH: NetworkApproach = "use_approved_existing_segment";
export const DEFAULT_ISOLATION_PROFILE: IsolationProfile = "fully_segregated";

export interface Option<T> {
  value: T;
  label: string;
  help: string;
}

export const ONBOARDING_MODES: Option<OnboardingMode>[] = [
  {
    value: "clean_server",
    label: "Clean / new server",
    help: "Bring a new or empty eligible server. SECP guides safe setup, then creates scenario resources automatically.",
  },
  {
    value: "existing_environment",
    label: "Existing environment",
    help: "Select an existing hypervisor/cluster boundary. This selects a boundary — it does NOT adopt existing VMs or containers.",
  },
];

export const ISOLATION_MODELS: Option<IsolationModelName>[] = [
  {
    value: "physical",
    label: "Physical isolation (recommended)",
    help: "A dedicated host/cluster reserved for disposable labs. The recommended secure preset.",
  },
  {
    value: "logical",
    label: "Logical isolation",
    help: "Allowed on a shared environment, but requires a complete verified boundary with NO route to management, home, corporate, storage, or public networks.",
  },
];

export const NETWORK_APPROACHES: Option<NetworkApproach>[] = [
  {
    value: "use_approved_existing_segment",
    label: "Use an approved existing segment",
    help: "Constrain the boundary to the target's already-approved network segments. No network is created.",
  },
  {
    value: "secp_managed_dedicated_segment",
    label: "SECP-managed dedicated segment",
    help: "SECP is intended to create a dedicated bridge/VNet later. Activation pending — no network is created in this release.",
  },
];

export interface IsolationProfileOption {
  value: IsolationProfile;
  label: string;
  description: string;
  available: boolean;
  recommended: boolean;
}

export const ISOLATION_PROFILES: IsolationProfileOption[] = [
  {
    value: "fully_segregated",
    label: "Fully segregated",
    description:
      "No Internet, no default route, no path to management/home/corporate/storage/public networks.",
    available: true,
    recommended: true,
  },
  {
    value: "internet_egress_only",
    label: "Internet egress only",
    description: "Outbound Internet with no inbound exposure.",
    available: false,
    recommended: false,
  },
  {
    value: "controlled_service_access",
    label: "Controlled service access",
    description: "Allow-listed access to specific services only.",
    available: false,
    recommended: false,
  },
  {
    value: "advanced_custom_policy",
    label: "Advanced custom policy",
    description: "Operator-defined allow rules.",
    available: false,
    recommended: false,
  },
];

export function isolationProfileAvailable(profile: IsolationProfile): boolean {
  return ISOLATION_PROFILES.some((p) => p.value === profile && p.available);
}

/** Ordered onboarding lifecycle steps for the progress UI. */
export const LIFECYCLE_STEPS: { status: OnboardingStatus; label: string }[] = [
  { status: "draft", label: "Draft" },
  { status: "preflight_pending", label: "Simulated preflight" },
  { status: "ready_for_review", label: "Ready for review" },
  { status: "approved", label: "Human approval" },
  { status: "active", label: "Active" },
];

/** Index of a status within LIFECYCLE_STEPS; -1 for off-track (rejected/retired/unknown). */
export function lifecycleIndex(status: OnboardingStatus): number {
  return LIFECYCLE_STEPS.findIndex((s) => s.status === status);
}

export function isTerminalRejected(status: OnboardingStatus): boolean {
  return status === "rejected" || status === "retired";
}

// --- Boundary draft (string-based form model) --------------------------------

export interface BoundaryDraft {
  nodes: string;
  storage: string;
  networkSegments: string;
  cidrs: string;
  vmidStart: string;
  vmidEnd: string;
  maxTeams: string;
  maxVms: string;
  maxContainers: string;
  maxVcpu: string;
  maxMemoryMb: string;
  maxDiskGb: string;
  credentialScope: string;
  networkApproach: NetworkApproach;
  isolationProfile: IsolationProfile;
}

export interface TargetScopeOptions {
  nodes: string[];
  storage: string[];
  networkSegments: string[];
  cidrs: string[];
  vmidRange?: { start: number; end: number };
  quotas: {
    maxTeams?: number;
    maxVms?: number;
    maxContainers?: number;
    maxVcpu?: number;
    maxMemoryMb?: number;
    maxDiskGb?: number;
  };
}

export const EMPTY_TARGET_SCOPE_OPTIONS: TargetScopeOptions = {
  nodes: [],
  storage: [],
  networkSegments: [],
  cidrs: [],
  quotas: {},
};

export const NO_APPROVED_SEGMENTS_MESSAGE =
  "This target has no approved lab network segments. Configure an approved segment in Provider Targets before onboarding.";

export const CIDR_HELPER_TEXT =
  "CIDRs are lab address ranges, for example 10.60.0.0/16. Select only approved ranges for this target.";

export const NETWORK_SEGMENT_HELPER_TEXT =
  "A network segment is a bridge, VNet, or VLAN name, not an IP range.";

export function emptyDraft(): BoundaryDraft {
  return {
    nodes: "",
    storage: "",
    networkSegments: "",
    cidrs: "",
    vmidStart: "",
    vmidEnd: "",
    maxTeams: "",
    maxVms: "",
    maxContainers: "",
    maxVcpu: "",
    maxMemoryMb: "",
    maxDiskGb: "",
    credentialScope: "least_privilege",
    networkApproach: DEFAULT_NETWORK_APPROACH,
    isolationProfile: DEFAULT_ISOLATION_PROFILE,
  };
}

/** Extract target-approved values from a provisioning scope policy. */
export function scopeOptionsFromPolicy(scopePolicy: unknown): TargetScopeOptions {
  const prov = ((scopePolicy as Record<string, unknown>)?.provisioning ??
    scopePolicy ??
    {}) as Record<string, any>;
  const list = (v: unknown): string[] => (Array.isArray(v) ? v.map(String) : []);
  const range = (prov.vmid_range ?? {}) as Record<string, unknown>;
  const start = typeof range.start === "number" ? range.start : undefined;
  const end = typeof range.end === "number" ? range.end : undefined;
  return {
    nodes: list(prov.allowed_nodes),
    storage: list(prov.allowed_storage),
    networkSegments: list(prov.allowed_bridges),
    cidrs: list(prov.allowed_cidr_reservations),
    vmidRange: start !== undefined && end !== undefined ? { start, end } : undefined,
    quotas: {
      maxTeams: typeof prov.max_teams === "number" ? prov.max_teams : undefined,
      maxVms: typeof prov.max_vms === "number" ? prov.max_vms : undefined,
      maxContainers: typeof prov.max_containers === "number" ? prov.max_containers : undefined,
      maxVcpu: typeof prov.max_total_vcpu === "number" ? prov.max_total_vcpu : undefined,
      maxMemoryMb:
        typeof prov.max_total_memory_mb === "number" ? prov.max_total_memory_mb : undefined,
      maxDiskGb: typeof prov.max_total_disk_gb === "number" ? prov.max_total_disk_gb : undefined,
    },
  };
}

/** Prefill a draft from a target's provisioning scope policy (a safe, in-scope starting point). */
export function draftFromScope(scopePolicy: unknown): BoundaryDraft {
  const options = scopeOptionsFromPolicy(scopePolicy);
  const num = (v: unknown): string => (v === undefined || v === null ? "" : String(v));
  return {
    ...emptyDraft(),
    nodes: options.nodes.join(", "),
    storage: options.storage.join(", "),
    networkSegments: options.networkSegments.join(", "),
    cidrs: options.cidrs.join(", "),
    vmidStart: num(options.vmidRange?.start),
    vmidEnd: num(options.vmidRange?.end),
    maxTeams: num(options.quotas.maxTeams),
    maxVms: num(options.quotas.maxVms),
    maxContainers: num(options.quotas.maxContainers),
    maxVcpu: num(options.quotas.maxVcpu),
    maxMemoryMb: num(options.quotas.maxMemoryMb),
    maxDiskGb: num(options.quotas.maxDiskGb),
  };
}

export function parseList(raw: string): string[] {
  return raw
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

const CIDR_RE = /^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/;

function toInt(raw: string): number | null {
  if (!/^-?\d+$/.test(raw.trim())) return null;
  return parseInt(raw.trim(), 10);
}

export interface BoundaryValidation {
  ok: boolean;
  errors: string[];
  boundary?: OnboardingBoundary;
}

/** Approved segments a user may pick from when using an existing segment. */
export function segmentsWithinApproved(
  segments: string[],
  approvedSegments: string[],
): string[] {
  const approved = new Set(approvedSegments);
  return segments.filter((s) => !approved.has(s));
}

export function valuesOutsideApproved(values: string[], approvedValues: string[]): string[] {
  const approved = new Set(approvedValues);
  return values.filter((s) => !approved.has(s));
}

function normalizeTargetOptions(
  approved: TargetScopeOptions | string[],
): TargetScopeOptions {
  if (Array.isArray(approved)) {
    return { ...EMPTY_TARGET_SCOPE_OPTIONS, networkSegments: approved };
  }
  return approved;
}

export function targetHasApprovedSegments(options: TargetScopeOptions): boolean {
  return options.networkSegments.length > 0;
}

export function canAdvanceWizardStep(
  step: number,
  targetSelected: boolean,
  targetHasSegments: boolean,
  validationOk: boolean,
  onboardingExists: boolean,
): boolean {
  if (step === 0) return targetSelected && targetHasSegments;
  if (step === 5) return validationOk || onboardingExists;
  return true;
}

export function canCreateOnboardingDraft(
  busy: boolean,
  targetSelected: boolean,
  targetHasSegments: boolean,
  validationOk: boolean,
): boolean {
  return !busy && targetSelected && targetHasSegments && validationOk;
}

export function toggleDraftListValue(raw: string, value: string, checked: boolean): string {
  const current = parseList(raw);
  const next = checked
    ? Array.from(new Set([...current, value]))
    : current.filter((item) => item !== value);
  return next.join(", ");
}

/**
 * Validate a boundary draft and build the provider-neutral boundary payload. Mirrors the
 * server contract (which re-validates authoritatively): non-empty allowlists, a bounded
 * VM-ID range, positive quotas, deny external connectivity, a supported isolation profile,
 * and — for the existing-segment approach — segments drawn only from the approved list.
 */
export function buildBoundary(
  draft: BoundaryDraft,
  approvedOptions: TargetScopeOptions | string[],
): BoundaryValidation {
  const errors: string[] = [];
  const targetOptions = normalizeTargetOptions(approvedOptions);
  const nodes = parseList(draft.nodes);
  const storage = parseList(draft.storage);
  const segments = parseList(draft.networkSegments);
  const cidrs = parseList(draft.cidrs);

  if (nodes.length === 0) errors.push("At least one allowed node is required.");
  if (storage.length === 0) errors.push("At least one allowed storage is required.");
  if (segments.length === 0) errors.push("At least one network segment is required.");
  if (cidrs.length === 0) errors.push("At least one CIDR is required.");
  for (const c of cidrs) {
    if (!CIDR_RE.test(c)) errors.push(`Invalid CIDR: ${c}`);
  }

  const start = toInt(draft.vmidStart);
  const end = toInt(draft.vmidEnd);
  if (start === null || end === null) {
    errors.push("VM-ID range start and end must be integers.");
  } else {
    if (start < 100) errors.push("VM-ID range start must be >= 100.");
    if (end <= start) errors.push("VM-ID range end must be greater than start.");
    if (
      targetOptions.vmidRange &&
      (start < targetOptions.vmidRange.start || end > targetOptions.vmidRange.end)
    ) {
      errors.push(
        `VM-ID range must stay within the target-approved range ${targetOptions.vmidRange.start}-${targetOptions.vmidRange.end}.`,
      );
    }
  }

  const quotaFields: [keyof BoundaryDraft, string, number][] = [
    ["maxTeams", "max_teams", 1],
    ["maxVms", "max_vms", 1],
    ["maxContainers", "max_containers", 0],
    ["maxVcpu", "max_total_vcpu", 1],
    ["maxMemoryMb", "max_total_memory_mb", 1],
    ["maxDiskGb", "max_total_disk_gb", 1],
  ];
  const quotas: Record<string, number> = {};
  for (const [field, key, min] of quotaFields) {
    const v = toInt(draft[field] as string);
    if (v === null || v < min) {
      errors.push(`Quota ${key} must be an integer >= ${min}.`);
    } else {
      quotas[key] = v;
    }
  }
  const quotaBounds: [string, keyof TargetScopeOptions["quotas"], string][] = [
    ["max_teams", "maxTeams", "max teams"],
    ["max_vms", "maxVms", "max VMs"],
    ["max_containers", "maxContainers", "max containers"],
    ["max_total_vcpu", "maxVcpu", "max vCPU"],
    ["max_total_memory_mb", "maxMemoryMb", "max memory MB"],
    ["max_total_disk_gb", "maxDiskGb", "max disk GB"],
  ];
  for (const [quotaKey, optionKey, label] of quotaBounds) {
    const approved = targetOptions.quotas[optionKey];
    if (approved !== undefined && quotas[quotaKey] !== undefined && quotas[quotaKey] > approved) {
      errors.push(`${label} must not exceed the target-approved limit of ${approved}.`);
    }
  }

  if (draft.credentialScope.trim().length === 0) {
    errors.push("A credential-scope label is required (opaque, non-secret).");
  }

  if (!isolationProfileAvailable(draft.isolationProfile)) {
    errors.push(
      `Isolation profile "${draft.isolationProfile}" is planned but not available yet.`,
    );
  }

  // The server enforces network_segments ⊆ target scope for BOTH approaches (boundary ⊆
  // scope). The existing-segment approach makes this explicit; the SECP-managed approach is
  // a durable declaration of intent (activation pending — no network is created here), and
  // the segment must still be within the target's approved segments.
  if (targetOptions.nodes.length > 0) {
    const outside = valuesOutsideApproved(nodes, targetOptions.nodes);
    if (outside.length > 0) {
      errors.push(`These nodes are not in the target's approved nodes: ${outside.join(", ")}.`);
    }
  }

  if (targetOptions.storage.length > 0) {
    const outside = valuesOutsideApproved(storage, targetOptions.storage);
    if (outside.length > 0) {
      errors.push(
        `These storage values are not in the target's approved storage: ${outside.join(", ")}.`,
      );
    }
  }

  if (targetOptions.networkSegments.length > 0 || segments.length > 0) {
    const outside = segmentsWithinApproved(segments, targetOptions.networkSegments);
    if (outside.length > 0) {
      errors.push(
        `These segments are not in the target's approved segments: ${outside.join(", ")}.`,
      );
    }
  }

  if (targetOptions.cidrs.length > 0) {
    const outside = valuesOutsideApproved(cidrs, targetOptions.cidrs);
    if (outside.length > 0) {
      errors.push(`These CIDRs are not approved for this target: ${outside.join(", ")}.`);
    }
  }

  if (errors.length > 0 || start === null || end === null) {
    return { ok: false, errors };
  }

  const boundary: OnboardingBoundary = {
    nodes,
    storage,
    network_segments: segments,
    cidrs,
    vmid_range: { start, end },
    quotas: {
      max_teams: quotas.max_teams,
      max_vms: quotas.max_vms,
      max_containers: quotas.max_containers,
      max_total_vcpu: quotas.max_total_vcpu,
      max_total_memory_mb: quotas.max_total_memory_mb,
      max_total_disk_gb: quotas.max_total_disk_gb,
    },
    external_connectivity: { policy: "deny" },
    credential_scope: draft.credentialScope.trim(),
    network_approach: draft.networkApproach,
    isolation_profile: draft.isolationProfile,
  };
  return { ok: true, errors: [], boundary };
}
