// Presentation view-models for the redesigned onboarding wizard.
//
// This module COMPOSES the tested contract in onboarding-wizard.ts — it never
// re-implements or bypasses its predicates. Step-rail reachability is derived
// from canAdvanceWizardStep exactly as the Next button uses it; lifecycle
// action availability mirrors the exact status-equality gates the previous
// wizard enforced.

import type { Onboarding, OnboardingStatus } from "../api/types";
import type { StepRailItem } from "../components/ui/StepRail";
import type { KeyValueItem } from "../components/ui/KeyValueList";
import {
  NO_APPROVED_SEGMENTS_MESSAGE,
  canAdvanceWizardStep,
  parseList,
  type BoundaryDraft,
} from "./onboarding-wizard";

export const STEP_TITLES = [
  "Select target",
  "Onboarding mode",
  "Isolation model",
  "Lab network approach",
  "Isolation profile",
  "Define & review boundary",
  "Lifecycle (simulated)",
] as const;

export interface StepGateArgs {
  targetSelected: boolean;
  targetHasSegments: boolean;
  validationOk: boolean;
  onboardingExists: boolean;
}

function gate(step: number, args: StepGateArgs): boolean {
  return canAdvanceWizardStep(
    step,
    args.targetSelected,
    args.targetHasSegments,
    args.validationOk,
    args.onboardingExists,
  );
}

function blockedReason(args: StepGateArgs): string {
  if (!args.targetSelected) return "Select a target first.";
  if (!args.targetHasSegments) return NO_APPROVED_SEGMENTS_MESSAGE;
  return "Complete a valid boundary or create the onboarding draft first.";
}

/** Per-step rail states. Forward reachability walks canAdvanceWizardStep from
 *  the current step, so the rail can never navigate anywhere the Next button
 *  could not. Backward navigation to visited steps is always allowed.
 *  "complete" means visited/satisfied — never approved or active. */
export function wizardStepStates(
  current: number,
  args: StepGateArgs,
): StepRailItem[] {
  let reach = current;
  while (reach < STEP_TITLES.length - 1 && gate(reach, args)) reach += 1;
  return STEP_TITLES.map((label, i) => {
    const state: StepRailItem["state"] =
      i === current
        ? "current"
        : i < current
          ? "complete"
          : i <= reach
            ? "available"
            : "blocked";
    return {
      id: String(i),
      label,
      state,
      blockedReason: state === "blocked" ? blockedReason(args) : undefined,
    };
  });
}

/** Closed onboarding action codes → fixed copy. Backend free-form messages
 *  and detail arrays are never rendered; the code stays visible. */
export const ONBOARDING_ERROR_TEXT: Record<string, string> = {
  validation_failed:
    "The declared boundary was rejected by the server's validation. Adjust the boundary and try again.",
  invalid_transition: "That action is not allowed in the onboarding's current state.",
  approval_required: "That action requires an approval that has not been recorded.",
  forbidden: "You are not permitted to perform this onboarding action.",
  not_found: "The requested onboarding or target was not found.",
  live_evidence_sealed:
    "Blocked: the live-evidence seal is in force — only simulated onboarding is possible in this release.",
};

/** Fixed copy for a failed target-list load (never the backend message). */
export const TARGETS_UNAVAILABLE_TEXT =
  "Execution targets could not be loaded. Check that the control-plane API is reachable.";

export const BOUNDARY_LOCKED_NOTICE =
  "The onboarding draft has been created — the boundary below is locked to the exact declared values that were hashed. Select a different target to start a new draft.";

export type LifecycleActionId = "preflight" | "submit" | "approve" | "activate";

export interface LifecycleActionView {
  id: LifecycleActionId;
  /** Button labels carried over verbatim from the previous wizard. */
  label: string;
  does: string;
  doesNot: string;
  next: string;
  simulated: boolean;
}

export const LIFECYCLE_ACTIONS: LifecycleActionView[] = [
  {
    id: "preflight",
    label: "Run simulated preflight",
    does: "Queues the fake preflight collector and records simulated comparison evidence.",
    doesNot:
      "Does not contact, inspect, or validate any real server — the live-evidence seal remains in force.",
    next: "The simulated collector records the result; submit for review afterwards.",
    simulated: true,
  },
  {
    id: "submit",
    label: "Submit for review",
    does: "Marks the drafted boundary ready for human review.",
    doesNot: "Does not approve or activate anything, and does not change the boundary.",
    next: "A human reviewer decides next.",
    simulated: true,
  },
  {
    id: "approve",
    label: "Approve (human)",
    does: "Records a human approval decision for this exact declared boundary.",
    doesNot:
      "Does not activate the boundary, create resources, or grant live access of any kind.",
    next: "The operator may activate the approved boundary next.",
    simulated: true,
  },
  {
    id: "activate",
    label: "Activate",
    does: "Marks the approved boundary active so SECP may later generate scenario plans inside it.",
    doesNot: "Does not create, adopt, or contact any infrastructure.",
    next: "SECP scenario planning consumes the active boundary.",
    simulated: true,
  },
];

/** Exact status-equality gates carried over from the previous wizard. */
export function lifecycleActionEnabled(
  id: LifecycleActionId,
  status: OnboardingStatus,
): boolean {
  switch (id) {
    case "preflight":
      return status === "draft";
    case "submit":
      return status === "preflight_pending";
    case "approve":
      return status === "ready_for_review";
    case "activate":
      return status === "approved";
  }
}

export const DRAFT_NOT_SAVED_NOTICE =
  "Draft only — nothing is saved until the onboarding draft is created at review.";

export const SUMMARY_TRUTH_NOTICE =
  "A draft is not approved, and an approved boundary is not active. Onboarding never contacts the target; no infrastructure is created, adopted, or modified.";

/** Summary rows for a CREATED onboarding — rendered from the server-recorded
 *  declared boundary (the values that were actually hashed), never from the
 *  possibly-diverged local draft. */
export function boundarySummaryDeclaredRows(onboarding: Onboarding): KeyValueItem[] {
  const b = onboarding.declared_boundary;
  const q = b.quotas;
  return [
    { key: "Mode", value: onboarding.onboarding_mode.replace(/_/g, " ") },
    { key: "Isolation", value: onboarding.isolation_model },
    {
      key: "Profile",
      value: (b.isolation_profile ?? onboarding.isolation_profile).replace(/_/g, " "),
    },
    {
      key: "Network approach",
      value: (b.network_approach ?? onboarding.network_approach).replace(/_/g, " "),
    },
    { key: "Nodes", value: b.nodes.join(", ") || "—", mono: true },
    { key: "Storage", value: b.storage.join(", ") || "—", mono: true },
    { key: "Segments", value: b.network_segments.join(", ") || "—", mono: true },
    { key: "CIDRs", value: b.cidrs.join(", ") || "—", mono: true },
    {
      key: "VM-ID range",
      value: `${b.vmid_range.start}–${b.vmid_range.end}`,
      mono: true,
    },
    {
      key: "Quotas",
      value: `${q.max_teams}t · ${q.max_vms}vm · ${q.max_containers}ct`,
      mono: true,
    },
    {
      key: "Compute limits",
      value: `${q.max_total_vcpu} vCPU · ${q.max_total_memory_mb} MB · ${q.max_total_disk_gb} GB`,
      mono: true,
    },
    { key: "External connectivity", value: "deny (fixed)" },
  ];
}

/** Accumulating right-rail summary of the in-progress draft. */
export function boundarySummaryDraftRows(
  mode: string,
  isolationModel: string,
  draft: BoundaryDraft,
): KeyValueItem[] {
  const list = (raw: string) => parseList(raw).join(", ") || "—";
  const vmid =
    draft.vmidStart && draft.vmidEnd ? `${draft.vmidStart}–${draft.vmidEnd}` : "—";
  const quotas =
    [draft.maxTeams && `${draft.maxTeams}t`, draft.maxVms && `${draft.maxVms}vm`, draft.maxContainers && `${draft.maxContainers}ct`]
      .filter(Boolean)
      .join(" · ") || "—";
  const compute =
    [draft.maxVcpu && `${draft.maxVcpu} vCPU`, draft.maxMemoryMb && `${draft.maxMemoryMb} MB`, draft.maxDiskGb && `${draft.maxDiskGb} GB`]
      .filter(Boolean)
      .join(" · ") || "—";
  return [
    { key: "Mode", value: mode.replace(/_/g, " ") },
    { key: "Isolation", value: isolationModel },
    { key: "Profile", value: draft.isolationProfile.replace(/_/g, " ") },
    { key: "Network approach", value: draft.networkApproach.replace(/_/g, " ") },
    { key: "Nodes", value: list(draft.nodes), mono: true },
    { key: "Storage", value: list(draft.storage), mono: true },
    { key: "Segments", value: list(draft.networkSegments), mono: true },
    { key: "CIDRs", value: list(draft.cidrs), mono: true },
    { key: "VM-ID range", value: vmid, mono: true },
    { key: "Quotas", value: quotas, mono: true },
    { key: "Compute limits", value: compute, mono: true },
    { key: "External connectivity", value: "deny (fixed)" },
  ];
}
