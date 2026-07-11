import type {
  TopologyDocumentDetail,
  TopologyRevisionDetail,
  TopologyRevisionSummary,
  TopologyValidationResult,
  TopologyValidationStatus,
} from "../api/types";

// Pure view-model for the durable topology persistence layer (PR-15). It wires
// the PR-13 local-draft workspace to the PR-14 authoring contract WITHOUT
// blurring any state boundary:
//
//   local browser draft ≠ saved immutable revision ≠ current authoritative
//   revision ≠ validated ≠ submitted ≠ approved ≠ generated plan ≠ deployed
//
// The backend content hash is authoritative — this module never claims to know
// the post-save hash, and never validates, submits, approves, generates a plan,
// or contacts infrastructure. Every control's eligibility is computed here so
// the component holds no gating logic.

// ------------------------------------------------------------------ copy

export const SAVE_REVISION_NOTE =
  "Save creates a new immutable revision from your local draft. It does not validate, submit, approve, generate a plan, or deploy anything.";

export const VALIDATE_NOTE =
  "Validation checks an exact saved revision against the schema. Valid does not mean approved or deployable.";

export const SUBMIT_NOTE =
  "Submission records this exact revision for review. It does not approve, generate a plan, or deploy anything.";

export const DECISION_NOTE =
  "Approval records a decision for this immutable revision. No deployment plan is generated and no infrastructure action occurs.";

export const CREATE_DRAFT_NOTE =
  "Creating a topology draft records revision 1 from the current planned topology. It does not validate, submit, approve, or contact infrastructure.";

export const STALE_BASE_NOTE =
  "Your local draft is based on a revision that is no longer current. Nothing was overwritten. Review the latest revision, or discard your local draft and load the latest — changes are never merged automatically.";

export const LOCAL_DRAFT_UNSAVED_NOTE =
  "Local unsaved changes — not yet saved as a revision. They live only in this browser session until you save.";

// ------------------------------------------------------------ closed codes

/** Closed-code copy for the topology-authoring contract (PR-14). Backend
 *  free-form messages are never rendered — only these fixed strings. */
export const TOPOLOGY_ERROR_TEXT: Record<string, string> = {
  domain_error: "That action is not allowed in the current state.",
  not_found: "The requested record was not found.",
  validation_failed: "The request was rejected by the server's validation.",
  forbidden: "You do not have permission for that action.",
  topology_not_found: "The topology document was not found.",
  topology_revision_not_found: "That topology revision was not found.",
  topology_revision_stale:
    "Your draft is based on a revision that is no longer current. Nothing was overwritten.",
  topology_hash_mismatch:
    "The base revision changed on the server. Nothing was overwritten — review the latest revision.",
  topology_revision_not_current:
    "That action targets a revision that is no longer the current one.",
  topology_schema_invalid:
    "The topology draft is not valid against the schema and was not saved.",
  topology_validation_required:
    "The revision must be validated before it can be submitted.",
  topology_validation_not_current:
    "The current validation no longer matches this revision. Re-validate before submitting.",
  topology_already_submitted:
    "That revision has already been submitted and is locked for review.",
  topology_revision_immutable: "That revision is immutable and cannot be changed.",
  topology_approval_required: "A recorded approval is required before this action.",
  topology_not_submitted: "That revision is not currently submitted for review.",
  topology_permission_denied: "You do not have permission for that action.",
  topology_document_too_large: "The topology draft is too large to save.",
  topology_secret_field_forbidden:
    "The draft contains a secret-shaped field and was rejected. Remove it and try again.",
  topology_unknown_object_kind:
    "The draft contains an unsupported node or relationship kind.",
  topology_invalid_relationship: "The draft contains an unsupported relationship.",
  topology_cross_org_forbidden: "That record belongs to another organization.",
  topology_source_not_found: "The source environment version was not found.",
};

// ------------------------------------------------------------ permissions

export interface TopologyPermissions {
  read: boolean;
  draft: boolean;
  validate: boolean;
  submit: boolean;
  decide: boolean;
}

/** Resolve topology permissions from the server-provided principal permission
 *  list. Permissions come only from the server contract, never local state. */
export function resolveTopologyPermissions(
  permissions: readonly string[] | null | undefined,
): TopologyPermissions {
  const has = (p: string) => Boolean(permissions?.includes(p));
  return {
    read: has("topology:read"),
    draft: has("topology:draft"),
    validate: has("topology:validate"),
    submit: has("topology:submit"),
    decide: has("topology:decide"),
  };
}

// --------------------------------------------------------------- posture

export type WorkspacePosture =
  | "disabled" // persistence feature off — local-only (PR-13)
  | "no-document" // no authoring document resolved yet
  | "unavailable" // authoring document failed to load (not a not-found)
  | "read-only" // loaded, but the user lacks draft permission
  | "matches-saved" // local draft equals the current authoritative revision
  | "local-unsaved" // local edits not yet saved as a revision
  | "stale-base" // local base revision is no longer the server's current one
  | "submitted-locked" // current revision is submitted — read-only for review
  | "approved" // current revision approved (decision recorded, not deployed)
  | "rejected"; // current revision rejected

export interface PostureInputs {
  enabled: boolean;
  documentId: string | null;
  loadFailed: boolean; // load failed AND it was not a not-found
  document: TopologyDocumentDetail | null;
  /** Current revision number the local draft is based on (null before load). */
  baseRevisionNumber: number | null;
  /** True when the local draft diverges from the loaded authoritative content. */
  dirty: boolean;
  permissions: TopologyPermissions;
}

export function derivePosture(inp: PostureInputs): WorkspacePosture {
  if (!inp.enabled) return "disabled";
  if (inp.loadFailed) return "unavailable";
  if (inp.documentId === null || inp.document === null) return "no-document";

  const rev = inp.document.current_revision;
  // Stale ONLY when the local base is BEHIND the server's current revision.
  // (A base ahead of the server is the brief transient window right after a
  // successful save, before the authoritative reload settles — never a stale
  // conflict, so it must not flash the conflict panel.)
  if (
    rev !== null &&
    inp.baseRevisionNumber !== null &&
    inp.baseRevisionNumber < rev.revision_number
  ) {
    return "stale-base";
  }

  const revStatus = rev?.status ?? "draft";
  if (revStatus === "submitted") return "submitted-locked";
  if (revStatus === "approved") return "approved";
  if (revStatus === "rejected") return "rejected";

  if (!inp.permissions.draft) return "read-only";
  return inp.dirty ? "local-unsaved" : "matches-saved";
}

/** Editing is only meaningful when the current revision is still an editable
 *  draft/validated revision and the user may draft. Submitted/approved/rejected
 *  and historical revisions are read-only. */
export function postureAllowsEditing(
  posture: WorkspacePosture,
  viewingHistorical: boolean,
): boolean {
  if (viewingHistorical) return false;
  return posture === "matches-saved" || posture === "local-unsaved";
}

// --------------------------------------------------------- control eligibility

export interface ControlEligibility {
  eligible: boolean;
  reason?: string;
}

export interface ControlsInputs {
  posture: WorkspacePosture;
  permissions: TopologyPermissions;
  dirty: boolean;
  hasSemanticChanges: boolean;
  /** The current revision's own status (draft/validated/submitted/...). */
  currentRevisionStatus: string | null;
  /** Validation status of the current revision, from the server read model. */
  currentValidationStatus: TopologyValidationStatus | null;
  viewingHistorical: boolean;
}

const OK: ControlEligibility = { eligible: true };
const no = (reason: string): ControlEligibility => ({ eligible: false, reason });

/** Save a new revision: needs draft permission, real semantic changes, an
 *  editable (non-locked) current revision, and not viewing history. */
export function canSaveRevision(c: ControlsInputs): ControlEligibility {
  if (!c.permissions.draft) return no("Requires topology:draft permission.");
  if (c.viewingHistorical)
    return no("Loading a historical revision is read-only. Load the latest to edit.");
  if (c.posture === "stale-base")
    return no("Your base revision is stale — review the latest before saving.");
  if (c.posture === "submitted-locked")
    return no("The current revision is submitted and locked for review.");
  if (!c.hasSemanticChanges) return no("No local changes to save.");
  return OK;
}

const TERMINAL_STATUS = new Set(["submitted", "approved", "rejected", "superseded"]);

/** Validate the CURRENT saved revision — never a local draft. Blocked while
 *  there are unsaved changes (an unsaved draft is not server content) and on
 *  any terminal/immutable revision (submitted/approved/rejected/superseded). */
export function canValidateRevision(c: ControlsInputs): ControlEligibility {
  if (!c.permissions.validate) return no("Requires topology:validate permission.");
  if (c.viewingHistorical) return no("Load the latest revision to validate.");
  if (c.dirty) return no("Save your changes before validating the revision.");
  if (c.currentRevisionStatus && TERMINAL_STATUS.has(c.currentRevisionStatus))
    return no("This revision is immutable and cannot be re-validated.");
  return OK;
}

/** Submit the current validated revision. Blocked by unsaved changes and by
 *  stale/absent validation (the contract requires a current valid result). */
export function canSubmitRevision(c: ControlsInputs): ControlEligibility {
  if (!c.permissions.submit) return no("Requires topology:submit permission.");
  if (c.viewingHistorical) return no("Load the latest revision to submit.");
  if (c.dirty) return no("Save your changes before submitting.");
  if (c.currentRevisionStatus && TERMINAL_STATUS.has(c.currentRevisionStatus))
    return no("This revision is immutable and cannot be submitted again.");
  if (
    c.currentValidationStatus !== "valid" &&
    c.currentValidationStatus !== "valid_with_warnings"
  ) {
    return no("Validate the revision (currently valid) before submitting.");
  }
  return OK;
}

export function canDecide(c: ControlsInputs): ControlEligibility {
  if (!c.permissions.decide) return no("Requires topology:decide permission.");
  if (c.viewingHistorical) return no("Load the submitted revision to decide.");
  if (c.currentRevisionStatus !== "submitted")
    return no("Only a submitted revision can be approved or rejected.");
  return OK;
}

// ----------------------------------------------------------- validation view

export type ValidationDisplay =
  | "not-run"
  | "valid"
  | "valid_with_warnings"
  | "invalid"
  | "unverifiable"
  | "stale";

const VALIDATION_LABEL: Record<ValidationDisplay, string> = {
  "not-run": "Not validated",
  valid: "Valid (schema only — not approval)",
  valid_with_warnings: "Valid — with warnings",
  invalid: "Invalid",
  unverifiable: "Unverifiable",
  stale: "Validation stale — re-run against the current revision",
};

export interface ValidationView {
  display: ValidationDisplay;
  label: string;
  errorCount: number;
  warningCount: number;
  findings: { severity: string; code: string; nodeId?: string; edgeId?: string }[];
}

const KNOWN_FINDING = /^[a-z0-9_]{1,48}$/;

/**
 * Structured, allowlisted view of a validation result. `dirtySinceValidation`
 * marks a validated revision whose local draft has since changed as stale — an
 * unsaved local draft can never be presented as server-validated.
 */
export function validationView(
  result: TopologyValidationResult | null,
  currentServerStatus: TopologyValidationStatus | null,
  dirtySinceValidation: boolean,
): ValidationView {
  if (result === null) {
    // The server read model may still report a stale posture for the current
    // revision even when no per-revision result is loaded.
    const display: ValidationDisplay =
      currentServerStatus === "stale" ? "stale" : "not-run";
    return { display, label: VALIDATION_LABEL[display], errorCount: 0, warningCount: 0, findings: [] };
  }
  let display: ValidationDisplay = result.status;
  if (dirtySinceValidation || currentServerStatus === "stale") display = "stale";
  const findings = (result.findings ?? [])
    .filter(
      (f) =>
        f &&
        typeof f.severity === "string" &&
        typeof f.code === "string" &&
        KNOWN_FINDING.test(f.code),
    )
    .slice(0, 50)
    .map((f) => ({
      severity: f.severity === "error" ? "error" : "warning",
      code: f.code,
      nodeId: typeof f.node_id === "string" ? f.node_id : undefined,
      edgeId: typeof f.edge_id === "string" ? f.edge_id : undefined,
    }));
  return {
    display,
    label: VALIDATION_LABEL[display],
    errorCount: typeof result.error_count === "number" ? result.error_count : 0,
    warningCount: typeof result.warning_count === "number" ? result.warning_count : 0,
    findings,
  };
}

// ------------------------------------------------------------- conflict

export interface ConflictInfo {
  localRevisionNumber: number | null;
  localBaseHash: string | null;
  serverRevisionNumber: number | null;
  serverHash: string | null;
}

/** Build the fixed conflict summary for a stale-base state. Shows local vs
 *  server revision/hash so the operator can decide — never auto-merges. */
export function conflictInfo(
  baseRevisionNumber: number | null,
  baseHash: string | null,
  document: TopologyDocumentDetail | null,
): ConflictInfo {
  const rev = document?.current_revision ?? null;
  return {
    localRevisionNumber: baseRevisionNumber,
    localBaseHash: baseHash,
    serverRevisionNumber: rev?.revision_number ?? null,
    serverHash: rev?.content_hash ?? null,
  };
}

// ------------------------------------------------------------- history

export interface RevisionRow {
  id: string;
  revisionNumber: number;
  contentHash: string;
  parentRevisionId: string | null;
  status: string;
  changeNote: string | null;
  createdBy: string | null;
  createdAt: string;
  isCurrent: boolean;
}

/** History rows in the API's order (newest first), marking the current
 *  revision. Actor/timestamp come only from real data. */
export function revisionRows(
  revisions: readonly TopologyRevisionSummary[],
  currentRevisionId: string | null,
): RevisionRow[] {
  return revisions.map((r) => ({
    id: r.id,
    revisionNumber: r.revision_number,
    contentHash: r.content_hash,
    parentRevisionId: r.parent_revision_id,
    status: r.status,
    changeNote: r.change_note,
    createdBy: r.created_by,
    createdAt: r.created_at,
    isCurrent: r.id === currentRevisionId,
  }));
}

export const REVISION_STATUS_LABEL: Record<string, string> = {
  draft: "Draft",
  validated: "Validated",
  submitted: "Submitted (locked for review)",
  approved: "Approved (decision recorded — not deployed)",
  rejected: "Rejected",
  superseded: "Superseded",
};

export function revisionStatusLabel(status: string): string {
  return REVISION_STATUS_LABEL[status] ?? status;
}

// ----------------------------------------------------------- posture copy

export const POSTURE_LABEL: Record<WorkspacePosture, string> = {
  disabled: "Local draft only",
  "no-document": "No topology document",
  unavailable: "Topology document unavailable",
  "read-only": "Read-only (no draft permission)",
  "matches-saved": "Matches saved revision",
  "local-unsaved": "Local unsaved changes",
  "stale-base": "Stale base revision — review latest",
  "submitted-locked": "Submitted — locked for review",
  approved: "Approved (decision recorded)",
  rejected: "Rejected",
};

export function postureLabel(posture: WorkspacePosture): string {
  return POSTURE_LABEL[posture];
}

/** The single most important truth line for a posture. */
export function postureNote(posture: WorkspacePosture): string {
  switch (posture) {
    case "local-unsaved":
      return LOCAL_DRAFT_UNSAVED_NOTE;
    case "stale-base":
      return STALE_BASE_NOTE;
    case "submitted-locked":
      return "This revision is submitted and immutable. Later edits create a new revision.";
    case "approved":
      return DECISION_NOTE;
    case "rejected":
      return "This revision was rejected. Create a new revision to continue.";
    case "matches-saved":
      return "Your workspace matches the current saved revision.";
    default:
      return "";
  }
}

/** Detail exposure guard: a revision detail's document_content is the canonical
 *  secret-free document, but never render a `document_content` that carries an
 *  unexpected/secret-shaped key. Returns true when safe to render. */
export function revisionContentIsRenderable(
  revision: TopologyRevisionDetail | null,
): boolean {
  if (revision === null) return true;
  const content = revision.document_content;
  if (content === null || typeof content !== "object") return false;
  const allowed = new Set(["schema_version", "nodes", "edges", "networks", "zones"]);
  return Object.keys(content).every((k) => allowed.has(k));
}
