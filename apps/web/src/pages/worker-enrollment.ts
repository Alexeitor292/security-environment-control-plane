// Worker-enrollment view model (SECP-PR5H-B1) — pure, no React, no I/O.
//
// This module is the tested source of truth for every predicate, grammar and piece of safety copy
// the page renders. It reinterprets no lifecycle rule: the state order, the id grammar, the site
// label grammar and the TTL bounds are all mirrored from the backend contract, and the service
// stays authoritative for all of them.
//
// SCOPE. The controller exposes exactly four enrollment routes to a browser principal: create an
// invitation, read the bounded status projection, list the organization's enrollments, and revoke.
// There is deliberately no approve or reject here — the enrollment lifecycle has no approval edge.
// Every forward transition is driven by the worker's signed cryptographic evidence, and revoke is
// the only operator write in the entire lifecycle.

import type { EnrollmentInvitation, EnrollmentStatus } from "../api/types";
import type { StepRailItem } from "../components/ui/StepRail";

// --------------------------------------------------------------------------- safety copy
//
// Rendered by the page as exported constants — never re-typed in JSX.

export const ENROLLMENT_INTRO =
  "Create a single-use invitation for one worker, hand it to that worker, and follow the enrollment it opens. The control plane contacts no worker and opens no outbound connection: it records the invitation and waits for the worker to arrive.";

/** The load-bearing disclosure on the hand-off panel. The invitation carries no private key, but
 *  possession of it is what lets a worker bind — so it is bearer-grade in practice. */
export const HANDOFF_BEARER_NOTICE =
  "Treat this invitation as a credential. It contains no private key, but whoever presents it first with a valid key becomes the enrolled worker. Deliver it to exactly one worker over a channel you trust, and revoke it if it goes anywhere else.";

/** Shown before the material is revealed, because no route re-serves it. */
export const HANDOFF_ONE_TIME_NOTICE =
  "This is the only time these values are available. No endpoint re-serves them — if you lose them, revoke this enrollment and create a new one.";

export const HANDOFF_REVEAL_LABEL = "Reveal invitation for hand-off";

/** Announced after the operator dismisses an invitation. Dismissing removes the whole card, which
 *  takes the focused control with it — so the outcome is stated in a persistent live region rather
 *  than left as a silent disappearance, and it says plainly that the material is not recoverable. */
export const INVITATION_CLEARED_NOTICE =
  "Invitation cleared from this browser. No endpoint re-serves it, so it cannot be shown again — create a new invitation if you still need to hand one over.";

/** Where the organization-wide view lives. This page stays the create-and-hand-over surface: a
 *  look-up by id is still the fastest path when an operator already has the id in front of them. */
export const NO_INVENTORY_NOTICE =
  "This looks up one enrollment at a time, by id. The Enrollment Inventory page lists every enrollment in your organization, including the ones waiting on a worker.";

/** The truthful framing for the lifecycle rail: these states are not operator decisions. */
export const WORKER_DRIVEN_NOTICE =
  "Enrollment advances only on evidence the worker signs. Nothing on this page approves or advances an enrollment — the one operator action is revoking it.";

export const REVOKE_CONFIRM_NOTICE =
  "Revoking is permanent for this enrollment. It cannot be undone, and a worker holding this invitation will no longer be able to enrol with it.";

// --------------------------------------------------------------------------- closed-code copy
//
// Fixed UI copy per closed code. A backend message is never rendered as display text.
//
// Two distinct 403s reach this surface and they mean different things:
//   "forbidden"            — AuthorizationError: the principal lacks the permission (errors.py).
//   "enrollment_forbidden" — the organization boundary refused a record owned by another org.

export const ENROLLMENT_ERROR_TEXT: Record<string, string> = {
  // Not an error condition. An uncommissioned controller has no active enrollment identity yet,
  // and this is exactly what that looks like — say so plainly rather than alarming the operator.
  enrollment_controller_identity_unavailable:
    "This controller has no active enrollment identity yet, so it cannot issue invitations. That is the expected state until the controller is commissioned — nothing is broken and nothing was written.",
  forbidden:
    "You are not permitted to perform this action. Creating and revoking invitations requires enrollment:manage, and reading status requires enrollment:read — these are separate permissions, and neither implies the other.",
  enrollment_forbidden:
    "That enrollment belongs to another organization. Records are never readable across the organization boundary.",
  enrollment_not_found:
    "No enrollment exists with that id. Check the id you pasted; ids are not guessable and are never listed.",
  enrollment_revision_conflict:
    "This enrollment changed since the status you are looking at. Reload it and try again — nothing was written.",
  enrollment_idempotency_conflict:
    "An invitation was already created with this request key but different details. Start a new invitation rather than reusing this one.",
  enrollment_invitation_expired:
    "This invitation has passed its expiry and can no longer be used. Create a new one.",
  enrollment_invitation_revoked:
    "This invitation was already revoked and can no longer be used.",
  enrollment_invitation_consumed:
    "This invitation has already been used by a worker. Each invitation admits exactly one worker.",
  enrollment_expired:
    "This enrollment has passed its expiry. Create a new invitation to enrol a worker.",
  enrollment_scope_mismatch:
    "The deployment site label was rejected. Use a label of letters, digits, dot, dash or underscore, starting with a letter or digit.",
  enrollment_identity_conflict:
    "The controller's enrollment identity changed while this request was in flight. Try again — nothing was written.",
  enrollment_state_corrupt:
    "This enrollment's stored state failed its own integrity check and will not be shown. Report this to an administrator; the record is preserved, not repaired.",
  // Both are list-route codes. They are in the shared map because the map is what any enrollment
  // call resolves against; the inventory layers a page-specific message over the first of them,
  // where "corrupt" means one row in a page rather than the record you asked for.
  enrollment_cursor_invalid:
    "The page position this request carried was not valid, so no page was returned. Load the list again from the first page.",
  enrollment_state_invalid:
    "That lifecycle filter was refused. Choose one of the filters offered above rather than editing the address bar.",
  enrollment_history_inconsistent:
    "This enrollment's history failed its own integrity check and will not be shown. Report this to an administrator; the record is preserved, not repaired.",
  configuration_invalid:
    "This deployment's API address is not valid, so no request was sent.",
};

// --------------------------------------------------------------------------- id grammar
//
// enrollment_id is the sha256 content address of the invitation ("sha256:" + 64 lowercase hex).
// Validated here so a pasted value is proven safe before it is interpolated into a request path.

const ENROLLMENT_ID = /^sha256:[0-9a-f]{64}$/;

export function isEnrollmentId(value: string): boolean {
  return ENROLLMENT_ID.test(value);
}

export const ENROLLMENT_ID_HINT =
  'An enrollment id looks like "sha256:" followed by 64 hexadecimal characters.';

/** Trim-and-validate a pasted id. Whitespace is forgiven because ids are copied, never typed. */
export function parseEnrollmentId(raw: string): {
  ok: boolean;
  value: string;
  error?: string;
} {
  const value = raw.trim();
  if (!value) return { ok: false, value, error: "Enter an enrollment id." };
  if (!isEnrollmentId(value)) {
    return { ok: false, value, error: ENROLLMENT_ID_HINT };
  }
  return { ok: true, value };
}

// --------------------------------------------------------------------------- site label
//
// Mirrors DEPLOYMENT_SITE_LABEL_PATTERN. The label is an opaque grouping label: it is never
// interpreted as a tenant, address, region, endpoint or provider, and organization remains the
// only authorization boundary.

const SITE_LABEL = /^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/;

export const SITE_LABEL_HINT =
  "An opaque grouping label for your own use — letters, digits, dot, dash or underscore, starting with a letter or digit. It is not a tenant, address or region, and it grants nothing.";

export function validateSiteLabel(raw: string): {
  ok: boolean;
  value: string;
  error?: string;
} {
  const value = raw.trim();
  if (!value) return { ok: false, value, error: "Enter a deployment site label." };
  if (value.length > 120) {
    return { ok: false, value, error: "Use 120 characters or fewer." };
  }
  if (!SITE_LABEL.test(value)) {
    return { ok: false, value, error: SITE_LABEL_HINT };
  }
  return { ok: true, value };
}

// --------------------------------------------------------------------------- ttl

export const TTL_MIN_SECONDS = 1;
export const TTL_MAX_SECONDS = 86400;
export const TTL_DEFAULT_SECONDS = 3600;

export const TTL_HINT =
  "How long the worker has to use this invitation, from 1 second to 24 hours. Shorter is safer.";

export function parseTtlSeconds(raw: string): {
  ok: boolean;
  value: number;
  error?: string;
} {
  const trimmed = raw.trim();
  if (!/^[0-9]+$/.test(trimmed)) {
    return { ok: false, value: 0, error: "Enter a whole number of seconds." };
  }
  const value = Number(trimmed);
  if (value < TTL_MIN_SECONDS || value > TTL_MAX_SECONDS) {
    return {
      ok: false,
      value,
      error: `Use between ${TTL_MIN_SECONDS} and ${TTL_MAX_SECONDS} seconds (24 hours).`,
    };
  }
  return { ok: true, value };
}

// --------------------------------------------------------------------------- idempotency key
//
// A high-entropy single-use request key the interface generates automatically — the backend
// grammar is 22-128 url-safe characters and it is explicitly never typed by a human. The raw key
// is never persisted or logged by the server; only its organization-bound digest becomes the
// durable nonce. 32 random bytes encode to 43 characters, comfortably inside the bound.

const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** Unpadded base64url over raw bytes. Pure, so the encoding is testable without a random source.
 *  Base64 consumes exactly 6 bits per character, so every byte value maps uniformly — there is no
 *  modulo bias, which matters because this value becomes a single-use nonce. */
export function encodeIdempotencyKey(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : undefined;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : undefined;
    out += B64URL[b0 >> 2];
    out += B64URL[((b0 & 0x03) << 4) | ((b1 ?? 0) >> 4)];
    if (b1 === undefined) break;
    out += B64URL[((b1 & 0x0f) << 2) | ((b2 ?? 0) >> 6)];
    if (b2 === undefined) break;
    out += B64URL[b2 & 0x3f];
  }
  return out;
}

const IDEMPOTENCY_KEY = /^[A-Za-z0-9_-]{22,128}$/;

export function isIdempotencyKey(value: string): boolean {
  return IDEMPOTENCY_KEY.test(value);
}

/** 256 bits from the platform CSPRNG. Not pure — the pure half is `encodeIdempotencyKey`. */
export function newIdempotencyKey(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return encodeIdempotencyKey(bytes);
}

// --------------------------------------------------------------------------- lifecycle

/** The five forward edges, in contract order. `refused` and `recovery_required` are terminals off
 *  this path, not steps on it, so they are not rail entries. */
export const ENROLLMENT_FORWARD_STATES = [
  "invited",
  "worker_bound",
  "offer_transported",
  "result_transported",
  "verified",
  "healthy",
] as const;

export type EnrollmentForwardState = (typeof ENROLLMENT_FORWARD_STATES)[number];

/** Operator-facing step labels. Each names who acts, so no step reads as a control-plane action. */
export const ENROLLMENT_STEP_LABELS: Record<EnrollmentForwardState, string> = {
  invited: "Invitation open — waiting for the worker",
  worker_bound: "Worker proved key possession",
  offer_transported: "Controller offer signed and delivered",
  result_transported: "Worker returned a signed result",
  verified: "Release verified",
  healthy: "Worker healthy",
};

export const ENROLLMENT_TERMINAL_LABELS: Record<string, string> = {
  refused: "Refused — no worker enrolled",
  recovery_required: "Recovery required — expired before completing",
};

export function isTerminalState(state: string): boolean {
  return state === "refused" || state === "recovery_required";
}

/**
 * The lifecycle rail for a status. Purely presentational — the page passes no `onSelect`, because
 * no step on this rail is an action a person can take.
 *
 * A terminal enrollment marks the steps it actually reached as complete and the rest as blocked,
 * with the terminal named as the reason. An unknown state (a backend that moved ahead of this
 * build) blocks every step rather than guessing a position.
 */
export function enrollmentStepItems(state: string): StepRailItem[] {
  const terminal = isTerminalState(state);
  const reachedIndex = ENROLLMENT_FORWARD_STATES.indexOf(
    state as EnrollmentForwardState,
  );
  const known = terminal || reachedIndex >= 0;
  const blockedReason = terminal
    ? ENROLLMENT_TERMINAL_LABELS[state]
    : "Not reached yet.";

  return ENROLLMENT_FORWARD_STATES.map((forward, index) => {
    let itemState: StepRailItem["state"];
    if (!known) {
      itemState = "blocked";
    } else if (terminal) {
      itemState = "blocked";
    } else if (index < reachedIndex) {
      itemState = "complete";
    } else if (index === reachedIndex) {
      // The last forward state is an end state, not an in-flight step.
      itemState = forward === "healthy" ? "complete" : "current";
    } else {
      itemState = "blocked";
    }
    return {
      id: forward,
      label: ENROLLMENT_STEP_LABELS[forward],
      state: itemState,
      ...(itemState === "blocked"
        ? {
            blockedReason: known
              ? blockedReason
              : "This enrollment reports a state this interface does not recognise.",
          }
        : {}),
    };
  });
}

// --------------------------------------------------------------------------- expiry

export interface ExpiryView {
  /** false when the timestamp could not be parsed — never guessed. */
  valid: boolean;
  expired: boolean;
  remainingSeconds: number;
  /** Fixed, human copy. Never a raw timestamp arithmetic result. */
  label: string;
}

/** Whole-unit, deliberately coarse: an operator needs "about an hour", not a ticking clock. */
function coarseDuration(seconds: number): string {
  if (seconds < 60) return `${seconds} second${seconds === 1 ? "" : "s"}`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? "" : "s"}`;
  const hours = Math.floor(minutes / 60);
  const restMinutes = minutes % 60;
  if (restMinutes === 0) return `${hours} hour${hours === 1 ? "" : "s"}`;
  return `${hours} h ${restMinutes} min`;
}

export function expiryView(expiresAt: string, nowMs: number): ExpiryView {
  const parsed = Date.parse(expiresAt);
  if (Number.isNaN(parsed)) {
    return {
      valid: false,
      expired: false,
      remainingSeconds: 0,
      label: "Expiry unavailable",
    };
  }
  const remainingSeconds = Math.floor((parsed - nowMs) / 1000);
  if (remainingSeconds <= 0) {
    return { valid: true, expired: true, remainingSeconds: 0, label: "Expired" };
  }
  return {
    valid: true,
    expired: false,
    remainingSeconds,
    label: `Expires in ${coarseDuration(remainingSeconds)}`,
  };
}

// --------------------------------------------------------------------------- hand-off material

export interface HandoffField {
  key: string;
  label: string;
  value: string;
}

/**
 * Exactly the fields a worker consumes to drive its enrollment, in the order the shipped worker
 * transport declares them. Nothing else is included: this block is bearer-grade, so it carries
 * what the worker needs and no more. The controller trust anchor is deliberately absent — the
 * worker pins the controller key id it already receives — and is surfaced separately as
 * out-of-band verification context.
 *
 * DELIBERATELY AN EXPLICIT ENUMERATION, never `Object.entries(invitation)`. Explicitness is the
 * whole safety property: a field added to `EnrollmentInvitation` tomorrow cannot auto-render into
 * a bearer-grade block that gets copied to a worker. Omission over leakage — a missing field is a
 * visible bug the worker reports, an unintended field is a silent disclosure nobody sees.
 *
 * `key` is the API's OWN field name, because this is what the CLI parses (see `handoffText`).
 * `transaction_id` is therefore not renamed to the worker-facing "controller transaction id" —
 * that name reaches the operator through `label`, which is display-only.
 */
export function handoffFields(invitation: EnrollmentInvitation): HandoffField[] {
  return [
    { key: "enrollment_id", label: "Enrollment id", value: invitation.enrollment_id },
    { key: "invitation_id", label: "Invitation id", value: invitation.invitation_id },
    {
      key: "controller_installation_id",
      label: "Controller installation id",
      value: invitation.controller_installation_id,
    },
    {
      key: "controller_key_id",
      label: "Controller key id",
      value: invitation.controller_key_id,
    },
    {
      key: "controller_origin",
      label: "Controller origin",
      value: invitation.controller_origin,
    },
    {
      key: "transaction_id",
      label: "Controller transaction id",
      value: invitation.transaction_id,
    },
    { key: "release_digest", label: "Release digest", value: invitation.release_digest },
    { key: "expires_at", label: "Expires at", value: invitation.expires_at },
  ];
}

/** The hand-off block as a plain object, built from `handoffFields` so there is exactly ONE
 *  producer. A second, independent enumeration would be free to drift from the displayed one —
 *  and every "nothing leaks before the reveal" assertion is only as good as the artefact it is
 *  derived from. Insertion order is preserved (no key is integer-like), so `JSON.stringify` emits
 *  the fields in the declared order. */
export function handoffPayload(invitation: EnrollmentInvitation): Record<string, string> {
  const payload: Record<string, string> = {};
  for (const field of handoffFields(invitation)) payload[field.key] = field.value;
  return payload;
}

/**
 * The hand-off block as one copyable document: strict JSON, two-space indented, stable key order,
 * so two operators comparing their copies see identical text.
 *
 * JSON rather than newline-delimited `key: value`, for two reasons that are not stylistic:
 *
 *  1. It is the format the shipped CLI already reads, and this is the load-bearing reason.
 *     `load_invitation_file` does a bounded read and `json.loads`, then requires exactly these
 *     eight API-named string keys. A newline-delimited block had no machine-readable path out of
 *     this interface at all: an operator could not save it and run
 *     `secpctl worker enroll --invitation <file>`. Now they can, byte for byte.
 *  2. `key: value` lines cannot represent every value the contract permits. Each of these fields is
 *     typed as an unconstrained string the server chooses; nothing in the browser stops one from
 *     containing a newline, and a line-delimited block would silently split it into two records.
 *     No field is multi-line today — this is about the format being closed under what the contract
 *     already allows, not about any particular field arriving later.
 */
export function handoffText(invitation: EnrollmentInvitation): string {
  return JSON.stringify(handoffPayload(invitation), null, 2);
}

/** Why the block is JSON, said to the operator rather than left implicit. */
export const HANDOFF_FILE_NOTICE =
  "Save this block as a .json file on the worker and run `secpctl worker enroll --invitation <file>`. The keys are the controller's own field names, so the file is read as-is — do not rename, reorder or add to it.";

// --------------------------------------------------------------------------- permissions
//
// UI gating is usability only — it explains why a control is unavailable instead of presenting a
// button that will fail. The service is authoritative and re-checks every call.

export interface EnrollmentPermissions {
  read: boolean;
  manage: boolean;
}

export function resolveEnrollmentPermissions(
  permissions: readonly string[] | null | undefined,
): EnrollmentPermissions {
  const has = (p: string) => Boolean(permissions?.includes(p));
  return { read: has("enrollment:read"), manage: has("enrollment:manage") };
}

export const MISSING_MANAGE_REASON =
  "Requires the enrollment:manage permission.";
export const MISSING_READ_REASON = "Requires the enrollment:read permission.";

/**
 * The consequence of the backend's pinned decision that enrollment:manage does NOT imply
 * enrollment:read: an operator who can create an invitation may be unable to read the status of
 * the enrollment they just opened. The page says so up front rather than letting it surface as an
 * unexplained refusal after the fact.
 */
export const MANAGE_WITHOUT_READ_NOTICE =
  "You can create and revoke invitations but not read enrollment status — these are separate permissions and manage does not include read. Invitations you create here will succeed; looking up their status will be refused until an organization admin grants enrollment:read.";

export function shouldWarnManageWithoutRead(p: EnrollmentPermissions): boolean {
  return p.manage && !p.read;
}

// --------------------------------------------------------------------------- action gates

export interface Gate {
  ok: boolean;
  reason?: string;
}

const allowed: Gate = { ok: true };
function denied(reason: string): Gate {
  return { ok: false, reason };
}

export function createGate(
  p: EnrollmentPermissions,
  site: { ok: boolean },
  ttl: { ok: boolean },
  busy: boolean,
): Gate {
  if (!p.manage) return denied(MISSING_MANAGE_REASON);
  if (!site.ok) return denied("Enter a valid deployment site label.");
  if (!ttl.ok) return denied("Enter a valid lifetime in seconds.");
  if (busy) return denied("A request is already in flight.");
  return allowed;
}

export function lookupGate(
  p: EnrollmentPermissions,
  id: { ok: boolean },
  busy: boolean,
): Gate {
  if (!p.read) return denied(MISSING_READ_REASON);
  if (!id.ok) return denied("Enter a valid enrollment id.");
  if (busy) return denied("A request is already in flight.");
  return allowed;
}

/**
 * Revoke is the only operator write in the lifecycle. It is offered only against a status that was
 * actually observed, because the request must carry that status's revision — never a typed value.
 * An already-terminal enrollment is refused here with an explanation; the backend would treat it
 * as an idempotent no-op, but presenting a live button for it would imply there is something left
 * to revoke.
 */
export function revokeGate(
  p: EnrollmentPermissions,
  status: EnrollmentStatus | null,
  busy: boolean,
): Gate {
  if (!p.manage) return denied(MISSING_MANAGE_REASON);
  if (status === null) {
    return denied("Look up an enrollment before revoking it.");
  }
  if (isTerminalState(status.state)) {
    return denied(
      status.state === "refused"
        ? "This enrollment is already refused."
        : "This enrollment already requires recovery and cannot be revoked.",
    );
  }
  if (busy) return denied("A request is already in flight.");
  return allowed;
}

// --------------------------------------------------------------------------- status detail

export interface DetailRow {
  key: string;
  value: string;
  mono: boolean;
}

export const NOT_ESTABLISHED = "Not established yet";

/** An empty fingerprint means "not established yet", which is meaningful lifecycle information —
 *  it is shown as such rather than as a blank cell or an invented placeholder. */
function fingerprint(value: string): string {
  return value === "" ? NOT_ESTABLISHED : value;
}

export const SITE_NOT_IN_PROJECTION = "Not carried by this controller's projection";

/**
 * The deployment site label from a status projection, or "" when this controller does not carry it.
 *
 * The label is part of the pinned projection contract, but the browser bundle and the controller
 * are deployed independently: a controller built before that projection change returns a body
 * without the key, and TypeScript cannot check a server response. Every read goes through here so
 * the fallback is one decision in one place, and so a missing label is never rendered as the string
 * "undefined" or quietly guessed from somewhere else.
 */
export function siteLabelOf(status: EnrollmentStatus): string {
  const label: unknown = status.deployment_site_label;
  return typeof label === "string" ? label : "";
}

/** The status projection as display rows. Every value here is already a bounded, secret-free
 *  server projection: identities appear only as short non-reversible fingerprints. */
export function statusDetailRows(status: EnrollmentStatus): DetailRow[] {
  const site = siteLabelOf(status);
  const rows: DetailRow[] = [
    { key: "Enrollment id", value: status.enrollment_id, mono: true },
    {
      key: "Deployment site",
      value: site === "" ? SITE_NOT_IN_PROJECTION : site,
      mono: site !== "",
    },
    { key: "Revision", value: String(status.revision), mono: false },
    {
      key: "Controller installation",
      value: status.controller_installation_id,
      mono: true,
    },
    {
      key: "Controller key fingerprint",
      value: fingerprint(status.controller_key_fingerprint),
      mono: true,
    },
    {
      key: "Worker installation",
      value: fingerprint(status.worker_installation_id),
      mono: true,
    },
    {
      key: "Worker key fingerprint",
      value: fingerprint(status.worker_key_fingerprint),
      mono: true,
    },
    {
      key: "Release fingerprint",
      value: fingerprint(status.release_fingerprint),
      mono: true,
    },
    {
      key: "Offer fingerprint",
      value: fingerprint(status.offer_fingerprint),
      mono: true,
    },
    {
      key: "Result fingerprint",
      value: fingerprint(status.result_fingerprint),
      mono: true,
    },
    { key: "Expires at", value: status.expires_at, mono: true },
    { key: "Last updated", value: status.updated_at, mono: true },
  ];
  if (status.refusal_reason !== "") {
    // A bounded lowercase reason code, never prose — displayed verbatim as the code it is.
    rows.push({ key: "Refusal reason", value: status.refusal_reason, mono: true });
  }
  return rows;
}

// --------------------------------------------------------------------------- evidence

/**
 * One rung of the enrollment's evidence chain. Each rung is a short non-reversible fingerprint the
 * controller recorded when a signed exchange step completed — the projection carries no signature,
 * no key and no transcript, so this is the whole of the evidence a browser can see.
 */
export interface EvidenceItem {
  /** The status-projection field this rung reads, shown verbatim so it can be matched to the API. */
  field: string;
  /** Human name for the rung. */
  label: string;
  /** What an established value on this rung actually proves. Never more than that. */
  proves: string;
  /**
   * "pass" once established, "unverifiable" until then — deliberately NEVER "fail". An unreached
   * rung has not happened; calling it a failure would invent a verdict the controller never
   * returned, and would make a healthy in-flight enrollment look broken.
   */
  status: "pass" | "unverifiable";
  value: string;
}

export const EVIDENCE_NOTICE =
  "Each rung records that one signed step completed, as a short non-reversible fingerprint. A rung that is not established yet simply has not happened — it is not a failed check, and nothing on this page renders it as one. The controller keeps the signatures; a browser never sees them.";

export function enrollmentEvidence(status: EnrollmentStatus): EvidenceItem[] {
  const rung = (
    field: string,
    label: string,
    proves: string,
    raw: string,
  ): EvidenceItem => ({
    field,
    label,
    proves,
    status: raw === "" ? "unverifiable" : "pass",
    value: fingerprint(raw),
  });
  return [
    rung(
      "controller_key_fingerprint",
      "Controller signing identity",
      "Which controller key this enrollment is bound to. It is set when the invitation is issued, so it is the one rung that is established from the start.",
      status.controller_key_fingerprint,
    ),
    rung(
      "worker_key_fingerprint",
      "Worker key possession",
      "A worker proved it holds the private key for this public key. It does not prove the worker was the intended recipient — the first valid binder wins.",
      status.worker_key_fingerprint,
    ),
    rung(
      "release_fingerprint",
      "Release pinned",
      "The exact release this enrollment is for. It is a content address, not a download location.",
      status.release_fingerprint,
    ),
    rung(
      "offer_fingerprint",
      "Controller offer signed",
      "The controller signed an offer bound to this enrollment and it was transported to the worker.",
      status.offer_fingerprint,
    ),
    rung(
      "result_fingerprint",
      "Worker result signed",
      "The worker returned a signed result for that offer. Verification of it is the next lifecycle step, not this rung.",
      status.result_fingerprint,
    ),
  ];
}

// --------------------------------------------------------------------------- recovery

/**
 * What an operator can actually do about an enrollment that will not complete. Every branch names
 * a real route or the absence of one; none of them promises a repair, because the lifecycle has no
 * edge out of a terminal and no way to extend an expiry.
 */
export interface RecoveryView {
  needed: boolean;
  title: string;
  body: string;
  steps: string[];
}

const NO_RECOVERY: RecoveryView = { needed: false, title: "", body: "", steps: [] };

export function recoveryView(state: string, expiry: ExpiryView): RecoveryView {
  if (state === "recovery_required") {
    return {
      needed: true,
      title: "Recovery required — no worker was enrolled",
      body: "The controller's expiry sweep closed this enrollment before the exchange finished. Nothing was enrolled and nothing partial is left running.",
      steps: [
        "No worker holds a controller-issued identity from this enrollment.",
        "This enrollment cannot be resumed or extended — the lifecycle has no edge out of recovery required, and no route accepts a new expiry.",
        "Create a new invitation and hand it to the worker again.",
        "The record stays readable by id for audit. It is not deleted, and it does not need to be cleaned up.",
      ],
    };
  }
  if (state === "refused") {
    return {
      needed: true,
      title: "Refused — no worker was enrolled",
      body: "This enrollment was refused. An operator revoke lands here, and so does a refusal the controller recorded on its own.",
      steps: [
        "The invitation can no longer be used by any worker.",
        "There is no un-revoke route. A refusal is permanent for this enrollment.",
        "Check the refusal reason above for which refusal this was.",
        "Create a new invitation if you still intend to enrol this worker.",
      ],
    };
  }
  if (!isTerminalState(state) && expiry.valid && expiry.expired) {
    return {
      needed: true,
      title: "Past its expiry — the worker did not finish in time",
      body: "This enrollment has not reached a terminal state, but its expiry has passed by this browser's clock. The controller decides what happens next, not this page.",
      steps: [
        "Look the enrollment up again. The controller's expiry sweep — not this interface — moves an unfinished enrollment to recovery required.",
        "An expiry cannot be extended. No route accepts a new one.",
        "Create a new invitation with a longer lifetime if the worker needs more time.",
        "Revoke this one if you would rather close it now than wait for the sweep.",
      ],
    };
  }
  return NO_RECOVERY;
}

// --------------------------------------------------------------------------- verification context
//
// The safe, non-secret half of the bootstrap material: the values that identify the CONTROLLER and
// the RELEASE rather than the invitation. They are shown so an operator can confirm out of band
// that the invitation came from the control plane they meant to enrol against.

export interface VerificationRow {
  field: string;
  label: string;
  proves: string;
  value: string;
}

export const VERIFICATION_CONTEXT_NOTICE =
  "These values identify the controller and the release, not the invitation, and none of them is a secret: an origin, two public installation identifiers, a public trust anchor and a content digest. Read them back to the controller's operator over a channel you already trust, to confirm this invitation came from the control plane you meant. The hand-off block itself still goes to exactly one worker.";

export function verificationContext(invitation: EnrollmentInvitation): VerificationRow[] {
  return [
    {
      field: "controller_origin",
      label: "Controller origin",
      proves:
        "The address this worker will contact. Confirm it is the control plane you meant to enrol against.",
      value: invitation.controller_origin,
    },
    {
      field: "controller_installation_id",
      label: "Controller installation",
      proves: "Which controller installation issued this invitation.",
      value: invitation.controller_installation_id,
    },
    {
      field: "controller_key_id",
      label: "Controller key id",
      proves:
        "The controller signing key this enrollment is bound to. The worker pins this key — it does not pin the trust anchor below.",
      value: invitation.controller_key_id,
    },
    {
      field: "controller_trust_anchor_hex",
      label: "Controller trust anchor",
      proves:
        "The controller's public trust anchor, for eyeball comparison out of band. It is not part of the hand-off block and the worker never receives it from you.",
      value: invitation.controller_trust_anchor_hex,
    },
    {
      field: "release_digest",
      label: "Release digest",
      proves:
        "The exact release this enrollment offers. A content address, not a download location.",
      value: invitation.release_digest,
    },
  ];
}

// --------------------------------------------------------------------------- control inventory
//
// What this interface can and cannot do, and why — stated as data so it is rendered rather than
// re-typed, and so a test can pin it. Availability here is not a UI preference: it is exactly
// whether the controller exposes a route a browser principal may call.

export interface EnrollmentControl {
  id: string;
  label: string;
  available: boolean;
  /** The route that backs it, or the reason there is none. Never a promise of future work. */
  detail: string;
}

export const ENROLLMENT_CONTROLS: readonly EnrollmentControl[] = [
  {
    id: "create",
    label: "Create a single-use invitation",
    available: true,
    detail:
      "POST /api/v1/enrollment/invitations — requires enrollment:manage. The invitation is returned once and never re-served.",
  },
  {
    id: "status",
    label: "Read one enrollment's status by id",
    available: true,
    detail:
      "GET /api/v1/enrollment/{enrollment_id} — requires enrollment:read, which enrollment:manage does not include.",
  },
  {
    id: "revoke",
    label: "Revoke an enrollment, which is also how you cancel one",
    available: true,
    detail:
      "POST /api/v1/enrollment/{enrollment_id}/revoke — requires enrollment:manage. There is no separate cancel route: a revoke is the cancel, and it is permanent.",
  },
  {
    id: "list",
    label: "List the enrollments in your organization",
    available: true,
    detail:
      "GET /api/v1/enrollment — requires enrollment:read. Organization-scoped and never cross-organization, one page at a time, and it returns no invitation material. The Enrollment Inventory page is built on it.",
  },
  {
    id: "decide",
    label: "Approve or reject an enrollment",
    available: false,
    detail:
      "The lifecycle has no approval edge and the controller exposes no route that would accept one. Every forward transition is driven by evidence the worker signs, so there is nothing here for an operator to decide.",
  },
  {
    id: "advance",
    label: "Advance an enrollment by hand when it is stuck",
    available: false,
    detail:
      "The per-step progression routes are sealed closed and hidden from the schema. A browser never drives the exchange — retrying is the worker's job, from the worker.",
  },
  {
    id: "reissue",
    label: "Show an invitation again after you have left the page",
    available: false,
    detail:
      "Decided, not missing: the create response is one-shot by design. A re-fetch route would let a stolen credential silently take over an enrolment in flight, so none exists and this interface stores nothing. Revoke and create a new invitation instead.",
  },
];

export const CONTROLS_NOTICE =
  "This list is the controller's routes, not a roadmap. A control marked unavailable has no endpoint behind it, so no interface could offer it honestly — and this one does not simulate it.";

// --------------------------------------------------------------------------- tab-local working set

/**
 * One entry in the tab-local working set. It deliberately holds NO invitation material: the
 * enrollment id (the public handle you look a record up by), the site label and timestamps this
 * tab already saw, and the last lifecycle state it actually observed. The bearer fields —
 * invitation id, controller key id, transaction id, release digest, origin — are never copied
 * here, so the working set could not leak the capability even if it were persisted, which it is
 * not.
 */
export interface TrackedEnrollment {
  enrollmentId: string;
  /** From the create response only. "" when the entry came from a look-up: the status projection
   *  deliberately does not carry the site label, and it is never guessed. */
  siteLabel: string;
  /** From the create response only; "" for a looked-up entry. */
  createdAt: string;
  expiresAt: string;
  /** The last state this tab actually observed — never inferred from the clock. */
  state: string;
  /** The revision that state was observed at. */
  revision: number;
}

export const TRACKED_LIMIT = 10;

export function trackedFromInvitation(
  invitation: EnrollmentInvitation,
): TrackedEnrollment {
  return {
    enrollmentId: invitation.enrollment_id,
    siteLabel: invitation.deployment_site_label,
    createdAt: invitation.created_at,
    expiresAt: invitation.expires_at,
    state: invitation.state,
    revision: invitation.revision,
  };
}

export function trackedFromStatus(status: EnrollmentStatus): TrackedEnrollment {
  return {
    enrollmentId: status.enrollment_id,
    // The site label now comes from the projection, and "" when this controller does not carry it
    // — `addTracked` then keeps whatever label the create response already gave this tab, rather
    // than overwriting a value we genuinely observed with a blank.
    siteLabel: siteLabelOf(status),
    // Creation time is still not in the projection, and inventing it would be worse than a blank.
    createdAt: "",
    expiresAt: status.expires_at,
    state: status.state,
    revision: status.revision,
  };
}

/**
 * Add or refresh one entry. Pure: the caller owns the React state.
 *
 * A new id goes to the front and the list stays bounded. An id already present is updated IN
 * PLACE, so refreshing a row does not make it jump — and the site label and creation time this tab
 * saw on the create response are retained, because the status projection cannot supply them and
 * dropping them would lose information we genuinely observed.
 *
 * A response that carries an OLDER revision than the one already displayed is discarded rather
 * than rendered: revisions advance monotonically, so an older one is a late reply from an earlier
 * request, and showing it would walk the row backwards.
 */
export function addTracked(
  list: readonly TrackedEnrollment[],
  entry: TrackedEnrollment,
): TrackedEnrollment[] {
  const index = list.findIndex((e) => e.enrollmentId === entry.enrollmentId);
  if (index === -1) return [entry, ...list].slice(0, TRACKED_LIMIT);
  const prior = list[index];
  const next = [...list];
  next[index] =
    entry.revision < prior.revision
      ? prior
      : {
          ...entry,
          siteLabel: entry.siteLabel || prior.siteLabel,
          createdAt: entry.createdAt || prior.createdAt,
        };
  return next;
}

export function removeTracked(
  list: readonly TrackedEnrollment[],
  enrollmentId: string,
): TrackedEnrollment[] {
  return list.filter((e) => e.enrollmentId !== enrollmentId);
}

/** The operator-meaningful grouping of a lifecycle state. `unknown` is its own group rather than
 *  being folded into "pending", so a build older than the controller never silently reports a
 *  state it does not understand as though it were progress. */
export type TrackedGroup = "pending" | "healthy" | "settled" | "unknown";

export function trackedGroup(state: string): TrackedGroup {
  if (isTerminalState(state)) return "settled";
  if (state === "healthy") return "healthy";
  return (ENROLLMENT_FORWARD_STATES as readonly string[]).includes(state)
    ? "pending"
    : "unknown";
}

export const TRACKED_FILTERS = ["pending", "healthy", "settled", "all"] as const;
export type TrackedFilter = (typeof TRACKED_FILTERS)[number];

export const TRACKED_FILTER_LABELS: Record<TrackedFilter, string> = {
  pending: "Waiting on a worker",
  healthy: "Worker healthy",
  settled: "No worker enrolled",
  all: "All tracked",
};

export function filterTracked(
  list: readonly TrackedEnrollment[],
  filter: TrackedFilter,
): TrackedEnrollment[] {
  if (filter === "all") return [...list];
  return list.filter((entry) => trackedGroup(entry.state) === filter);
}

export interface TrackedSummary {
  total: number;
  pending: number;
  healthy: number;
  settled: number;
  unknown: number;
  pastExpiry: number;
}

/** True when an unfinished enrollment's expiry has passed by the clock this page was given. It is
 *  deliberately NOT a lifecycle claim: the controller's sweep decides the record's state. */
export function isPastExpiry(entry: TrackedEnrollment, nowMs: number): boolean {
  const group = trackedGroup(entry.state);
  if (group === "healthy" || group === "settled") return false;
  const view = expiryView(entry.expiresAt, nowMs);
  return view.valid && view.expired;
}

export function trackedSummary(
  list: readonly TrackedEnrollment[],
  nowMs: number,
): TrackedSummary {
  const summary: TrackedSummary = {
    total: list.length,
    pending: 0,
    healthy: 0,
    settled: 0,
    unknown: 0,
    pastExpiry: 0,
  };
  for (const entry of list) {
    summary[trackedGroup(entry.state)] += 1;
    if (isPastExpiry(entry, nowMs)) summary.pastExpiry += 1;
  }
  return summary;
}

/** The session-scoped working set is honest about being a local convenience, not a server query. */
export const TRACKED_LIST_NOTICE =
  "Enrollments this browser tab has created or looked up, kept only until you reload. It is a scratchpad, not the inventory: nothing created elsewhere appears here, and a row stays until you forget it. The Enrollment Inventory page is the organization-wide, server-side view.";

export const TRACKED_STALENESS_NOTICE =
  "Each row shows the last state this tab observed, at the revision it observed. Nothing polls: refresh a row to ask the controller again.";

export const TRACKED_UNKNOWN_NOTICE =
  "A state this build does not recognise is counted separately and appears only under All tracked, so it is never filed as progress it might not be.";

export const PAST_EXPIRY_NOTICE =
  "Past its expiry by this browser's clock. The controller decides the record's real state — its expiry sweep is what moves an unfinished enrollment to recovery required.";
