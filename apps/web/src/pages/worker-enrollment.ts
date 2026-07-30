// Worker-enrollment view model (SECP-PR5H-B1) — pure, no React, no I/O.
//
// This module is the tested source of truth for every predicate, grammar and piece of safety copy
// the page renders. It reinterprets no lifecycle rule: the state order, the id grammar, the site
// label grammar and the TTL bounds are all mirrored from the backend contract, and the service
// stays authoritative for all of them.
//
// SCOPE. The controller exposes exactly three enrollment routes to a browser principal: create an
// invitation, read the bounded status projection, and revoke. There is deliberately no approve or
// reject here — the enrollment lifecycle has no approval edge. Every forward transition is driven
// by the worker's signed cryptographic evidence, and revoke is the only operator write in the
// entire lifecycle.

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

/** The session-scoped list is honest about being a local convenience, not a server inventory. */
export const RECENT_LIST_NOTICE =
  "Invitations you created in this browser tab, kept only until you reload. This is not an inventory: the control plane has no endpoint that lists enrollments, so nothing created elsewhere — or before this reload — can appear here.";

/** Why there is no inventory or queue on this page. */
export const NO_INVENTORY_NOTICE =
  "There is no enrollment inventory or pending queue in this milestone. Status is available for one enrollment at a time, by id.";

/** The truthful framing for the lifecycle rail: these states are not operator decisions. */
export const WORKER_DRIVEN_NOTICE =
  "Enrollment advances only on evidence the worker signs. Nothing on this page approves or advances an enrollment — the one operator action is revoking it.";

export const REVOKE_CONFIRM_NOTICE =
  "Revoking is permanent for this enrollment. It cannot be undone, and a worker holding this invitation will no longer be able to enrol with it.";

export const TRUST_ANCHOR_NOTICE =
  "The controller's public trust anchor, shown so you can compare it out of band. It is not part of the hand-off — the worker pins the controller key it already receives.";

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
      key: "controller_transaction_id",
      label: "Controller transaction id",
      value: invitation.transaction_id,
    },
    { key: "release_digest", label: "Release digest", value: invitation.release_digest },
    { key: "expires_at", label: "Expires at", value: invitation.expires_at },
  ];
}

/** The hand-off block as one copyable document. Stable key order, so two operators comparing
 *  their copies see identical text. */
export function handoffText(invitation: EnrollmentInvitation): string {
  return handoffFields(invitation)
    .map((field) => `${field.key}: ${field.value}`)
    .join("\n");
}

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

/** An empty fingerprint means "not established yet", which is meaningful lifecycle information —
 *  it is shown as such rather than as a blank cell or an invented placeholder. */
function fingerprint(value: string): string {
  return value === "" ? "Not established yet" : value;
}

/** The status projection as display rows. Every value here is already a bounded, secret-free
 *  server projection: identities appear only as short non-reversible fingerprints. */
export function statusDetailRows(status: EnrollmentStatus): DetailRow[] {
  const rows: DetailRow[] = [
    { key: "Enrollment id", value: status.enrollment_id, mono: true },
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

// --------------------------------------------------------------------------- session-scoped list

/** One entry in the tab-local recent list. It deliberately holds no invitation material — only
 *  what is needed to look the enrollment up again. */
export interface RecentEnrollment {
  enrollmentId: string;
  siteLabel: string;
  createdAt: string;
  expiresAt: string;
}

export const RECENT_LIMIT = 10;

/** Newest first, de-duplicated by id, bounded. Pure: the caller owns the React state. */
export function addRecent(
  list: readonly RecentEnrollment[],
  entry: RecentEnrollment,
): RecentEnrollment[] {
  return [entry, ...list.filter((e) => e.enrollmentId !== entry.enrollmentId)].slice(
    0,
    RECENT_LIMIT,
  );
}
