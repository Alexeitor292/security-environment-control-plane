// Projecting `GET /api/v1/audit` onto the audit surface, without inventing anything.
//
// TWO PROBLEMS, AND NEITHER IS THE FETCHING.
//
// 1. THE OUTCOME VOCABULARIES DO NOT MATCH. The migrated domain type declares
//    `outcome: 'success' | 'denied' | 'failed'`. The control plane emits at
//    least SEVEN distinct values from production code: `success` (13 sites),
//    `denied` (9), `revoked` (6), `expired` (5), `refused` (4), `failed` (2),
//    and `failure` (1).
//
//    Four of those have no home in the domain union, and the nearest-looking
//    coercion is the wrong one. `revoked -> failed` asserts a different fact: a
//    revoked authorization did not fail, it was withdrawn. `refused -> failed`
//    is the unknown-versus-negative collapse this codebase keeps fighting. And
//    dropping unrecognised rows is the worst option available, because hiding an
//    entry is the specific failure an audit page exists to prevent.
//
//    So nothing is coerced. A value outside the known three is carried through
//    VERBATIM and rendered in a neutral tone, exactly as an undetermined
//    capability is. The reader sees `revoked` and reads `revoked`.
//
// 2. `origin` HAS NO SOURCE ON THE WIRE. `AuditEventOut` publishes `id`,
//    `action`, `actor`, `created_at`, `data`, `outcome`, `resource_id` and
//    `resource_type`. There is no origin. It renders as NOT SUPPLIED, never as
//    an empty string or a dash that could be mistaken for a reading of "no
//    origin".
//
// WHY `failure` IS NOT NORMALISED TO `failed`, AND MUST NOT BE LATER.
//
// They are two spellings of one concept, written by different services
// (`worker_enrollment.py` writes `failure`; `inventory.py` and
// `provisioning.py` write `failed`). That is a data-quality defect in the
// ledger, and normalising it here would launder it out of sight of the people
// who can fix it.
//
// More importantly: THE AUDIT LEDGER IS APPEND-ONLY. Fixing the emitting service
// stops new `failure` rows; it cannot rewrite the ones already written. Both
// spellings will be in that ledger permanently. So rendering them verbatim is
// not a stopgap awaiting an upstream fix — it is the only display that can ever
// be truthful about this data. Do not "tidy" it when the emitter is corrected.

import type { components } from "../../api/generated/openapi";

type AuditEventOut = components["schemas"]["AuditEventOut"];

/** The three the migrated surface has tones for. Not the full server vocabulary. */
export const TONED_OUTCOMES = ["success", "denied", "failed"] as const;

export type TonedOutcome = (typeof TONED_OUTCOMES)[number];

/**
 * An outcome as it will be displayed.
 *
 * `toned` is non-null only for the three values with a designed tone. Everything
 * else keeps `raw` and renders neutrally — which is what makes an eighth value
 * appearing on the wire a display question rather than a correctness one.
 */
export interface OutcomeView {
  readonly raw: string;
  readonly toned: TonedOutcome | null;
}

export function outcomeView(raw: string): OutcomeView {
  const toned = (TONED_OUTCOMES as readonly string[]).includes(raw)
    ? (raw as TonedOutcome)
    : null;
  return { raw, toned };
}

/**
 * A field the control plane does not supply.
 *
 * A distinct type rather than `null`, so a renderer cannot accidentally treat it
 * as an empty value: "" and "not supplied" look identical on screen and mean
 * different things.
 */
export const NOT_SUPPLIED = Symbol("not-supplied-by-control-plane");
export type NotSupplied = typeof NOT_SUPPLIED;

export interface AuditRowView {
  readonly id: string;
  readonly time: string;
  readonly actor: string;
  readonly action: string;
  /** `resource_type` and `resource_id` composed; the id is null for org-wide acts. */
  readonly resource: string;
  readonly outcome: OutcomeView;
  /** No wire source. Always `NOT_SUPPLIED` — see the header. */
  readonly origin: NotSupplied;
}

export function auditRow(event: AuditEventOut): AuditRowView {
  return {
    id: event.id,
    time: event.created_at,
    actor: event.actor,
    action: event.action,
    resource: event.resource_id
      ? `${event.resource_type} ${event.resource_id}`
      : event.resource_type,
    outcome: outcomeView(event.outcome),
    origin: NOT_SUPPLIED,
  };
}

export function auditRows(events: readonly AuditEventOut[]): AuditRowView[] {
  return events.map(auditRow);
}
