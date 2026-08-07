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
//    So nothing is coerced. EVERY value is carried through VERBATIM -- this
//    module does not classify them at all. The reader sees `revoked` and reads
//    `revoked`.
//
//    Colour is a separate question with a separate owner: the design system's
//    `toneForState`, which classifies five of the seven (`success` ok;
//    `denied`/`failed`/`revoked`/`expired` error) and resolves the two it has
//    never been told about -- `refused`, `failure` -- to `unknown` rather than to
//    a healthy default. Deciding tone here, from what the migrated domain type
//    happened to allow, is what put `revoked` in a neutral badge.
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

// WHAT USED TO BE HERE, AND WHY IT IS NOT.
//
// This module exported `TONED_OUTCOMES` / `TonedOutcome` / `OutcomeView`, where
// `toned` was non-null for the three values the MIGRATED DOMAIN TYPE allows. It
// read as "does this surface have a tone for it" and meant "is this in
// `models/types.ts`'s union" — two different questions.
//
// The audit page asked it the first way and picked a badge colour from the
// answer, so `revoked` and `expired` rendered in the neutral "we don't know"
// badge although `STATE_TONE` has always classified both as errors: grey with a
// question mark, in a ledger where `failed` is red. Under-claimed severity, which
// is the direction someone gets hurt.
//
// The tone now comes from `toneForState`, the design system's own map, whose
// documented rule is that an unrecognised state resolves to `unknown` and never
// to a healthy default. That left `toned` with no consumers — and an unused
// export encoding the inadequate type is what made "three" feel authoritative in
// the first place, so it is gone rather than deprecated.
//
// THE DON'T-COERCE PROPERTY DID NOT GO WITH IT. It moved to where it is visible:
// `AuditPage.render.test.tsx` asserts every server outcome reaches the DOM as its
// own word. That is strictly stronger than asserting a flag, because the flag
// could be correct while the render collapses it.

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
  /** The server's word, carried unchanged. Toning is the renderer's business. */
  readonly outcome: string;
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
    outcome: event.outcome,
    origin: NOT_SUPPLIED,
  };
}

export function auditRows(events: readonly AuditEventOut[]): AuditRowView[] {
  return events.map(auditRow);
}
