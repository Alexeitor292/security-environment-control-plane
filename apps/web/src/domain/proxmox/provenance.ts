// Where a value on a Proxmox surface CAME FROM, carried in the type system.
//
// #112 gave the Proxmox lifecycle an HTTP surface: ten read projections under
// `/api/v1/ranges/{range_id}/proxmox/*` plus the approval and authorization routes, all on the
// provider-neutral `routers/ranges.py`. Most of what a browser needs is now a real reading of a
// real endpoint, and their shapes are generated into `src/api/generated/openapi.ts`.
//
// Some documents still have no endpoint. The worker-side gate records — the OpenTofu plan
// document, the emitted apply authorization, the destroy approval the gate consumes, the
// reconcile decision — are produced inside the privileged worker and the API publishes only what
// it has recorded ABOUT them. A surface that wants to show one has two honest options: show
// nothing, or show a worked example that is UNMISTAKABLY not a reading of anyone's cluster. This
// module is what makes the second option safe, and it is what lets a reviewer tell at a glance
// which of the two any given panel is doing.
//
// THE RULE: no fake Proxmox record may render as live data.
//
// It is enforced structurally rather than by convention:
//
//   - `Sourced<T>` is a discriminated union. A value cannot exist without a provenance, because
//     there is no constructor that produces a bare `T` — `live()` demands the endpoint that
//     returned it, `offlineFixture()` demands the reason no endpoint exists.
//   - `OfflineRecord<T>` is a NARROWER type than `Sourced<T>`. Every export of `proxmox-fixtures`
//     is declared as one, so a fixture cannot be passed where a live reading is required, and
//     `proxmox-fixtures.test.ts` re-checks that at runtime for every export.
//   - Rendering goes through `<SourcedPanel>`, which derives the banner FROM the provenance. A
//     panel cannot render fixture data and omit the label, because the label is not a separate
//     prop anyone could forget to pass.
//
// The label is deliberately blunt. "Sample data" or "demo" invites the reading that it is a sample
// OF something real. It is not: no Proxmox cluster was contacted to produce any of it.

/** A value read from a real control-plane endpoint in this session. */
export interface LiveSource {
  readonly kind: "live";
  /** The path that returned it, e.g. `GET /api/v1/targets`. Shown to the operator verbatim. */
  readonly endpoint: string;
}

/**
 * A worked example compiled into the bundle. Never a reading of any cluster.
 *
 * `reason` says WHY there is no live reading — always the absence of a server surface, never a
 * failed request. A failed request is an error state and must render as one; substituting a
 * fixture for a request that failed would be the exact confusion this type exists to prevent.
 */
export interface OfflineSource {
  readonly kind: "offline-fixture";
  readonly reason: string;
  /** The backend module this example was transcribed from, so a reader can check it. */
  readonly modelledOn: string;
}

export type Provenance = LiveSource | OfflineSource;

export interface Sourced<T> {
  readonly provenance: Provenance;
  readonly value: T;
}

/** A `Sourced<T>` statically known to be fixture-backed. Fixtures are declared as this. */
export interface OfflineRecord<T> extends Sourced<T> {
  readonly provenance: OfflineSource;
}

/** A `Sourced<T>` statically known to have come off the wire. */
export interface LiveRecord<T> extends Sourced<T> {
  readonly provenance: LiveSource;
}

export const OFFLINE_DATA_LABEL = "OFFLINE DEVELOPMENT DATA";

export const OFFLINE_DATA_EXPLANATION =
  "Not a reading of any Proxmox cluster. No Proxmox host was contacted to produce this. These values are a worked example compiled into this build, shown so the operator surface can be reviewed before the endpoint that would serve it exists.";

export const LIVE_DATA_EXPLANATION =
  "Read from the control plane in this session.";

/** Wrap a value that came off the wire. `endpoint` is the path that returned it. */
export function live<T>(endpoint: string, value: T): LiveRecord<T> {
  return { provenance: { kind: "live", endpoint }, value };
}

/**
 * Wrap a worked example. Both strings are required and both are RENDERED, so an example cannot be
 * added without stating what it stands in for and which backend module defines its shape.
 */
export function offlineFixture<T>(
  reason: string,
  modelledOn: string,
  value: T,
): OfflineRecord<T> {
  return { provenance: { kind: "offline-fixture", reason, modelledOn }, value };
}

export function isOffline<T>(record: Sourced<T>): record is OfflineRecord<T> {
  return record.provenance.kind === "offline-fixture";
}

export function isLive<T>(record: Sourced<T>): record is LiveRecord<T> {
  return record.provenance.kind === "live";
}

/**
 * Map the value while KEEPING the provenance. Projection cannot launder a fixture into a live
 * reading, which is why there is no `unwrap`-shaped export anywhere in this module.
 */
export function mapSourced<T, U>(record: Sourced<T>, fn: (value: T) => U): Sourced<U> {
  return { provenance: record.provenance, value: fn(record.value) };
}

/**
 * Combine two records. Offline is ABSORBING: a panel built from one live reading and one fixture
 * is a fixture panel, and is labelled as one. Mixing must degrade toward the more cautious claim,
 * never toward the more confident one.
 */
export function combineProvenance(a: Provenance, b: Provenance): Provenance {
  if (a.kind === "offline-fixture") return a;
  if (b.kind === "offline-fixture") return b;
  return a;
}

/** One-line source description for the operator, rendered beside the banner. */
export function provenanceSummary(p: Provenance): string {
  return p.kind === "live" ? p.endpoint : p.reason;
}
