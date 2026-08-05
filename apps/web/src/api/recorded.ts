// Narrowing for the API members the OpenAPI contract deliberately leaves opaque.
//
// WHY THIS FILE EXISTS, AND WHY IT IS THE ONLY HAND-WRITTEN TRANSPORT CODE
//
// `./generated/openapi.ts` is generated from `contracts/openapi/openapi.json` and is the single
// source of truth for every shape that crosses the wire. Seven Proxmox members resist that,
// because `secp_api.schemas_proxmox` declares them `dict[str, Any]` / `list[dict[str, Any]]` and
// OpenAPI can only publish `{ [key: string]: unknown }`:
//
//   ProxmoxVerificationOut.infrastructure_checks   ProxmoxVerificationOut.isolation_checks
//   ProxmoxResetDispositionsOut.dispositions       ProxmoxResidueOut.resources
//   ProxmoxDestroyPlanOut.deletion_set             ProxmoxTopologyOut.topology
//   ProxmoxPlanOut.document
//
// The API is right to keep them opaque: `secp_api.proxmox_projection` copies them verbatim out of
// what the worker recorded, and a Pydantic model over them would silently drop any key the model
// did not know. But "opaque on the wire" must not become "unchecked in the client", and one
// consequence is severe enough to name:
//
//   **`CheckFinding`'s `(observed, ok)` pair does not survive generation.** In Python the pair is
//   two typed booleans on `proxmox_verification.CheckFinding`. On the wire it sits inside an
//   opaque dict, so the generated TypeScript for `infrastructure_checks` is
//   `{ [key: string]: unknown }[] | null` and the distinction between "the check could not be
//   observed" and "the check ran and failed" is available to a client only if the client goes and
//   gets it. That is what `asCheckFindings` does, and why it REFUSES an entry missing either
//   boolean rather than defaulting: a missing `observed` defaulted to `true` turns every
//   unobservable check into a reported failure, which is the exact confusion the pair prevents.
//
// The rules every reader here follows:
//
//  1. NEVER FABRICATE. A field that is absent or the wrong type makes the entry UNREADABLE. It is
//     never defaulted, coerced, or dropped — an unreadable entry is returned alongside the good
//     ones so a surface can say "the worker recorded 9 checks and 1 we could not read", which is
//     true, instead of showing 9, which is not.
//  2. ABSENT IS NOT EMPTY. `RecordedList.present` is false when the member was null and true when
//     it was `[]`. "The residue probe has not run" and "the probe ran and found no residue" are
//     different facts; so are "no destroy plan was generated" and "the destroy plan deletes
//     nothing". Reading `.entries.length === 0` alone conflates them.
//  3. VALIDATE AGAINST THE REAL MEMBER SET. Enum-valued strings are checked against the `as const`
//     arrays in `./recorded-documents.ts`, so a worker that records a member this build has never
//     heard of is reported as unreadable rather than rendered as an unstyled tone.

import {
  type AbsenceFinding,
  type CheckFinding,
  type DeletionSet,
  type ObjectProvenance,
  type OwnedResource,
  type ProtectedResource,
  type ResetAction,
  type ResetDisposition,
  type ResetSubject,
  type ResidueClass,
  type TeardownOutcome,
  type VerificationCheck,
  OBJECT_PROVENANCES,
  RESET_DISPOSITIONS,
  RESET_SUBJECTS,
  RESIDUE_CLASSES,
  TEARDOWN_OUTCOMES,
  VERIFICATION_CHECKS,
} from "./recorded-documents";

// ------------------------------------------------------------------------------ failure carrier

/**
 * Why one value could not be read.
 *
 * A distinct object rather than a magic string, because half these fields ARE strings: a reader
 * that signals failure by returning a string cannot tell a refusal from a legitimate value, and
 * the field most likely to collide is the free-text `detail` on every finding.
 */
interface Refusal {
  readonly refused: string;
}

function refuse(reason: string): Refusal {
  return { refused: reason };
}

function isRefusal(value: unknown): value is Refusal {
  return typeof value === "object" && value !== null && typeof (value as Refusal).refused === "string";
}

/** One entry of an opaque list that could not be read, kept with the reason and the raw value. */
export interface UnreadableEntry {
  /** Position in the recorded list, so an operator can find it in the raw payload. */
  readonly index: number;
  /** Which expectation failed, e.g. `missing boolean "observed"`. Rendered, not swallowed. */
  readonly reason: string;
  readonly raw: unknown;
}

/**
 * The result of reading one opaque list member.
 *
 * `present: false` means the member was null — the stage has not run. It is NOT the same as
 * `present: true` with no entries, which means the stage ran and recorded nothing.
 */
export interface RecordedList<T> {
  readonly present: boolean;
  readonly entries: readonly T[];
  readonly unreadable: readonly UnreadableEntry[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function readList<T>(
  recorded: readonly unknown[] | null | undefined,
  read: (raw: Record<string, unknown>) => T | Refusal,
): RecordedList<T> {
  if (recorded === null || recorded === undefined) {
    return { present: false, entries: [], unreadable: [] };
  }
  const entries: T[] = [];
  const unreadable: UnreadableEntry[] = [];
  recorded.forEach((raw, index) => {
    if (!isRecord(raw)) {
      unreadable.push({ index, reason: "entry is not a JSON object", raw });
      return;
    }
    const result = read(raw);
    if (isRefusal(result)) unreadable.push({ index, reason: result.refused, raw });
    else entries.push(result);
  });
  return { present: true, entries, unreadable };
}

// ------------------------------------------------------------------ primitive field readers

function readBoolean(raw: Record<string, unknown>, key: string): boolean | Refusal {
  const value = raw[key];
  // `typeof` and nothing else. `!!value` would read a missing key as false, and reading a MISSING
  // `observed` as false is only marginally less wrong than reading it as true — both invent an
  // answer to a question the worker did not record.
  return typeof value === "boolean" ? value : refuse(`missing boolean "${key}"`);
}

/** Free text. Absent reads as the empty string: a missing `detail` is a missing note, not a lie. */
function readDetail(raw: Record<string, unknown>): string {
  const value = raw["detail"];
  return typeof value === "string" ? value : "";
}

/** An optional string: absent and null both read as null; any other type is a refusal. */
function readNullableString(raw: Record<string, unknown>, key: string): string | null | Refusal {
  const value = raw[key];
  if (value === null || value === undefined) return null;
  return typeof value === "string" ? value : refuse(`"${key}" is neither a string nor null`);
}

/** A string field whose value must be one of a known member set. */
function readMember<T extends string>(
  raw: Record<string, unknown>,
  key: string,
  members: readonly T[],
): T | Refusal {
  const value = raw[key];
  if (typeof value !== "string") return refuse(`missing string "${key}"`);
  if (!(members as readonly string[]).includes(value)) {
    return refuse(`"${key}" is "${value}", which is not a member this build knows`);
  }
  return value as T;
}

// ------------------------------------------------------------------------ verification checks

/**
 * Read `ProxmoxVerificationOut.infrastructure_checks` / `.isolation_checks`.
 *
 * BOTH booleans are required. An entry carrying only `ok` is unreadable, because there is no
 * honest way to render it: `ok: false` from an unobserved check is not a failure, and nothing in
 * the entry says which it was.
 */
export function asCheckFindings(
  recorded: readonly unknown[] | null | undefined,
): RecordedList<CheckFinding> {
  return readList<CheckFinding>(recorded, (raw) => {
    const check = readMember<VerificationCheck>(raw, "check", VERIFICATION_CHECKS);
    if (isRefusal(check)) return check;
    const observed = readBoolean(raw, "observed");
    if (isRefusal(observed)) return observed;

    // `ok` is a TRIPLE, not a boolean. The worker's `CheckFinding.ok` is `bool | None` and
    // `verification_evidence` emits `ok: null` explicitly rather than omitting the key:
    //
    //     observed=false, ok=null    the check could not be made
    //     observed=true,  ok=false   the check was made and failed
    //     observed=true,  ok=true    the check was made and passed
    //
    // The key must still be PRESENT. Absent is not null: a payload with no `ok` at all is a
    // payload this reader cannot interpret, and defaulting it is how "nobody could look" becomes
    // "this failed".
    if (!("ok" in raw)) return refuse('missing "ok" (null is a value; absent is not)');
    const rawOk = raw["ok"];
    if (rawOk !== null && typeof rawOk !== "boolean") {
      return refuse('"ok" is neither a boolean nor null');
    }

    // The contradiction, refused. "The check ran and produced no verdict" is not a state the
    // worker can emit — its `__post_init__` rejects it — so seeing it here means the payload is
    // not what it claims to be. Resolving it silently is how it would become a pass.
    if (observed && rawOk === null) {
      return refuse('"observed" is true but "ok" is null, which is not an outcome');
    }

    // The other direction is NOT refused, deliberately. Two producer sites emitted
    // `observed=false, ok=false` before `ok` became nullable, and those events are already
    // recorded and durable. Refusing them would discard evidence that was legitimately written,
    // to enforce a rule that did not exist when it was written. `checkStatus` reads the pair and
    // maps any unobserved check to `not_observed` regardless of `ok`, so nothing downstream can
    // mistake the legacy shape for a verdict.
    return { check, observed, ok: rawOk, detail: readDetail(raw) };
  });
}

/**
 * Per-check status, derived from the `(observed, ok)` pair rather than from `ok` alone.
 *
 * `observed: false` means the check could not be run and `ok` carries no information. Reading only
 * `ok` renders an unobservable check as a failure, which claims a finding nobody made.
 */
export type CheckStatus = "passed" | "failed" | "not_observed";

export function checkStatus(finding: CheckFinding): CheckStatus {
  if (!finding.observed) return "not_observed";
  // `ok === null` cannot reach here through `asCheckFindings`, which refuses the combination. It
  // is handled explicitly anyway rather than left to falsiness: `null ? a : b` takes the `false`
  // branch, so a `CheckFinding` built by hand with the contradiction would silently render as a
  // FAILURE — the exact substitution this module exists to prevent, arriving through the one path
  // that skips the reader.
  if (finding.ok === null) return "not_observed";
  return finding.ok ? "passed" : "failed";
}

// -------------------------------------------------------------------------- reset dispositions

/** Read `ProxmoxResetDispositionsOut.dispositions`. */
export function asResetActions(
  recorded: readonly unknown[] | null | undefined,
): RecordedList<ResetAction> {
  return readList<ResetAction>(recorded, (raw) => {
    const subject = readMember<ResetSubject>(raw, "subject", RESET_SUBJECTS);
    if (isRefusal(subject)) return subject;
    const disposition = readMember<ResetDisposition>(raw, "disposition", RESET_DISPOSITIONS);
    if (isRefusal(disposition)) return disposition;
    return { subject, disposition, detail: readDetail(raw) };
  });
}

// ------------------------------------------------------------------------------------- residue

function readOwnedResource(raw: Record<string, unknown>): OwnedResource | Refusal {
  const residueClass = readMember<ResidueClass>(raw, "residue_class", RESIDUE_CLASSES);
  if (isRefusal(residueClass)) return residueClass;
  const identifier = raw["identifier"];
  if (typeof identifier !== "string") return refuse('missing string "identifier"');
  const address = readNullableString(raw, "address");
  if (isRefusal(address)) return address;
  return { residue_class: residueClass, identifier, address };
}

/**
 * Read `ProxmoxResidueOut.resources`.
 *
 * `outcome` and `probe_healthy` are read as a pair for the same reason as `(observed, ok)`: a
 * `removed` verdict from an unhealthy probe proves nothing, so a reader that drops `probe_healthy`
 * turns "we could not check" into "it is gone".
 */
export function asAbsenceFindings(
  recorded: readonly unknown[] | null | undefined,
): RecordedList<AbsenceFinding> {
  return readList<AbsenceFinding>(recorded, (raw) => {
    const nested = raw["resource"];
    if (!isRecord(nested)) return refuse('missing object "resource"');
    const resource = readOwnedResource(nested);
    if (isRefusal(resource)) return resource;
    const outcome = readMember<TeardownOutcome>(raw, "outcome", TEARDOWN_OUTCOMES);
    if (isRefusal(outcome)) return outcome;
    const probeHealthy = readBoolean(raw, "probe_healthy");
    if (isRefusal(probeHealthy)) return probeHealthy;
    return { resource, outcome, probe_healthy: probeHealthy, detail: readDetail(raw) };
  });
}

/**
 * True only when every finding is `removed` AND the probe that produced it was healthy.
 *
 * An EMPTY finding list returns false. Nothing was proved, because nothing was probed — "the
 * residue probe has not run" must never render as a clean teardown.
 */
export function residueProvedClean(findings: readonly AbsenceFinding[]): boolean {
  return findings.length > 0 && findings.every((f) => f.outcome === "removed" && f.probe_healthy);
}

// -------------------------------------------------------------------------------- deletion set

/**
 * The reading of `ProxmoxDestroyPlanOut.deletion_set`.
 *
 * Three outcomes, and collapsing any two of them is a real defect:
 *   `present: false`                    the destroy plan did not compile — NOTHING was enumerated.
 *   `present: true, value: null`        something was recorded and could not be read.
 *   `present: true, value: DeletionSet` the enumerated scope, which may legitimately be empty.
 */
export type DeletionSetReading =
  | { readonly present: false }
  | { readonly present: true; readonly value: null; readonly reason: string }
  | { readonly present: true; readonly value: DeletionSet; readonly reason: null };

function readOwnedResourceBucket(value: unknown, bucket: string): OwnedResource[] | Refusal {
  if (!Array.isArray(value)) return refuse(`"${bucket}": not an array`);
  const out: OwnedResource[] = [];
  for (const raw of value) {
    if (!isRecord(raw)) return refuse(`"${bucket}": entry is not a JSON object`);
    const resource = readOwnedResource(raw);
    if (isRefusal(resource)) return refuse(`"${bucket}": ${resource.refused}`);
    out.push(resource);
  }
  return out;
}

function readProtectedBucket(value: unknown): ProtectedResource[] | Refusal {
  if (!Array.isArray(value)) return refuse('"protected": not an array');
  const out: ProtectedResource[] = [];
  for (const raw of value) {
    if (!isRecord(raw)) return refuse('"protected": entry is not a JSON object');
    const nested = raw["resource"];
    if (!isRecord(nested)) return refuse('"protected": missing object "resource"');
    const resource = readOwnedResource(nested);
    if (isRefusal(resource)) return refuse(`"protected": ${resource.refused}`);
    const provenance = readMember<ObjectProvenance>(raw, "provenance", OBJECT_PROVENANCES);
    if (isRefusal(provenance)) return refuse(`"protected": ${provenance.refused}`);
    out.push({ resource, provenance, detail: readDetail(raw) });
  }
  return out;
}

/**
 * Read `ProxmoxDestroyPlanOut.deletion_set`.
 *
 * The API publishes this member as a LIST of opaque objects; the worker's `DeletionSet` is a
 * single document with four named buckets. Both shapes are accepted: a one-element list holding
 * the document, or the document itself. A list of loose resources is NOT accepted — every one of
 * them would have to be assigned to a bucket, and guessing which one is how a PROTECTED object
 * becomes a deletable one.
 */
export function asDeletionSet(
  recorded: readonly unknown[] | Record<string, unknown> | null | undefined,
): DeletionSetReading {
  if (recorded === null || recorded === undefined) return { present: false };

  const asList: readonly unknown[] | null = Array.isArray(recorded) ? recorded : null;
  let document: Record<string, unknown> | null = null;
  if (asList !== null) {
    if (asList.length === 1 && isRecord(asList[0])) document = asList[0];
  } else if (isRecord(recorded)) {
    document = recorded;
  }
  if (document === null) {
    return {
      present: true,
      value: null,
      reason:
        Array.isArray(recorded) && recorded.length === 0
          ? "the destroy plan recorded an empty deletion-set list, which names no bucket at all"
          : "the deletion set is a list of loose entries, not a bucketed DeletionSet document",
    };
  }

  const deletable = readOwnedResourceBucket(document["deletable"], "deletable");
  if (isRefusal(deletable)) return { present: true, value: null, reason: deletable.refused };
  const alreadyAbsent = readOwnedResourceBucket(document["already_absent"], "already_absent");
  if (isRefusal(alreadyAbsent)) return { present: true, value: null, reason: alreadyAbsent.refused };
  const undetermined = readOwnedResourceBucket(document["undetermined"], "undetermined");
  if (isRefusal(undetermined)) return { present: true, value: null, reason: undetermined.refused };
  const protectedResources = readProtectedBucket(document["protected"]);
  if (isRefusal(protectedResources)) {
    return { present: true, value: null, reason: protectedResources.refused };
  }

  return {
    present: true,
    value: {
      deletable,
      protected: protectedResources,
      already_absent: alreadyAbsent,
      undetermined,
    },
    reason: null,
  };
}
