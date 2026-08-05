// The invariants the opaque-member readers exist to hold.
//
// These are not shape tests. Each one names a way a client could turn an honest recording into a
// dishonest reading, and pins the reader against it.

import { describe, expect, it } from "vitest";

import {
  asAbsenceFindings,
  asCheckFindings,
  asDeletionSet,
  asResetActions,
  checkStatus,
  residueProvedClean,
} from "./recorded";
import type { AbsenceFinding } from "./recorded-documents";

describe("asCheckFindings — the (observed, ok) pair", () => {
  it("keeps an unobserved check distinguishable from a failed one", () => {
    const read = asCheckFindings([
      { check: "guest_inventory", observed: true, ok: true, detail: "12 guests" },
      { check: "cross_team_denial", observed: true, ok: false, detail: "team a reached team b" },
      { check: "power_state", observed: false, ok: false, detail: "node unreachable" },
    ]);

    expect(read.unreadable).toEqual([]);
    expect(read.entries.map(checkStatus)).toEqual(["passed", "failed", "not_observed"]);
  });

  it("refuses an entry with no `observed`, rather than assuming the check ran", () => {
    // The whole defect in one payload: `ok: false` alone. Defaulting `observed` to true reports a
    // failure the worker never claimed; defaulting it to false hides a failure the worker did.
    const read = asCheckFindings([{ check: "guest_inventory", ok: false, detail: "" }]);

    expect(read.entries).toEqual([]);
    expect(read.unreadable).toHaveLength(1);
    expect(read.unreadable[0].reason).toContain("observed");
  });

  it("refuses an entry with no `ok` — absent is not null", () => {
    // `ok: null` is a VALUE, and the one that means "could not be made". A payload with no `ok`
    // key at all is a different thing: uninterpretable, and defaulting it is how "nobody could
    // look" becomes "this failed".
    const read = asCheckFindings([{ check: "guest_inventory", observed: true, detail: "" }]);
    expect(read.entries).toEqual([]);
    expect(read.unreadable[0].reason).toContain('"ok"');
  });

  it("reads the canonical unknown, `observed=false, ok=null`, as not observed", () => {
    // The shape `verification_evidence` emits. Before the worker's `ok` became `bool | None` this
    // reader refused it outright, which would have rejected real payloads the day it landed.
    const read = asCheckFindings([
      { check: "cross_team_denial", observed: false, ok: null, detail: "no prober" },
    ]);
    expect(read.unreadable).toEqual([]);
    expect(read.entries[0].ok).toBeNull();
    expect(checkStatus(read.entries[0])).toBe("not_observed");
  });

  it("refuses `observed=true, ok=null` — a check cannot run and produce no verdict", () => {
    // The worker's `__post_init__` refuses to construct this, so encountering it means the
    // payload is not what it claims. Resolving it silently is how it would become a pass.
    const read = asCheckFindings([
      { check: "cross_team_denial", observed: true, ok: null, detail: "" },
    ]);
    expect(read.entries).toEqual([]);
    expect(read.unreadable[0].reason).toContain("not an outcome");
  });

  it("still reads the legacy `observed=false, ok=false` shape recorded before the triple", () => {
    // Two producer sites emitted this, and those events are durable. Refusing them now would
    // discard evidence legitimately written under the rules of its time — and `checkStatus` maps
    // any unobserved check to not_observed regardless of `ok`, so nothing can mistake it for a
    // verdict.
    const read = asCheckFindings([
      { check: "power_state", observed: false, ok: false, detail: "node unreachable" },
    ]);
    expect(read.unreadable).toEqual([]);
    expect(checkStatus(read.entries[0])).toBe("not_observed");
  });

  it("refuses an `ok` that is neither boolean nor null", () => {
    const read = asCheckFindings([
      { check: "power_state", observed: true, ok: "yes", detail: "" },
    ]);
    expect(read.entries).toEqual([]);
    expect(read.unreadable[0].reason).toContain("neither a boolean nor null");
  });

  it("refuses a truthy non-boolean rather than coercing it", () => {
    // `"false"` is a truthy string. `!!value` would read it as an observed check.
    const read = asCheckFindings([
      { check: "guest_inventory", observed: "false", ok: true, detail: "" },
    ]);
    expect(read.entries).toEqual([]);
    expect(read.unreadable[0].reason).toContain("observed");
  });

  it("refuses a check name this build does not know, instead of rendering it untyped", () => {
    const read = asCheckFindings([
      { check: "quantum_entanglement_denial", observed: true, ok: true, detail: "" },
    ]);
    expect(read.entries).toEqual([]);
    expect(read.unreadable[0].reason).toContain("not a member this build knows");
  });

  it("reports readable and unreadable entries side by side, dropping neither", () => {
    const read = asCheckFindings([
      { check: "guest_inventory", observed: true, ok: true, detail: "" },
      { check: "guest_names", ok: true },
      42,
    ]);
    expect(read.entries).toHaveLength(1);
    expect(read.unreadable.map((u) => u.index)).toEqual([1, 2]);
    expect(read.unreadable[1].reason).toBe("entry is not a JSON object");
  });

  it("separates a stage that has not run from a stage that recorded nothing", () => {
    // `infrastructure_checks: null` is what ProxmoxVerificationOut carries before any verification
    // is recorded. It is not an empty report; `state` is `undetermined`, which is not a pass.
    expect(asCheckFindings(null).present).toBe(false);
    expect(asCheckFindings(undefined).present).toBe(false);

    const ran = asCheckFindings([]);
    expect(ran.present).toBe(true);
    expect(ran.entries).toEqual([]);
  });
});

describe("asResetActions", () => {
  it("reads the recorded dispositions", () => {
    const read = asResetActions([
      { subject: "guests", disposition: "recreated", detail: "4 guests recreated" },
      { subject: "scores", disposition: "cleared", detail: "" },
    ]);
    expect(read.present).toBe(true);
    expect(read.entries).toHaveLength(2);
    expect(read.entries[0].disposition).toBe("recreated");
  });

  it("refuses an unknown disposition rather than showing it with no tone", () => {
    const read = asResetActions([{ subject: "guests", disposition: "vapourised", detail: "" }]);
    expect(read.entries).toEqual([]);
    expect(read.unreadable[0].reason).toContain("not a member this build knows");
  });

  it("distinguishes a reset that has not run from one that touched nothing", () => {
    expect(asResetActions(null).present).toBe(false);
    expect(asResetActions([]).present).toBe(true);
  });
});

describe("asAbsenceFindings — the (outcome, probe_healthy) pair", () => {
  const resource = { residue_class: "qemu_vm", identifier: "vm/101", address: null };

  it("reads a healthy removal", () => {
    const read = asAbsenceFindings([
      { resource, outcome: "removed", probe_healthy: true, detail: "" },
    ]);
    expect(read.entries).toHaveLength(1);
    expect(residueProvedClean(read.entries as AbsenceFinding[])).toBe(true);
  });

  it("does not treat a removal from an unhealthy probe as proof of absence", () => {
    const read = asAbsenceFindings([
      { resource, outcome: "removed", probe_healthy: false, detail: "probe timed out" },
    ]);
    expect(read.entries).toHaveLength(1);
    expect(residueProvedClean(read.entries as AbsenceFinding[])).toBe(false);
  });

  it("does not treat an empty finding list as a clean teardown", () => {
    // Nothing was probed, so nothing was proved. `unproven` is never folded into `clean`.
    expect(residueProvedClean([])).toBe(false);
  });

  it("keeps `unproven` out of the clean verdict", () => {
    const read = asAbsenceFindings([
      { resource, outcome: "removed", probe_healthy: true, detail: "" },
      { resource, outcome: "unproven", probe_healthy: true, detail: "cluster unreachable" },
    ]);
    expect(residueProvedClean(read.entries as AbsenceFinding[])).toBe(false);
  });

  it("separates a probe that has not run from a probe that found nothing", () => {
    expect(asAbsenceFindings(null).present).toBe(false);
    expect(asAbsenceFindings([]).present).toBe(true);
  });

  it("refuses a residue class this build does not know", () => {
    const read = asAbsenceFindings([
      {
        resource: { residue_class: "quantum_volume", identifier: "x", address: null },
        outcome: "removed",
        probe_healthy: true,
        detail: "",
      },
    ]);
    expect(read.entries).toEqual([]);
    expect(read.unreadable[0].reason).toContain("not a member this build knows");
  });
});

describe("asDeletionSet", () => {
  const document = {
    deletable: [{ residue_class: "qemu_vm", identifier: "vm/101", address: "qemu/101" }],
    protected: [
      {
        resource: { residue_class: "vnet", identifier: "vnet0", address: null },
        provenance: "untagged",
        detail: "no ownership tag",
      },
    ],
    already_absent: [],
    undetermined: [{ residue_class: "disk_volume", identifier: "vm-101-disk-0", address: null }],
  };

  it("keeps `undetermined` as its own bucket", () => {
    const read = asDeletionSet([document]);
    expect(read.present).toBe(true);
    if (!read.present || read.value === null) throw new Error("expected a readable deletion set");
    expect(read.value.deletable).toHaveLength(1);
    expect(read.value.protected).toHaveLength(1);
    expect(read.value.already_absent).toHaveLength(0);
    expect(read.value.undetermined).toHaveLength(1);
  });

  it("accepts the document unwrapped as well as wrapped in a one-element list", () => {
    const wrapped = asDeletionSet([document]);
    const bare = asDeletionSet(document);
    expect(bare).toEqual(wrapped);
  });

  it("distinguishes a destroy plan that did not compile from one that deletes nothing", () => {
    // `deletion_set: null` means NOTHING WAS ENUMERATED. An empty bucketed document means the
    // scope was computed and is empty. Rendering both as "0 objects" makes a destroy look safe
    // when in truth nobody has looked.
    expect(asDeletionSet(null).present).toBe(false);

    const empty = asDeletionSet({
      deletable: [],
      protected: [],
      already_absent: [],
      undetermined: [],
    });
    expect(empty.present).toBe(true);
    if (!empty.present || empty.value === null) throw new Error("expected a readable set");
    expect(empty.value.deletable).toEqual([]);
  });

  it("refuses a flat list of resources rather than guessing a bucket for each", () => {
    const read = asDeletionSet([
      { residue_class: "qemu_vm", identifier: "vm/101", address: null },
      { residue_class: "vnet", identifier: "vnet0", address: null },
    ]);
    expect(read.present).toBe(true);
    if (!read.present) throw new Error("unreachable");
    expect(read.value).toBeNull();
    expect(read.reason).toContain("loose entries");
  });

  it("refuses a protected entry whose provenance is unknown", () => {
    const read = asDeletionSet({
      ...document,
      protected: [
        {
          resource: { residue_class: "vnet", identifier: "vnet0", address: null },
          provenance: "probably_ours",
          detail: "",
        },
      ],
    });
    expect(read.present).toBe(true);
    if (!read.present) throw new Error("unreachable");
    expect(read.value).toBeNull();
    expect(read.reason).toContain("protected");
  });
});
