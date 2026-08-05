// The invariants the opaque-member readers exist to hold.
//
// These are not shape tests. Each one names a way a client could turn an honest recording into a
// dishonest reading, and pins the reader against it.

import { describe, expect, it } from "vitest";

import {
  asAbsenceFindings,
  asDeletionSet,
  asResetActions,
  checkStatus,
  residueProvedClean,
} from "./recorded";
import type { AbsenceFinding } from "./recorded-documents";
import type { CheckFindingOut } from "./generated/openapi";

describe("checkStatus reads the (observed, ok) pair, not `ok` alone", () => {
  // The hand-written reader that used to recover this pair from an opaque dict is gone: the
  // contract types it now. What survives is the RULE, which no type system enforces — reading
  // `ok` alone reports an unobserved check as a failure, a finding nobody made.
  const finding = (observed: boolean, ok: boolean | null): CheckFindingOut => ({
    check: "cross_team_denial",
    observed,
    ok,
    detail: "",
  });

  it("reports an unobserved check as not_observed whatever `ok` says", () => {
    // Both legacy and current shapes. `ok: false` is what two producers emitted before `ok`
    // became nullable, and those events are durable; `ok: null` is what the worker writes now.
    expect(checkStatus(finding(false, null))).toBe("not_observed");
    expect(checkStatus(finding(false, false))).toBe("not_observed");
    expect(checkStatus(finding(false, true))).toBe("not_observed");
  });

  it("reports observed checks normally", () => {
    expect(checkStatus(finding(true, true))).toBe("passed");
    expect(checkStatus(finding(true, false))).toBe("failed");
  });

  it("does not read a null verdict as a failure", () => {
    // `null ? a : b` takes the false branch, so an `ok: null` that reached here through a
    // hand-built value would render as FAILED without the explicit check. The worker cannot emit
    // `observed=true, ok=null` — its __post_init__ refuses it — but the guard costs one line.
    expect(checkStatus(finding(true, null))).toBe("not_observed");
  });

  it("treats an absent `ok` as no verdict, since the contract marks it optional", () => {
    const absent = { check: "power_state", observed: false, detail: "" } as CheckFindingOut;
    expect(checkStatus(absent)).toBe("not_observed");
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
