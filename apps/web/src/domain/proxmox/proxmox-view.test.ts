import { describe, expect, it } from "vitest";

import {
  APPLY_REFUSAL_CODES,
  DESTROY_REFUSAL_CODES,
  EXECUTION_STATUS_NOT_APPLIED,
  RECONCILE_ACTIONS,
  RESET_DISPOSITIONS,
  VERIFICATION_OUTCOMES,
  type CheckFinding,
  type PlanDocument,
} from "../../api/recorded-documents";
import {
  APPLY_AUTHORIZATION_LABEL,
  APPLY_AUTHORIZATION_TONE,
  CHECK_STATUS_TONE,
  DESTROY_AUTHORIZATION_LABEL,
  DESTROY_AUTHORIZATION_TONE,
  OBJECT_PROVENANCE_TONE,
  PLAN_NOT_APPLIED_NOTE,
  RECONCILE_ACTION_TONE,
  RESET_DISPOSITION_TONE,
  TEARDOWN_OUTCOME_TONE,
  TRISTATE_TONE,
  VERIFICATION_OUTCOME_TONE,
  assertSeparateAuthorizations,
  changeCounts,
  checkStatus,
  destroyPreconditionRows,
  guestRows,
  isProxmoxProvider,
  mutationAvailability,
  planHashRows,
  planIsUnapplied,
  providerApplicability,
  residueSummary,
  teamTopology,
  triState,
  verificationSummary,
} from "./proxmox-view";
import {
  absenceFindingsFixture,
  deletionSetFixture,
  destroyPlanFixture,
  planDocumentFixture,
  topologyFixture,
  verificationFixture,
} from "./proxmox-fixtures";

// ------------------------------------------------------- three outcomes, never two

describe("unproven is a third outcome", () => {
  it("gives recovery_required a tone that is neither the success nor a failure tone", () => {
    const ok = VERIFICATION_OUTCOME_TONE.verified;
    const failed = VERIFICATION_OUTCOME_TONE.verification_failed;
    const isolationFailed = VERIFICATION_OUTCOME_TONE.isolation_failed;
    const recovery = VERIFICATION_OUTCOME_TONE.recovery_required;
    expect(recovery).not.toBe(ok);
    expect(recovery).not.toBe(failed);
    expect(recovery).not.toBe(isolationFailed);
  });

  it("gives state_disagreement a tone distinct from both success and failure", () => {
    const disagreement = VERIFICATION_OUTCOME_TONE.state_disagreement;
    expect(disagreement).not.toBe(VERIFICATION_OUTCOME_TONE.verified);
    expect(disagreement).not.toBe(VERIFICATION_OUTCOME_TONE.verification_failed);
  });

  it("maps every VerificationOutcome member (no member falls through)", () => {
    for (const outcome of VERIFICATION_OUTCOMES) {
      expect(VERIFICATION_OUTCOME_TONE[outcome]).toBeTypeOf("string");
    }
  });

  it("separates not_observed from passed and failed", () => {
    expect(CHECK_STATUS_TONE.not_observed).not.toBe(CHECK_STATUS_TONE.passed);
    expect(CHECK_STATUS_TONE.not_observed).not.toBe(CHECK_STATUS_TONE.failed);
  });

  it("separates the teardown unproven verdict from removed and present", () => {
    expect(TEARDOWN_OUTCOME_TONE.unproven).not.toBe(TEARDOWN_OUTCOME_TONE.removed);
    expect(TEARDOWN_OUTCOME_TONE.unproven).not.toBe(TEARDOWN_OUTCOME_TONE.present);
  });

  it("separates a not-stated precondition from yes and from no", () => {
    expect(TRISTATE_TONE.not_stated).not.toBe(TRISTATE_TONE.yes);
    expect(TRISTATE_TONE.not_stated).not.toBe(TRISTATE_TONE.no);
  });

  it("treats an unclassifiable object as neither ours nor a failure", () => {
    expect(OBJECT_PROVENANCE_TONE.unreadable).not.toBe(OBJECT_PROVENANCE_TONE.secp_owned);
    expect(OBJECT_PROVENANCE_TONE.untagged).not.toBe(OBJECT_PROVENANCE_TONE.secp_owned);
  });
});

describe("checkStatus reads the (observed, ok) pair, not ok alone", () => {
  const finding = (observed: boolean, ok: boolean): CheckFinding => ({
    check: "cross_team_denial",
    observed,
    ok,
    detail: "",
  });

  it("reports an unobserved check as not_observed even when ok is false", () => {
    // The trap: the backend emits ok=false for a check it could not run. Reading ok alone reports
    // a segmentation FAILURE nobody observed.
    expect(checkStatus(finding(false, false))).toBe("not_observed");
  });

  it("reports an unobserved check as not_observed even when ok is true", () => {
    expect(checkStatus(finding(false, true))).toBe("not_observed");
  });

  it("reports observed checks normally", () => {
    expect(checkStatus(finding(true, true))).toBe("passed");
    expect(checkStatus(finding(true, false))).toBe("failed");
  });
});

describe("verificationSummary", () => {
  const summary = verificationSummary(verificationFixture.value);

  it("counts unobserved checks separately from failures", () => {
    expect(summary.notObserved).toBe(4);
    expect(summary.failed).toBe(0);
  });

  it("names the isolation checks that were not observed", () => {
    expect(summary.isolationNotObserved).toEqual([
      "cross_team_denial",
      "management_denial",
      "protected_denial",
      "external_denial",
    ]);
  });

  it("does not round an unobservable outcome to verified", () => {
    expect(summary.outcome).toBe("recovery_required");
  });
});

describe("triState", () => {
  it("maps null to not_stated rather than to no", () => {
    expect(triState(null)).toBe("not_stated");
    expect(triState(undefined)).toBe("not_stated");
    expect(triState(false)).toBe("no");
    expect(triState(true)).toBe("yes");
  });
});

// ------------------------------------------------------- the plan has not run

describe("plan execution status", () => {
  it("says NOT APPLIED", () => {
    expect(EXECUTION_STATUS_NOT_APPLIED).toBe("NOT APPLIED");
    expect(planIsUnapplied(planDocumentFixture.value)).toBe(true);
  });

  it("reads the status from the document, never from a lifecycle state", () => {
    const applied: PlanDocument = { ...planDocumentFixture.value, execution_status: "APPLIED" };
    expect(planIsUnapplied(applied)).toBe(false);
  });

  it("states plainly in the notice copy that nothing has run and nothing here starts apply", () => {
    expect(PLAN_NOT_APPLIED_NOTE).toContain("NOT APPLIED");
    expect(PLAN_NOT_APPLIED_NOTE).toContain("has not run");
    expect(PLAN_NOT_APPLIED_NOTE).toContain("nothing on this screen starts apply");
  });

  it("exposes the three hashes the gate checks independently", () => {
    const rows = planHashRows(planDocumentFixture.value);
    expect(rows.map((r) => r.key)).toEqual([
      "plan_document_hash",
      "change_set_hash",
      "desired_state_hash",
    ]);
  });

  it("counts the apply plan's intended change", () => {
    expect(changeCounts(planDocumentFixture.value)).toEqual({ create: 16, update: 0, destroy: 0 });
  });
});

// ------------------------------------------------------- apply and destroy stay separate

describe("apply and destroy authorization are separate", () => {
  it("throws if the two plans ever share a change-set hash", () => {
    expect(() => assertSeparateAuthorizations("sha256:aaa", "sha256:aaa")).toThrow(
      /distinct plan with a distinct hash/,
    );
  });

  it("permits distinct hashes", () => {
    expect(() => assertSeparateAuthorizations("sha256:aaa", "sha256:bbb")).not.toThrow();
  });

  it("holds for the shipped fixtures — the destroy plan is a different plan", () => {
    expect(destroyPlanFixture.value.change_set_hash).not.toBe(
      planDocumentFixture.value.change_set_hash,
    );
    expect(() =>
      assertSeparateAuthorizations(
        planDocumentFixture.value.change_set_hash,
        destroyPlanFixture.value.change_set_hash,
      ),
    ).not.toThrow();
  });

  it("keeps the two authorization state vocabularies disjoint", () => {
    const applyStates = Object.keys(APPLY_AUTHORIZATION_TONE);
    const destroyStates = Object.keys(DESTROY_AUTHORIZATION_TONE);
    const shared = applyStates.filter((s) => destroyStates.includes(s) && s !== "not_requested");
    expect(shared).toEqual([]);
  });

  it("never renders an approved plan as though apply were authorized", () => {
    expect(APPLY_AUTHORIZATION_LABEL.plan_approved_apply_not_authorized).toContain(
      "NOT authorized",
    );
    expect(APPLY_AUTHORIZATION_TONE.plan_approved_apply_not_authorized).not.toBe(
      APPLY_AUTHORIZATION_TONE.apply_authorized,
    );
  });

  it("never renders an approved destroy plan as though destroy were authorized", () => {
    expect(DESTROY_AUTHORIZATION_LABEL.destroy_plan_approved_not_authorized).toContain(
      "NOT authorized",
    );
    expect(DESTROY_AUTHORIZATION_TONE.destroy_plan_approved_not_authorized).not.toBe(
      DESTROY_AUTHORIZATION_TONE.destroy_authorized,
    );
  });

  it("keeps the backend refusal-code namespaces disjoint too", () => {
    for (const code of APPLY_REFUSAL_CODES) expect(code.startsWith("proxmox.apply.")).toBe(true);
    for (const code of DESTROY_REFUSAL_CODES) {
      expect(code.startsWith("proxmox.destroy.")).toBe(true);
    }
    const overlap = (APPLY_REFUSAL_CODES as readonly string[]).filter((c) =>
      (DESTROY_REFUSAL_CODES as readonly string[]).includes(c),
    );
    expect(overlap).toEqual([]);
  });

  it("binds a destroy approval to the destroy operation kind", () => {
    expect(DESTROY_REFUSAL_CODES).toContain("proxmox.destroy.approval_is_not_for_destroy");
  });
});

describe("destroyPreconditionRows", () => {
  it("inverts approval_already_consumed so yes is always the safe answer", () => {
    const consumed = destroyPreconditionRows({
      ownership_verified: true,
      discovery_fresh: true,
      remote_state_lock_held: true,
      credential_resolved: true,
      approval_already_consumed: true,
    });
    const row = consumed.find((r) => r.key === "approval_not_consumed");
    expect(row?.state).toBe("no");

    const unconsumed = destroyPreconditionRows({
      ownership_verified: true,
      discovery_fresh: true,
      remote_state_lock_held: true,
      credential_resolved: true,
      approval_already_consumed: false,
    });
    expect(unconsumed.find((r) => r.key === "approval_not_consumed")?.state).toBe("yes");
  });
});

// ------------------------------------------------------- the browser is not the boundary

describe("mutationAvailability", () => {
  it("gives a reason when a control is offered", () => {
    const a = mutationAvailability("draft", ["draft"], "Recording a decision");
    expect(a.enabled).toBe(true);
    expect(a.reason).toContain("server still authorizes it independently");
  });

  it("gives a reason when a control is NOT offered, and says the absence is not the boundary", () => {
    const a = mutationAvailability("destroyed", ["draft"], "Recording a decision");
    expect(a.enabled).toBe(false);
    expect(a.reason).toContain("not the boundary");
    expect(a.reason).toContain("refused server-side");
  });
});

// ------------------------------------------------------- residue accounting

describe("residueSummary", () => {
  const summary = residueSummary(deletionSetFixture.value, absenceFindingsFixture.value);

  it("does not count a removed verdict from an unhealthy probe as confirmed", () => {
    // The fixture has 5 removed findings; one of the unproven rows also has probe_healthy false.
    expect(summary.confirmedAbsent).toBe(5);
  });

  it("counts an unhealthy probe as unproven regardless of its stated outcome", () => {
    expect(summary.unproven).toBe(2);
  });

  it("refuses to call a teardown clean while anything is present, unproven or undetermined", () => {
    expect(summary.provedClean).toBe(false);
  });

  it("carries the undetermined bucket through as its own number", () => {
    expect(summary.undetermined).toBe(1);
  });

  it("would not report clean on an empty finding set", () => {
    const empty = residueSummary(
      { deletable: [], protected: [], already_absent: [], undetermined: [] },
      [],
    );
    expect(empty.provedClean).toBe(false);
  });
});

// ------------------------------------------------------- topology projection

describe("topology projection", () => {
  const topology = topologyFixture.value;

  it("groups segments and guests by team ref", () => {
    const teams = teamTopology(topology.network, topology.guests);
    expect(teams.map((t) => t.teamRef)).toEqual(["team-alpha", "team-bravo"]);
    for (const team of teams) {
      expect(team.segments.length).toBe(2);
      expect(team.guests.length).toBe(3);
    }
  });

  it("keeps published and probe addresses separate, including when there is no probe address", () => {
    const rows = guestRows(topology.guests);
    const sensor = rows.find((g) => g.guestRef === "alpha-sensor");
    expect(sensor?.publishedAddress).toBe("10.80.17.30");
    expect(sensor?.probeAddress).toBeNull();
  });

  it("surfaces MACs, VMIDs, node placement and storage per guest", () => {
    const rows = guestRows(topology.guests);
    const attacker = rows.find((g) => g.guestRef === "alpha-attacker");
    expect(attacker?.vmid).toBe(9101);
    expect(attacker?.node).toBe("pve-node-1");
    expect(attacker?.macs).toEqual(["BC:24:11:00:1A:01"]);
    expect(attacker?.storageIds).toEqual(["local-lvm"]);
    expect(attacker?.totalDiskGb).toBe(60);
  });

  it("puts the ownership identifiers on every guest row", () => {
    for (const row of guestRows(topology.guests)) {
      expect(row.ownershipLine).toContain("org=");
      expect(row.ownershipLine).toContain("range=");
      expect(row.ownershipLine).toContain("gen=");
    }
  });
});

// ------------------------------------------------------- provider applicability

describe("providerApplicability", () => {
  it("recognises the Proxmox provider names", () => {
    expect(isProxmoxProvider("proxmox")).toBe(true);
    expect(isProxmoxProvider("Proxmox")).toBe(true);
    expect(isProxmoxProvider("proxmox_ve")).toBe(true);
    expect(isProxmoxProvider("local_docker")).toBe(false);
  });

  it("says plainly that the page does not describe a non-Proxmox range", () => {
    const a = providerApplicability("local_docker");
    expect(a.applies).toBe(false);
    expect(a.note).toContain("not Proxmox");
    expect(a.note).toContain("Nothing on these Proxmox tabs describes this range");
  });

  it("says the page applies for a Proxmox range", () => {
    expect(providerApplicability("proxmox").applies).toBe(true);
  });
});

// ------------------------------------------------------- exhaustiveness

describe("tone maps are exhaustive over their enums", () => {
  it("covers every ReconcileAction", () => {
    for (const a of RECONCILE_ACTIONS) expect(RECONCILE_ACTION_TONE[a]).toBeTypeOf("string");
  });

  it("covers every ResetDisposition", () => {
    for (const d of RESET_DISPOSITIONS) expect(RESET_DISPOSITION_TONE[d]).toBeTypeOf("string");
  });
});
