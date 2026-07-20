import type {
  DiscoveryCandidatePlan,
  DiscoveryEnrollment,
  DiscoveryEvidence,
} from "../api/types";
import { resolveClosedCodeCopy } from "../components/ui/closed-code-error";
import {
  DISCOVERY_ERROR_TEXT,
  PLAN_APPROVAL_DECISION_NOTICE,
  PLAN_NON_EXECUTABLE_NOTICE,
  REQUEST_ENQUEUE_NOTICE,
  WORKER_QUEUED_NOTICE,
  WORKER_RUNNING_NOTICE,
  candidatePlanRows,
  discoveryRailItems,
  eligibilityView,
  evidenceFacts,
  isOffRail,
  planIsApprovable,
  workerPostureRows,
} from "./discovery-view";

const enrollment = (over: Partial<DiscoveryEnrollment> = {}): DiscoveryEnrollment =>
  ({
    id: "e1",
    display_name: "secp-disc/alpha",
    ownership_label: "secp-owned/alpha",
    status: "requested",
    enrollment_version: 1,
    revision: 0,
    active_plan_hash: "",
    approved_plan_hash: "",
    approved_at: null,
    failure_code: null,
    ...over,
  }) as DiscoveryEnrollment;

const evidence = (over: Partial<DiscoveryEvidence> = {}): DiscoveryEvidence =>
  ({
    eligibility: "eligible",
    reason_code: null,
    version_major: 8,
    version_minor: 1,
    is_clustered: false,
    node: "pve-a",
    node_count: 1,
    cpu_total: 16,
    mem_total_mb: 65536,
    mem_free_mb: 40000,
    nested_available: true,
    selected_storage: "local-zfs",
    storage_count: 2,
    candidate_vmids: [9000, 9001],
    evidence_hash: "sha256:abc",
    bundle_available: true,
    contact_state: "contacted",
    created_at: "2026-07-10T09:00:00Z",
    ...over,
  }) as DiscoveryEvidence;

describe("discoveryRailItems", () => {
  it("keeps requested/discovering/discovered distinct and never marks later steps complete", () => {
    const items = discoveryRailItems("discovering");
    expect(items.find((i) => i.id === "requested")!.state).toBe("complete");
    expect(items.find((i) => i.id === "discovering")!.state).toBe("current");
    expect(items.find((i) => i.id === "discovered")!.state).toBe("blocked");
    expect(items.find((i) => i.id === "plan_ready")!.state).toBe("blocked");
    expect(items.find((i) => i.id === "approved")!.state).toBe("blocked");
  });

  it("plan_ready marks evidence recorded complete but approved still blocked", () => {
    const items = discoveryRailItems("plan_ready");
    expect(items.find((i) => i.id === "discovered")!.state).toBe("complete");
    expect(items.find((i) => i.id === "plan_ready")!.state).toBe("current");
    expect(items.find((i) => i.id === "approved")!.state).toBe("blocked");
  });

  it("failed is off-rail (all blocked), never marking skipped states complete", () => {
    expect(isOffRail("failed")).toBe(true);
    const items = discoveryRailItems("failed");
    expect(items.every((i) => i.state === "blocked")).toBe(true);
  });

  it("keeps queued copy distinct from running copy (queued is not running)", () => {
    expect(WORKER_QUEUED_NOTICE).toContain("queued");
    expect(WORKER_QUEUED_NOTICE).toContain("will claim");
    expect(WORKER_RUNNING_NOTICE).toContain("has claimed");
    expect(WORKER_RUNNING_NOTICE.toLowerCase()).toContain("running is not completed");
    expect(WORKER_QUEUED_NOTICE).not.toBe(WORKER_RUNNING_NOTICE);
  });
});

describe("eligibilityView", () => {
  it("is pending (not recorded) when evidence is absent — never a false ineligible", () => {
    const v = eligibilityView(null);
    expect(v).toMatchObject({ state: "pending", recorded: false, reasonCode: null });
  });

  it("distinguishes eligible / ineligible / unverifiable and keeps the reason code visible", () => {
    expect(eligibilityView(evidence({ eligibility: "eligible" })).state).toBe("eligible");
    const ineligible = eligibilityView(
      evidence({ eligibility: "ineligible", reason_code: "nested_virtualization_unavailable" }),
    );
    expect(ineligible.state).toBe("ineligible");
    expect(ineligible.reasonCode).toBe("nested_virtualization_unavailable");
    const unverifiable = eligibilityView(evidence({ eligibility: "unverifiable" }));
    expect(unverifiable.state).toBe("unverifiable");
    expect(unverifiable.label).toContain("neither pass nor fail");
  });
});

describe("evidenceFacts", () => {
  it("returns nothing before evidence is recorded", () => {
    expect(evidenceFacts(null)).toEqual([]);
  });

  it("renders only allowlisted facts and drops unknown keys", () => {
    const facts = evidenceFacts(
      Object.assign(evidence(), { totally_unknown_key: "leaked", raw_output: "secret" } as never),
    );
    const keys = facts.map((f) => f.key);
    expect(keys).toContain("proxmox_version");
    expect(keys).toContain("nested_available");
    expect(keys).toContain("candidate_vmids");
    expect(keys).not.toContain("totally_unknown_key");
    expect(keys).not.toContain("raw_output");
    expect(facts.find((f) => f.key === "nested_available")!.value).toBe("yes");
  });

  it("omits null/absent facts (no false zeros)", () => {
    const facts = evidenceFacts(
      evidence({ node: null, mem_free_mb: null, candidate_vmids: [] }),
    );
    const keys = facts.map((f) => f.key);
    expect(keys).not.toContain("node");
    expect(keys).not.toContain("mem_free_mb");
    expect(keys).not.toContain("candidate_vmids");
  });
});

describe("candidate plan", () => {
  const plan = (over: Partial<DiscoveryCandidatePlan> = {}): DiscoveryCandidatePlan =>
    ({
      plan_version: 1,
      plan_hash: "sha256:plan1",
      enrollment_version: 1,
      ownership_tag: "secp/alpha",
      resource_profile: "small_lab",
      node: "pve-a",
      storage: "local-zfs",
      capacity_snapshot_hash: "sha256:cap",
      evidence_hash: "sha256:ev",
      expires_at: "2026-07-11T09:00:00Z",
      executable: false,
      status: "draft",
      resources: [],
      ...over,
    }) as DiscoveryCandidatePlan;

  it("is approvable only when draft and pinned to the enrollment's active hash", () => {
    const e = enrollment({ status: "plan_ready", active_plan_hash: "sha256:plan1" });
    expect(planIsApprovable(plan(), e)).toBe(true);
    // stale: plan hash differs from active hash
    expect(planIsApprovable(plan({ plan_hash: "sha256:OLD" }), e)).toBe(false);
    // not draft
    expect(planIsApprovable(plan({ status: "superseded" }), e)).toBe(false);
    // no plan
    expect(planIsApprovable(null, e)).toBe(false);
  });

  it("summarizes real plan fields without inventing values", () => {
    const rows = candidatePlanRows(plan());
    const byKey = Object.fromEntries(rows.map((r) => [r.key, r.value]));
    expect(byKey["Plan version"]).toBe("1");
    expect(byKey["Node"]).toBe("pve-a");
    expect(byKey["Status"]).toBe("draft");
  });

  it("truth copy separates decision from execution", () => {
    expect(PLAN_APPROVAL_DECISION_NOTICE).toContain("records a decision");
    expect(PLAN_APPROVAL_DECISION_NOTICE.toLowerCase()).toContain("sealed");
    expect(PLAN_NON_EXECUTABLE_NOTICE).toContain("non-executable");
    expect(PLAN_NON_EXECUTABLE_NOTICE).toContain("exact plan hash");
  });
});

describe("workerPostureRows", () => {
  it("shows server-owned identity, version and revision", () => {
    const rows = workerPostureRows(enrollment({ enrollment_version: 2, revision: 1 }));
    const byKey = Object.fromEntries(rows.map((r) => [r.key, r.value]));
    expect(byKey["Ownership identity"]).toBe("secp-owned/alpha");
    expect(byKey["Enrollment version"]).toBe("2");
    expect(byKey["Revision"]).toBe("1");
  });
});

describe("DISCOVERY_ERROR_TEXT", () => {
  it("maps real reason/failure codes to fixed copy, never the backend message", () => {
    const err = Object.assign(new Error("raw backend at :8006"), {
      code: "probe_source_sealed",
    });
    const copy = resolveClosedCodeCopy(err, DISCOVERY_ERROR_TEXT);
    expect(copy.text).toBe(DISCOVERY_ERROR_TEXT.probe_source_sealed);
    expect(copy.text).not.toContain("8006");
  });

  it("guards malformed and prototype-key codes; unknown-valid falls back", () => {
    expect(
      resolveClosedCodeCopy(Object.assign(new Error("x"), { code: "Trace at :9 !!" }), DISCOVERY_ERROR_TEXT).code,
    ).toBe("error");
    for (const code of ["constructor", "__proto__", "toString"]) {
      const c = resolveClosedCodeCopy(Object.assign(new Error("x"), { code }), DISCOVERY_ERROR_TEXT);
      expect(typeof c.text).toBe("string");
      expect(c.text).not.toContain("function");
    }
  });

  it("keeps all fixed copy free of endpoints and secret material", () => {
    for (const text of [
      ...Object.values(DISCOVERY_ERROR_TEXT),
      REQUEST_ENQUEUE_NOTICE,
      PLAN_NON_EXECUTABLE_NOTICE,
    ]) {
      expect(text).not.toMatch(/:\/\//);
      expect(text).not.toMatch(/:\d{4,5}\b/);
      expect(text).not.toMatch(/-----BEGIN [A-Z ]*PRIVATE KEY-----/);
    }
  });
});
