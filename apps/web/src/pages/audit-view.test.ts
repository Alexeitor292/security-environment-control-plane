import type { AuditEvent } from "../api/types";
import {
  EMPTY_LEDGER_FILTER,
  LEDGER_UNAVAILABLE,
  OPERATOR_SAFE_NOTE,
  QUEUE_EXECUTES_NOTHING,
  QUEUE_INTRO,
  actionCategory,
  actionVerb,
  decisionRecords,
  detailFields,
  filterLedger,
  hiddenFieldsNote,
  isDecisionAction,
  isFlaggedOutcome,
  isRefusalDecision,
  ledgerCategories,
  ledgerTally,
  ledgerTimestamp,
} from "./audit-view";

function ev(over: Partial<AuditEvent>): AuditEvent {
  return {
    id: over.id ?? "e1",
    actor: "dev-admin",
    action: "onboarding.approved",
    resource_type: "target_onboarding",
    resource_id: "abc123",
    outcome: "success",
    data: {},
    created_at: "2026-07-10T12:00:00Z",
    ...over,
  };
}

describe("ledgerTimestamp", () => {
  it("formats the recorded naive-UTC string verbatim, never via Date parsing", () => {
    // A naive string parsed with `new Date(...)` would shift by the local
    // offset; string slicing preserves the recorded UTC wall clock.
    expect(ledgerTimestamp("2026-07-10T22:50:32.098707")).toBe(
      "2026-07-10 22:50:32",
    );
    expect(ledgerTimestamp("2026-07-10T22:50:32Z")).toBe("2026-07-10 22:50:32");
  });
});

describe("action structure", () => {
  it("derives category and verb from category.verb actions", () => {
    expect(actionCategory("onboarding.approved")).toBe("onboarding");
    expect(actionCategory("live_read.authorization_approved")).toBe("live_read");
    expect(actionVerb("live_read.authorization_approved")).toBe(
      "authorization_approved",
    );
  });

  it("groups malformed actions under 'other' instead of inventing categories", () => {
    expect(actionCategory("no-dots-here")).toBe("other");
    expect(actionCategory("")).toBe("other");
    expect(actionCategory("Weird Category.thing")).toBe("other");
  });

  it("derives categories only from loaded events", () => {
    const cats = ledgerCategories([
      ev({ action: "plan.approved" }),
      ev({ action: "onboarding.refused" }),
      ev({ action: "plan.rejected" }),
    ]);
    expect(cats).toEqual(["onboarding", "plan"]);
  });
});

describe("filterLedger", () => {
  const events = [
    ev({ id: "a", action: "plan.approved", outcome: "success" }),
    ev({ id: "b", action: "authorization.denied", outcome: "denied" }),
    ev({ id: "c", action: "onboarding.created", outcome: "success" }),
  ];

  it("flagged means any non-success outcome", () => {
    expect(isFlaggedOutcome("denied")).toBe(true);
    expect(isFlaggedOutcome("revoked")).toBe(true);
    expect(isFlaggedOutcome("success")).toBe(false);
    const flagged = filterLedger(events, {
      ...EMPTY_LEDGER_FILTER,
      outcome: "flagged",
    });
    expect(flagged.map((e) => e.id)).toEqual(["b"]);
  });

  it("filters by category and case-insensitive query", () => {
    expect(
      filterLedger(events, { ...EMPTY_LEDGER_FILTER, category: "plan" }).map(
        (e) => e.id,
      ),
    ).toEqual(["a"]);
    expect(
      filterLedger(events, { ...EMPTY_LEDGER_FILTER, query: "DENIED" }).map(
        (e) => e.id,
      ),
    ).toEqual(["b"]);
  });

  it("tally counts only loaded events", () => {
    const t = ledgerTally(events);
    expect(t).toEqual({ total: 3, flagged: 1, decisions: 2 });
  });
});

describe("decision classification — refusal keyed on verb, not outcome", () => {
  it("detects decision actions including compound verbs", () => {
    expect(isDecisionAction("plan.approved")).toBe(true);
    expect(isDecisionAction("live_read.authorization_validation_refused")).toBe(
      true,
    );
    expect(isDecisionAction("deploy.started")).toBe(false);
    expect(isDecisionAction("lifecycle.transition")).toBe(false);
  });

  it("a rejected decision recorded with outcome success is still a refusal", () => {
    const rejected = ev({ action: "plan.rejected", outcome: "success" });
    expect(isRefusalDecision(rejected)).toBe(true);
  });

  it("splits records with refusals separated from approvals, newest first", () => {
    const { refusals, approvals } = decisionRecords([
      ev({ id: "ok", action: "onboarding.approved", created_at: "2026-07-10T10:00:00Z" }),
      ev({ id: "no", action: "onboarding.rejected", created_at: "2026-07-10T11:00:00Z" }),
      ev({
        id: "deny",
        action: "authorization.denied",
        outcome: "denied",
        created_at: "2026-07-10T12:00:00Z",
      }),
      ev({ id: "noise", action: "deploy.completed" }),
    ]);
    expect(refusals.map((r) => r.id)).toEqual(["deny", "no"]);
    expect(approvals.map((r) => r.id)).toEqual(["ok"]);
  });

  it("an approval recorded with a non-success outcome is never shown as an approval", () => {
    const { refusals, approvals } = decisionRecords([
      ev({ id: "x", action: "onboarding.approved", outcome: "failed" }),
    ]);
    expect(approvals).toEqual([]);
    expect(refusals.map((r) => r.id)).toEqual(["x"]);
  });

  it("extracts only grammar-safe reason codes", () => {
    const { refusals } = decisionRecords([
      ev({
        id: "r",
        action: "onboarding.refused",
        data: { reason_code: "boundary_mismatch" },
      }),
      ev({
        id: "bad",
        action: "onboarding.refused",
        data: { reason_code: "<script>alert(1)</script>" },
      }),
    ]);
    expect(refusals.find((r) => r.id === "r")?.reasonCode).toBe(
      "boundary_mismatch",
    );
    expect(refusals.find((r) => r.id === "bad")?.reasonCode).toBeNull();
  });
});

describe("detailFields — operator-safe allowlist", () => {
  it("shows allowlisted primitives and counts everything else", () => {
    const { fields, hiddenCount } = detailFields(
      ev({
        data: {
          reason_code: "capacity_insufficient",
          plan_hash: "sha256:" + "ab".repeat(32),
          team_count: 3,
          error: "Traceback (most recent call last): boom", // blocked free-form
          nested: { deep: true }, // non-primitive
          unknown_key: "whatever", // not allowlisted
        },
      }),
    );
    const keys = fields.map((f) => f.key);
    expect(keys).toEqual(["reason_code", "team_count", "plan_hash"]);
    expect(fields.find((f) => f.key === "plan_hash")?.hash).toBe(true);
    expect(hiddenCount).toBe(3);
    expect(hiddenFieldsNote(1)).toContain("1 recorded field not displayed");
  });

  it("never renders free-form backend internals or secret-shaped values", () => {
    const { fields, hiddenCount } = detailFields(
      ev({
        data: {
          error: "raw backend message",
          message: "another",
          summary: "yet another",
          reason: "-----BEGIN OPENSSH PRIVATE KEY----- oops",
        },
      }),
    );
    expect(fields).toEqual([]);
    expect(hiddenCount).toBe(4);
  });

  it("caps long recorded reasons without truncating hashes", () => {
    // Realistic prose (spaces break any unbroken run) longer than the cap.
    const long = Array(40).fill("declared boundary check").join(" ");
    const hash = "sha256:" + "cd".repeat(32);
    const { fields } = detailFields(
      ev({ data: { reason: long, evidence_hash: hash } }),
    );
    const reason = fields.find((f) => f.key === "reason");
    expect(reason).toBeDefined();
    expect(reason?.value.length).toBeLessThanOrEqual(161);
    expect(fields.find((f) => f.key === "evidence_hash")?.value).toBe(hash);
  });

  it("withholds secret-shaped values in free-form fields, visibly", () => {
    const { fields, hiddenCount } = detailFields(
      ev({
        data: {
          reason: "token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload",
          label: "AKIAIOSFODNN7EXAMPLE0",
          slug: "a".repeat(80), // long unbroken run
          status: "rejected", // normal value stays
        },
      }),
    );
    expect(fields.map((f) => f.key)).toEqual(["status"]);
    expect(hiddenCount).toBe(3);
  });

  it("never withholds hash fields for being long hex (content addresses render)", () => {
    const hash = "sha256:" + "ab".repeat(32);
    const { fields } = detailFields(ev({ data: { plan_hash: hash } }));
    expect(fields.find((f) => f.key === "plan_hash")?.value).toBe(hash);
  });

  it("is safe against prototype-pollution keys", () => {
    const data = JSON.parse('{"__proto__": {"reason_code": "fake"}}');
    const { fields } = detailFields(ev({ data }));
    expect(fields).toEqual([]);
  });
});

describe("decision-verb vocabulary — pinned against the backend action catalog", () => {
  // Every decision-recording AuditAction the backend defines today (grepped
  // from apps/api/secp_api/enums.py). If the backend grows a decision verb
  // outside the closed form set, this list must be extended together with
  // DECISION_VERBS — otherwise the new decisions silently drop from the tally.
  const BACKEND_DECISION_ACTIONS = [
    "version.mutation_rejected",
    "plan.approved",
    "plan.rejected",
    "apply.refused",
    "execution.refused",
    "authorization.denied",
    "provider.operation_refused",
    "deploy.target_refused",
    "manifest.generation_refused",
    "provisioning.refused",
    "toolchain.profile_refused",
    "provisioning.change_set_approved",
    "provisioning.change_set_rejected",
    "provisioning.real_refused",
    "onboarding.approved",
    "onboarding.rejected",
    "onboarding.refused",
    "live_read.authorization_approved",
    "live_read.authorization_revoked",
    "live_read.authorization_validation_refused",
    "staging_lab.approved",
    "staging_lab.rejected",
  ];

  it("classifies every backend decision action as a decision", () => {
    for (const action of BACKEND_DECISION_ACTIONS) {
      expect(isDecisionAction(action), action).toBe(true);
    }
  });

  it("keeps non-decision lifecycle actions out of the decision tally", () => {
    for (const action of [
      "deploy.started",
      "deploy.completed",
      "onboarding.activated",
      "plan.generated",
      "plan.submitted",
      "lifecycle.transition",
      "target.created",
    ]) {
      expect(isDecisionAction(action), action).toBe(false);
    }
  });
});

describe("truth copy", () => {
  it("queue copy records decisions and never implies execution", () => {
    expect(QUEUE_EXECUTES_NOTHING).toContain("records a decision");
    expect(QUEUE_EXECUTES_NOTHING.toLowerCase()).toContain("remain sealed");
    expect(QUEUE_INTRO).toContain("owning surface");
    expect(QUEUE_INTRO.toLowerCase()).not.toContain("execute");
  });

  it("unavailability copy is closed (no backend text interpolation)", () => {
    expect(LEDGER_UNAVAILABLE).toBe("Audit log unavailable.");
    expect(OPERATOR_SAFE_NOTE.toLowerCase()).toContain("allowlisted");
  });
});
