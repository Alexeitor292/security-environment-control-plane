import { resolveClosedCodeCopy } from "../components/ui/closed-code-error";
import { NO_APPROVED_SEGMENTS_MESSAGE, emptyDraft } from "./onboarding-wizard";
import {
  DRAFT_NOT_SAVED_NOTICE,
  LIFECYCLE_ACTIONS,
  ONBOARDING_ERROR_TEXT,
  STEP_TITLES,
  SUMMARY_TRUTH_NOTICE,
  boundarySummaryDeclaredRows,
  boundarySummaryDraftRows,
  lifecycleActionEnabled,
  wizardStepStates,
} from "./onboarding-wizard-view";

const gates = (over: Partial<Parameters<typeof wizardStepStates>[1]> = {}) => ({
  targetSelected: true,
  targetHasSegments: true,
  validationOk: false,
  onboardingExists: false,
  ...over,
});

describe("wizardStepStates", () => {
  it("blocks everything past step 0 until a target with segments is selected", () => {
    const states = wizardStepStates(0, gates({ targetSelected: false }));
    expect(states[0].state).toBe("current");
    for (const s of states.slice(1)) {
      expect(s.state).toBe("blocked");
      expect(s.blockedReason).toBe("Select a target first.");
    }
    const noSegments = wizardStepStates(0, gates({ targetHasSegments: false }));
    expect(noSegments[1].blockedReason).toBe(NO_APPROVED_SEGMENTS_MESSAGE);
  });

  it("never lets the rail reach further than chained canAdvanceWizardStep gates", () => {
    // Valid target: steps 1..5 pass trivially, but step 5 gates step 6.
    const states = wizardStepStates(0, gates());
    expect(states.map((s) => s.state)).toEqual([
      "current",
      "available",
      "available",
      "available",
      "available",
      "available",
      "blocked",
    ]);
    const withValidation = wizardStepStates(0, gates({ validationOk: true }));
    expect(withValidation[6].state).toBe("available");
    const withOnboarding = wizardStepStates(5, gates({ onboardingExists: true }));
    expect(withOnboarding[6].state).toBe("available");
  });

  it("always allows revisiting earlier steps", () => {
    const states = wizardStepStates(5, gates());
    for (const s of states.slice(0, 5)) expect(s.state).toBe("complete");
  });

  it("has one rail entry per wizard step", () => {
    expect(wizardStepStates(0, gates())).toHaveLength(STEP_TITLES.length);
  });
});

describe("lifecycleActionEnabled", () => {
  it("mirrors the exact status-equality gates of the previous wizard", () => {
    expect(lifecycleActionEnabled("preflight", "draft")).toBe(true);
    expect(lifecycleActionEnabled("preflight", "preflight_pending")).toBe(false);
    expect(lifecycleActionEnabled("submit", "preflight_pending")).toBe(true);
    expect(lifecycleActionEnabled("submit", "draft")).toBe(false);
    expect(lifecycleActionEnabled("approve", "ready_for_review")).toBe(true);
    expect(lifecycleActionEnabled("approve", "approved")).toBe(false);
    expect(lifecycleActionEnabled("activate", "approved")).toBe(true);
    expect(lifecycleActionEnabled("activate", "active")).toBe(false);
  });
});

describe("lifecycle action copy", () => {
  it("keeps every stage explanation truthful and simulated-labeled", () => {
    for (const action of LIFECYCLE_ACTIONS) {
      expect(action.simulated).toBe(true);
      expect(action.doesNot.length).toBeGreaterThan(0);
      const text = `${action.does} ${action.doesNot} ${action.next}`.toLowerCase();
      expect(text).not.toContain("coming soon");
      expect(text).not.toMatch(/:\/\//);
    }
    const approve = LIFECYCLE_ACTIONS.find((a) => a.id === "approve")!;
    expect(approve.doesNot.toLowerCase()).toContain("does not activate");
    expect(approve.doesNot.toLowerCase()).toContain("live access");
  });

  it("keeps the truth notices honest about draft/approved/active separation", () => {
    expect(SUMMARY_TRUTH_NOTICE).toContain("draft is not approved");
    expect(SUMMARY_TRUTH_NOTICE).toContain("approved boundary is not active");
    expect(DRAFT_NOT_SAVED_NOTICE.toLowerCase()).toContain("nothing is saved");
  });
});

describe("ONBOARDING_ERROR_TEXT", () => {
  it("resolves closed codes to fixed copy and never a backend message", () => {
    const err = Object.assign(new Error("raw backend text at :8006"), {
      code: "invalid_transition",
    });
    const copy = resolveClosedCodeCopy(err, ONBOARDING_ERROR_TEXT);
    expect(copy.text).toBe(ONBOARDING_ERROR_TEXT.invalid_transition);
    expect(copy.text).not.toContain("8006");
  });

  it("keeps fixed copy free of endpoints and secret language", () => {
    for (const text of Object.values(ONBOARDING_ERROR_TEXT)) {
      expect(text).not.toMatch(/:\/\//);
      expect(text.toLowerCase()).not.toContain("token");
    }
  });
});

describe("boundarySummaryDeclaredRows", () => {
  it("renders the server-recorded boundary, not the local draft", () => {
    const rows = boundarySummaryDeclaredRows({
      onboarding_mode: "existing_environment",
      isolation_model: "physical",
      network_approach: "use_approved_existing_segment",
      isolation_profile: "fully_segregated",
      declared_boundary: {
        nodes: ["pve-staging-a"],
        storage: ["local-zfs"],
        network_segments: ["lab-isolated-segment"],
        cidrs: ["10.61.0.0/16"],
        vmid_range: { start: 9000, end: 9050 },
        quotas: {
          max_teams: 2,
          max_vms: 8,
          max_containers: 4,
          max_total_vcpu: 16,
          max_total_memory_mb: 32768,
          max_total_disk_gb: 256,
        },
        external_connectivity: { policy: "deny" },
        credential_scope: "least_privilege",
      },
    } as never);
    const byKey = Object.fromEntries(rows.map((r) => [r.key, r.value]));
    expect(byKey["Nodes"]).toBe("pve-staging-a");
    expect(byKey["VM-ID range"]).toBe("9000–9050");
    expect(byKey["Quotas"]).toBe("2t · 8vm · 4ct");
    expect(byKey["External connectivity"]).toBe("deny (fixed)");
  });
});

describe("boundarySummaryDraftRows", () => {
  it("summarizes the draft strings without inventing values", () => {
    const rows = boundarySummaryDraftRows("existing_environment", "physical", {
      ...emptyDraft(),
      nodes: "lab-node-a",
      cidrs: "10.60.0.0/16",
      vmidStart: "9000",
      vmidEnd: "9100",
      maxTeams: "2",
      maxVms: "8",
      maxContainers: "4",
    });
    const byKey = Object.fromEntries(rows.map((r) => [r.key, r.value]));
    expect(byKey["Mode"]).toBe("existing environment");
    expect(byKey["Nodes"]).toBe("lab-node-a");
    expect(byKey["Storage"]).toBe("—");
    expect(byKey["VM-ID range"]).toBe("9000–9100");
    expect(byKey["Quotas"]).toBe("2t · 8vm · 4ct");
    expect(byKey["External connectivity"]).toBe("deny (fixed)");
  });
});
