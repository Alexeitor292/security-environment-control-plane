import { describe, expect, it } from "vitest";

import type { LifecycleState } from "../../api/types";
import { RANGE_OPERATION_TONE } from "../../components/ui";
import {
  DEPLOYMENT_STEPS,
  deploymentProgress,
  deploymentStepStatus,
  hasLiveInfrastructure,
  isInFlight,
  isTerminal,
  permittedActions,
  rangeLifecycle,
  RANGE_PHASE_LABEL,
  RANGE_PHASE_ORDER,
  RANGE_PHASE_TONE,
} from "./range-lifecycle";

const ALL_RECORDED_STATES: LifecycleState[] = [
  "draft",
  "validated",
  "planned",
  "awaiting_approval",
  "approved",
  "deploying",
  "running",
  "resetting",
  "destroying",
  "destroyed",
  "failed",
];

describe("rangeLifecycle projection", () => {
  it("maps every recorded control-plane state to a known phase", () => {
    for (const state of ALL_RECORDED_STATES) {
      const lc = rangeLifecycle(state);
      expect(lc.known, `${state} must project to a known phase`).toBe(true);
      expect(lc.recorded).toBe(state);
      expect(RANGE_PHASE_ORDER).toContain(lc.phase);
    }
  });

  it("collapses all five pre-deployment states to draft", () => {
    for (const state of ["draft", "validated", "planned", "awaiting_approval", "approved"]) {
      expect(rangeLifecycle(state).phase).toBe("draft");
    }
  });

  it("projects running to active, never to ready", () => {
    // Lead ruling 2026-08-04: `active` IS the shipped `running`. In the range contract `ready`
    // specifically means "deployed AND OBSERVED REACHABLE"; the exercise surface observes nothing,
    // so projecting `running` to `ready` would claim a probe that never ran.
    expect(rangeLifecycle("running").phase).toBe("active");
  });

  it("passes the range API's own nine states through unchanged", () => {
    // These arrive from the range backend as RangeState and must not be re-mapped.
    for (const phase of RANGE_PHASE_ORDER) {
      const lc = rangeLifecycle(phase);
      expect(lc.known, `${phase} must be recognized`).toBe(true);
      expect(lc.phase, `${phase} must pass through unchanged`).toBe(phase);
    }
  });

  it("honours ready and recovery_required from the range backend", () => {
    // Neither exists in the legacy enum; both must survive rather than falling to the unknown branch.
    expect(rangeLifecycle("ready")).toMatchObject({ phase: "ready", known: true });
    expect(rangeLifecycle("recovery_required")).toMatchObject({
      phase: "recovery_required",
      known: true,
    });
  });

  it("reports an unknown state as recovery_required and known:false", () => {
    const lc = rangeLifecycle("teleporting");
    expect(lc.known).toBe(false);
    expect(lc.phase).toBe("recovery_required");
    expect(lc.recorded).toBe("teleporting");
  });

  it("does not resolve inherited Object.prototype keys as states", () => {
    for (const key of ["constructor", "toString", "hasOwnProperty", "__proto__"]) {
      expect(rangeLifecycle(key).known, `${key} must not resolve`).toBe(false);
    }
  });

  it("preserves the recorded state verbatim so the UI can always show it", () => {
    expect(rangeLifecycle("awaiting_approval").recorded).toBe("awaiting_approval");
  });
});

describe("phase metadata completeness", () => {
  it("has a label and a tone for every phase", () => {
    for (const phase of RANGE_PHASE_ORDER) {
      expect(RANGE_PHASE_LABEL[phase]).toBeTruthy();
      expect(RANGE_PHASE_TONE[phase]).toBeTruthy();
    }
  });

  it("covers exactly the nine product phases", () => {
    expect(RANGE_PHASE_ORDER).toHaveLength(9);
  });
});

describe("the three end states are visually distinct", () => {
  // This is the guard for the defect the program exists to prevent. `failed` means it broke,
  // `recovery_required` means nobody could prove what happened, `destroyed` means proved gone.
  // Any two of them sharing a tone lets an unprovable outcome read as a settled one.
  it("gives failed, recovery_required and destroyed three different tones", () => {
    const tones = [
      RANGE_PHASE_TONE.failed,
      RANGE_PHASE_TONE.recovery_required,
      RANGE_PHASE_TONE.destroyed,
    ];
    expect(new Set(tones).size).toBe(3);
  });

  it("never renders recovery_required as a success tone", () => {
    expect(RANGE_PHASE_TONE.recovery_required).not.toBe("ok");
  });

  it("never renders recovery_required with the same tone as destroyed", () => {
    // The dangerous confusion: "we could not prove it is gone" shown as "it is gone".
    expect(RANGE_PHASE_TONE.recovery_required).not.toBe(RANGE_PHASE_TONE.destroyed);
  });

  it("keeps amber for recovery_required alone, not shared with in-flight phases", () => {
    const amber = RANGE_PHASE_TONE.recovery_required;
    for (const phase of ["deploying", "resetting", "destroying"] as const) {
      expect(RANGE_PHASE_TONE[phase], `${phase} must not share the recovery amber`).not.toBe(amber);
    }
  });
});

describe("unproven is a third outcome", () => {
  it("renders unproven as neither success nor failure", () => {
    const unproven = RANGE_OPERATION_TONE.unproven;
    expect(unproven).not.toBe("ok");
    expect(unproven).not.toBe("danger");
    expect(unproven).toBeTruthy();
  });

  it("separates unproven from succeeded, verified and clean", () => {
    for (const settled of ["succeeded", "verified", "clean", "removed"]) {
      expect(RANGE_OPERATION_TONE[settled]).toBe("ok");
    }
    expect(RANGE_OPERATION_TONE.unproven).not.toBe("ok");
  });

  it("separates unproven from failed and residue", () => {
    for (const bad of ["failed", "residue", "present"]) {
      expect(RANGE_OPERATION_TONE[bad]).toBe("danger");
    }
    expect(RANGE_OPERATION_TONE.unproven).not.toBe("danger");
  });
});

describe("phase predicates", () => {
  it("treats only mid-operation phases as in flight", () => {
    expect(isInFlight("deploying")).toBe(true);
    expect(isInFlight("resetting")).toBe(true);
    expect(isInFlight("destroying")).toBe(true);
    expect(isInFlight("ready")).toBe(false);
    expect(isInFlight("failed")).toBe(false);
    expect(isInFlight("draft")).toBe(false);
  });

  it("treats only destroyed as terminal", () => {
    expect(isTerminal("destroyed")).toBe(true);
    expect(isTerminal("failed")).toBe(false);
  });

  it("reports live infrastructure only where something exists to reach", () => {
    expect(hasLiveInfrastructure("ready")).toBe(true);
    expect(hasLiveInfrastructure("active")).toBe(true);
    expect(hasLiveInfrastructure("resetting")).toBe(true);
    expect(hasLiveInfrastructure("draft")).toBe(false);
    expect(hasLiveInfrastructure("destroyed")).toBe(false);
  });
});

describe("permittedActions", () => {
  it("offers deploy only from draft", () => {
    expect(permittedActions(rangeLifecycle("draft"))).toEqual(["deploy"]);
  });

  it("offers reset and destroy on a ready range", () => {
    expect(permittedActions(rangeLifecycle("running"))).toEqual(["reset", "destroy"]);
  });

  it("offers destroy but not deploy on a failed range", () => {
    const actions = permittedActions(rangeLifecycle("failed"));
    expect(actions).toContain("destroy");
    expect(actions).not.toContain("deploy");
  });

  it("offers nothing while an operation is in flight", () => {
    for (const state of ["deploying", "resetting", "destroying"]) {
      expect(permittedActions(rangeLifecycle(state))).toEqual([]);
    }
  });

  it("offers nothing on a destroyed range", () => {
    expect(permittedActions(rangeLifecycle("destroyed"))).toEqual([]);
  });

  it("offers NOTHING when the state is unknown", () => {
    // An unrecognized state is the worst possible moment to render a destroy button.
    expect(permittedActions(rangeLifecycle("who-knows"))).toEqual([]);
  });
});

describe("deployment step rail", () => {
  it("marks the in-flight step current while deploying", () => {
    const lc = rangeLifecycle("deploying");
    expect(deploymentStepStatus("draft", lc)).toBe("done");
    expect(deploymentStepStatus("deploying", lc)).toBe("current");
    expect(deploymentStepStatus("ready", lc)).toBe("upcoming");
  });

  it("marks every step done once ready", () => {
    const lc = rangeLifecycle("running");
    for (const step of DEPLOYMENT_STEPS) {
      expect(deploymentStepStatus(step, lc)).toBe("done");
    }
  });

  it("distinguishes a failed deploy from a stalled one", () => {
    const lc = rangeLifecycle("failed");
    expect(deploymentStepStatus("deploying", lc)).toBe("failed");
    expect(deploymentStepStatus("ready", lc)).toBe("upcoming");
  });

  it("advances progress monotonically through the happy path", () => {
    const draft = deploymentProgress(rangeLifecycle("draft"));
    const deploying = deploymentProgress(rangeLifecycle("deploying"));
    const ready = deploymentProgress(rangeLifecycle("running"));
    expect(draft).toBeLessThan(deploying);
    expect(deploying).toBeLessThan(ready);
    expect(ready).toBe(1);
  });

  it("does not report a failed deployment as complete", () => {
    expect(deploymentProgress(rangeLifecycle("failed"))).toBeLessThan(1);
  });
});
