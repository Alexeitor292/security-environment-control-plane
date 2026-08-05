import { describe, expect, it } from "vitest";

import type { LifecycleState } from "../../api/types";
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

  it("projects running to ready, never to active", () => {
    // The backend records that the range is up. It does not record that a competition is running
    // on it, so "active" must not be claimed from `running`.
    expect(rangeLifecycle("running").phase).toBe("ready");
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
