import { resolveClosedCodeCopy } from "../components/ui/closed-code-error";
import {
  LIFECYCLE_STEPS as DEPLOYMENT_STEPS,
  isInFlight,
  lifecycleIndex as deploymentIndex,
  statusLabel as deploymentStatusLabel,
} from "./staging-deployment";
import {
  LIFECYCLE_STEPS as LAB_STEPS,
  isQueuedOrRunning,
  lifecycleIndex as labIndex,
  statusLabel as labStatusLabel,
} from "./staging-lab";
import {
  DEPLOYMENT_APPROVAL_SCOPE_NOTICE,
  LAB_APPROVAL_SCOPE_NOTICE,
  OBSERVATIONS_EMPTY_TITLE,
  PLAN_PIN_NOTICE,
  STAGING_ERROR_TEXT,
  isOffRail,
  lifecycleRailItems,
} from "./staging-view";

describe("lifecycleRailItems (labs)", () => {
  it("keeps queued distinct from running and completed", () => {
    // simulation_queued IS a rail step: current there, ready stays pending.
    const idx = labIndex("simulation_queued");
    const items = lifecycleRailItems(LAB_STEPS, idx);
    expect(items.find((i) => i.id === "simulation_queued")!.state).toBe("current");
    expect(items.find((i) => i.id === "simulated_ready")!.state).toBe("blocked");
    expect(items.find((i) => i.id === "approved")!.state).toBe("complete");
    expect(isQueuedOrRunning("simulation_queued")).toBe(true);
    expect(labStatusLabel("simulation_queued")).toBe(
      "Simulation queued (worker will process)",
    );
  });

  it("treats worker-running states as off-rail with the module's own wording", () => {
    const idx = labIndex("simulating");
    expect(isOffRail(idx)).toBe(true);
    const items = lifecycleRailItems(LAB_STEPS, idx);
    expect(items.every((i) => i.state === "blocked")).toBe(true);
    expect(labStatusLabel("simulating")).toBe("Simulating (worker running)");
  });

  it("can preserve durable progress for worker-running states without marking ready", () => {
    const items = lifecycleRailItems(LAB_STEPS, labIndex("simulating"), {
      completedStatuses: [
        "draft",
        "planned",
        "awaiting_approval",
        "approved",
        "simulation_queued",
      ],
    });
    expect(items.find((i) => i.id === "simulation_queued")!.state).toBe("complete");
    expect(items.find((i) => i.id === "simulated_ready")!.state).toBe("blocked");
    expect(items.find((i) => i.id === "destroyed")!.state).toBe("blocked");
  });

  it("does not mark never-run simulation steps complete on the approved-to-teardown skip path", () => {
    const items = lifecycleRailItems(LAB_STEPS, labIndex("destroyed"), {
      currentStatus: "destroyed",
      completedStatuses: ["draft", "planned", "awaiting_approval", "approved"],
    });
    expect(items.find((i) => i.id === "approved")!.state).toBe("complete");
    expect(items.find((i) => i.id === "simulation_queued")!.state).toBe("blocked");
    expect(items.find((i) => i.id === "simulated_ready")!.state).toBe("blocked");
    expect(items.find((i) => i.id === "destroyed")!.state).toBe("current");
  });

  it("keeps approval distinct from execution and ready", () => {
    const approvedIdx = labIndex("approved");
    const items = lifecycleRailItems(LAB_STEPS, approvedIdx);
    expect(items.find((i) => i.id === "approved")!.state).toBe("current");
    expect(items.find((i) => i.id === "approved")!.label).toBe("Approved (sim only)");
    expect(items.find((i) => i.id === "simulated_ready")!.state).toBe("blocked");
  });
});

describe("lifecycleRailItems (deployments)", () => {
  it("never marks ready before the worker records it", () => {
    const idx = deploymentIndex("applying");
    const items = lifecycleRailItems(DEPLOYMENT_STEPS, idx);
    expect(items.find((i) => i.id === "applying")!.state).toBe("current");
    expect(items.find((i) => i.id === "ready")!.state).toBe("blocked");
    expect(isInFlight("applying")).toBe(true);
  });

  it("failure and rollback statuses are off-rail with explicit labels", () => {
    for (const status of ["failed", "rollback_required", "rolling_back", "rolled_back"] as const) {
      expect(isOffRail(deploymentIndex(status))).toBe(true);
    }
    expect(deploymentStatusLabel("rolling_back")).toBe("Rolling back (worker running)");
    expect(deploymentStatusLabel("rollback_required")).toBe("Rollback required");
  });
});

describe("plan/approval truth copy", () => {
  it("pins approval to the exact hash and separates approval from execution", () => {
    expect(PLAN_PIN_NOTICE).toContain("exact plan hash");
    expect(PLAN_PIN_NOTICE).toContain("re-approved");
    for (const text of [LAB_APPROVAL_SCOPE_NOTICE, DEPLOYMENT_APPROVAL_SCOPE_NOTICE]) {
      expect(text).toContain("live-read authorization");
      expect(text.toLowerCase()).toContain("resolver");
      expect(text.toLowerCase()).toContain("collector");
    }
    expect(LAB_APPROVAL_SCOPE_NOTICE).toContain("no real infrastructure");
    expect(DEPLOYMENT_APPROVAL_SCOPE_NOTICE.toLowerCase()).toContain("sealed");
  });

  it("keeps fixed copy free of endpoints and secret material", () => {
    for (const text of [
      PLAN_PIN_NOTICE,
      LAB_APPROVAL_SCOPE_NOTICE,
      DEPLOYMENT_APPROVAL_SCOPE_NOTICE,
      OBSERVATIONS_EMPTY_TITLE,
      ...Object.values(STAGING_ERROR_TEXT),
    ]) {
      expect(text).not.toMatch(/:\/\//);
      expect(text).not.toMatch(/:\d{4,5}\b/);
      expect(text.toLowerCase()).not.toContain("password");
    }
  });
});

describe("STAGING_ERROR_TEXT", () => {
  it("resolves closed codes to fixed copy, never the backend message", () => {
    const err = Object.assign(new Error("raw backend detail"), {
      code: "invalid_transition",
    });
    const copy = resolveClosedCodeCopy(err, STAGING_ERROR_TEXT);
    expect(copy.text).toBe(STAGING_ERROR_TEXT.invalid_transition);
    expect(copy.text).not.toContain("raw backend detail");
    // Unknown/malformed codes degrade safely via the shared resolver guards.
    expect(
      resolveClosedCodeCopy(Object.assign(new Error("x"), { code: "constructor" }), STAGING_ERROR_TEXT).text,
    ).not.toContain("function");
  });
});
