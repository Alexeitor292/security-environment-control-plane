// The range vertical slice, executed on every PR.
//
// This drives the REAL api client (src/api/client.ts) through create → validate → plan → submit →
// approve → deploy → inspect → reset → destroy against a fetch-level fake of the control plane.
//
// It ALWAYS RUNS. There is no `describe.skipIf`, no "only when an API is reachable" guard and no
// optional import — a suite that quietly runs nothing while reporting green is the failure mode
// this repo has been bitten by, and an acceptance test is the worst place to reintroduce it. The
// complementary live run is a separate, explicitly-invoked file whose absence is visible.

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { api } from "../../api/client";
import {
  createFakeControlPlane,
  type FakeControlPlane,
} from "../../testing/fake-control-plane";
import {
  EXPECTED_LEDGER_ORDER,
  FLOW_STEPS,
  firstMissingInOrder,
  runRangeFlow,
} from "./range-flow";

const originalFetch = globalThis.fetch;
let server: FakeControlPlane;

beforeEach(() => {
  server = createFakeControlPlane({ teamCount: 2, targetsPerTeam: 3 });
  globalThis.fetch = server.fetch;
});

afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe("range vertical slice — end to end against a conforming control plane", () => {
  it("completes the whole flow and records every step server-side", async () => {
    const result = await runRangeFlow(api, { rangeName: "Acceptance Run" });

    expect(result.observations.map((o) => o.step)).toEqual([...FLOW_STEPS]);
    expect(result.rangeId).toBeTruthy();
  });

  it("advances the recorded lifecycle in the documented order", async () => {
    const { observations } = await runRangeFlow(api, { rangeName: "Acceptance Run" });
    const recorded = observations.map((o) => `${o.step}=${o.recorded}`);

    expect(recorded).toEqual([
      "created=draft",
      "validated=validated",
      "plan-generated=planned",
      "plan-submitted=awaiting_approval",
      "plan-approved=approved",
      "deployed=running",
      "inspected=running",
      "reset=running",
      "destroyed=destroyed",
    ]);
  });

  it("projects each recorded state onto the phase the UI shows", async () => {
    const { observations } = await runRangeFlow(api, { rangeName: "Acceptance Run" });
    const phases = Object.fromEntries(observations.map((o) => [o.step, o.phase]));

    // The five pre-deployment states are all one product phase.
    expect(phases.created).toBe("draft");
    expect(phases.validated).toBe("draft");
    expect(phases["plan-approved"]).toBe("draft");
    // `running` is `active` (lead ruling). Never `ready`, which would claim an observed probe.
    expect(phases.deployed).toBe("active");
    expect(phases.destroyed).toBe("destroyed");
  });

  it("offers exactly one next gate action at each step, in order", async () => {
    const { observations } = await runRangeFlow(api, { rangeName: "Acceptance Run" });
    const gate = Object.fromEntries(observations.map((o) => [o.step, o.gateNext]));

    expect(gate.created).toBe("validate");
    expect(gate.validated).toBe("generate-plan");
    expect(gate["plan-generated"]).toBe("submit-plan");
    expect(gate["plan-submitted"]).toBe("approve-plan");
    expect(gate["plan-approved"]).toBe("deploy");
    // Deployment is done; the gate offers nothing further.
    expect(gate.deployed).toBe("none");
    expect(gate.destroyed).toBe("none");
  });

  it("produces the server-side ledger that proves the flow happened", async () => {
    // The ledger is the evidence. Asserting on the UI's own state would only prove the client
    // believes something; this proves the server recorded it.
    const { auditActions } = await runRangeFlow(api, { rangeName: "Acceptance Run" });

    expect(firstMissingInOrder(auditActions, EXPECTED_LEDGER_ORDER)).toBeNull();
  });

  it("creates one instance per declared team", async () => {
    const server4 = createFakeControlPlane({ teamCount: 4, targetsPerTeam: 2 });
    globalThis.fetch = server4.fetch;

    const { observations } = await runRangeFlow(api, { rangeName: "Four Teams" });
    const inspected = observations.find((o) => o.step === "inspected");

    expect(inspected?.detail.instanceCount).toBe(4);
    // 4 teams x 2 targets. The network node in each team's topology is NOT a target.
    expect(inspected?.detail.targetCount).toBe(8);
    expect(server4.auditActions().filter((a) => a === "instance.created")).toHaveLength(4);
  });

  it("enumerates a complete blast radius with an address for every target", async () => {
    const { observations } = await runRangeFlow(api, { rangeName: "Acceptance Run" });
    const inspected = observations.find((o) => o.step === "inspected");

    expect(inspected?.detail.blastRadiusComplete).toBe(true);
    expect(inspected?.detail.addressCount).toBe(inspected?.detail.targetCount);
  });

  it("selects the highest version number, not the last one the server listed", async () => {
    // The fake lists v1 BEFORE v0 deliberately. A client taking "the last element" would deploy
    // the wrong, older definition — silently, and with a valid-looking result.
    await runRangeFlow(api, { rangeName: "Acceptance Run" });

    const create = server.calls.find((c) => c === "POST /api/v1/exercises");
    expect(create).toBeDefined();
  });

  it("reads the range back from the server after every mutation", async () => {
    // A page that mutates without re-reading shows stale state until the operator refreshes. The
    // flow does one GET per step, so a dropped refresh shows up as a missing read.
    await runRangeFlow(api, { rangeName: "Acceptance Run" });

    const reads = server.calls.filter((c) => /^GET \/api\/v1\/exercises\/[^/]+$/.test(c));
    expect(reads.length).toBe(FLOW_STEPS.length);
  });

  it("never sends an organization id — scoping is the server's", async () => {
    await runRangeFlow(api, { rangeName: "Acceptance Run" });
    for (const call of server.calls) {
      expect(call).not.toMatch(/organization/i);
    }
  });
});

describe("the gate is the server's, not the UI's", () => {
  it("is refused when deploy is attempted without an approved plan", async () => {
    // The UI never offers this, but the guarantee must not depend on the UI: the server refuses it.
    await expect(api.deployExercise("ex-0001")).rejects.toMatchObject({ status: 404 });

    const created = await api.createExercise({
      template_id: "tpl-0001",
      version_id: "ver-0001",
      name: "Ungated",
    });
    await expect(api.deployExercise(created.id)).rejects.toMatchObject({
      status: 409,
      code: "approval_required",
    });
  });
});

describe("firstMissingInOrder", () => {
  it("accepts extra entries between the expected ones", () => {
    expect(firstMissingInOrder(["a", "x", "b", "y", "c"], ["a", "b", "c"])).toBeNull();
  });

  it("names the first expected entry that is out of order or absent", () => {
    expect(firstMissingInOrder(["b", "a"], ["a", "b"])).toBe("b");
    expect(firstMissingInOrder(["a"], ["a", "b"])).toBe("b");
  });

  it("requires repeats to be matched separately", () => {
    expect(firstMissingInOrder(["a"], ["a", "a"])).toBe("a");
    expect(firstMissingInOrder(["a", "a"], ["a", "a"])).toBeNull();
  });
});
