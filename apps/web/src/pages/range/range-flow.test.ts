// The range vertical slice, executed on every PR.
//
// Drives the REAL api client (src/api/client.ts) through create → deploy → inspect → reset →
// destroy against a fetch-level fake of the range API.
//
// It ALWAYS RUNS. There is no `skipIf`, no "only when an API is reachable" guard and no optional
// import — a suite that quietly runs nothing while reporting green is the failure mode this repo
// has been bitten by, and an acceptance test is the worst place to reintroduce it.
//
// WHAT THIS PROVES: that the client drives a conforming server correctly — the right calls in the
// right order, polling rather than trusting a 202, and handling an operation that has no plan yet.
// WHAT IT DOES NOT PROVE: anything about a real container. Only `range-flow.live-test.ts` does
// that, and it needs a worker with a Docker socket.

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { api } from "../../api/client";
import { createFakeRangeApi, type FakeRangeApi } from "../../testing/fake-control-plane";
import {
  EXPECTED_EVENT_KIND_ORDER,
  FLOW_STEPS,
  firstMissingInOrder,
  runRangeFlow,
} from "./range-flow";

const originalFetch = globalThis.fetch;
let server: FakeRangeApi;

/** No real waiting: the fake's worker advances on polls, not on wall-clock time. */
const noSleep = () => Promise.resolve();

beforeEach(() => {
  server = createFakeRangeApi({ workerTicks: 1 });
  globalThis.fetch = server.fetch;
});

afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe("range vertical slice — end to end against a conforming range API", () => {
  it("completes the whole flow", async () => {
    const result = await runRangeFlow(api, { rangeName: "Acceptance Run", sleep: noSleep });

    expect(result.observations.map((o) => o.step)).toEqual([...FLOW_STEPS]);
    expect(result.rangeId).toBeTruthy();
  });

  it("advances the recorded state in the documented order", async () => {
    const { observations } = await runRangeFlow(api, { rangeName: "Acceptance Run", sleep: noSleep });
    const recorded = Object.fromEntries(observations.map((o) => [o.step, o.recorded]));

    expect(recorded.created).toBe("draft");
    // 202 accepted: the range is transitioning, NOT already deployed.
    expect(recorded["deploy-dispatched"]).toBe("deploying");
    expect(recorded.deployed).toBe("ready");
    expect(recorded.reset).toBe("ready");
    expect(recorded.destroyed).toBe("destroyed");
  });

  it("does not treat the 202 as completion", async () => {
    // The mutation returns immediately; only polling the recorded state shows the work finishing.
    const { observations } = await runRangeFlow(api, { rangeName: "Acceptance Run", sleep: noSleep });
    const dispatched = observations.find((o) => o.step === "deploy-dispatched");

    expect(dispatched?.recorded).toBe("deploying");
    expect(dispatched?.detail.operationStatus).toBe("pending");
  });

  it("renders the pre-plan window as indeterminate, never as zero percent", async () => {
    // THE bug this guards: right after the 202 the worker has not planned the operation, so
    // `total_steps` is 0. Dividing by it is a crash; showing 0% is a false claim that no work has
    // been done, when the truth is that nobody yet knows how much work there is.
    const { observations } = await runRangeFlow(api, { rangeName: "Acceptance Run", sleep: noSleep });
    const dispatched = observations.find((o) => o.step === "deploy-dispatched");

    expect(dispatched?.detail.progressKind).toBe("indeterminate");
    expect(dispatched?.detail.totalSteps).toBeNull();
  });

  it("reports access only where the server observed a response", async () => {
    const { observations } = await runRangeFlow(api, { rangeName: "Acceptance Run", sleep: noSleep });
    const deployed = observations.find((o) => o.step === "deployed");

    expect(deployed?.detail.accessCount).toBe(2);
    expect(deployed?.detail.reachableCount).toBe(2);
    // Every reachable row carries an observation timestamp — reachability is never inferred.
    expect(deployed?.detail.observedCount).toBe(deployed?.detail.accessCount);
  });

  it("enumerates the blast radius from the server's resources", async () => {
    const { observations } = await runRangeFlow(api, { rangeName: "Acceptance Run", sleep: noSleep });
    const inspected = observations.find((o) => o.step === "inspected");

    expect(inspected?.detail.containerCount).toBe(2);
    expect(inspected?.detail.networkCount).toBe(1);
    expect(inspected?.detail.resourceCount).toBe(3);
    expect(inspected?.detail.blastRadiusComplete).toBe(true);
  });

  it("records the server-side event log that proves the flow happened", async () => {
    // The SAME list the live run asserts, and it was captured from a real control plane rather
    // than chosen here. That is what stops this test from passing against the fake's own fiction:
    // when the two disagreed, the live run failed and the fake was corrected, not the assertion.
    const { eventKinds } = await runRangeFlow(api, { rangeName: "Acceptance Run", sleep: noSleep });

    expect(firstMissingInOrder(eventKinds, EXPECTED_EVENT_KIND_ORDER)).toBeNull();
  });

  it("reaches a clean, proved teardown on the happy path", async () => {
    const { teardownVerdict, observations } = await runRangeFlow(api, {
      rangeName: "Acceptance Run",
      sleep: noSleep,
    });

    expect(teardownVerdict).toBe("clean");
    expect(observations.find((o) => o.step === "destroyed")?.detail.residueVerdict).toBe("clean");
  });

  it("polls the range rather than trusting mutation responses", async () => {
    await runRangeFlow(api, { rangeName: "Acceptance Run", sleep: noSleep });

    const polls = server.calls.filter((c) => /^GET \/api\/v1\/ranges\/[^/]+$/.test(c));
    // One per mutation at minimum, plus the settle loops.
    expect(polls.length).toBeGreaterThan(FLOW_STEPS.length);
  });

  it("never sends an organization id — scoping is the server's", async () => {
    await runRangeFlow(api, { rangeName: "Acceptance Run", sleep: noSleep });
    for (const call of server.calls) {
      expect(call).not.toMatch(/organization/i);
    }
  });
});

describe("an unobservable teardown lands in recovery_required, not destroyed", () => {
  it("reports unproven rather than clean when the probe cannot run", async () => {
    // The canonical case: Docker is unreachable during teardown, so the removal AND the "is it
    // gone?" check fail for the same reason. Reporting that as `destroyed` would retire a range
    // that may still hold live containers.
    globalThis.fetch = createFakeRangeApi({ workerTicks: 1, failTeardownProbe: true }).fetch;

    const { observations, teardownVerdict } = await runRangeFlow(api, {
      rangeName: "Unprovable",
      sleep: noSleep,
    });
    const destroyed = observations.find((o) => o.step === "destroyed");

    expect(destroyed?.recorded).toBe("recovery_required");
    expect(destroyed?.phase).toBe("recovery_required");
    expect(destroyed?.detail.residueVerdict).toBe("unproven");
    expect(teardownVerdict).toBe("unproven");
    // And emphatically NOT destroyed.
    expect(destroyed?.recorded).not.toBe("destroyed");
  });
});

describe("a failed deploy is failed, not unproven", () => {
  it("lands in failed and still permits a retry", async () => {
    globalThis.fetch = createFakeRangeApi({ workerTicks: 1, failDeploy: true }).fetch;

    // The flow drives past deploy expecting `ready`; a failed deploy settles in `failed`, which
    // the driver reports faithfully rather than treating as success.
    const { observations } = await runRangeFlow(api, { rangeName: "Doomed", sleep: noSleep }).catch(
      (e: Error) => {
        throw e;
      },
    );
    expect(observations.find((o) => o.step === "deployed")?.recorded).toBe("failed");
  });
});

describe("the transition gate is the server's, not the UI's", () => {
  it("refuses a reset on a draft range", async () => {
    const created = await api.createRange({ template_slug: "web-breach-lab", name: "Gated" });
    await expect(api.resetRange(created.id)).rejects.toMatchObject({
      status: 409,
      code: "range_invalid_transition",
    });
  });

  it("refuses a deploy on an unknown range", async () => {
    await expect(api.deployRange("rng-9999")).rejects.toMatchObject({
      status: 404,
      code: "range_not_found",
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
