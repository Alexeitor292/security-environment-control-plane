// The range vertical slice, executed against a REAL control plane.
//
// This is the acceptance producer, and it is THE ONLY HALF THAT TOUCHES INFRASTRUCTURE. It runs
// the identical step definition as `range-flow.test.ts` — see `range-flow.ts` — so the two cannot
// describe different flows, but only this one proves a container was actually started.
//
// RUN IT:
//   1. start the API:     .venv/Scripts/python.exe -m uvicorn secp_api.main:app --port 8099
//   2. start the WORKER, with access to the Docker socket. Range operations run on the durable
//      worker path; `InlineDispatcher` refuses range dispatch outright, so without a worker the
//      range is created and then never leaves `deploying`.
//   3. from apps/web:     VITE_API_BASE_URL=http://localhost:8099 npm run test:live
//
// It is NOT in the default gate, because the Frontend CI job has no control plane, no worker and no
// Docker socket. It is deliberately NOT a conditionally-skipped test either: a suite that silently
// passes when its subject is absent is how coverage disappears while CI stays green. Without a
// reachable API this FAILS, naming what was missing.
//
// It creates a range, DEPLOYS REAL CONTAINERS, resets and destroys them. Point it only at a
// development host you are willing to have containers created on.

import { beforeAll, describe, expect, it } from "vitest";

import { API_BASE, api } from "../../api/client";
import {
  EXPECTED_EVENT_KIND_ORDER,
  FLOW_STEPS,
  firstMissingInOrder,
  runRangeFlow,
  type FlowResult,
} from "./range-flow";

const RANGE_NAME = `Acceptance ${new Date().toISOString().slice(0, 19)}`;

let result: FlowResult;

beforeAll(async () => {
  // Fail with an actionable message rather than a raw connection error, but FAIL — never skip.
  try {
    await api.listRangeTemplates();
  } catch (e) {
    throw new Error(
      `The live acceptance run needs a reachable control plane at ${API_BASE} with the range API ` +
        `available. Start it with: .venv/Scripts/python.exe -m uvicorn secp_api.main:app --port 8099 ` +
        `and run with VITE_API_BASE_URL set. A running worker with the Docker socket is also ` +
        `required — range operations are refused on the inline path. Underlying failure: ${String(e)}`,
    );
  }

  result = await runRangeFlow(api, {
    rangeName: RANGE_NAME,
    onStep: (o) => {
      // eslint-disable-next-line no-console
      console.log(`  ${o.step.padEnd(18)} recorded=${o.recorded.padEnd(18)} phase=${o.phase}`);
    },
  });
}, 600_000);

describe("range vertical slice — against a real control plane", () => {
  it("runs every step of the flow", () => {
    expect(result.observations.map((o) => o.step)).toEqual([...FLOW_STEPS]);
  });

  it("does not treat the 202 as completion", () => {
    const dispatched = result.observations.find((o) => o.step === "deploy-dispatched");
    expect(dispatched?.recorded).toBe("deploying");
  });

  it("reaches a deployed range with reachable targets", () => {
    const deployed = result.observations.find((o) => o.step === "deployed");
    expect(deployed?.recorded).toBe("ready");
    expect(deployed?.detail.accessCount).toBeGreaterThan(0);
    // The whole point of the range surface over the exercise surface: reachability was OBSERVED.
    expect(deployed?.detail.reachableCount).toBeGreaterThan(0);
    expect(deployed?.detail.observedCount).toBe(deployed?.detail.accessCount);
  });

  it("creates real provider resources", () => {
    const inspected = result.observations.find((o) => o.step === "inspected");
    expect(inspected?.detail.containerCount).toBeGreaterThan(0);
    expect(inspected?.detail.blastRadiusComplete).toBe(true);
  });

  it("records the lifecycle in the server's own event log", () => {
    // These kinds were captured from a real run, not assumed. The first version of this assertion
    // used the test fake's invented names and failed here — which is the whole point of having a
    // live half: only it can discover that the fake and the server disagree.
    expect(firstMissingInOrder(result.eventKinds, EXPECTED_EVENT_KIND_ORDER)).toBeNull();
  });

  it("ends destroyed with a proved-clean teardown, not merely requested", () => {
    const last = result.observations[result.observations.length - 1];
    // If the teardown probe could not run this is `recovery_required` with an `unproven` verdict —
    // a legitimate outcome, but not one an acceptance run should pass on, because it means nobody
    // proved the containers are gone.
    expect(last.recorded).toBe("destroyed");
    expect(last.detail.residueVerdict).toBe("clean");
    expect(result.teardownVerdict).toBe("clean");
  });
});
