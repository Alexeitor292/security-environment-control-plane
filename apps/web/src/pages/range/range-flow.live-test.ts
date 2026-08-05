// The range vertical slice, executed against a REAL control plane.
//
// This is the acceptance producer: the same flow that used to exist only as a sequence of manual
// browser steps and a folder of screenshots. It runs the identical step definition as
// `range-flow.test.ts` — see `range-flow.ts` — so the two cannot describe different flows.
//
// RUN IT:
//   1. start the API:  .venv/Scripts/python.exe -m uvicorn secp_api.main:app --port 8099
//   2. from apps/web:  VITE_API_BASE_URL=http://localhost:8099 npm run test:live
//
// It is NOT in the default gate, because it needs a server the Frontend CI job does not have.
// It is deliberately NOT a conditionally-skipped test either: a suite that silently passes when
// its subject is absent is how coverage disappears while CI stays green. If the API is unreachable
// this FAILS, loudly, naming what was missing — an absent acceptance run is visible as a failure or
// as a command nobody ran, never as a pass.
//
// It creates a range, deploys it, resets a team and DESTROYS it. Point it only at a development
// control plane.

import { beforeAll, describe, expect, it } from "vitest";

import { API_BASE, api } from "../../api/client";
import {
  EXPECTED_LEDGER_ORDER,
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
    await api.listTemplates();
  } catch (e) {
    throw new Error(
      `The live acceptance run needs a reachable control plane at ${API_BASE}. ` +
        `Start it with: .venv/Scripts/python.exe -m uvicorn secp_api.main:app --port 8099 ` +
        `and run with VITE_API_BASE_URL set. Underlying failure: ${String(e)}`,
    );
  }

  result = await runRangeFlow(api, {
    rangeName: RANGE_NAME,
    onStep: (o) => {
      // Progress is printed so a human watching a real deployment can see it advance.
      // eslint-disable-next-line no-console
      console.log(`  ${o.step.padEnd(16)} recorded=${o.recorded.padEnd(18)} phase=${o.phase}`);
    },
  });
}, 120_000);

describe("range vertical slice — against a real control plane", () => {
  it("runs every step of the flow", () => {
    expect(result.observations.map((o) => o.step)).toEqual([...FLOW_STEPS]);
  });

  it("reaches a deployed range and then a destroyed one", () => {
    const byStep = Object.fromEntries(result.observations.map((o) => [o.step, o]));
    expect(byStep.deployed.phase).toBe("active");
    expect(byStep.destroyed.recorded).toBe("destroyed");
  });

  it("creates real team instances with reachable-looking targets", () => {
    const inspected = result.observations.find((o) => o.step === "inspected");
    expect(inspected?.detail.instanceCount).toBeGreaterThan(0);
    expect(inspected?.detail.targetCount).toBeGreaterThan(0);
    expect(inspected?.detail.blastRadiusComplete).toBe(true);
  });

  it("records the full lifecycle in the server's own audit ledger", () => {
    // The ledger is the evidence that this happened on the server, not merely in the client.
    expect(firstMissingInOrder(result.auditActions, EXPECTED_LEDGER_ORDER)).toBeNull();
  });

  it("leaves the range destroyed, not merely requested", () => {
    const last = result.observations[result.observations.length - 1];
    expect(last.recorded).toBe("destroyed");
    expect(last.phase).toBe("destroyed");
  });
});
