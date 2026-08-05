// Fidelity pin for the range contract.
//
// The test fake in `src/testing/fake-control-plane.ts` is a SECOND IMPLEMENTATION of the range API.
// That is what makes the in-gate acceptance run possible without a control plane, and it is also
// its weakness: if the fake drifts from the contract, the gate stays green about the wrong thing.
//
// This file pins the two places drift would hide:
//
//   1. Every enum value the fake can emit is a member of the declared contract enum. A fake that
//      invented a state, or kept one the backend removed, fails here.
//   2. Every declared enum value has a badge tone. A value the UI cannot render would otherwise
//      surface as the neutral "unknown" badge at runtime, in front of an operator, rather than as
//      a failure here.
//
// It cannot prove the DECLARED enums still match the backend — only the live run can do that. What
// it does guarantee is that the fake and the UI never disagree with this repo's own declaration,
// so there is exactly one place to edit when the backend changes.

import { describe, expect, it } from "vitest";

import {
  RANGE_EVENT_LEVELS,
  RANGE_OPERATION_KINDS,
  RANGE_OPERATION_STATUSES,
  RANGE_RESOURCE_KINDS,
  RANGE_RESOURCE_STATES,
  RANGE_STATES,
  RANGE_STEP_STATUSES,
  RESIDUE_VERDICTS,
  TEARDOWN_RESOURCE_VERDICTS,
} from "../../api/range-types";
import {
  RANGE_EVENT_TONE,
  RANGE_OPERATION_TONE,
  RANGE_TONE,
  resolveStatusTone,
} from "../../components/ui";
import { createFakeRangeApi } from "../../testing/fake-control-plane";
import { RANGE_PHASE_HELP, RANGE_PHASE_LABEL, RANGE_PHASE_ORDER } from "./range-lifecycle";
import { runRangeFlow } from "./range-flow";
import { api } from "../../api/client";

const noSleep = () => Promise.resolve();

describe("the declared contract covers the UI", () => {
  it("gives every range state a phase, a label, a help line and a tone", () => {
    for (const state of RANGE_STATES) {
      expect(RANGE_PHASE_ORDER, `${state} missing from the phase order`).toContain(state);
      expect(RANGE_PHASE_LABEL[state], `${state} has no label`).toBeTruthy();
      expect(RANGE_PHASE_HELP[state], `${state} has no help text`).toBeTruthy();
      expect(RANGE_TONE[state], `${state} has no tone`).toBeTruthy();
    }
  });

  it("declares exactly the nine range states the UI knows", () => {
    expect([...RANGE_STATES].sort()).toEqual([...RANGE_PHASE_ORDER].sort());
  });

  it("gives every operation, step and resource value a tone", () => {
    const values = [
      ...RANGE_OPERATION_STATUSES,
      ...RANGE_STEP_STATUSES,
      ...RANGE_RESOURCE_STATES,
      ...RESIDUE_VERDICTS,
      ...TEARDOWN_RESOURCE_VERDICTS,
    ];
    for (const value of values) {
      const resolved = resolveStatusTone(value, "range-operation");
      expect(resolved.known, `${value} has no tone in the range-operation domain`).toBe(true);
    }
  });

  it("gives every event level a tone", () => {
    for (const level of RANGE_EVENT_LEVELS) {
      expect(resolveStatusTone(level, "range-event").known, `${level} has no tone`).toBe(true);
    }
  });

  it("never resolves unproven as a settled outcome, in any of the enums that carry it", () => {
    // `unproven` appears on the operation status, the step status, the resource state and the
    // residue verdict. It must read the same everywhere: not good, not bad.
    expect(RANGE_OPERATION_TONE.unproven).not.toBe("ok");
    expect(RANGE_OPERATION_TONE.unproven).not.toBe("danger");
    for (const enumeration of [
      RANGE_OPERATION_STATUSES,
      RANGE_STEP_STATUSES,
      RANGE_RESOURCE_STATES,
      RESIDUE_VERDICTS,
      TEARDOWN_RESOURCE_VERDICTS,
    ]) {
      expect(enumeration as readonly string[]).toContain("unproven");
    }
  });

  it("keeps the info event level visually distinct from a warning", () => {
    expect(RANGE_EVENT_TONE.info).not.toBe(RANGE_EVENT_TONE.warning);
    expect(RANGE_EVENT_TONE.error).toBe("danger");
  });
});

describe("the test fake emits only contract values", () => {
  /** Run every branch of the fake and collect what it produced. */
  async function harvest(opts: Parameters<typeof createFakeRangeApi>[0]) {
    const original = globalThis.fetch;
    const server = createFakeRangeApi(opts);
    globalThis.fetch = server.fetch;
    try {
      const result = await runRangeFlow(api, { rangeName: "Contract Pin", sleep: noSleep });
      const range = await api.getRange(result.rangeId);
      const resources = await api.listRangeResources(result.rangeId);
      const events = await api.listRangeEvents(result.rangeId);
      const evidence = await api.listTeardownEvidence(result.rangeId);
      const operation =
        range.current_operation === null
          ? null
          : await api.getRangeOperation(range.current_operation.id);
      return { range, resources, events, evidence, operation, result };
    } finally {
      globalThis.fetch = original;
    }
  }

  it("emits only declared states, statuses, kinds and verdicts on the happy path", async () => {
    const { range, resources, events, evidence, operation, result } = await harvest({
      workerTicks: 1,
    });

    expect(RANGE_STATES as readonly string[]).toContain(range.state);
    for (const o of result.observations) {
      expect(RANGE_STATES as readonly string[], `state ${o.recorded}`).toContain(o.recorded);
    }
    if (operation !== null) {
      expect(RANGE_OPERATION_KINDS as readonly string[]).toContain(operation.kind);
      expect(RANGE_OPERATION_STATUSES as readonly string[]).toContain(operation.status);
      for (const step of operation.steps) {
        expect(RANGE_STEP_STATUSES as readonly string[], `step ${step.key}`).toContain(step.status);
      }
    }
    for (const r of resources) {
      expect(RANGE_RESOURCE_KINDS as readonly string[]).toContain(r.kind);
      expect(RANGE_RESOURCE_STATES as readonly string[], `resource ${r.name}`).toContain(r.state);
    }
    for (const e of events) {
      expect(RANGE_EVENT_LEVELS as readonly string[], `event ${e.kind}`).toContain(e.level);
    }
    for (const ev of evidence) {
      expect(RESIDUE_VERDICTS as readonly string[]).toContain(ev.verdict);
      for (const r of ev.resources) {
        expect(TEARDOWN_RESOURCE_VERDICTS as readonly string[], `teardown ${r.name}`).toContain(
          r.verdict,
        );
      }
    }
  });

  it("emits only declared values on the unprovable-teardown path", async () => {
    const { range, evidence, resources } = await harvest({
      workerTicks: 1,
      failTeardownProbe: true,
    });

    expect(RANGE_STATES as readonly string[]).toContain(range.state);
    expect(range.state).toBe("recovery_required");
    expect(RESIDUE_VERDICTS as readonly string[]).toContain(range.residue_verdict ?? "clean");
    for (const r of resources) {
      expect(RANGE_RESOURCE_STATES as readonly string[]).toContain(r.state);
    }
    for (const ev of evidence) {
      expect(RESIDUE_VERDICTS as readonly string[]).toContain(ev.verdict);
    }
  });

  it("emits only declared values on the failed-deploy path", async () => {
    const { result, operation } = await harvest({ workerTicks: 1, failDeploy: true });

    // Asserted on the OBSERVATION, not the final state: the flow continues past a failed deploy
    // (reset is legal from `failed`), so by the end the range has been destroyed.
    expect(result.observations.find((o) => o.step === "deployed")?.recorded).toBe("failed");
    for (const o of result.observations) {
      expect(RANGE_STATES as readonly string[], `state ${o.recorded}`).toContain(o.recorded);
    }
    if (operation !== null) {
      expect(RANGE_OPERATION_STATUSES as readonly string[]).toContain(operation.status);
    }
  });

  it("produces a pre-plan window with total_steps of exactly 0", async () => {
    // The fidelity detail that matters most for the UI: the fake must reproduce the window the
    // real API has, or the indeterminate-progress test would be passing against a fiction.
    const original = globalThis.fetch;
    const server = createFakeRangeApi({ workerTicks: 2 });
    globalThis.fetch = server.fetch;
    try {
      const range = await api.createRange({ template_slug: "web-breach-lab", name: "Pre-plan" });
      const op = await api.deployRange(range.id);
      expect(op.status).toBe("pending");
      expect(op.total_steps).toBe(0);
      expect(op.steps).toEqual([]);

      const polled = await api.getRange(range.id);
      expect(polled.current_operation?.total_steps).toBe(0);
    } finally {
      globalThis.fetch = original;
    }
  });
});
