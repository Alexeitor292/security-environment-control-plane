import type {
  DiscoveryEnrollment,
  ExecutionTarget,
  Exercise,
  Onboarding,
  ReadonlyPreflight,
  StagingLab,
} from "../api/types";
import {
  NOT_RECORDED,
  SOURCE_UNAVAILABLE_DETAIL,
  activityRows,
  apiReachabilityView,
  boundariesMetric,
  decisionCountValue,
  deriveDecisionItems,
  labsMetric,
  latestPreflightView,
  targetsMetric,
  unavailableSourceCount,
} from "./overview";

const target = (status: string): ExecutionTarget =>
  ({ id: "t1", status } as ExecutionTarget);
const onboarding = (status: string, created = "2026-07-01T10:00:00Z"): Onboarding =>
  ({
    id: `o-${status}-${created}`,
    status,
    onboarding_mode: "existing_environment",
    isolation_model: "physical",
    created_at: created,
  }) as Onboarding;
const lab = (status: string, created = "2026-07-02T10:00:00Z"): StagingLab =>
  ({
    id: `l-${status}`,
    status,
    display_name: "staging-alpha-lab-01",
    plan_version: 1,
    created_at: created,
  }) as StagingLab;

describe("metric views", () => {
  it("renders unavailable sources as an explicit dash, never a number", () => {
    for (const m of [
      targetsMetric(null),
      boundariesMetric(null),
      labsMetric(null),
    ]) {
      expect(m.value).toBe("—");
      expect(m.detail).toBe(SOURCE_UNAVAILABLE_DETAIL);
      expect(m.unavailable).toBe(true);
    }
  });

  it("counts targets with active/disabled breakdown", () => {
    const m = targetsMetric([target("active"), target("disabled")]);
    expect(m.value).toBe("2");
    expect(m.detail).toBe("registered · 1 active · 1 disabled");
    expect(targetsMetric([target("active")]).detail).toBe("registered · 1 active");
  });

  it("counts only active onboardings as onboarded boundaries", () => {
    const m = boundariesMetric([
      onboarding("active"),
      onboarding("draft"),
      onboarding("rejected"),
    ]);
    expect(m.value).toBe("1");
    expect(m.detail).toBe("active of 3 declared");
  });

  it("summarizes staging labs by approved and simulated-ready", () => {
    const m = labsMetric([lab("approved"), lab("simulated_ready"), lab("draft")]);
    expect(m.value).toBe("3");
    expect(m.detail).toBe("1 approved · 1 simulated-ready");
  });
});

describe("latestPreflightView", () => {
  const preflight = (
    created: string,
    outcome: string | null,
    status = "completed",
    completed: string | null = null,
  ): ReadonlyPreflight =>
    ({
      id: `p-${created}`,
      created_at: created,
      completed_at: completed,
      outcome_code: outcome,
      status,
    }) as ReadonlyPreflight;

  it("is truthful when nothing is recorded or the source failed", () => {
    expect(latestPreflightView([]).value).toBe(NOT_RECORDED);
    expect(latestPreflightView(null).unavailable).toBe(true);
  });

  it("dates an outcome by when it was recorded (completed_at), not queued", () => {
    const v = latestPreflightView([
      preflight("2026-07-01T15:20:44Z", "authorization_expired", "refused", "2026-07-01T15:21:00Z"),
      preflight("2026-07-01T09:54:00Z", "credential_unavailable", "completed", "2026-07-03T09:56:31Z"),
    ]);
    // Newest by created_at is the expired one; its outcome dates to completion.
    expect(v.value).toBe("authorization expired");
    expect(v.detail).toBe("recorded 2026-07-01");
    const w = latestPreflightView([
      preflight("2026-07-01T09:54:00Z", "credential_unavailable", "completed", "2026-07-03T09:56:31Z"),
    ]);
    expect(w.detail).toBe("recorded 2026-07-03");
  });

  it("labels a pending preflight as requested and exposes status for tone", () => {
    const v = latestPreflightView([preflight("2026-07-03T09:54:02Z", null, "queued")]);
    expect(v.value).toBe("queued");
    expect(v.outcome).toBeNull();
    expect(v.status).toBe("queued");
    expect(v.detail).toBe("requested 2026-07-03");
  });

  it("marks partially unreachable fan-outs in the detail line", () => {
    const v = latestPreflightView(
      [preflight("2026-07-03T09:54:02Z", null, "queued")],
      true,
    );
    expect(v.detail).toContain("some targets unreachable");
    expect(boundariesMetric([], true).detail).toContain("some targets unreachable");
  });
});

describe("apiReachabilityView", () => {
  it("claims Responding when at least one request group answered, with honest failure counts", () => {
    expect(apiReachabilityView(["loaded", "loaded"])).toMatchObject({
      value: "Responding",
      tone: "ok",
      detail: "all 2 request groups answered",
    });
    expect(
      apiReachabilityView(["loaded", "http_error", "network_error"]).detail,
    ).toBe("2 of 3 request groups failed");
  });

  it("never claims Unreachable while requests are in flight", () => {
    expect(apiReachabilityView(["loading", "network_error"]).value).toBe("—");
  });

  it("distinguishes a responding-but-erroring API from network failure", () => {
    expect(apiReachabilityView(["http_error", "network_error"])).toMatchObject({
      value: "Requests failing",
      tone: "danger",
    });
    expect(apiReachabilityView(["network_error", "network_error"])).toMatchObject({
      value: "Unreachable",
      tone: "danger",
    });
  });
});

describe("deriveDecisionItems", () => {
  it("derives items from the exact review states each surface uses", () => {
    const items = deriveDecisionItems({
      exercises: [
        {
          id: "e1",
          name: "Exercise from v1",
          lifecycle_state: "awaiting_approval",
          team_count: 2,
          created_at: "2026-07-03T08:00:00Z",
        } as Exercise,
        { id: "e2", lifecycle_state: "running", created_at: "x" } as Exercise,
      ],
      onboardings: [onboarding("ready_for_review", "2026-07-03T09:00:00Z")],
      stagingLabs: [lab("awaiting_approval", "2026-07-03T10:00:00Z")],
      stagingDeployments: null,
      discoveryEnrollments: [
        {
          id: "d1",
          display_name: "secp-staging/alpha",
          status: "plan_ready",
          created_at: "2026-07-03T07:00:00Z",
        } as DiscoveryEnrollment,
      ],
    });
    expect(items.map((i) => i.chip)).toEqual(["LAB", "ONBOARDING", "PLAN", "DISCOVERY"]);
    expect(items[2].href).toBe("/exercises/e1/plan");
    expect(items.every((i) => i.href.startsWith("/"))).toBe(true);
  });

  it("returns nothing when no source has reviewable items", () => {
    expect(
      deriveDecisionItems({
        exercises: [],
        onboardings: [],
        stagingLabs: [],
        stagingDeployments: [],
        discoveryEnrollments: [],
      }),
    ).toEqual([]);
  });

  it("renders a verified zero only when every source loaded", () => {
    expect(decisionCountValue(0, 5)).toBe("—");
    expect(decisionCountValue(0, 2)).toBe("—");
    expect(decisionCountValue(0, 0)).toBe("0");
    // A positive count is real regardless of other sources failing.
    expect(decisionCountValue(3, 1)).toBe("3");
  });

  it("counts failed sources for the truthful caveat", () => {
    expect(
      unavailableSourceCount({
        exercises: null,
        onboardings: [],
        stagingLabs: null,
        stagingDeployments: [],
        discoveryEnrollments: [],
      }),
    ).toBe(2);
  });
});

describe("activityRows", () => {
  it("sorts newest first, limits, and formats UTC times from the record", () => {
    const rows = activityRows(
      [
        {
          id: "a1",
          created_at: "2026-07-03T10:14:22Z",
          action: "exercise.deploy",
          resource_type: "exercise",
          resource_id: "7c1f20aa4b7de91c",
          actor: "dev-admin",
          outcome: "success",
          data: {},
        },
        {
          id: "a2",
          created_at: "2026-07-03T10:12:31Z",
          action: "exercise.deploy",
          resource_type: "exercise",
          resource_id: null,
          actor: "dev-admin",
          outcome: "denied",
          data: {},
        },
      ],
      1,
    );
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      time: "10:14:22",
      action: "exercise.deploy",
      resource: "exercise/7c1f20aa",
      outcome: "success",
    });
  });

  it("handles a missing resource id and a failed source", () => {
    expect(activityRows(null, 5)).toEqual([]);
    const rows = activityRows(
      [
        {
          id: "a2",
          created_at: "2026-07-03T10:12:31Z",
          action: "plan.approve",
          resource_type: "deployment_plan",
          resource_id: null,
          actor: "dev-admin",
          outcome: "denied",
          data: {},
        },
      ],
      5,
    );
    expect(rows[0].resource).toBe("deployment_plan");
  });
});
