// What the transport layer must not lose on the way through.
//
// An adapter that flattens is worse than no adapter: the page cannot recover what the wire
// carried, and every screen downstream inherits the loss. So these are not "does it call fetch"
// tests. Each one names a distinction the control plane draws and pins that it survives.

import { describe, expect, it, vi, afterEach } from "vitest";

import {
  RANGE_STATES_ARE_NOT_BINARY,
  fixtureReader,
  isFixtureReader,
  liveReader,
  type ControlPlaneReader,
} from "./control-plane-reader";
import type { RangeOperationOut, TeardownEvidenceOut } from "./generated/openapi";
import { api } from "./client";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("provenance is declared, not inferred from which module was imported", () => {
  it("marks the live reader live", () => {
    expect(liveReader.provenance).toBe("live");
    expect(isFixtureReader(liveReader)).toBe(false);
  });

  it("marks a fixture reader fixture, and offers no way to say otherwise", () => {
    // `fixtureReader` takes rows and nothing else. There is no parameter that produces fixture
    // data wearing a live label, which is why this is a factory and not an object literal a
    // caller assembles.
    const reader = fixtureReader({ targets: [] });
    expect(reader.provenance).toBe("fixture");
    expect(isFixtureReader(reader)).toBe(true);
  });

  it("distinguishes the two at RUNTIME, not only at the type level", () => {
    // The failure this exists to prevent: a build that imports the fixture reader by mistake and
    // renders it as live. A type-only distinction is erased before that can be caught.
    const readers: ControlPlaneReader[] = [liveReader, fixtureReader({ targets: [] })];
    expect(readers.map((r) => r.provenance)).toEqual(["live", "fixture"]);
  });
});

describe("an unsupplied fixture is not an empty one", () => {
  it("throws rather than returning [] for rows nobody provided", async () => {
    // `[]` is a claim — "the control plane looked and found none". Over an unsupplied fixture it
    // is a claim nobody made, and a screen would render "no targets" as though that were a finding.
    const reader = fixtureReader({ targets: [] });
    await expect(reader.listWorkers()).rejects.toThrow(/was not given workers/);
  });

  it("returns the empty list when one was deliberately supplied", async () => {
    const reader = fixtureReader({ targets: [] });
    await expect(reader.listTargets()).resolves.toEqual([]);
  });
});

describe("listWorkers joins both sources and drops neither side", () => {
  const enrollment = {
    enrollment_id: "enr-1",
    worker_installation_id: "wi-1",
    state: "healthy",
    release_fingerprint: "rel-aaa",
    worker_key_fingerprint: "SHA256:kkk",
    refusal_reason: "",
    updated_at: "2026-08-05T00:00:00Z",
    deployment_site_label: "site-one",
  };
  const node = {
    id: "node-1",
    node_label: "pve-1",
    ssh_public_key_fingerprint: "SHA256:kkk",
    admission_anchor_fingerprint: "SHA256:aaa",
    worker_identity_registration_id: "reg-1",
    updated_at: "2026-08-05T00:00:00Z",
  };

  it("requests both endpoints, never one with a fallback", async () => {
    const enrollments = vi
      .spyOn(api, "listEnrollments")
      .mockResolvedValue({ items: [enrollment], next_cursor: null } as never);
    const nodes = vi.spyOn(api, "listWorkerNodes").mockResolvedValue([node] as never);

    const rows = await liveReader.listWorkers();

    expect(enrollments).toHaveBeenCalledTimes(1);
    expect(nodes).toHaveBeenCalledTimes(1);
    expect(rows).toHaveLength(1);
    expect(rows[0].nodeLabel).toBe("pve-1");
    expect(rows[0].enrollmentState).toBe("healthy");
  });

  it("keeps a worker that only ONE source knows about", async () => {
    // An enrolled worker that never published keys, and published keys with no enrollment, are
    // both real states. A join that dropped either would under-report the fleet silently.
    vi.spyOn(api, "listEnrollments").mockResolvedValue({
      items: [{ ...enrollment, worker_key_fingerprint: "SHA256:zzz" }],
      next_cursor: null,
    } as never);
    vi.spyOn(api, "listWorkerNodes").mockResolvedValue([node] as never);

    const rows = await liveReader.listWorkers();

    expect(rows).toHaveLength(2);
    expect(rows.filter((r) => r.enrollmentId !== null)).toHaveLength(1);
    expect(rows.filter((r) => r.nodeLabel !== null)).toHaveLength(1);
  });

  it("does not call an unenrolled node healthy", async () => {
    vi.spyOn(api, "listEnrollments").mockResolvedValue({ items: [], next_cursor: null } as never);
    vi.spyOn(api, "listWorkerNodes").mockResolvedValue([node] as never);

    const rows = await liveReader.listWorkers();

    // `null`, not `"unhealthy"` and not `"healthy"`. Nobody enrolled it, which is its own state.
    expect(rows[0].enrollmentState).toBeNull();
  });
});

describe("the deployment reading keeps the range and its resources apart", () => {
  it("returns both rather than merging them", async () => {
    // `RangeResourceOut.removed_at` says a resource WAS in this deployment. Merging the two reads
    // into one flat list is where that gets lost, and a torn-down resource then renders as live.
    vi.spyOn(api, "getRange").mockResolvedValue({ id: "rng-1", state: "ready" } as never);
    vi.spyOn(api, "listRangeResources").mockResolvedValue([
      { id: "res-1", name: "web", removed_at: null },
      { id: "res-2", name: "old-web", removed_at: "2026-08-01T00:00:00Z" },
    ] as never);

    const reading = await liveReader.getDeployment("rng-1");

    expect(reading.range.id).toBe("rng-1");
    expect(reading.resources).toHaveLength(2);
    expect(reading.resources.filter((r) => r.removed_at !== null)).toHaveLength(1);
  });
});

describe("the distinctions the contract draws survive to the caller", () => {
  it("keeps nine range states, not two", () => {
    // `recovery_required` means the range could not be OBSERVED — not running, not failed.
    // Mapping it to either claims knowledge nobody has.
    expect(RANGE_STATES_ARE_NOT_BINARY).toHaveLength(9);
    expect(RANGE_STATES_ARE_NOT_BINARY).toContain("recovery_required");
    expect(RANGE_STATES_ARE_NOT_BINARY).toContain("destroyed");
    expect(RANGE_STATES_ARE_NOT_BINARY).toContain("failed");
  });

  it("passes `stale` through on an operation, beside whatever `status` still says", async () => {
    // The pair, not either half. A stale operation's `status` is unchanged — it still reads
    // "running" — so a surface reading `status` alone shows a stalled run progressing forever.
    // This field was MISSING from the hand-written range types until this slice added it.
    const stalled: Partial<RangeOperationOut> = {
      id: "op-1",
      status: "running",
      stale: true,
      stale_reason: "lease expired",
      percent: 40,
    };
    vi.spyOn(api, "listRangeOperations").mockResolvedValue([stalled] as never);

    const [operation] = await liveReader.listWorkflowRuns("rng-1");

    expect(operation.status).toBe("running");
    expect(operation.stale).toBe(true);
    expect(operation.stale_reason).toBe("lease expired");
  });

  it("passes `unproven_count` through on teardown evidence", async () => {
    // `unproven` is not `removed`. A teardown with anything unproven has not proved zero residue,
    // however many resources it did confirm gone.
    const evidence: Partial<TeardownEvidenceOut> = {
      id: "ev-1",
      verdict: "unproven",
      probe_reachable: false,
      expected_count: 4,
      removed_confirmed: 3,
      still_present: 0,
      unproven_count: 1,
    };
    vi.spyOn(api, "listTeardownEvidence").mockResolvedValue([evidence] as never);

    const [record] = await liveReader.listTeardownEvidence("rng-1");

    expect(record.unproven_count).toBe(1);
    expect(record.still_present).toBe(0);
    // The trap: 3 confirmed and 0 present looks clean until the unproven one is read.
    expect(record.verdict).toBe("unproven");
    expect(record.probe_reachable).toBe(false);
  });

  it("does not invent score components the server does not hold", async () => {
    // The domain model wants defense/availability/attack/penalties. The scoreboard holds ONE
    // total per team. Deriving the components in a browser would invent the scoring model.
    vi.spyOn(api, "getScoreboard").mockResolvedValue({
      competition_id: "comp-1",
      state: "running",
      total_points: 500,
      generated_at: "2026-08-05T00:00:00Z",
      entries: [{ team_id: "t1", team_name: "alpha", rank: 1, score: 300, solved_count: 3 }],
    } as never);

    const board = await liveReader.listScores("rng-1");

    expect(board.entries[0].score).toBe(300);
    expect(board.entries[0]).not.toHaveProperty("defense");
    expect(board.entries[0]).not.toHaveProperty("penalties");
  });

  it("keeps `simulated` distinct from healthy on an integration", async () => {
    // `simulated: true` is not "implemented". A plugin that reports healthy while simulating is
    // healthily simulating, and mapping that to an operational capability is a false claim about
    // the platform.
    vi.spyOn(api, "plugins").mockResolvedValue([
      { name: "simulator", version: "1.0", capabilities: [], healthy: true, simulated: true },
    ] as never);

    const [plugin] = await liveReader.listIntegrations();

    expect(plugin.healthy).toBe(true);
    expect(plugin.simulated).toBe(true);
  });
});

describe("the range log is not the event list", () => {
  it("is named for the log it reads", () => {
    // `listEvents` on the spatial adapter means scheduled competitions. This reads the append-only
    // range log. The route is /ranges/{id}/events, which makes the wrong wiring look right — the
    // method name is the only thing standing in the way, so it refuses to help.
    expect(liveReader).not.toHaveProperty("listEvents");
    expect(liveReader).toHaveProperty("listRangeLog");
  });

  it("has no method at all for the seven unserved adapter methods", () => {
    // Absent, not present-and-returning-[]. An empty array is a claim; a missing method is a
    // compile error at the call site, which is where somebody can act on it.
    for (const method of [
      "listEvents",
      "listAccessProfiles",
      "listApprovals",
      "listAlerts",
      "listReports",
      "listUsers",
      "listSecretRefs",
    ]) {
      expect(liveReader, `${method} should not exist on the reader`).not.toHaveProperty(method);
    }
  });
});
