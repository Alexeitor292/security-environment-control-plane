// Placement projection: discovery freshness, eligibility, and the worker join.
//
// WHY THIS FILE EXISTS. `placement-view.ts` was preserved from PR #111 alongside
// `proxmox-view.ts` and `provenance.ts`, and the stated reason those modules were
// worth preserving is that their tests are what make them trustworthy. This one
// arrived with no tests at all — it is the only module of the three without a
// suite, and nothing on main imports it yet, so no consumer exercises it either.
// Preserving it on the strength of an argument that does not apply to it would
// have been taking it on trust.
//
// WHAT IS ACTUALLY WORTH ASSERTING. Not that the functions copy fields across —
// that is restatement. The invariants below are the ones the module's own
// comments claim, each of which is a distinction that a careless projection
// collapses:
//
//   * "never completed" is NOT "stale". A discovery that has not finished is not
//     evidence of staleness; it is the absence of evidence.
//   * An unparseable timestamp must not read as fresh. Refusing to guess is the
//     whole point.
//   * A worker present in only one of the two sources is a real state, and
//     neither source may silently drop it.
//   * A node with no enrollment is neither healthy nor failed.
//
// Each of those is tested as a DISTINCTION — the wrong value is asserted absent,
// not merely the right one present — because "collapses two cases into one" is
// exactly the failure that a presence-only assertion cannot see.

import { describe, expect, it } from "vitest";

import type {
  DiscoveryEnrollment,
  EnrollmentStatus,
  ExecutionTarget,
  InventorySnapshot,
  WorkerDiscoveryNode,
} from "../../api/types";
import {
  DISCOVERY_AGING_SECONDS,
  DISCOVERY_STALE_SECONDS,
  discoveryRow,
  eligibilityRows,
  formatAge,
  healthyWorkers,
  latestDiscovery,
  PROXMOX_PLUGIN_NAME,
  proxmoxTargets,
  targetRows,
  workerRows,
} from "./placement-view";

const NOW = "2026-08-05T12:00:00Z";

function at(secondsAgo: number): string {
  return new Date(Date.parse(NOW) - secondsAgo * 1000).toISOString();
}

function snapshot(over: Partial<InventorySnapshot> = {}): InventorySnapshot {
  return {
    id: "snap-1",
    execution_target_id: "tgt-1",
    plugin_name: PROXMOX_PLUGIN_NAME,
    plugin_version: "1.0.0",
    target_config_hash: "h",
    status: "succeeded",
    workflow_run_id: null,
    requested_at: at(120),
    completed_at: at(60),
    summary: {},
    error: null,
    ...over,
  };
}

function target(over: Partial<ExecutionTarget> = {}): ExecutionTarget {
  return {
    id: "tgt-1",
    organization_id: "org-1",
    display_name: "Main Proxmox",
    plugin_name: PROXMOX_PLUGIN_NAME,
    config: {},
    config_hash: "cfg",
    secret_ref: null,
    status: "active",
    scope_policy: {},
    created_at: NOW,
    ...over,
  };
}

function enrollment(over: Partial<EnrollmentStatus> = {}): EnrollmentStatus {
  return {
    enrollment_id: "enr-1",
    state: "healthy",
    revision: 1,
    controller_installation_id: "ctl-1",
    controller_key_fingerprint: "cfp",
    worker_installation_id: "wi-1",
    worker_key_fingerprint: "wfp-1",
    release_fingerprint: "rel-1",
    offer_fingerprint: "off",
    result_fingerprint: "res",
    expires_at: NOW,
    updated_at: NOW,
    refusal_reason: "",
    deployment_site_label: "site-a",
    ...over,
  };
}

function node(over: Partial<WorkerDiscoveryNode> = {}): WorkerDiscoveryNode {
  return {
    id: "nd-1",
    organization_id: "org-1",
    node_label: "pve-01",
    ssh_public_key: "ssh-ed25519 AAAA...",
    ssh_public_key_fingerprint: "wfp-1",
    admission_anchor_hex: "ab",
    admission_anchor_fingerprint: "anchor-1",
    revision: 1,
    worker_identity_registration_id: "reg-1",
    created_at: NOW,
    updated_at: NOW,
    ...over,
  };
}

function discoveryEnrollment(over: Partial<DiscoveryEnrollment> = {}): DiscoveryEnrollment {
  return {
    id: "de-1",
    organization_id: "org-1",
    execution_target_id: "tgt-1",
    display_name: "Main Proxmox",
    ownership_label: "own",
    resource_profile: "std",
    status: "approved" as DiscoveryEnrollment["status"],
    decision_code: "ok",
    enrollment_version: 1,
    revision: 1,
    active_plan_hash: "hash-a",
    approved_plan_hash: "hash-a",
    approved_at: NOW,
    failure_code: null,
    created_at: NOW,
    ...over,
  };
}

describe("discovery freshness — absence of evidence is not staleness", () => {
  it("reports a never-completed discovery as never_completed, NOT stale", () => {
    const row = discoveryRow(snapshot({ completed_at: null }), NOW);

    expect(row.freshness).toBe("never_completed");
    // The distinction is the point: a projection that treats "no completion" as
    // an infinitely old completion would report `stale` here and read as though
    // the cluster had been observed long ago. It has not been observed at all.
    expect(row.freshness).not.toBe("stale");
    expect(row.ageSeconds).toBeNull();
  });

  it("treats an empty-string completion the same as a missing one", () => {
    const row = discoveryRow(snapshot({ completed_at: "" }), NOW);

    expect(row.freshness).toBe("never_completed");
    expect(row.completedAt).toBeNull();
  });

  it("refuses to read an unparseable timestamp as fresh", () => {
    const row = discoveryRow(snapshot({ completed_at: "not-a-date" }), NOW);

    // Both halves matter. Guessing `fresh` would present garbage as a current
    // observation; guessing `stale` would invent an observation that never
    // happened.
    expect(row.freshness).toBe("never_completed");
    expect(row.freshness).not.toBe("fresh");
    expect(row.ageSeconds).toBeNull();
  });

  it("reports a failed discovery as failed regardless of how recent it was", () => {
    const row = discoveryRow(snapshot({ completed_at: at(1), error: "boom" }), NOW);

    // A discovery that failed one second ago is not fresh evidence. Recency must
    // not override the error.
    expect(row.freshness).toBe("failed");
    expect(row.freshness).not.toBe("fresh");
  });

  it("crosses fresh -> aging -> stale exactly at the declared thresholds", () => {
    const freshness = (secondsAgo: number) =>
      discoveryRow(snapshot({ completed_at: at(secondsAgo) }), NOW).freshness;

    expect(freshness(DISCOVERY_AGING_SECONDS - 1)).toBe("fresh");
    expect(freshness(DISCOVERY_AGING_SECONDS)).toBe("aging");
    expect(freshness(DISCOVERY_STALE_SECONDS - 1)).toBe("aging");
    expect(freshness(DISCOVERY_STALE_SECONDS)).toBe("stale");
  });

  it("never reports a negative age when a completion is stamped in the future", () => {
    // Clock skew between the control plane and the browser is ordinary. A
    // negative age would render as a nonsense string.
    const row = discoveryRow(snapshot({ completed_at: at(-600) }), NOW);
    expect(row.ageSeconds).toBe(0);
  });
});

describe("latestDiscovery", () => {
  it("returns null rather than an empty shape when there is nothing to report", () => {
    // An empty row object would render as a discovery that happened with blank
    // values. Null is the only honest answer.
    expect(latestDiscovery([], NOW)).toBeNull();
  });

  it("selects the most recently requested snapshot", () => {
    const older = snapshot({ id: "old", requested_at: at(9000), completed_at: at(8000) });
    const newer = snapshot({ id: "new", requested_at: at(100), completed_at: at(50) });

    expect(latestDiscovery([older, newer], NOW)?.snapshotId).toBe("new");
    expect(latestDiscovery([newer, older], NOW)?.snapshotId).toBe("new");
  });

  it("does not mutate the caller's array while sorting", () => {
    const snaps = [snapshot({ id: "a", requested_at: at(10) }), snapshot({ id: "b", requested_at: at(99) })];
    latestDiscovery(snaps, NOW);
    expect(snaps.map((s) => s.id)).toEqual(["a", "b"]);
  });
});

describe("formatAge", () => {
  it("renders an absent age as a dash, not as zero", () => {
    // "0s ago" would claim an observation that did not happen.
    expect(formatAge(null)).toBe("—");
  });

  it("scales units without ever showing a bare number", () => {
    expect(formatAge(30)).toBe("30s ago");
    expect(formatAge(600)).toBe("10m ago");
    expect(formatAge(7200)).toBe("2h ago");
    expect(formatAge(86400 * 3)).toBe("3d ago");
  });
});

describe("target matching", () => {
  it("matches on the plugin the server recorded, never on the display name", () => {
    const decoy = target({ id: "tgt-2", display_name: "proxmox-lookalike", plugin_name: "simulator" });
    const real = target({ id: "tgt-1", display_name: "Cluster A" });

    const matched = proxmoxTargets([decoy, real]);

    expect(matched.map((t) => t.id)).toEqual(["tgt-1"]);
  });

  it("reports credential presence as a boolean without exposing the reference", () => {
    const [withRef] = targetRows([target({ secret_ref: "vault://a/b" })]);
    const [without] = targetRows([target({ secret_ref: null })]);

    expect(withRef.hasCredentialRef).toBe(true);
    expect(without.hasCredentialRef).toBe(false);
    // The opaque reference itself must not travel into the view model.
    expect(JSON.stringify(withRef)).not.toContain("vault://");
  });
});

describe("eligibility — plan hash divergence", () => {
  it("flags divergence only when both hashes are present and differ", () => {
    const diverged = eligibilityRows([
      discoveryEnrollment({ active_plan_hash: "a", approved_plan_hash: "b" }),
    ]);
    expect(diverged[0].planHashDiverged).toBe(true);
  });

  it("does not flag divergence when nothing has been approved yet", () => {
    // An unapproved enrollment has not diverged from anything. Reporting it as
    // diverged would send an operator to re-review a decision never made.
    const rows = eligibilityRows([
      discoveryEnrollment({ active_plan_hash: "a", approved_plan_hash: "" }),
    ]);
    expect(rows[0].planHashDiverged).toBe(false);
  });

  it("does not flag divergence when there is no active plan", () => {
    const rows = eligibilityRows([
      discoveryEnrollment({ active_plan_hash: "", approved_plan_hash: "b" }),
    ]);
    expect(rows[0].planHashDiverged).toBe(false);
  });

  it("does not flag matching hashes", () => {
    expect(eligibilityRows([discoveryEnrollment()])[0].planHashDiverged).toBe(false);
  });
});

describe("worker join — neither source may be silently dropped", () => {
  it("joins an enrollment to its discovery node on the ssh key fingerprint", () => {
    const rows = workerRows([enrollment()], [node()]);

    expect(rows).toHaveLength(1);
    expect(rows[0].nodeLabel).toBe("pve-01");
    expect(rows[0].enrollmentId).toBe("enr-1");
    expect(rows[0].identityRegistrationId).toBe("reg-1");
  });

  it("also joins on the admission anchor fingerprint", () => {
    const rows = workerRows(
      [enrollment({ worker_key_fingerprint: "anchor-1" })],
      [node({ ssh_public_key_fingerprint: "other" })],
    );

    expect(rows).toHaveLength(1);
    expect(rows[0].nodeLabel).toBe("pve-01");
  });

  it("keeps an enrolled worker that never published keys", () => {
    const rows = workerRows([enrollment()], []);

    expect(rows).toHaveLength(1);
    expect(rows[0].enrollmentState).toBe("healthy");
    expect(rows[0].nodeLabel).toBeNull();
  });

  it("keeps a published node with no enrollment, as its own state", () => {
    const rows = workerRows([], [node()]);

    expect(rows).toHaveLength(1);
    // The load-bearing assertion: an unenrolled node is neither healthy nor a
    // failure. Rendering it as either would be an invented claim about a real
    // machine — one direction hides a gap, the other raises a false alarm.
    expect(rows[0].enrollmentState).toBeNull();
    expect(rows[0].enrollmentState).not.toBe("healthy");
    expect(rows[0].refusalReason).toBeNull();
    expect(rows[0].nodeLabel).toBe("pve-01");
  });

  it("emits both when the two sources describe different workers", () => {
    const rows = workerRows(
      [enrollment({ worker_key_fingerprint: "wfp-A" })],
      [node({ ssh_public_key_fingerprint: "wfp-B", admission_anchor_fingerprint: "anchor-B" })],
    );

    expect(rows).toHaveLength(2);
    expect(rows.map((r) => r.key).sort()).toEqual(["enr:enr-1", "node:nd-1"]);
  });

  it("normalizes empty strings to null rather than rendering blanks", () => {
    const rows = workerRows(
      [enrollment({ worker_installation_id: "", release_fingerprint: "", refusal_reason: "" })],
      [],
    );

    expect(rows[0].workerInstallationId).toBeNull();
    expect(rows[0].releaseFingerprint).toBeNull();
    expect(rows[0].refusalReason).toBeNull();
  });

  it("tolerates a controller that omits the site label entirely", () => {
    // `deployment_site_label` is typed as required, but a browser cannot
    // type-check a server response: a controller built before that projection
    // change returns a body without the key. The cast reproduces that wire
    // shape, which is the only way to exercise the guard the module documents.
    const legacy = enrollment();
    delete (legacy as Partial<EnrollmentStatus>).deployment_site_label;

    const rows = workerRows([legacy as EnrollmentStatus], []);

    expect(rows[0].siteLabel).toBeNull();
    expect(rows[0].enrollmentState).toBe("healthy");
  });

  it("treats an empty site label as absent", () => {
    expect(workerRows([enrollment({ deployment_site_label: "" })], [])[0].siteLabel).toBeNull();
  });
});

describe("healthyWorkers", () => {
  it("counts only the healthy state, not merely 'not failed'", () => {
    const rows = workerRows(
      [
        enrollment({ enrollment_id: "a", state: "healthy", worker_key_fingerprint: "f-a" }),
        enrollment({ enrollment_id: "b", state: "recovery_required", worker_key_fingerprint: "f-b" }),
        enrollment({ enrollment_id: "c", state: "pending", worker_key_fingerprint: "f-c" }),
      ],
      [],
    );

    expect(healthyWorkers(rows).map((r) => r.enrollmentId)).toEqual(["a"]);
  });

  it("does not count an unenrolled node as healthy", () => {
    // The null state must not pass a "not explicitly broken" filter.
    expect(healthyWorkers(workerRows([], [node()]))).toEqual([]);
  });
});
