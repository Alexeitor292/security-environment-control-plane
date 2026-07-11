import type {
  TopologyDocumentDetail,
  TopologyRevisionDetail,
  TopologyValidationResult,
} from "../api/types";
import {
  DECISION_NOTE,
  SAVE_REVISION_NOTE,
  SUBMIT_NOTE,
  TOPOLOGY_ERROR_TEXT,
  canDecide,
  canSaveRevision,
  canSubmitRevision,
  canValidateRevision,
  conflictInfo,
  derivePosture,
  postureAllowsEditing,
  resolveTopologyPermissions,
  revisionContentIsRenderable,
  revisionRows,
  validationView,
  type ControlsInputs,
  type PostureInputs,
} from "./topology-persistence";

function rev(over: Partial<TopologyRevisionDetail> = {}): TopologyRevisionDetail {
  return {
    id: "r1",
    document_id: "d1",
    revision_number: 1,
    parent_revision_id: null,
    schema_version: "secp.topology/v1",
    content_hash: "sha256:aaa",
    status: "draft",
    change_note: null,
    source_environment_version_id: null,
    created_by: "u1",
    created_at: "2026-07-11T00:00:00",
    decided_by: null,
    decided_at: null,
    document_content: { schema_version: "secp.topology/v1", nodes: [], edges: [], networks: [], zones: [] },
    ...over,
  };
}

function doc(over: Partial<TopologyDocumentDetail> = {}): TopologyDocumentDetail {
  return {
    id: "d1",
    organization_id: "o1",
    display_name: "T",
    status: "draft",
    source_environment_version_id: null,
    exercise_id: null,
    current_revision_id: "r1",
    validated_revision_id: null,
    submitted_revision_id: null,
    approved_revision_id: null,
    revision_count: 1,
    created_at: "2026-07-11T00:00:00",
    updated_at: "2026-07-11T00:00:00",
    current_revision: rev(),
    current_validation_status: "unverifiable",
    ...over,
  };
}

function postureInputs(over: Partial<PostureInputs> = {}): PostureInputs {
  return {
    enabled: true,
    documentId: "d1",
    loadFailed: false,
    document: doc(),
    baseRevisionNumber: 1,
    dirty: false,
    permissions: { read: true, draft: true, validate: true, submit: true, decide: true },
    ...over,
  };
}

function controls(over: Partial<ControlsInputs> = {}): ControlsInputs {
  return {
    posture: "matches-saved",
    permissions: { read: true, draft: true, validate: true, submit: true, decide: true },
    dirty: false,
    hasSemanticChanges: false,
    currentRevisionStatus: "draft",
    currentValidationStatus: null,
    viewingHistorical: false,
    ...over,
  };
}

describe("permissions come only from the server permission list", () => {
  it("maps topology:* permissions", () => {
    const p = resolveTopologyPermissions(["topology:read", "topology:draft"]);
    expect(p).toEqual({ read: true, draft: true, validate: false, submit: false, decide: false });
    expect(resolveTopologyPermissions(null).read).toBe(false);
  });
});

describe("derivePosture — every state boundary distinct", () => {
  it("disabled retains local-only", () => {
    expect(derivePosture(postureInputs({ enabled: false }))).toBe("disabled");
  });
  it("load failure is unavailable, distinct from no-document", () => {
    expect(derivePosture(postureInputs({ loadFailed: true }))).toBe("unavailable");
    expect(derivePosture(postureInputs({ documentId: null, document: null }))).toBe("no-document");
  });
  it("stale base only when the local base is BEHIND the server (never when ahead)", () => {
    // local behind server → stale
    expect(derivePosture(postureInputs({ baseRevisionNumber: 1, document: doc({ current_revision: rev({ revision_number: 3 }) }) }))).toBe(
      "stale-base",
    );
    // local ahead of server (transient post-save window before reload) → NOT stale
    expect(derivePosture(postureInputs({ baseRevisionNumber: 3, document: doc({ current_revision: rev({ revision_number: 2 }) }) }))).toBe(
      "matches-saved",
    );
  });
  it("submitted/approved/rejected are locked read-only states", () => {
    expect(derivePosture(postureInputs({ document: doc({ current_revision: rev({ status: "submitted" }) }) }))).toBe("submitted-locked");
    expect(derivePosture(postureInputs({ document: doc({ current_revision: rev({ status: "approved" }) }) }))).toBe("approved");
    expect(derivePosture(postureInputs({ document: doc({ current_revision: rev({ status: "rejected" }) }) }))).toBe("rejected");
  });
  it("read-only when the user lacks draft permission", () => {
    expect(
      derivePosture(postureInputs({ permissions: { read: true, draft: false, validate: false, submit: false, decide: false } })),
    ).toBe("read-only");
  });
  it("distinguishes matches-saved from local-unsaved by dirty", () => {
    expect(derivePosture(postureInputs({ dirty: false }))).toBe("matches-saved");
    expect(derivePosture(postureInputs({ dirty: true }))).toBe("local-unsaved");
  });
});

describe("editing eligibility", () => {
  it("only editable when matches-saved or local-unsaved, never historical/locked", () => {
    expect(postureAllowsEditing("local-unsaved", false)).toBe(true);
    expect(postureAllowsEditing("matches-saved", false)).toBe(true);
    expect(postureAllowsEditing("local-unsaved", true)).toBe(false); // historical
    expect(postureAllowsEditing("submitted-locked", false)).toBe(false);
    expect(postureAllowsEditing("stale-base", false)).toBe(false);
  });
});

describe("control eligibility — strict separation", () => {
  it("save requires draft permission, real changes, editable, non-historical, non-stale", () => {
    expect(canSaveRevision(controls({ hasSemanticChanges: true })).eligible).toBe(true);
    expect(canSaveRevision(controls({ hasSemanticChanges: false })).eligible).toBe(false);
    expect(canSaveRevision(controls({ hasSemanticChanges: true, viewingHistorical: true })).eligible).toBe(false);
    expect(canSaveRevision(controls({ hasSemanticChanges: true, posture: "stale-base" })).eligible).toBe(false);
    expect(canSaveRevision(controls({ hasSemanticChanges: true, posture: "submitted-locked" })).eligible).toBe(false);
    expect(
      canSaveRevision(controls({ hasSemanticChanges: true, permissions: { read: true, draft: false, validate: true, submit: true, decide: true } })).eligible,
    ).toBe(false);
  });

  it("validate targets a SAVED revision — blocked by unsaved changes", () => {
    expect(canValidateRevision(controls({ dirty: false })).eligible).toBe(true);
    expect(canValidateRevision(controls({ dirty: true })).eligible).toBe(false);
    expect(canValidateRevision(controls({ dirty: false, currentRevisionStatus: "submitted" })).eligible).toBe(false);
    // a terminal (approved/rejected/superseded) revision is immutable — never re-validate/submit
    for (const st of ["approved", "rejected", "superseded"]) {
      expect(canValidateRevision(controls({ currentRevisionStatus: st })).eligible, st).toBe(false);
      expect(
        canSubmitRevision(controls({ currentRevisionStatus: st, currentValidationStatus: "valid" })).eligible,
        st,
      ).toBe(false);
    }
  });

  it("submit needs a current valid validation and no unsaved changes; never auto-approves", () => {
    expect(canSubmitRevision(controls({ currentValidationStatus: "valid" })).eligible).toBe(true);
    expect(canSubmitRevision(controls({ currentValidationStatus: "valid_with_warnings" })).eligible).toBe(true);
    expect(canSubmitRevision(controls({ currentValidationStatus: "invalid" })).eligible).toBe(false);
    expect(canSubmitRevision(controls({ currentValidationStatus: null })).eligible).toBe(false);
    expect(canSubmitRevision(controls({ currentValidationStatus: "stale" })).eligible).toBe(false);
    expect(canSubmitRevision(controls({ currentValidationStatus: "valid", dirty: true })).eligible).toBe(false);
  });

  it("decide only on a submitted revision and only with decide permission", () => {
    expect(canDecide(controls({ currentRevisionStatus: "submitted" })).eligible).toBe(true);
    expect(canDecide(controls({ currentRevisionStatus: "validated" })).eligible).toBe(false);
    expect(
      canDecide(controls({ currentRevisionStatus: "submitted", permissions: { read: true, draft: true, validate: true, submit: true, decide: false } })).eligible,
    ).toBe(false);
  });
});

describe("validationView — unsaved draft never shown as validated", () => {
  function vr(over: Partial<TopologyValidationResult> = {}): TopologyValidationResult {
    return {
      id: "v1",
      revision_id: "r1",
      content_hash: "sha256:aaa",
      status: "valid",
      error_count: 0,
      warning_count: 0,
      findings: [],
      result_hash: "sha256:res",
      validated_by: "u1",
      validated_at: "2026-07-11T00:00:00",
      ...over,
    };
  }
  it("not-run when no result", () => {
    expect(validationView(null, null, false).display).toBe("not-run");
    expect(validationView(null, "stale", false).display).toBe("stale");
  });
  it("valid result becomes stale after local edits", () => {
    expect(validationView(vr(), "valid", false).display).toBe("valid");
    expect(validationView(vr(), "valid", true).display).toBe("stale");
  });
  it("drops malformed finding codes and caps the list", () => {
    const v = validationView(
      vr({
        status: "invalid",
        error_count: 1,
        findings: [
          { severity: "error", code: "invalid_connection", edge_id: "e1" },
          { severity: "error", code: "<script>" as unknown as string },
        ],
      }),
      "invalid",
      false,
    );
    expect(v.findings.map((f) => f.code)).toEqual(["invalid_connection"]);
  });
});

describe("conflict info — shows local vs server, never merges", () => {
  it("surfaces both revision numbers and hashes", () => {
    const info = conflictInfo(1, "sha256:local", doc({ current_revision: rev({ revision_number: 3, content_hash: "sha256:server" }) }));
    expect(info).toEqual({
      localRevisionNumber: 1,
      localBaseHash: "sha256:local",
      serverRevisionNumber: 3,
      serverHash: "sha256:server",
    });
  });
});

describe("revision history", () => {
  it("marks the current revision and preserves API order", () => {
    const rows = revisionRows(
      [
        { ...rev({ id: "r2", revision_number: 2 }) },
        { ...rev({ id: "r1", revision_number: 1 }) },
      ] as never,
      "r2",
    );
    expect(rows.map((r) => r.id)).toEqual(["r2", "r1"]);
    expect(rows.find((r) => r.id === "r2")?.isCurrent).toBe(true);
    expect(rows.find((r) => r.id === "r1")?.isCurrent).toBe(false);
  });
});

describe("closed codes + truth copy", () => {
  it("every code maps to fixed non-interpolated copy", () => {
    for (const text of Object.values(TOPOLOGY_ERROR_TEXT)) {
      expect(text).not.toContain("{");
      expect(text.length).toBeGreaterThan(8);
    }
    expect(TOPOLOGY_ERROR_TEXT.topology_revision_stale).toContain("Nothing was overwritten");
  });
  it("truth copy keeps every boundary distinct", () => {
    expect(SAVE_REVISION_NOTE).toContain("does not validate");
    expect(SUBMIT_NOTE).toContain("does not approve");
    expect(DECISION_NOTE).toContain("No deployment plan is generated");
    expect(DECISION_NOTE.toLowerCase()).toContain("no infrastructure");
  });
});

describe("content-render guard", () => {
  it("rejects a document_content with an unexpected key", () => {
    expect(revisionContentIsRenderable(rev())).toBe(true);
    expect(
      revisionContentIsRenderable(rev({ document_content: { schema_version: "x", secret: "y" } as never })),
    ).toBe(false);
  });
});
