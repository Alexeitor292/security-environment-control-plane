import yaml from "js-yaml";
import { describe, expect, it } from "vitest";

import type {
  EnvironmentPublicationClientResult,
  Template,
  TopologyDocumentDetail,
  TopologyRevisionDetail,
  TopologyValidationResult,
  Version,
} from "../api/types";
import {
  CONFIRM_LABEL,
  PUBLICATION_ERROR_TEXT,
  V1ALPHA2,
  buildPublicationRequest,
  buildReview,
  canOfferPublish,
  definitionReadiness,
  findVersionById,
  generateInitialDraft,
  hasPublishPermission,
  inspectDefinition,
  libraryProvenanceView,
  parseDefinitionYaml,
  resolveAuthoritativeInputs,
  resolveDestinationForSource,
  resolveDestinationSourceless,
  resolveLibrarySelection,
  resultView,
  sourcePolicy,
} from "./environment-publication";

const HASH = "sha256:" + "a".repeat(64);
const VHASH = "sha256:" + "b".repeat(64);

function rev(over: Partial<TopologyRevisionDetail> = {}): TopologyRevisionDetail {
  return {
    id: "rev-1",
    document_id: "doc-1",
    revision_number: 1,
    parent_revision_id: null,
    schema_version: "secp.topology/v1",
    content_hash: HASH,
    status: "approved",
    change_note: null,
    source_environment_version_id: null,
    created_by: null,
    created_at: "2026-01-01T00:00:00",
    decided_by: null,
    decided_at: null,
    document_content: { schema_version: "secp.topology/v1", nodes: [], edges: [], networks: [], zones: [] },
    ...over,
  };
}

function doc(over: Partial<TopologyDocumentDetail> = {}): TopologyDocumentDetail {
  const current = over.current_revision === undefined ? rev() : over.current_revision;
  return {
    id: "doc-1",
    organization_id: "org-1",
    display_name: "Doc",
    status: "approved",
    source_environment_version_id: null,
    exercise_id: null,
    current_revision_id: current ? current.id : "rev-1",
    validated_revision_id: null,
    submitted_revision_id: null,
    approved_revision_id: current ? current.id : "rev-1",
    revision_count: 1,
    created_at: "2026-01-01T00:00:00",
    updated_at: "2026-01-01T00:00:00",
    current_revision: current,
    current_validation_status: "valid",
    ...over,
  };
}

function val(over: Partial<TopologyValidationResult> = {}): TopologyValidationResult {
  return {
    id: "val-1",
    revision_id: "rev-1",
    content_hash: HASH,
    status: "valid",
    error_count: 0,
    warning_count: 0,
    findings: [],
    result_hash: VHASH,
    validated_by: null,
    validated_at: "2026-01-01T00:00:00",
    ...over,
  };
}

function ver(over: Partial<Version> = {}): Version {
  return {
    id: "ver-1",
    template_id: "tmpl-1",
    version_number: 1,
    api_version: "controlplane.security/v1alpha1",
    content_hash: "sha256:" + "c".repeat(64),
    spec: { apiVersion: "controlplane.security/v1alpha1", kind: "Environment", metadata: { name: "x" }, spec: {} },
    created_at: "2026-01-01T00:00:00",
    publication_provenance: null,
    ...over,
  };
}

function tmpl(over: Partial<Template> = {}): Template {
  return {
    id: "tmpl-1",
    organization_id: "org-1",
    name: "T",
    slug: "t",
    display_name: "Template One",
    description: "",
    created_at: "2026-01-01T00:00:00",
    ...over,
  };
}

// --- contextual entry point (§4) ---------------------------------------------------------------

describe("canOfferPublish", () => {
  const base = {
    document: doc(),
    validation: val(),
    hasPublishPermission: true,
    dirty: false,
    viewingHistorical: false,
    busy: false,
  };

  it("is eligible only when every UI-visible precondition holds", () => {
    expect(canOfferPublish(base).eligible).toBe(true);
  });

  it("requires version:publish", () => {
    const r = canOfferPublish({ ...base, hasPublishPermission: false });
    expect(r.eligible).toBe(false);
    expect(r.reason).toMatch(/version:publish/);
  });

  it("blocks a dirty workspace", () => {
    expect(canOfferPublish({ ...base, dirty: true }).eligible).toBe(false);
  });

  it("blocks a historical revision view", () => {
    expect(canOfferPublish({ ...base, viewingHistorical: true }).eligible).toBe(false);
  });

  it("blocks while a mutation is in progress", () => {
    expect(canOfferPublish({ ...base, busy: true }).eligible).toBe(false);
  });

  it("requires an approved revision", () => {
    expect(
      canOfferPublish({ ...base, document: doc({ approved_revision_id: null }) }).eligible,
    ).toBe(false);
  });

  it("requires the current revision to be the approved one", () => {
    const d = doc({ current_revision_id: "rev-2" });
    expect(canOfferPublish({ ...base, document: d }).eligible).toBe(false);
  });

  it("requires passing validation matching the approved revision", () => {
    expect(canOfferPublish({ ...base, validation: val({ status: "invalid", error_count: 2 }) }).eligible).toBe(false);
    expect(canOfferPublish({ ...base, validation: val({ content_hash: "sha256:" + "9".repeat(64) }) }).eligible).toBe(false);
    expect(canOfferPublish({ ...base, validation: null }).eligible).toBe(false);
  });
});

// --- authoritative resolution (§5) -------------------------------------------------------------

describe("resolveAuthoritativeInputs", () => {
  it("resolves pins from server values only", () => {
    const r = resolveAuthoritativeInputs(doc(), rev(), val());
    expect(r).toEqual({
      ok: true,
      pins: {
        topology_document_id: "doc-1",
        topology_revision_id: "rev-1",
        expected_topology_content_hash: HASH,
        validation_result_id: "val-1",
      },
    });
  });

  it("blocks when not approved", () => {
    expect(resolveAuthoritativeInputs(doc({ approved_revision_id: null }), rev(), val())).toEqual({
      ok: false,
      code: "version_publish_topology_not_approved",
    });
  });

  it("blocks when the revision is not the approved head", () => {
    const r = resolveAuthoritativeInputs(doc({ approved_revision_id: "rev-2" }), rev({ id: "rev-1" }), val());
    expect(r.ok).toBe(false);
  });

  it("blocks stale validation (wrong revision or hash)", () => {
    expect(resolveAuthoritativeInputs(doc(), rev(), val({ revision_id: "other" }))).toEqual({
      ok: false,
      code: "version_publish_validation_stale",
    });
    expect(resolveAuthoritativeInputs(doc(), rev(), val({ content_hash: "sha256:" + "0".repeat(64) }))).toEqual({
      ok: false,
      code: "version_publish_topology_hash_mismatch",
    });
  });

  it("blocks a missing validation", () => {
    expect(resolveAuthoritativeInputs(doc(), rev(), null)).toEqual({
      ok: false,
      code: "version_publish_validation_missing",
    });
  });
});

// --- source/base/template policy (§6) ----------------------------------------------------------

describe("source/base/template policy", () => {
  it("classifies source-derived vs sourceless", () => {
    expect(sourcePolicy(doc()).kind).toBe("sourceless");
    expect(sourcePolicy(doc({ source_environment_version_id: "ver-1" })).kind).toBe("source-derived");
  });

  it("locks base + template to the exact source version", () => {
    const found = { template: tmpl(), version: ver({ id: "ver-1", template_id: "tmpl-1" }) };
    const r = resolveDestinationForSource("ver-1", found);
    expect(r).toMatchObject({
      destinationTemplateId: "tmpl-1",
      base_environment_version_id: "ver-1",
      locked: true,
      blocked: false,
    });
    expect(r.sourceVersion?.id).toBe("ver-1");
  });

  it("blocks when the exact source version is unresolvable (no latest inference)", () => {
    const r = resolveDestinationForSource("ver-1", null);
    expect(r.blocked).toBe(true);
    expect(r.destinationTemplateId).toBeNull();
  });

  it("finds a version by EXACT id only", () => {
    const set = [
      { template: tmpl({ id: "ta" }), versions: [ver({ id: "va" })] },
      { template: tmpl({ id: "tb" }), versions: [ver({ id: "vb" })] },
    ];
    expect(findVersionById("vb", set)?.template.id).toBe("tb");
    expect(findVersionById("missing", set)).toBeNull();
  });

  it("sourceless sends base=null and requires an explicit template choice", () => {
    expect(resolveDestinationSourceless(null)).toMatchObject({
      destinationTemplateId: null,
      base_environment_version_id: null,
      locked: false,
    });
    expect(resolveDestinationSourceless("tmpl-9").destinationTemplateId).toBe("tmpl-9");
    expect(resolveDestinationSourceless("tmpl-9").base_environment_version_id).toBeNull();
  });
});

// --- definition draft + inspection (§7/8) ------------------------------------------------------

describe("generateInitialDraft", () => {
  it("retargets a source draft to v1alpha2 and excludes topology/provenance without mutating source", () => {
    const source = ver({
      spec: {
        apiVersion: "controlplane.security/v1alpha2",
        kind: "Environment",
        metadata: { name: "x" },
        spec: { roles: [{ name: "r" }], topology: { nodes: [] }, publicationProvenance: { x: 1 } },
      },
    });
    const before = JSON.stringify(source.spec);
    const draft = generateInitialDraft(source);
    expect(draft.excludedServerSections).toBe(true);
    const parsed = yaml.load(draft.yaml) as Record<string, unknown>;
    expect(parsed.apiVersion).toBe(V1ALPHA2);
    const spec = parsed.spec as Record<string, unknown>;
    expect("topology" in spec).toBe(false);
    expect("publicationProvenance" in spec).toBe(false);
    expect(spec.roles).toEqual([{ name: "r" }]);
    // source object is never mutated
    expect(JSON.stringify(source.spec)).toBe(before);
  });

  it("uses a clear v1alpha2 starter for sourceless", () => {
    const draft = generateInitialDraft(null);
    expect(draft.excludedServerSections).toBe(false);
    const parsed = yaml.load(draft.yaml) as Record<string, unknown>;
    expect(parsed.apiVersion).toBe(V1ALPHA2);
    expect((parsed.spec as Record<string, unknown>).topology).toBeUndefined();
  });
});

describe("inspectDefinition", () => {
  const good = { apiVersion: V1ALPHA2, kind: "Environment", metadata: { name: "x" }, spec: { roles: [] } };
  it("accepts a clean v1alpha2 Environment", () => {
    expect(inspectDefinition(good)).toEqual({ ok: true, definition: good });
  });
  it("refuses a non-object", () => {
    expect(inspectDefinition("a string")).toEqual({ ok: false, code: "version_publish_definition_invalid" });
    expect(inspectDefinition([1, 2])).toEqual({ ok: false, code: "version_publish_definition_invalid" });
  });
  it("refuses a non-v1alpha2 apiVersion", () => {
    expect(inspectDefinition({ ...good, apiVersion: "controlplane.security/v1alpha1" }).ok).toBe(false);
  });
  it("refuses spec.topology WITHOUT stripping it (page keeps the text)", () => {
    expect(inspectDefinition({ ...good, spec: { topology: { nodes: [] } } })).toEqual({
      ok: false,
      code: "version_publish_topology_in_payload_forbidden",
    });
  });
  it("refuses spec.publicationProvenance", () => {
    expect(inspectDefinition({ ...good, spec: { publicationProvenance: {} } })).toEqual({
      ok: false,
      code: "version_publish_provenance_in_payload_forbidden",
    });
  });
});

describe("definitionReadiness", () => {
  const good = { apiVersion: V1ALPHA2, kind: "Environment", metadata: { name: "x" }, spec: { roles: [] } };
  it("is ready only when parsed, clean, and validated for the exact current text", () => {
    expect(definitionReadiness({ ok: true, parsed: good }, true, true).validatedCurrent).toBe(true);
  });
  it("is stale after an edit (validatedForCurrentText=false)", () => {
    expect(definitionReadiness({ ok: true, parsed: good }, false, true).validatedCurrent).toBe(false);
  });
  it("reports the forbidden code and is not ready when topology is present", () => {
    const r = definitionReadiness({ ok: true, parsed: { ...good, spec: { topology: {} } } }, true, true);
    expect(r.inspectionOk).toBe(false);
    expect(r.code).toBe("version_publish_topology_in_payload_forbidden");
  });
  it("is not ready when YAML does not parse", () => {
    expect(definitionReadiness({ ok: false, message: "bad" }, true, true).parseOk).toBe(false);
  });
});

// --- request payload + review (§10/9) ----------------------------------------------------------

describe("buildPublicationRequest", () => {
  it("contains only the seven allowlisted fields", () => {
    const req = buildPublicationRequest(
      {
        topology_document_id: "doc-1",
        topology_revision_id: "rev-1",
        expected_topology_content_hash: HASH,
        validation_result_id: "val-1",
      },
      { templateId: "tmpl-1", base: null },
      { apiVersion: V1ALPHA2 },
    );
    expect(Object.keys(req).sort()).toEqual(
      [
        "base_environment_version_id",
        "definition",
        "expected_topology_content_hash",
        "template_id",
        "topology_document_id",
        "topology_revision_id",
        "validation_result_id",
      ].sort(),
    );
    expect(req).not.toHaveProperty("idempotency_key");
    expect(req).not.toHaveProperty("publication_fingerprint");
    // no topology document content (the pin is a hash, not bytes) and no caller provenance
    expect(req).not.toHaveProperty("topology_document_content");
    expect(req).not.toHaveProperty("publicationProvenance");
  });

  it("carries a non-null base only when provided (source-derived)", () => {
    const pins = {
      topology_document_id: "doc-1",
      topology_revision_id: "rev-1",
      expected_topology_content_hash: HASH,
      validation_result_id: "val-1",
    };
    expect(buildPublicationRequest(pins, { templateId: "t", base: "ver-1" }, {}).base_environment_version_id).toBe("ver-1");
    expect(buildPublicationRequest(pins, { templateId: "t", base: null }, {}).base_environment_version_id).toBeNull();
  });
});

describe("buildReview", () => {
  it("exposes allowlisted values including role/network counts", () => {
    const r = buildReview({
      destinationTemplate: tmpl(),
      base: null,
      pins: {
        topology_document_id: "doc-1",
        topology_revision_id: "rev-1",
        expected_topology_content_hash: HASH,
        validation_result_id: "val-1",
      },
      validation: val(),
      definition: {
        apiVersion: V1ALPHA2,
        kind: "Environment",
        metadata: { name: "env", displayName: "Env" },
        spec: { roles: [{ name: "a" }, { name: "b" }], networks: [{ name: "n" }] },
      },
    });
    expect(r.baseVersionId).toBe("none");
    expect(r.roleCount).toBe(2);
    expect(r.networkCount).toBe(1);
    expect(r.validationResultHash).toBe(VHASH);
    expect(r.definitionApiVersion).toBe(V1ALPHA2);
  });
});

// --- result (§10) ------------------------------------------------------------------------------

describe("resultView", () => {
  const version = ver({ api_version: V1ALPHA2, version_number: 3 });
  it("uses new-creation language for 201", () => {
    const r = resultView({ version, created: true, status: 201 });
    expect(r.headline).toMatch(/new immutable/i);
    expect(r.note).not.toMatch(/already existed/i);
  });
  it("uses already-existed language for 200 and never claims creation", () => {
    const r = resultView({ version, created: false, status: 200 });
    expect(r.headline).toMatch(/already existed/i);
    expect(r.headline).not.toMatch(/new/i);
    expect(r.note).toMatch(/no new version/i);
  });
  it("reads provenance straight from the typed response", () => {
    const prov = {
      topology_document_id: "d",
      topology_revision_id: "r",
      topology_content_hash: HASH,
      topology_validation_result_id: "v",
      topology_validation_result_hash: VHASH,
      base_environment_version_id: null,
      publication_contract_version: "secp.publication/v1",
      publication_fingerprint: "sha256:" + "f".repeat(64),
    };
    const result: EnvironmentPublicationClientResult = {
      version: ver({ publication_provenance: prov }),
      created: true,
      status: 201,
    };
    expect(resultView(result).provenance).toEqual(prov);
  });
});

// --- library provenance (§12) ------------------------------------------------------------------

describe("libraryProvenanceView", () => {
  it("labels legacy v1alpha1 with no provenance", () => {
    const r = libraryProvenanceView(ver({ publication_provenance: null }));
    expect(r.kind).toBe("legacy");
    expect(r.provenance).toBeNull();
  });
  it("labels published v1alpha2 with typed provenance from the API", () => {
    const prov = {
      topology_document_id: "d",
      topology_revision_id: "r",
      topology_content_hash: HASH,
      topology_validation_result_id: "v",
      topology_validation_result_hash: VHASH,
      base_environment_version_id: null,
      publication_contract_version: "secp.publication/v1",
      publication_fingerprint: "sha256:" + "f".repeat(64),
    };
    const r = libraryProvenanceView(ver({ api_version: V1ALPHA2, publication_provenance: prov }));
    expect(r.kind).toBe("published");
    expect(r.provenance).toEqual(prov);
  });
});

describe("resolveLibrarySelection", () => {
  const templates = [tmpl({ id: "ta" }), tmpl({ id: "tb" })];
  it("accepts valid ids and ignores invalid ones safely", () => {
    const versions = [ver({ id: "va" })];
    expect(resolveLibrarySelection("ta", "va", templates, () => versions)).toEqual({
      templateId: "ta",
      versionId: "va",
    });
    expect(resolveLibrarySelection("bogus", "va", templates, () => versions)).toEqual({
      templateId: null,
      versionId: null,
    });
    expect(resolveLibrarySelection("ta", "bogus", templates, () => versions)).toEqual({
      templateId: "ta",
      versionId: null,
    });
  });
});

// --- misc --------------------------------------------------------------------------------------

describe("copy + permissions", () => {
  it("has a confirmation label that disclaims downstream effects", () => {
    expect(CONFIRM_LABEL).toMatch(/does not create an exercise/i);
  });
  it("resolves version:publish", () => {
    expect(hasPublishPermission(["version:publish"])).toBe(true);
    expect(hasPublishPermission(["version:create"])).toBe(false);
    expect(hasPublishPermission(null)).toBe(false);
  });
  it("covers every current backend publication code plus client codes", () => {
    const required = [
      "invalid_environment_publication_input",
      "version_publish_permission_denied",
      "version_publish_cross_org_forbidden",
      "version_publish_template_not_found",
      "version_publish_topology_not_found",
      "version_publish_topology_not_approved",
      "version_publish_topology_hash_mismatch",
      "version_publish_validation_missing",
      "version_publish_validation_not_passing",
      "version_publish_validation_stale",
      "version_publish_definition_invalid",
      "version_publish_topology_in_payload_forbidden",
      "version_publish_provenance_in_payload_forbidden",
      "version_publish_role_topology_mismatch",
      "version_publish_network_topology_mismatch",
      "version_publish_unsupported_role_kind",
      "version_publish_topology_invalid",
      "version_publish_provenance_invalid",
      "version_publish_base_version_required",
      "version_publish_base_version_not_found",
      "version_publish_base_version_mismatch",
      "version_publish_base_version_cross_org_forbidden",
      "version_publish_template_mismatch",
      "version_publish_conflict",
      "version_publish_audit_failure",
      "environment_publication_unexpected_status",
      "api_unreachable",
    ];
    for (const code of required) {
      expect(typeof PUBLICATION_ERROR_TEXT[code]).toBe("string");
    }
  });
});

describe("parseDefinitionYaml", () => {
  it("parses valid YAML and bounds error messages", () => {
    expect(parseDefinitionYaml("apiVersion: x").ok).toBe(true);
    const bad = parseDefinitionYaml("a: [unterminated");
    expect(bad.ok).toBe(false);
  });
});
