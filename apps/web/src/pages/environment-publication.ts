import yaml from "js-yaml";

import type {
  EnvironmentPublicationClientResult,
  EnvironmentPublicationRequest,
  Template,
  TopologyDocumentDetail,
  TopologyRevisionDetail,
  TopologyValidationResult,
  Version,
  VersionPublicationProvenance,
} from "../api/types";
import { definitionSummary } from "./environments-view";
import type { ControlEligibility } from "./topology-persistence";

// Pure view-model for the EnvironmentVersion publication workflow (ADR-016 PR D).
//
// The backend publication service (SECP-B10 / PR C) is the ONLY authoritative permission and
// precondition boundary. Everything here is usability/truthfulness gating: it never guesses a
// destination/base, never infers "latest", never trusts cached workspace state or URL params for
// immutable pins, never silently strips user-entered forbidden content, and never claims a 200
// idempotent replay created a new version. Publication creates one immutable version and nothing
// else — no exercise, plan, workflow, or infrastructure action.

export const V1ALPHA2 = "controlplane.security/v1alpha2";

// ------------------------------------------------------------------ copy

export const PUBLICATION_INTRO =
  "Publish an approved topology revision + its passing validation + a non-topology v1alpha2 definition into one new immutable EnvironmentVersion. Nothing else happens: no exercise, plan, workflow, or infrastructure action.";

export const CONFIRM_LABEL =
  "I understand publication creates an immutable environment version only. It does not create an exercise, generate a plan, approve deployment, or contact infrastructure.";

export const VALIDATION_IS_NOT_PUBLICATION_NOTE =
  "Definition validation is not topology approval, not publication, not plan approval, and not deployment. The publication service performs the authoritative topology consistency checks.";

export const DRAFT_EXCLUDED_NOTICE =
  "Server-owned publication sections (spec.topology and spec.publicationProvenance) were excluded from this editable draft. The server reconstructs them from the approved topology at publish time.";

export const CREATED_HEADLINE = "New immutable environment version published";
export const REPLAY_HEADLINE = "Exact publication already existed";
export const CREATED_NOTE =
  "A new immutable EnvironmentVersion was created and audited. Nothing was deployed: no exercise, plan, workflow, or infrastructure action occurred.";
export const REPLAY_NOTE =
  "This exact publication already existed — no new version and no mutation audit were created. Nothing was deployed.";

export const PUBLISH_ENTRY_NOTE =
  "Publishing is a separate, explicit step. It creates one immutable environment version from this approved topology — it does not deploy, generate a plan, or create an exercise. Approval never publishes automatically.";

export const RELOAD_REQUIRED_NOTE =
  "The approved topology head changed while this page was open. Publication was blocked. Reload to resolve the exact current inputs — cached state is never trusted.";

// ------------------------------------------------------------ closed codes (§11)

/** Allowlisted publication error copy. Backend free-form messages are never rendered; only these
 *  fixed strings, keyed by the closed code, plus a generic fallback for unknown codes. */
export const PUBLICATION_ERROR_TEXT: Record<string, string> = {
  invalid_environment_publication_input:
    "The publication request was malformed and was rejected before it reached the service. Fix the highlighted inputs.",
  version_publish_permission_denied:
    "You do not have permission to publish environment versions (version:publish is required).",
  version_publish_cross_org_forbidden:
    "A referenced record belongs to another organization.",
  version_publish_template_not_found: "The destination template was not found.",
  version_publish_topology_not_found: "The topology document or revision was not found.",
  version_publish_topology_not_approved:
    "The topology revision is not the current approved head. Approve a current revision before publishing.",
  version_publish_topology_hash_mismatch:
    "The topology content hash no longer matches the approved revision. Reload and try again.",
  version_publish_validation_missing:
    "The required validation result for this revision was not found.",
  version_publish_validation_not_passing:
    "The topology validation is not passing (valid / valid-with-warnings with zero errors is required).",
  version_publish_validation_stale:
    "The validation no longer matches the approved revision. Re-validate the current revision.",
  version_publish_definition_invalid:
    "The definition is not a valid controlplane.security/v1alpha2 Environment definition.",
  version_publish_topology_in_payload_forbidden:
    "The definition must not contain spec.topology — the server owns the topology.",
  version_publish_provenance_in_payload_forbidden:
    "The definition must not contain spec.publicationProvenance — the server owns provenance.",
  version_publish_role_topology_mismatch:
    "The definition roles do not match the approved topology exactly.",
  version_publish_network_topology_mismatch:
    "The definition networks do not match the approved topology exactly.",
  version_publish_unsupported_role_kind:
    "The definition uses a role kind that is not supported for publication.",
  version_publish_topology_invalid:
    "The approved topology could not be validated for publication.",
  version_publish_provenance_invalid: "The server-derived provenance was rejected.",
  version_publish_base_version_required:
    "This topology was derived from a source version, so its exact base version is required.",
  version_publish_base_version_not_found: "The required base version was not found.",
  version_publish_base_version_mismatch:
    "The base version does not match the topology's source version.",
  version_publish_base_version_cross_org_forbidden:
    "The base version belongs to another organization.",
  version_publish_template_mismatch:
    "The destination template must be the base version's template.",
  version_publish_conflict:
    "A different version already occupies this publication slot. Reload and review.",
  version_publish_audit_failure:
    "The publication audit could not be recorded, so no version was created. Try again.",
  environment_publication_unexpected_status:
    "The publication API returned an unexpected status. No assumptions were made about the result.",
  api_unreachable: "Cannot reach the control-plane API. Check that the backend is running.",
};

// ------------------------------------------------------------ permissions

export function hasPublishPermission(
  permissions: readonly string[] | null | undefined,
): boolean {
  return Boolean(permissions?.includes("version:publish"));
}

// ------------------------------------------------- contextual entry point (§4)

const okEligible: ControlEligibility = { eligible: true };
const noEligible = (reason: string): ControlEligibility => ({ eligible: false, reason });

const PASSING = new Set(["valid", "valid_with_warnings"]);

export interface PublishOfferInputs {
  document: TopologyDocumentDetail | null;
  /** Latest validation result for the CURRENT (approved) revision, from the server read model. */
  validation: TopologyValidationResult | null;
  hasPublishPermission: boolean;
  dirty: boolean;
  viewingHistorical: boolean;
  busy: boolean;
}

/**
 * Whether the contextual "Publish version" action may be offered from the topology workspace.
 * Every condition is UI usability only — the backend re-checks all of them. A false result carries
 * a truthful reason. The action itself only ever navigates (never publishes).
 */
export function canOfferPublish(inp: PublishOfferInputs): ControlEligibility {
  if (!inp.hasPublishPermission) return noEligible("Requires the version:publish permission.");
  if (inp.busy) return noEligible("Another action is in progress.");
  if (inp.viewingHistorical)
    return noEligible("Historical revisions cannot be published. Load the current revision.");
  if (inp.dirty)
    return noEligible("Resolve unsaved local changes before publishing (save or discard).");
  const doc = inp.document;
  if (!doc) return noEligible("No topology document.");
  if (!doc.approved_revision_id)
    return noEligible("An approved topology revision is required before publishing.");
  if (doc.current_revision_id !== doc.approved_revision_id)
    return noEligible("Only the current approved revision can be published.");
  const rev = doc.current_revision;
  if (!rev || rev.status !== "approved")
    return noEligible("The current revision is not approved.");
  const val = inp.validation;
  if (!val || val.revision_id !== rev.id || val.content_hash !== rev.content_hash)
    return noEligible("A current passing validation for the approved revision is required.");
  if (!PASSING.has(val.status) || val.error_count !== 0)
    return noEligible("Passing validation (no errors) is required before publishing.");
  return okEligible;
}

// ------------------------------------------- authoritative input resolution (§5)

export interface PublicationPins {
  topology_document_id: string;
  topology_revision_id: string;
  expected_topology_content_hash: string;
  validation_result_id: string;
}

export type ResolveInputs =
  | { ok: true; pins: PublicationPins }
  | { ok: false; code: string };

/**
 * Resolve the immutable publication pins from ONLY server-returned values (never cached workspace
 * state or URL params). If the approved head/validation no longer line up, fail closed with a
 * closed code so the page can require a reload.
 */
export function resolveAuthoritativeInputs(
  document: TopologyDocumentDetail,
  revision: TopologyRevisionDetail,
  validation: TopologyValidationResult | null,
): ResolveInputs {
  if (!document.approved_revision_id)
    return { ok: false, code: "version_publish_topology_not_approved" };
  if (revision.id !== document.approved_revision_id)
    return { ok: false, code: "version_publish_topology_not_approved" };
  if (revision.status !== "approved")
    return { ok: false, code: "version_publish_topology_not_approved" };
  if (validation === null) return { ok: false, code: "version_publish_validation_missing" };
  if (validation.revision_id !== revision.id)
    return { ok: false, code: "version_publish_validation_stale" };
  if (validation.content_hash !== revision.content_hash)
    return { ok: false, code: "version_publish_topology_hash_mismatch" };
  if (!PASSING.has(validation.status) || validation.error_count !== 0)
    return { ok: false, code: "version_publish_validation_not_passing" };
  return {
    ok: true,
    pins: {
      topology_document_id: document.id,
      topology_revision_id: revision.id,
      expected_topology_content_hash: revision.content_hash,
      validation_result_id: validation.id,
    },
  };
}

// --------------------------------------------------- source/base/template (§6)

export type SourceKind = "source-derived" | "sourceless";

export interface SourcePolicy {
  kind: SourceKind;
  sourceVersionId: string | null;
}

export function sourcePolicy(document: TopologyDocumentDetail): SourcePolicy {
  const src = document.source_environment_version_id;
  return src
    ? { kind: "source-derived", sourceVersionId: src }
    : { kind: "sourceless", sourceVersionId: null };
}

export interface DestinationResolution {
  /** Locked (source-derived) or user-chosen (sourceless); null when unresolved. */
  destinationTemplateId: string | null;
  base_environment_version_id: string | null;
  /** The exact source version (source-derived only) for prefill; never mutated. */
  sourceVersion: Version | null;
  locked: boolean;
  /** True when the exact source version could not be resolved — publication is blocked. */
  blocked: boolean;
}

/** Find the EXACT version by id across pre-fetched (template, versions) pairs — never a nearby or
 *  first match. Returns null when the exact id is absent. */
export function findVersionById(
  versionId: string,
  templates: readonly { template: Template; versions: readonly Version[] }[],
): { template: Template; version: Version } | null {
  for (const { template, versions } of templates) {
    const match = versions.find((v) => v.id === versionId);
    if (match) return { template, version: match };
  }
  return null;
}

/** Source-derived destination: base + template are server-derived and locked to the exact source
 *  version. Blocked if the exact source version cannot be resolved. */
export function resolveDestinationForSource(
  sourceVersionId: string,
  found: { template: Template; version: Version } | null,
): DestinationResolution {
  if (found === null || found.version.id !== sourceVersionId) {
    return {
      destinationTemplateId: null,
      base_environment_version_id: sourceVersionId,
      sourceVersion: null,
      locked: true,
      blocked: true,
    };
  }
  return {
    destinationTemplateId: found.template.id,
    base_environment_version_id: sourceVersionId,
    sourceVersion: found.version,
    locked: true,
    blocked: false,
  };
}

/** Sourceless destination: base is always null; the user must explicitly choose a template. */
export function resolveDestinationSourceless(
  chosenTemplateId: string | null,
): DestinationResolution {
  return {
    destinationTemplateId: chosenTemplateId,
    base_environment_version_id: null,
    sourceVersion: null,
    locked: false,
    blocked: false,
  };
}

// --------------------------------------------- definition draft + inspection (§7/8)

export const SOURCELESS_STARTER = `apiVersion: controlplane.security/v1alpha2
kind: Environment
metadata:
  name: published-environment
  displayName: Published Environment
spec:
  teams:
    count: 1
    isolationPolicy: strict
  networks:
    - name: team-network
      cidrStrategy: per-team
      baseCidr: 10.20.0.0/16
      isolated: true
  roles:
    - name: attacker
      kind: attacker
      image: kali-linux
      network: team-network
    - name: web-server
      kind: target
      image: ubuntu-server-22.04
      network: team-network
  requiredPlugins: [simulator]
`;

export interface InitialDraft {
  yaml: string;
  /** True when server-owned sections were removed from the generated draft (disclosed to the user). */
  excludedServerSections: boolean;
}

/**
 * Build the initial editable draft. For a source-derived document, deep-clone the source spec
 * (NEVER mutate the source Version), retarget apiVersion to v1alpha2, and remove spec.topology /
 * spec.publicationProvenance from the GENERATED DRAFT only (disclosed). Sourceless uses a clear
 * v1alpha2 starter.
 */
export function generateInitialDraft(sourceVersion: Version | null): InitialDraft {
  if (sourceVersion === null) {
    return { yaml: SOURCELESS_STARTER, excludedServerSections: false };
  }
  // Deep clone so the source Version object is never mutated (its spec is JSON-safe).
  const clone = JSON.parse(JSON.stringify(sourceVersion.spec)) as Record<string, unknown>;
  clone.apiVersion = V1ALPHA2;
  let excluded = false;
  const spec = clone.spec;
  if (spec !== null && typeof spec === "object" && !Array.isArray(spec)) {
    const s = spec as Record<string, unknown>;
    if ("topology" in s) {
      delete s.topology;
      excluded = true;
    }
    if ("publicationProvenance" in s) {
      delete s.publicationProvenance;
      excluded = true;
    }
  }
  return { yaml: yaml.dump(clone), excludedServerSections: excluded };
}

export type ParseResult =
  | { ok: true; parsed: unknown }
  | { ok: false; message: string };

/** Parse editor YAML with a bounded error message (never rendered as raw HTML). */
export function parseDefinitionYaml(text: string): ParseResult {
  try {
    return { ok: true, parsed: yaml.load(text) };
  } catch (e) {
    return { ok: false, message: e instanceof Error ? e.message.slice(0, 300) : "YAML parse error" };
  }
}

export type DefinitionInspection =
  | { ok: true; definition: Record<string, unknown> }
  | { ok: false; code: string };

/**
 * Local (client-side) refusal of a non-object / non-v1alpha2 definition and of caller-supplied
 * server-owned sections. It NEVER strips content — it refuses and returns a closed code so the page
 * can preserve the user's text for correction. The backend remains authoritative.
 */
export function inspectDefinition(parsed: unknown): DefinitionInspection {
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { ok: false, code: "version_publish_definition_invalid" };
  }
  const root = parsed as Record<string, unknown>;
  if (root.apiVersion !== V1ALPHA2) return { ok: false, code: "version_publish_definition_invalid" };
  if (root.kind !== "Environment") return { ok: false, code: "version_publish_definition_invalid" };
  const spec = root.spec;
  if (spec !== null && typeof spec === "object" && !Array.isArray(spec)) {
    const s = spec as Record<string, unknown>;
    if ("topology" in s) return { ok: false, code: "version_publish_topology_in_payload_forbidden" };
    if ("publicationProvenance" in s)
      return { ok: false, code: "version_publish_provenance_in_payload_forbidden" };
  }
  return { ok: true, definition: root };
}

export interface DefinitionReadiness {
  parseOk: boolean;
  inspectionOk: boolean;
  /** The exact current text was validated by the server (POST /definitions/validate ok=true). */
  validatedCurrent: boolean;
  code: string | null;
}

/**
 * Whether the edited definition is eligible for the review/publish step: it parses, is a v1alpha2
 * Environment with no forbidden server-owned keys, and the LATEST schema validation returned ok
 * for EXACTLY the current text. Any edit after validation makes it stale (validatedCurrent=false).
 */
export function definitionReadiness(
  parse: ParseResult,
  validatedForCurrentText: boolean,
  validationOk: boolean,
): DefinitionReadiness {
  if (!parse.ok) {
    return { parseOk: false, inspectionOk: false, validatedCurrent: false, code: null };
  }
  const inspection = inspectDefinition(parse.parsed);
  if (!inspection.ok) {
    return { parseOk: true, inspectionOk: false, validatedCurrent: false, code: inspection.code };
  }
  return {
    parseOk: true,
    inspectionOk: true,
    validatedCurrent: validatedForCurrentText && validationOk,
    code: null,
  };
}

// ------------------------------------------------- review + request builder (§9/10)

export interface PublicationReview {
  destinationTemplateName: string;
  destinationTemplateId: string;
  baseVersionId: string;
  topologyDocumentId: string;
  approvedRevisionId: string;
  topologyContentHash: string;
  validationResultId: string;
  validationResultHash: string;
  validationStatus: string;
  definitionApiVersion: string;
  definitionName: string;
  roleCount: number;
  networkCount: number;
}

/** Allowlisted review values — safe ids/hashes/counts only; never raw topology JSON or secrets. */
export function buildReview(args: {
  destinationTemplate: Template;
  base: string | null;
  pins: PublicationPins;
  validation: TopologyValidationResult;
  definition: Record<string, unknown>;
}): PublicationReview {
  const summary = definitionSummary(args.definition);
  return {
    destinationTemplateName: args.destinationTemplate.display_name || args.destinationTemplate.name,
    destinationTemplateId: args.destinationTemplate.id,
    baseVersionId: args.base ?? "none",
    topologyDocumentId: args.pins.topology_document_id,
    approvedRevisionId: args.pins.topology_revision_id,
    topologyContentHash: args.pins.expected_topology_content_hash,
    validationResultId: args.pins.validation_result_id,
    validationResultHash: args.validation.result_hash,
    validationStatus: args.validation.status,
    definitionApiVersion: summary?.apiVersion || "",
    definitionName: summary?.displayName || summary?.name || "",
    roleCount: summary?.roles.length ?? 0,
    networkCount: summary?.networks.length ?? 0,
  };
}

/** The EXACT publication request body — the only seven allowlisted fields, in server-owned form. */
export function buildPublicationRequest(
  pins: PublicationPins,
  destination: { templateId: string; base: string | null },
  definition: Record<string, unknown>,
): EnvironmentPublicationRequest {
  return {
    template_id: destination.templateId,
    definition,
    topology_document_id: pins.topology_document_id,
    topology_revision_id: pins.topology_revision_id,
    expected_topology_content_hash: pins.expected_topology_content_hash,
    validation_result_id: pins.validation_result_id,
    base_environment_version_id: destination.base,
  };
}

// --------------------------------------------------------------- result (§10)

export interface PublicationResultView {
  created: boolean;
  headline: string;
  note: string;
  provenance: VersionPublicationProvenance | null;
  versionNumber: number;
  versionId: string;
  contentHash: string;
  apiVersion: string;
}

export function resultView(result: EnvironmentPublicationClientResult): PublicationResultView {
  const v = result.version;
  return {
    created: result.created,
    headline: result.created ? CREATED_HEADLINE : REPLAY_HEADLINE,
    note: result.created ? CREATED_NOTE : REPLAY_NOTE,
    provenance: v.publication_provenance,
    versionNumber: v.version_number,
    versionId: v.id,
    contentHash: v.content_hash,
    apiVersion: v.api_version,
  };
}

// -------------------------------------------------- library provenance (§12)

export type VersionProvenanceKind = "legacy" | "published";

export interface LibraryProvenanceView {
  kind: VersionProvenanceKind;
  label: string;
  note: string;
  provenance: VersionPublicationProvenance | null;
}

/** Library display posture for an immutable version, driven ONLY by the typed
 *  Version.publication_provenance from the API — never derived from spec. */
export function libraryProvenanceView(version: Version): LibraryProvenanceView {
  if (version.publication_provenance) {
    return {
      kind: "published",
      label: "Published from approved topology",
      note: "This immutable version was published from an approved topology revision. The provenance below is server-owned.",
      provenance: version.publication_provenance,
    };
  }
  return {
    kind: "legacy",
    label: "Legacy/manual immutable version",
    note: "Created directly from a definition (not published from topology). No publication provenance exists.",
    provenance: null,
  };
}

/** Validate deterministic ?template=&version= link params against the actually-returned data;
 *  invalid values are ignored safely (never a mutation). */
export function resolveLibrarySelection(
  templateParam: string | null,
  versionParam: string | null,
  templates: readonly Template[],
  versionsByTemplate: (id: string) => readonly Version[] | null,
): { templateId: string | null; versionId: string | null } {
  const templateId = templateParam && templates.some((t) => t.id === templateParam) ? templateParam : null;
  if (templateId === null) return { templateId: null, versionId: null };
  const versions = versionsByTemplate(templateId);
  const versionId =
    versionParam && versions && versions.some((v) => v.id === versionParam) ? versionParam : null;
  return { templateId, versionId };
}
