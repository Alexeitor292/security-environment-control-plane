import "./environments.css";

import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";

import { api } from "../api/client";
import type { Template, Version } from "../api/types";
import { BlueprintMeshBackground } from "../components/backgrounds";
import {
  CyberButton,
  CyberCard,
  CyberSelect,
  EmptyState,
  HashChip,
  KeyValueList,
  SafetyNotice,
  Skeleton,
  StepRail,
  useAction,
} from "../components/ui";
import { useAsync } from "../hooks";
import { onlyNotFoundAsNull } from "./environments-view";
import {
  CONFIRM_LABEL,
  DRAFT_EXCLUDED_NOTICE,
  PUBLICATION_ERROR_TEXT,
  PUBLICATION_INTRO,
  VALIDATION_IS_NOT_PUBLICATION_NOTE,
  buildPublicationRequest,
  buildReview,
  definitionReadiness,
  findVersionById,
  generateInitialDraft,
  hasPublishPermission,
  inspectDefinition,
  parseDefinitionYaml,
  resolveAuthoritativeInputs,
  resolveDestinationForSource,
  resolveDestinationSourceless,
  resultView,
  sourcePolicy,
  type DestinationResolution,
} from "./environment-publication";

function ProvenanceList({
  provenance,
}: {
  provenance: {
    topology_document_id: string;
    topology_revision_id: string;
    topology_content_hash: string;
    topology_validation_result_id: string;
    topology_validation_result_hash: string;
    base_environment_version_id: string | null;
    publication_contract_version: string;
    publication_fingerprint: string;
  };
}) {
  return (
    <KeyValueList
      items={[
        { key: "Topology document", value: <HashChip value={provenance.topology_document_id} digits={12} /> },
        { key: "Topology revision", value: <HashChip value={provenance.topology_revision_id} digits={12} /> },
        { key: "Topology content hash", value: <HashChip value={provenance.topology_content_hash} digits={14} /> },
        { key: "Validation result", value: <HashChip value={provenance.topology_validation_result_id} digits={12} /> },
        { key: "Validation result hash", value: <HashChip value={provenance.topology_validation_result_hash} digits={14} /> },
        {
          key: "Base version",
          value: provenance.base_environment_version_id ? (
            <HashChip value={provenance.base_environment_version_id} digits={12} />
          ) : (
            "none"
          ),
        },
        { key: "Publication contract", value: provenance.publication_contract_version, mono: true },
        { key: "Publication fingerprint", value: <HashChip value={provenance.publication_fingerprint} digits={14} /> },
      ]}
    />
  );
}

export function EnvironmentPublication() {
  const { documentId } = useParams<{ documentId: string }>();

  const me = useAsync(() => api.me(), []);
  const canPublishPerm = hasPublishPermission(me.data?.permissions);

  const doc = useAsync(
    () => (documentId ? api.getTopologyDocument(documentId) : Promise.resolve(null)),
    [documentId],
  );
  const document = doc.data ?? null;
  const approvedRevisionId = document?.approved_revision_id ?? null;

  // The EXACT approved revision + its validation — fetched from the server; never cached workspace.
  const revision = useAsync(
    () =>
      documentId && approvedRevisionId
        ? api.getTopologyRevision(documentId, approvedRevisionId)
        : Promise.resolve(null),
    [documentId, approvedRevisionId],
  );
  const validation = useAsync(
    () =>
      documentId && approvedRevisionId
        ? api.getTopologyValidation(documentId, approvedRevisionId).catch(onlyNotFoundAsNull)
        : Promise.resolve(null),
    [documentId, approvedRevisionId],
  );

  // Templates: the destination dropdown (sourceless) AND the destination-name lookup (source-derived).
  const templates = useAsync(() => api.listTemplates(), []);

  const sp = document ? sourcePolicy(document) : null;

  // Source-derived: resolve the EXACT source version by id (scan existing template/version reads).
  const sourceResolve = useAsync<DestinationResolution | null>(async () => {
    if (!sp || sp.kind !== "source-derived" || !sp.sourceVersionId) return null;
    const ts = await api.listTemplates();
    const withVersions = await Promise.all(
      ts.map(async (t) => ({ template: t, versions: await api.listVersions(t.id) })),
    );
    return resolveDestinationForSource(sp.sourceVersionId, findVersionById(sp.sourceVersionId, withVersions));
  }, [sp?.kind, sp?.sourceVersionId]);

  // --- editable state (no mutation on render) ---
  const [text, setText] = useState<string | null>(null); // null until the initial draft seeds
  const [chosenTemplateId, setChosenTemplateId] = useState<string | null>(null);
  const [validated, setValidated] = useState<{ forText: string; ok: boolean } | null>(null);
  const [confirmed, setConfirmed] = useState(false);

  const sourceVersion: Version | null = sourceResolve.data?.sourceVersion ?? null;
  const sourceReady = sp?.kind === "sourceless" || sourceResolve.data !== null;

  // Seed the initial draft exactly once, when the source (if any) is resolved.
  const seededRef = useRef(false);
  useEffect(() => {
    if (text !== null || !sp || !sourceReady) return;
    if (sp.kind === "source-derived" && sourceResolve.data?.blocked) return; // blocked → no draft
    seededRef.current = true;
    setText(generateInitialDraft(sp.kind === "source-derived" ? sourceVersion : null).yaml);
  }, [text, sp, sourceReady, sourceResolve.data, sourceVersion]);

  const draftExcluded =
    sp?.kind === "source-derived" && sourceVersion !== null
      ? generateInitialDraft(sourceVersion).excludedServerSections
      : false;

  const publishAction = useAction({ codeText: PUBLICATION_ERROR_TEXT });
  const validateAction = useAction({ codeText: PUBLICATION_ERROR_TEXT });
  const [result, setResult] = useState<ReturnType<typeof resultView> | null>(null);

  // Any input change clears the confirmation and validation freshness.
  function onTextChange(next: string) {
    setText(next);
    setConfirmed(false);
  }
  function onTemplateChange(next: string) {
    setChosenTemplateId(next || null);
    setConfirmed(false);
  }

  // --- derived model ---
  const parse = useMemo(() => (text === null ? { ok: false as const, message: "" } : parseDefinitionYaml(text)), [text]);
  const readiness = definitionReadiness(parse, validated?.forText === text, validated?.ok ?? false);

  const destination: DestinationResolution | null =
    sp === null
      ? null
      : sp.kind === "source-derived"
        ? (sourceResolve.data ?? null)
        : resolveDestinationSourceless(chosenTemplateId);

  const destTemplate: Template | null =
    destination?.destinationTemplateId != null
      ? (templates.data?.find((t) => t.id === destination.destinationTemplateId) ?? null)
      : null;

  const pins = document && revision.data ? resolveAuthoritativeInputs(document, revision.data, validation.data ?? null) : null;

  // Changing ANY publication input clears the confirmation — including the server-derived approved
  // revision / destination / base (e.g. the approved head changed after a reload). Text and template
  // changes also clear it in their handlers; this covers the derived inputs (§5/§9 fail-closed).
  const pinRevisionId = pins?.ok ? pins.pins.topology_revision_id : null;
  const destKey = `${destination?.destinationTemplateId ?? ""}:${destination?.base_environment_version_id ?? ""}`;
  useEffect(() => {
    setConfirmed(false);
  }, [pinRevisionId, destKey]);

  const inspection = parse.ok ? inspectDefinition(parse.parsed) : null;
  const definitionObject = inspection && inspection.ok ? inspection.definition : null;

  const review =
    pins?.ok && destTemplate && definitionObject && validation.data
      ? buildReview({
          destinationTemplate: destTemplate,
          base: destination?.base_environment_version_id ?? null,
          pins: pins.pins,
          validation: validation.data,
          definition: definitionObject,
        })
      : null;

  const publishReady = Boolean(
    pins?.ok &&
      destination &&
      !destination.blocked &&
      destination.destinationTemplateId &&
      destTemplate &&
      readiness.validatedCurrent &&
      definitionObject &&
      confirmed &&
      !publishAction.busy &&
      result === null,
  );

  const errorRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    if (publishAction.error) errorRef.current?.focus();
  }, [publishAction.error]);

  function runValidate() {
    if (!parse.ok || !inspection?.ok || text === null) return;
    const forText = text;
    void validateAction.run(async () => {
      const r = await api.validateDefinition(definitionObject);
      setValidated({ forText, ok: r.ok });
    });
  }

  function runPublish() {
    if (!publishReady || !pins?.ok || !destination?.destinationTemplateId || !definitionObject) return;
    const request = buildPublicationRequest(
      pins.pins,
      { templateId: destination.destinationTemplateId, base: destination.base_environment_version_id },
      definitionObject,
    );
    void publishAction.run(async () => {
      const res = await api.publishEnvironmentVersion(request);
      setResult(resultView(res));
    });
  }

  // --- render ---

  if (!documentId) {
    return (
      <div className="env">
        <div className="error-box" role="alert">
          No topology document specified.
        </div>
      </div>
    );
  }

  const steps = [
    { id: "topology", label: "Approved topology" },
    { id: "destination", label: "Destination & base" },
    { id: "definition", label: "Definition" },
    { id: "review", label: "Review & publish" },
    { id: "result", label: "Result" },
  ];
  const currentStepId = result ? "result" : review && confirmed ? "review" : readiness.validatedCurrent ? "review" : text !== null ? "definition" : "destination";
  const stepIndex = steps.findIndex((s) => s.id === currentStepId);

  return (
    <div className="env">
      <BlueprintMeshBackground intensity="subtle" className="env-bg" />
      <div className="env-head">
        <div>
          <h1>Publish environment version</h1>
          <p className="env-sub">{PUBLICATION_INTRO}</p>
        </div>
      </div>

      <StepRail
        items={steps.map((s, i) => ({
          id: s.id,
          label: s.label,
          state: i < stepIndex ? "complete" : i === stepIndex ? "current" : "blocked",
        }))}
      />

      {(doc.loading || revision.loading || validation.loading || !sp) && !document ? (
        <CyberCard>
          <Skeleton lines={6} />
        </CyberCard>
      ) : document === null ? (
        <div className="error-box" role="alert">
          The topology document was not found.
        </div>
      ) : sp === null ? (
        <CyberCard>
          <Skeleton lines={4} />
        </CyberCard>
      ) : (
        <>
          {/* Step 1 — approved topology + authoritative pins */}
          <CyberCard heading="Approved topology">
            {pins === null ? (
              <Skeleton lines={3} />
            ) : !pins.ok ? (
              <SafetyNotice role="alert" tone="warn">
                <p>{PUBLICATION_ERROR_TEXT[pins.code] ?? PUBLICATION_ERROR_TEXT.version_publish_topology_not_approved}</p>
                <div className="env-actions">
                  <CyberButton
                    variant="secondary"
                    size="sm"
                    onClick={() => {
                      void doc.reload();
                      void revision.reload();
                      void validation.reload();
                    }}
                  >
                    Reload
                  </CyberButton>
                </div>
              </SafetyNotice>
            ) : (
              <KeyValueList
                items={[
                  { key: "Topology document", value: <HashChip value={pins.pins.topology_document_id} digits={12} /> },
                  { key: "Approved revision", value: <HashChip value={pins.pins.topology_revision_id} digits={12} /> },
                  { key: "Topology content hash", value: <HashChip value={pins.pins.expected_topology_content_hash} digits={14} /> },
                  { key: "Validation result", value: <HashChip value={pins.pins.validation_result_id} digits={12} /> },
                  { key: "Validation status", value: validation.data?.status ?? "—" },
                ]}
              />
            )}
          </CyberCard>

          {/* Step 2 — destination & base */}
          <CyberCard surface="well" heading="Destination template & base version">
            {sp.kind === "source-derived" ? (
              sourceResolve.loading ? (
                <Skeleton lines={2} />
              ) : sourceResolve.data?.blocked ? (
                <SafetyNotice role="alert" tone="warn">
                  The exact source environment version for this topology could not be resolved.
                  Publication is blocked — the base and destination template are derived from that
                  exact version and are never inferred.
                </SafetyNotice>
              ) : (
                <>
                  <p className="env-note">
                    This topology was derived from a source version. Its base version and destination
                    template are fixed (server-derived) and cannot be changed here.
                  </p>
                  <KeyValueList
                    items={[
                      { key: "Destination template", value: destTemplate ? destTemplate.display_name || destTemplate.name : "—" },
                      { key: "Template id", value: <HashChip value={destination?.destinationTemplateId ?? ""} digits={12} /> },
                      {
                        key: "Base version (locked)",
                        value: <HashChip value={destination?.base_environment_version_id ?? ""} digits={12} />,
                      },
                    ]}
                  />
                </>
              )
            ) : (
              <>
                <p className="env-note">
                  This topology has no source version, so no base is sent. Choose the destination
                  template explicitly.
                </p>
                {templates.loading && !templates.data ? (
                  <Skeleton lines={2} />
                ) : (templates.data?.length ?? 0) === 0 ? (
                  <EmptyState title="No templates">Create a template before publishing.</EmptyState>
                ) : (
                  <CyberSelect
                    label="Destination template"
                    value={chosenTemplateId ?? ""}
                    onChange={(e) => onTemplateChange(e.target.value)}
                    options={[
                      { value: "", label: "— choose a template —" },
                      ...(templates.data ?? []).map((t) => ({ value: t.id, label: t.display_name || t.name })),
                    ]}
                  />
                )}
                <p className="env-note">Base version: none (sourceless publication).</p>
              </>
            )}
          </CyberCard>

          {/* Step 3 — definition */}
          <CyberCard heading="Non-topology v1alpha2 definition (YAML)">
            {draftExcluded && (
              <SafetyNotice role="note" tone="info">
                {DRAFT_EXCLUDED_NOTICE}
              </SafetyNotice>
            )}
            {text === null ? (
              <Skeleton lines={6} />
            ) : (
              <>
                <textarea
                  value={text}
                  onChange={(e) => onTextChange(e.target.value)}
                  aria-label="Environment definition YAML (v1alpha2, non-topology)"
                  spellCheck={false}
                />
                {!parse.ok && parse.message && (
                  <div className="error-box" role="alert" style={{ marginTop: 8 }}>
                    YAML parse error: <code className="mono">{parse.message}</code>
                  </div>
                )}
                {parse.ok && readiness.code && (
                  <div className="error-box" role="alert" style={{ marginTop: 8 }}>
                    {PUBLICATION_ERROR_TEXT[readiness.code]} <code className="mono">{readiness.code}</code>
                  </div>
                )}
                <p className="env-note">
                  {validated === null
                    ? "Not validated yet."
                    : readiness.validatedCurrent
                      ? "Validated against exactly this content."
                      : "Changed since validation — re-run before publishing."}
                </p>
                {validateAction.error && (
                  <div className="error-box" role="alert">
                    {validateAction.error.text} <code className="mono">{validateAction.error.code}</code>
                  </div>
                )}
                <div className="env-actions">
                  <CyberButton
                    variant="secondary"
                    disabled={!parse.ok || !readiness.inspectionOk || validateAction.busy}
                    title={
                      !parse.ok
                        ? "Fix the YAML first."
                        : !readiness.inspectionOk
                          ? "Resolve the forbidden/invalid definition first."
                          : VALIDATION_IS_NOT_PUBLICATION_NOTE
                    }
                    onClick={runValidate}
                  >
                    {validateAction.busy ? "Validating…" : "Validate definition"}
                  </CyberButton>
                </div>
                <p className="env-note">{VALIDATION_IS_NOT_PUBLICATION_NOTE}</p>
              </>
            )}
          </CyberCard>

          {/* Step 4 — review & publish */}
          <CyberCard surface="well" heading="Review & publish">
            {!canPublishPerm && (
              <SafetyNotice role="status" tone="warn">
                You do not have the version:publish permission. You can review, but publication is
                disabled. The backend is the authoritative permission boundary.
              </SafetyNotice>
            )}
            {review ? (
              <>
                <KeyValueList
                  items={[
                    { key: "Destination template", value: review.destinationTemplateName },
                    { key: "Template id", value: <HashChip value={review.destinationTemplateId} digits={12} /> },
                    {
                      key: "Base version",
                      value: review.baseVersionId === "none" ? "none" : <HashChip value={review.baseVersionId} digits={12} />,
                    },
                    { key: "Topology document", value: <HashChip value={review.topologyDocumentId} digits={12} /> },
                    { key: "Approved revision", value: <HashChip value={review.approvedRevisionId} digits={12} /> },
                    { key: "Topology content hash", value: <HashChip value={review.topologyContentHash} digits={14} /> },
                    { key: "Validation result", value: <HashChip value={review.validationResultId} digits={12} /> },
                    { key: "Validation result hash", value: <HashChip value={review.validationResultHash} digits={14} /> },
                    { key: "Validation status", value: review.validationStatus },
                    { key: "Definition API version", value: review.definitionApiVersion, mono: true },
                    { key: "Definition name", value: review.definitionName || "—" },
                    { key: "Roles", value: String(review.roleCount) },
                    { key: "Networks", value: String(review.networkCount) },
                  ]}
                />
                <label className="env-confirm">
                  <input
                    type="checkbox"
                    checked={confirmed}
                    disabled={!canPublishPerm || publishAction.busy || result !== null}
                    onChange={(e) => setConfirmed(e.target.checked)}
                  />
                  <span>{CONFIRM_LABEL}</span>
                </label>
                {publishAction.error && (
                  <div className="error-box" role="alert" tabIndex={-1} ref={errorRef}>
                    {publishAction.error.text} <code className="mono">{publishAction.error.code}</code>
                  </div>
                )}
                <div className="env-actions" style={{ marginTop: 10 }}>
                  <CyberButton
                    disabled={!publishReady}
                    title={
                      publishReady
                        ? "Publishes one immutable environment version. Nothing is deployed."
                        : !canPublishPerm
                          ? "Requires version:publish."
                          : !confirmed
                            ? "Confirm the acknowledgement to enable publishing."
                            : !readiness.validatedCurrent
                              ? "Validate the current definition first."
                              : "Resolve the inputs above first."
                    }
                    onClick={runPublish}
                  >
                    {publishAction.busy ? "Publishing…" : "Publish version"}
                  </CyberButton>
                </div>
              </>
            ) : (
              <EmptyState title="Not ready to review">
                Resolve the approved topology, destination, and a validated v1alpha2 definition to
                review the exact publication inputs.
              </EmptyState>
            )}
          </CyberCard>

          {/* Step 5 — result */}
          <div aria-live="polite">
            {result && (
              <CyberCard heading={result.headline}>
                <SafetyNotice role="status" tone="info">
                  {result.note}
                </SafetyNotice>
                <KeyValueList
                  items={[
                    { key: "Result", value: result.created ? "Created (HTTP 201)" : "Idempotent replay (HTTP 200)" },
                    { key: "Version number", value: String(result.versionNumber) },
                    { key: "Version id", value: <HashChip value={result.versionId} digits={12} /> },
                    { key: "API version", value: result.apiVersion, mono: true },
                    { key: "Environment content hash", value: <HashChip value={result.contentHash} digits={14} /> },
                  ]}
                />
                {result.provenance && <ProvenanceList provenance={result.provenance} />}
                <p className="env-links">
                  <Link to={`/templates?template=${review?.destinationTemplateId ?? ""}&version=${result.versionId}`}>
                    Open Environment Library →
                  </Link>
                  {document.exercise_id && (
                    <Link to={`/exercises/${document.exercise_id}/topology?doc=${documentId}`}>
                      Back to topology workspace →
                    </Link>
                  )}
                </p>
              </CyberCard>
            )}
          </div>
        </>
      )}
    </div>
  );
}
