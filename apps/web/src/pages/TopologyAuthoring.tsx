import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";

import { ApiClientError, api } from "../api/client";
import type {
  TeamTopology,
  TopologyRevisionDetail,
} from "../api/types";
import {
  draftFromCanonicalDocument,
  draftToCanonicalDocument,
} from "../api/topology-authoring-adapter";
import { CyberButton, CyberCard, EmptyState, Skeleton, useAction } from "../components/ui";
import { useAsync } from "../hooks";
import { TopologyPersistencePanel } from "./TopologyPersistencePanel";
import { TopologyWorkspace, type WorkspacePersistence } from "./TopologyWorkspace";
import { draftFromTopology, type Draft } from "./topology-workspace";
import {
  CREATE_DRAFT_NOTE,
  TOPOLOGY_ERROR_TEXT,
  canDecide,
  canSaveRevision,
  canSubmitRevision,
  canValidateRevision,
  derivePosture,
  postureAllowsEditing,
  resolveTopologyPermissions,
  revisionContentIsRenderable,
  validationView,
} from "./topology-persistence";

/** Only a not_found means "no such document"; any other error is unavailable. */
function isNotFound(e: unknown): boolean {
  return e instanceof ApiClientError && (e.status === 404 || e.code === "not_found");
}

/**
 * Durable topology authoring controller for one exercise team instance. Resolves
 * the authoring document from the ?doc=<id> query param (server-owned id; no
 * document is created merely by viewing), loads the authoritative revision +
 * history + validation, and wires the workspace + persistence panel with
 * concurrency-safe save/validate/submit/decide callbacks. Local edits are never
 * merged or overwritten; every mutation is hash-pinned.
 */
export function TopologyAuthoring({ topo }: { topo: TeamTopology }) {
  const [params, setParams] = useSearchParams();
  const documentId = params.get("doc");

  const me = useAsync(() => api.me(), []);
  const permissions = resolveTopologyPermissions(me.data?.permissions);

  // Authoritative document (reloaded after every mutation).
  const doc = useAsync(
    () => (documentId ? api.getTopologyDocument(documentId) : Promise.resolve(null)),
    [documentId],
  );
  const revisions = useAsync(
    () => (documentId ? api.listTopologyRevisions(documentId) : Promise.resolve(null)),
    [documentId],
  );

  // The revision the workspace is currently baselined from (updated only on an
  // explicit load or a successful save — NOT on a failed/stale save).
  const [baseRevision, setBaseRevision] = useState<TopologyRevisionDetail | null>(null);
  const [viewingRevisionId, setViewingRevisionId] = useState<string | null>(null);
  const [dirty, setDirty] = useState(false);
  const draftRef = useRef<Draft | null>(null);

  const createAction = useAction({ codeText: TOPOLOGY_ERROR_TEXT });
  const action = useAction({ codeText: TOPOLOGY_ERROR_TEXT });

  const document = doc.data ?? null;
  const loadFailed = doc.error !== null && doc.error !== undefined && !isNotFound(doc.error);

  // Switching to a DIFFERENT document (e.g. via back/forward or a new ?doc)
  // clears the identity-derived state so the previous document's revision can
  // never leak into the new one; the seed effect below re-seeds.
  useEffect(() => {
    setBaseRevision(null);
    setViewingRevisionId(null);
    setDirty(false);
  }, [documentId]);

  // Seed the workspace baseline from the current authoritative revision once the
  // document has loaded (baseRevision stays null until then).
  const currentRev = document?.current_revision ?? null;
  useEffect(() => {
    if (currentRev && baseRevision === null) {
      setBaseRevision(currentRev);
      setViewingRevisionId(currentRev.id);
    }
  }, [currentRev, baseRevision]);

  const viewingHistorical =
    baseRevision !== null &&
    document !== null &&
    baseRevision.id !== document.current_revision_id;

  // Validation for the revision the workspace is baselined on.
  const validation = useAsync(
    () =>
      documentId && baseRevision
        ? api.getTopologyValidation(documentId, baseRevision.id)
        : Promise.resolve(null),
    [documentId, baseRevision?.id],
  );

  const baseRevisionNumber = baseRevision?.revision_number ?? null;
  const baseHash = baseRevision?.content_hash ?? null;

  const posture = derivePosture({
    enabled: true,
    documentId,
    loadFailed,
    document,
    baseRevisionNumber,
    dirty,
    permissions,
  });
  const editingEnabled =
    postureAllowsEditing(posture, viewingHistorical) && permissions.draft;

  const authoritativeDraft = useMemo<Draft>(
    () =>
      baseRevision
        ? (draftFromCanonicalDocument(baseRevision.document_content) as Draft)
        : { nodes: [], edges: [] },
    [baseRevision],
  );

  const onDraftChange = useCallback((draft: Draft, isDirty: boolean) => {
    draftRef.current = draft;
    setDirty(isDirty);
  }, []);

  async function reloadAll() {
    await Promise.all([doc.reload(), revisions.reload(), validation.reload()]);
  }

  // --- actions -----------------------------------------------------------

  function onCreateDraft() {
    const canonical = draftToCanonicalDocument(draftFromTopology(topo));
    void createAction.run(async () => {
      const created = await api.createTopologyDraft({
        display_name: `Topology — ${topo.team_ref}`,
        exercise_id: null,
        document: canonical,
      });
      // Resolve identity via the URL so back/forward and reload are stable. The
      // documentId-change effect resets state and the seed effect baselines from
      // the freshly-loaded document — no manual baseRevision set (which the
      // reset effect would clear anyway).
      const next = new URLSearchParams(params);
      next.set("doc", created.id);
      setParams(next, { replace: false });
    });
  }

  function onSave(changeNote: string) {
    if (!documentId || !baseRevision || !draftRef.current) return;
    const canonical = draftToCanonicalDocument(draftRef.current);
    void action.run(async () => {
      const saved = await api.createTopologyRevision(documentId, {
        base_revision_number: baseRevision.revision_number,
        base_content_hash: baseRevision.content_hash,
        document: canonical,
        change_note: changeNote.trim() || null,
      });
      // Rebase to the exact saved content; the workspace re-baselines and the
      // dirty flag resets. Local draft is now the saved revision.
      setBaseRevision(saved);
      setViewingRevisionId(saved.id);
      await reloadAll();
    });
    // On failure, action.error renders closed-code copy; baseRevision is
    // unchanged so the local draft is preserved. "Reload authoritative"
    // surfaces the server's advanced revision as a stale-base conflict.
  }

  function onValidate() {
    if (!documentId || !baseRevision) return;
    void action.run(
      () => api.validateTopologyRevision(documentId, baseRevision.id, baseRevision.content_hash),
      reloadAll,
    );
  }

  function onSubmit() {
    if (!documentId || !baseRevision) return;
    void action.run(
      () => api.submitTopologyRevision(documentId, baseRevision.id, baseRevision.content_hash),
      reloadAll,
    );
  }

  function onApprove(reason: string) {
    if (!documentId || !baseRevision) return;
    void action.run(
      () =>
        api.approveTopologyRevision(
          documentId, baseRevision.id, baseRevision.content_hash, reason.trim() || undefined,
        ),
      reloadAll,
    );
  }

  function onReject(reason: string) {
    if (!documentId || !baseRevision) return;
    void action.run(
      () =>
        api.rejectTopologyRevision(
          documentId, baseRevision.id, baseRevision.content_hash, reason.trim() || undefined,
        ),
      reloadAll,
    );
  }

  function onReload() {
    // Refresh the server view WITHOUT rebasing the workspace, so a server that
    // advanced while we edited surfaces as a stale-base conflict.
    void reloadAll();
  }

  function loadRevisionContent(revisionId: string) {
    if (!documentId) return;
    void action.run(async () => {
      const rev = await api.getTopologyRevision(documentId, revisionId);
      setBaseRevision(rev);
      setViewingRevisionId(rev.id);
    });
  }

  function onLoadRevision(revisionId: string) {
    if (
      dirty &&
      !window.confirm(
        "Loading another revision discards your local unsaved changes. Changes are never merged. Continue?",
      )
    ) {
      return;
    }
    loadRevisionContent(revisionId);
  }

  function onDiscardAndLoadLatest() {
    if (!document?.current_revision_id) return;
    loadRevisionContent(document.current_revision_id);
  }

  // --- render ------------------------------------------------------------

  // No document resolved yet: read-only preview handled by the caller; here we
  // offer explicit creation only when permitted. Never auto-create.
  if (documentId === null) {
    return (
      <CyberCard surface="well" heading="Durable topology authoring">
        {permissions.draft ? (
          <>
            <p className="tw-note">{CREATE_DRAFT_NOTE}</p>
            {createAction.error && (
              <div className="error-box" role="alert">
                {createAction.error.text}{" "}
                <code className="mono">{createAction.error.code}</code>
              </div>
            )}
            <CyberButton disabled={createAction.busy} onClick={onCreateDraft}>
              {createAction.busy ? "Creating…" : "Create topology draft"}
            </CyberButton>
          </>
        ) : (
          <EmptyState title="Read-only">
            You do not have permission to author topology drafts. This is the
            read-only planned topology.
          </EmptyState>
        )}
      </CyberCard>
    );
  }

  if (loadFailed) {
    return (
      <div className="error-box" role="alert">
        Topology document unavailable.
      </div>
    );
  }
  if ((doc.loading && !document) || baseRevision === null) {
    return (
      <CyberCard>
        <Skeleton lines={5} />
      </CyberCard>
    );
  }
  if (document === null) {
    return (
      <div className="error-box" role="alert">
        The topology document was not found.
      </div>
    );
  }
  // Defense in depth: never reconstruct/render a revision whose content carries
  // an unexpected (non-allowlisted) key, even though the canonical documents are
  // secret-free by the backend contract.
  if (!revisionContentIsRenderable(baseRevision)) {
    return (
      <div className="error-box" role="alert">
        This revision's content could not be safely displayed.
      </div>
    );
  }

  const controlsInputs = {
    posture,
    permissions,
    dirty,
    hasSemanticChanges: dirty,
    currentRevisionStatus: currentRev?.status ?? null,
    currentValidationStatus: document.current_validation_status ?? null,
    viewingHistorical,
  };

  const persistence: WorkspacePersistence = {
    authoritativeDraft,
    revisionKey: `${documentId}:${baseRevision.id}`,
    editingEnabled,
    onDraftChange,
    panel: (
      <TopologyPersistencePanel
        posture={posture}
        document={document}
        revisions={revisions.data ?? null}
        validation={validationView(
          validation.data ?? null,
          document.current_validation_status ?? null,
          dirty,
        )}
        validationResult={validation.data ?? null}
        baseRevisionNumber={baseRevisionNumber}
        baseHash={baseHash}
        actions={{
          save: canSaveRevision(controlsInputs),
          validate: canValidateRevision(controlsInputs),
          submit: canSubmitRevision(controlsInputs),
          approve: canDecide(controlsInputs),
          reject: canDecide(controlsInputs),
        }}
        busy={action.busy}
        error={action.error}
        onSave={onSave}
        onValidate={onValidate}
        onSubmit={onSubmit}
        onApprove={onApprove}
        onReject={onReject}
        onReload={onReload}
        onLoadRevision={onLoadRevision}
        onDiscardAndLoadLatest={onDiscardAndLoadLatest}
        viewingRevisionId={viewingRevisionId}
      />
    ),
  };

  return <TopologyWorkspace topo={topo} persistence={persistence} />;
}
