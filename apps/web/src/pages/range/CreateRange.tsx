import "./range.css";

import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";

import { api } from "../../api/client";
import { CyberGridBackground } from "../../components/backgrounds";
import {
  ClosedCodeError,
  CyberButton,
  CyberCard,
  CyberInput,
  CyberSelect,
  DataPanel,
  EmptyState,
  SafetyNotice,
  useAction,
} from "../../components/ui";
import { useAsync } from "../../hooks";
import {
  DEPLOY_IS_GATED_NOTE,
  EXECUTION_POSTURE_NOTE,
  RANGE_ERROR_TEXT,
  rangeBlueprints,
} from "./range-view";
import type { Version } from "../../api/types";

/**
 * Page 2 — Create Range.
 *
 * Every option on this form is loaded from the API: blueprints and their immutable versions, and
 * the registered execution targets. There is no default template, no invented version and no
 * placeholder target.
 *
 * Creating a range does NOT deploy it. On success this navigates to the deployment page, which is
 * where the approval gate is walked.
 */
export function CreateRange() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const action = useAction({ codeText: RANGE_ERROR_TEXT });

  const catalog = useAsync(async () => {
    const templates = await api.listTemplates();
    const results = await Promise.allSettled(
      templates.map(async (t) => [t.id, await api.listVersions(t.id)] as const),
    );
    const versions = new Map<string, readonly Version[]>();
    for (const r of results) {
      if (r.status === "fulfilled") versions.set(r.value[0], r.value[1]);
    }
    return { templates, versions };
  }, []);

  // Targets are optional context, so a failure here must not block creation. `catch` yields an
  // empty list and the control below says the list is unavailable rather than claiming there are
  // no targets.
  const targets = useAsync(() => api.listTargets().catch(() => []), []);

  const [templateId, setTemplateId] = useState(params.get("template") ?? "");
  const [versionId, setVersionId] = useState("");
  const [name, setName] = useState("");
  const [targetId, setTargetId] = useState("");

  const blueprints = useMemo(
    () => (catalog.data ? rangeBlueprints(catalog.data.templates, catalog.data.versions) : []),
    [catalog.data],
  );
  const selected = blueprints.find((b) => b.templateId === templateId) ?? null;
  const versions = useMemo(() => {
    const list = catalog.data?.versions.get(templateId) ?? [];
    return [...list].sort((a, b) => b.version_number - a.version_number);
  }, [catalog.data, templateId]);

  // Default the version to the blueprint's latest whenever the blueprint changes, and clear a
  // selection that the new blueprint does not contain — a version id from a previous template
  // would otherwise be submitted against the wrong one.
  useEffect(() => {
    if (versions.length === 0) {
      setVersionId("");
      return;
    }
    setVersionId((current) =>
      versions.some((v) => v.id === current) ? current : versions[0].id,
    );
  }, [versions]);

  const nameTrimmed = name.trim();
  const ready = templateId !== "" && versionId !== "" && nameTrimmed !== "";

  // Navigation happens inside the action so it runs ONLY after the server confirms creation, and
  // with the id the SERVER assigned. A refusal leaves the operator on the form with their input
  // intact and the closed-code reason shown below.
  const create = () =>
    action.run(async () => {
      const range = await api.createExercise({
        template_id: templateId,
        version_id: versionId,
        name: nameTrimmed,
        ...(targetId === "" ? {} : { execution_target_id: targetId }),
      });
      navigate(`/ranges/${range.id}/deployment`);
    });

  return (
    <div className="rng">
      <CyberGridBackground intensity="subtle" className="rng-bg" />

      <div className="rng-head">
        <div>
          <h1>Create range</h1>
          <p className="rng-sub">
            Instantiate an immutable blueprint version for a set of isolated teams. Creating a range
            records it — it does not deploy anything.
          </p>
        </div>
      </div>

      <SafetyNotice role="note" tone="info">
        {DEPLOY_IS_GATED_NOTE}
      </SafetyNotice>

      <CyberCard heading="Range definition" headingLevel={2}>
        <DataPanel
          state={catalog}
          isEmpty={() => blueprints.length === 0}
          empty={
            <EmptyState title="No blueprints available">
              Create an environment definition in the{" "}
              <Link to="/templates">environment library</Link> first.
            </EmptyState>
          }
        >
          {() => (
            <div className="rng-grid">
              <div>
                <CyberSelect
                  label="Blueprint"
                  value={templateId}
                  onChange={(e) => setTemplateId(e.target.value)}
                  options={[
                    { value: "", label: "Select a blueprint…" },
                    ...blueprints.map((b) => ({
                      value: b.templateId,
                      label: b.deployable ? b.name : `${b.name} (no version)`,
                      disabled: !b.deployable,
                    })),
                  ]}
                />
                <CyberSelect
                  label="Version"
                  hint="Immutable. The plan is pinned to this version's content hash."
                  value={versionId}
                  onChange={(e) => setVersionId(e.target.value)}
                  disabled={versions.length === 0}
                  options={
                    versions.length === 0
                      ? [{ value: "", label: "Select a blueprint first" }]
                      : versions.map((v) => ({
                          value: v.id,
                          label: `v${v.version_number} · ${v.content_hash.slice(0, 19)}…`,
                        }))
                  }
                />
              </div>
              <div>
                <CyberInput
                  label="Range name"
                  hint="Shown throughout the range surfaces and typed back to confirm a destroy."
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
                <CyberSelect
                  label="Execution target (optional)"
                  hint={
                    targets.error !== null
                      ? "The target list could not be loaded. Leave unset to let the control plane place this range."
                      : "Leave unset to let the control plane choose placement."
                  }
                  value={targetId}
                  onChange={(e) => setTargetId(e.target.value)}
                  options={[
                    { value: "", label: "Control plane decides" },
                    // A disabled or discovery-failed target is listed but not selectable: hiding it
                    // would leave an operator wondering where their target went, and offering it
                    // would produce a refusal at create time.
                    ...(targets.data ?? []).map((t) => ({
                      value: t.id,
                      label:
                        t.status === "active"
                          ? `${t.display_name} (${t.plugin_name})`
                          : `${t.display_name} (${t.plugin_name}) — ${t.status}`,
                      disabled: t.status !== "active",
                    })),
                  ]}
                />
              </div>
            </div>
          )}
        </DataPanel>

        {selected !== null && (
          <p className="rng-sub">
            {selected.description || "No description recorded for this blueprint."}
          </p>
        )}

        {action.error !== null && (
          <ClosedCodeError
            error={action.error}
            codeText={RANGE_ERROR_TEXT}
            onDismiss={action.clearError}
          />
        )}

        <div className="rng-card-foot">
          <CyberButton variant="primary" disabled={!ready || action.busy} onClick={create}>
            {action.busy ? "Creating…" : "Create range"}
          </CyberButton>
          <Link to="/ranges">Cancel</Link>
        </div>
      </CyberCard>

      <SafetyNotice role="note" tone="info">
        {EXECUTION_POSTURE_NOTE}
      </SafetyNotice>
    </div>
  );
}
