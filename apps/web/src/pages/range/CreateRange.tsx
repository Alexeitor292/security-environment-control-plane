import "./range.css";

import { useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";

import { api } from "../../api/client";
import { CyberGridBackground } from "../../components/backgrounds";
import {
  ClosedCodeError,
  CyberButton,
  CyberCard,
  CyberInput,
  CyberSelect,
  CyberTable,
  DataPanel,
  EmptyState,
  SafetyNotice,
  useAction,
} from "../../components/ui";
import { useAsync } from "../../hooks";
import { ProxmoxCreatePlacement } from "./proxmox/ProxmoxCreatePlacement";
import { isProxmoxProvider } from "./proxmox/proxmox-view";
import {
  EXECUTION_POSTURE_NOTE,
  RANGE_ERROR_TEXT,
  estimatedDuration,
  rangeBlueprints,
} from "./range-view";

/**
 * Page 2 — Create Range.
 *
 * Every option is loaded from `GET /range-templates`. Creating a range records it in `draft` and
 * deploys nothing — deployment is a separate, explicit action on the next page.
 *
 * The component list is shown before creation because it is the honest answer to "what am I about
 * to run on my machine": specific images, by tag.
 */
export function CreateRange() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const action = useAction({ codeText: RANGE_ERROR_TEXT });

  const catalog = useAsync(() => api.listRangeTemplates(), []);
  const blueprints = useMemo(
    () => (catalog.data ? rangeBlueprints(catalog.data) : []),
    [catalog.data],
  );

  const [slug, setSlug] = useState(params.get("template") ?? "");
  const [name, setName] = useState("");

  const selected = blueprints.find((b) => b.slug === slug) ?? null;
  const template = catalog.data?.find((t) => t.slug === slug) ?? null;
  const nameTrimmed = name.trim();
  const ready = slug !== "";

  // Navigation happens inside the action so it runs ONLY after the server confirms creation, with
  // the id the SERVER assigned. A refusal leaves the operator on the form with the reason shown.
  const create = () =>
    action.run(async () => {
      const range = await api.createRange({
        template_slug: slug,
        // `name` is optional server-side and defaults to the template name. Sending an empty
        // string would override that default with a blank name, so it is omitted instead.
        ...(nameTrimmed === "" ? {} : { name: nameTrimmed }),
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
            Creating a range records it as a draft. Nothing is deployed until you deploy it.
          </p>
        </div>
      </div>

      <SafetyNotice role="note" tone="warn">
        {EXECUTION_POSTURE_NOTE}
      </SafetyNotice>

      <CyberCard heading="Range definition" headingLevel={2}>
        <DataPanel
          state={catalog}
          isEmpty={() => blueprints.length === 0}
          empty={<EmptyState title="No blueprints available">The range catalog is empty.</EmptyState>}
        >
          {() => (
            <>
              <div className="rng-grid">
                <CyberSelect
                  label="Blueprint"
                  value={slug}
                  onChange={(e) => setSlug(e.target.value)}
                  options={[
                    { value: "", label: "Select a blueprint…" },
                    ...blueprints.map((b) => ({ value: b.slug, label: b.name })),
                  ]}
                />
                <CyberInput
                  label="Range name (optional)"
                  hint="Defaults to the blueprint name. Typed back to confirm a destroy."
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder={selected?.name ?? ""}
                />
              </div>

              {selected !== null && (
                <>
                  <p className="rng-sub">{selected.description || selected.summary}</p>
                  <div className="rng-meta">
                    <span className="mono">{selected.provider}</span>
                    <span>{selected.difficulty}</span>
                    <span>{estimatedDuration(selected.estimatedDeploySeconds)} to deploy</span>
                    <span>
                      {selected.challengeCount} challenge
                      {selected.challengeCount === 1 ? "" : "s"} · {selected.totalPoints} pts
                    </span>
                  </div>
                  {selected.warning !== "" && (
                    <SafetyNotice role="alert" tone="warn">
                      {selected.warning}
                    </SafetyNotice>
                  )}
                </>
              )}

              {/* The provider step of the flow. A Proxmox blueprint runs on a cluster this control
                  plane does not own, so the operator sees the registered targets and enrolled
                  workers before creating one — no picker, because the create contract has no field
                  to carry a choice. */}
              {selected !== null && isProxmoxProvider(selected.provider) && (
                <ProxmoxCreatePlacement />
              )}

              {/* What will actually run, by image and tag. An operator about to start containers on
                  their own machine is entitled to see exactly which ones before they commit. */}
              {template !== null && template.components.length > 0 && (
                <CyberTable
                  label="Components"
                  head={["Component", "Role", "Image", "Port"]}
                  caption={`${template.components.length} component${template.components.length === 1 ? "" : "s"} will be created when this range is deployed`}
                >
                  {template.components.map((c) => (
                    <tr key={c.key}>
                      <td>{c.name}</td>
                      <td className="muted">{c.role}</td>
                      <td className="mono">{c.image}</td>
                      <td className="muted mono">
                        {c.container_port === null ? "—" : c.container_port}
                      </td>
                    </tr>
                  ))}
                </CyberTable>
              )}
            </>
          )}
        </DataPanel>

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
    </div>
  );
}
