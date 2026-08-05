import "../range.css";
import "./proxmox.css";

import { useMemo } from "react";

import { api } from "../../../api/client";
import {
  CyberButton,
  CyberCard,
  CyberTable,
  DataPanel,
  EmptyState,
  HashChip,
  KeyValueList,
  MetricTile,
  SafetyNotice,
  StatusBadge,
  shortId,
} from "../../../components/ui";
import { useAsync } from "../../../hooks";
import { useRange } from "../RangeLayout";
import { ProxmoxSection } from "./ProxmoxSection";
import { SourcedPanel } from "./SourcedPanel";
import { live } from "./provenance";
import {
  absenceFindingsFixture,
  deletionSetFixture,
  deletionSetHashFixture,
  destroyApprovalFixture,
  destroyAuthorizationStateFixture,
  destroyPlanFixture,
  destroyPreconditionsFixture,
  planDocumentFixture,
  zeroResidueProofFixture,
} from "./proxmox-fixtures";
import { DESTROY_OPERATION_KIND, EXECUTION_STATUS_NOT_APPLIED } from "./proxmox-types";
import {
  APPLY_AND_DESTROY_ARE_SEPARATE_NOTE,
  AUTHORIZATION_IS_SERVER_SIDE_NOTE,
  DESTROY_AUTHORIZATION_HELP,
  DESTROY_AUTHORIZATION_LABEL,
  DESTROY_AUTHORIZATION_TONE,
  DESTROY_PLAN_NOTE,
  OBJECT_PROVENANCE_LABEL,
  OBJECT_PROVENANCE_TONE,
  OWNERSHIP_NOTE,
  TEARDOWN_OUTCOME_TONE,
  TRISTATE_LABEL,
  TRISTATE_TONE,
  UNPROVEN_IS_NOT_CLEAN_NOTE,
  assertSeparateAuthorizations,
  destroyPreconditionRows,
  humanize,
  mutationAvailability,
  residueSummary,
} from "./proxmox-view";

const NO_ENDPOINT_TITLE =
  "No endpoint accepts a Proxmox destroy-approval decision in this build. Disabling is not the boundary — the destroy gate authorizes independently and refuses an approval that is not for a destroy.";

/**
 * Destroy plan, destroy approval and teardown evidence.
 *
 * MIXED, and the mix is the point. The teardown evidence panel is LIVE — the range API has served
 * `GET /ranges/{id}/teardown-evidence` since the range work landed, and its three-valued verdict is
 * the same vocabulary the Proxmox residue prover uses. Everything Proxmox-specific above it (the
 * destroy plan, the destroy approval, the deletion set, the zero-residue proof) is offline.
 *
 * The separation this page holds: a destroy authorization is NOT a continuation of an apply
 * authorization. It is taken against a different plan, carries a deletion-set hash the apply plan
 * does not have at all, and binds an `operation_kind` the gate checks — an apply approval replayed
 * here is refused with `proxmox.destroy.approval_is_not_for_destroy`. Nothing on this page
 * describes destroy as "continuing", "finishing" or "completing" anything.
 */
export function ProxmoxTeardown() {
  const { range, lifecycle } = useRange();

  const evidence = useAsync(() => api.listTeardownEvidence(range.id), [range.id, range.updated_at]);

  const destroyDoc = destroyPlanFixture.value;
  const authorization = destroyAuthorizationStateFixture.value;
  const preconditions = destroyPreconditionRows(destroyPreconditionsFixture.value);
  const deletionSet = deletionSetFixture.value;
  const findings = absenceFindingsFixture.value;

  const summary = useMemo(() => residueSummary(deletionSet, findings), [deletionSet, findings]);

  // The apply plan's hash is read here only to prove the two differ. If they ever matched, the
  // separation would be cosmetic and this page must not render.
  assertSeparateAuthorizations(planDocumentFixture.value.change_set_hash, destroyDoc.change_set_hash);

  const approveAvailability = mutationAvailability(
    lifecycle.recorded,
    ["ready", "active", "failed", "recovery_required"],
    "Recording a destroy-approval decision",
  );

  return (
    <div className="rng">
      <ProxmoxSection>
      <SafetyNotice role="alert" tone="warn">
        {APPLY_AND_DESTROY_ARE_SEPARATE_NOTE}
      </SafetyNotice>

      <div className="rng-grid">
        <div className="ui-metric pmx-execution-status">
          <div className="ui-metric__label">Destroy plan execution status</div>
          <div className="ui-metric__value pmx-not-applied">
            {destroyDoc.execution_status === EXECUTION_STATUS_NOT_APPLIED
              ? EXECUTION_STATUS_NOT_APPLIED
              : destroyDoc.execution_status}
          </div>
          <div className="ui-metric__detail">
            Nothing has been deleted. Read from the destroy plan document.
          </div>
        </div>
        <MetricTile
          label="Destroy authorization"
          value={DESTROY_AUTHORIZATION_LABEL[authorization]}
          detail={DESTROY_AUTHORIZATION_HELP[authorization]}
          tone={
            DESTROY_AUTHORIZATION_TONE[authorization] === "ok"
              ? "ok"
              : DESTROY_AUTHORIZATION_TONE[authorization] === "danger"
                ? "danger"
                : DESTROY_AUTHORIZATION_TONE[authorization] === "warn"
                  ? "warn"
                  : "default"
          }
        />
        <MetricTile
          label="Objects to delete"
          value={deletionSet.deletable.length}
          detail={`${deletionSet.protected.length} protected · ${deletionSet.undetermined.length} undetermined`}
        />
      </div>

      <SourcedPanel
        heading="Destroy plan"
        record={destroyPlanFixture}
        intro={DESTROY_PLAN_NOTE}
        render={(d) => (
          <>
            <CyberTable
              label="Destroy plan hashes"
              head={["Hash", "Value"]}
              caption="The deletion-set hash exists only on the destroy side. The apply plan has no such hash, which is why the two authorizations cannot be interchanged."
            >
              <tr>
                <td>Destroy-plan document hash</td>
                <td>
                  <HashChip value={d.plan_document_hash} digits={16} />
                </td>
              </tr>
              <tr>
                <td>Destroy change-set hash</td>
                <td>
                  <HashChip value={d.change_set_hash} digits={16} />
                </td>
              </tr>
              <tr className="pmx-row-emphasis">
                <td>Deletion-set hash</td>
                <td>
                  <HashChip value={deletionSetHashFixture.value} digits={16} />
                </td>
              </tr>
              <tr>
                <td className="muted">Apply change-set hash (for comparison — a different plan)</td>
                <td className="muted">
                  <HashChip value={planDocumentFixture.value.change_set_hash} digits={16} />
                </td>
              </tr>
            </CyberTable>
            <CyberTable
              label="Addresses the destroy plan would delete"
              head={["Action", "Address"]}
              caption={`${d.delete_addresses.length} addresses · none deleted`}
            >
              {d.delete_addresses.map((a) => (
                <tr key={a}>
                  <td>
                    <span className="badge danger">destroy</span>
                  </td>
                  <td className="mono">{a}</td>
                </tr>
              ))}
            </CyberTable>
          </>
        )}
      />

      <SourcedPanel
        heading="Destroy approval binding"
        record={destroyApprovalFixture}
        intro="An approval is bound to an operation kind, a plan, a target, a cluster and a worker. The gate checks every one of them; the first is what stops an apply approval being replayed as a destroy approval."
        render={(a) => (
          <KeyValueList
            items={[
              {
                key: "Operation kind",
                value: (
                  <span className={`badge ${a.operation_kind === DESTROY_OPERATION_KIND ? "ok" : "danger"}`}>
                    {a.operation_kind}
                  </span>
                ),
              },
              { key: "Approval id", value: a.approval_id, mono: true },
              { key: "Deletion-set hash", value: <HashChip value={a.deletion_set_hash} digits={16} /> },
              { key: "Change-set hash", value: <HashChip value={a.change_set_hash} digits={16} /> },
              { key: "Plan document hash", value: <HashChip value={a.plan_document_hash} digits={16} /> },
              { key: "Ownership scope", value: a.ownership_scope.join(" / "), mono: true },
              { key: "Target", value: a.target_id, mono: true },
              { key: "Cluster fingerprint", value: <HashChip value={a.cluster_fingerprint} /> },
              { key: "Worker", value: `${a.worker_id} @ ${a.worker_release}`, mono: true },
            ]}
          />
        )}
      />

      <SourcedPanel
        heading="Destroy-gate preconditions"
        record={destroyPreconditionsFixture}
        intro="Ownership must be VERIFIED on the cluster before anything is deleted — not assumed from the plan. An approval that has already been consumed is refused rather than replayed."
        render={() => (
          <CyberTable
            label="Destroy preconditions"
            head={["Precondition", "State"]}
            caption="Anything but yes means the gate refuses. 'Not stated' is its own answer."
          >
            {preconditions.map((p) => (
              <tr key={p.key}>
                <td>{p.label}</td>
                <td>
                  <span className={`badge ${TRISTATE_TONE[p.state]}`}>{TRISTATE_LABEL[p.state]}</span>
                </td>
              </tr>
            ))}
          </CyberTable>
        )}
      />

      <CyberCard heading="Destroy-approval decision" headingLevel={2}>
        <SafetyNotice role="note" tone="info">
          {AUTHORIZATION_IS_SERVER_SIDE_NOTE}
        </SafetyNotice>
        <p className="rng-sub">{approveAvailability.reason}</p>
        <div className="pmx-actions">
          <CyberButton type="button" variant="danger" disabled title={NO_ENDPOINT_TITLE}>
            Approve destroy plan
          </CyberButton>
          <CyberButton type="button" variant="secondary" disabled title={NO_ENDPOINT_TITLE}>
            Reject destroy plan
          </CyberButton>
        </div>
        <p className="rng-sub">
          Inert in this build: no endpoint accepts a Proxmox destroy-approval decision. This is a
          separate decision from plan approval on the Plan &amp; apply tab and shares nothing with
          it — not the hash, not the approval record, and not the authorization.
        </p>
      </CyberCard>

      <SourcedPanel
        heading="Deletion set"
        record={deletionSetFixture}
        intro={OWNERSHIP_NOTE}
        render={(set) => (
          <>
            <CyberTable
              label="Deletable objects"
              head={["Class", "Identifier", "Address"]}
              caption={`${set.deletable.length} objects proved to carry this range's ownership stamp`}
            >
              {set.deletable.map((r) => (
                <tr key={`${r.residue_class}:${r.identifier}`}>
                  <td className="muted mono">{humanize(r.residue_class)}</td>
                  <td className="mono">{r.identifier}</td>
                  <td className="muted mono">{r.address ?? "—"}</td>
                </tr>
              ))}
            </CyberTable>

            <CyberCard heading="Protected — never deleted" headingLevel={3} surface="well">
              <CyberTable
                label="Protected objects"
                head={["Class", "Identifier", "Provenance", "Why"]}
                caption={`${set.protected.length} objects excluded from deletion because they are not provably ours`}
              >
                {set.protected.map((p) => (
                  <tr key={`${p.resource.residue_class}:${p.resource.identifier}`}>
                    <td className="muted mono">{humanize(p.resource.residue_class)}</td>
                    <td className="mono">{p.resource.identifier}</td>
                    <td>
                      <span className={`badge ${OBJECT_PROVENANCE_TONE[p.provenance]}`}>
                        {OBJECT_PROVENANCE_LABEL[p.provenance] ?? p.provenance}
                      </span>
                    </td>
                    <td className="muted">{p.detail}</td>
                  </tr>
                ))}
              </CyberTable>
            </CyberCard>

            {set.undetermined.length > 0 && (
              <CyberCard heading="Undetermined" headingLevel={3} surface="well">
                <SafetyNotice role="alert" tone="warn">
                  These objects could not be classified as ours or not ours. They are neither
                  deleted nor written off: an undetermined object is a fourth answer, and a teardown
                  that leaves any is not a clean teardown.
                </SafetyNotice>
                <CyberTable label="Undetermined objects" head={["Class", "Identifier"]}>
                  {set.undetermined.map((r) => (
                    <tr key={`${r.residue_class}:${r.identifier}`} className="pmx-row-unproven">
                      <td className="muted mono">{humanize(r.residue_class)}</td>
                      <td className="mono">{r.identifier}</td>
                    </tr>
                  ))}
                </CyberTable>
              </CyberCard>
            )}
          </>
        )}
      />

      <SourcedPanel
        heading="Residue evidence"
        record={absenceFindingsFixture}
        intro={UNPROVEN_IS_NOT_CLEAN_NOTE}
        render={(rows) => (
          <>
            <div className="rng-grid">
              <MetricTile
                label="Confirmed absent"
                value={summary.confirmedAbsent}
                detail="Proved gone by a probe that was itself working"
                tone={summary.confirmedAbsent > 0 ? "ok" : "default"}
              />
              <MetricTile
                label="Still present"
                value={summary.stillPresent}
                detail="Observed still there"
                tone={summary.stillPresent > 0 ? "danger" : "default"}
              />
              <MetricTile
                label="Unproven"
                value={summary.unproven}
                detail="Nothing was proved either way"
                tone={summary.unproven > 0 ? "warn" : "default"}
              />
            </div>
            <CyberTable
              label="Absence findings"
              head={["Class", "Identifier", "Outcome", "Probe", "Detail"]}
              caption="A 'removed' verdict from an unhealthy probe proves nothing and is not counted as confirmed."
            >
              {rows.map((f) => (
                <tr
                  key={`${f.resource.residue_class}:${f.resource.identifier}`}
                  className={f.outcome === "unproven" || !f.probe_healthy ? "pmx-row-unproven" : undefined}
                >
                  <td className="muted mono">{humanize(f.resource.residue_class)}</td>
                  <td className="mono">{f.resource.identifier}</td>
                  <td>
                    <span className={`badge ${TEARDOWN_OUTCOME_TONE[f.outcome]}`}>{f.outcome}</span>
                  </td>
                  <td className={f.probe_healthy ? "muted" : "pmx-unproven"}>
                    {f.probe_healthy ? "healthy" : "not working"}
                  </td>
                  <td className="muted">{f.detail}</td>
                </tr>
              ))}
            </CyberTable>
          </>
        )}
      />

      <SourcedPanel
        heading="Zero-residue proof"
        record={zeroResidueProofFixture}
        intro="The overall verdict. `unproven` is not a weak `clean` — it means the proof was not obtained, and the range must be treated as possibly still holding infrastructure."
        render={(p) => (
          <KeyValueList
            items={[
              {
                key: "Verdict",
                value: (
                  <span className={`badge ${TEARDOWN_OUTCOME_TONE[p.verdict] ?? "warn"}`}>{p.verdict}</span>
                ),
              },
              { key: "Expected", value: String(p.expected_count), mono: true },
              { key: "Confirmed absent", value: String(p.confirmed_absent), mono: true },
              { key: "Still present", value: String(p.still_present), mono: true },
              { key: "Unproven", value: String(p.unproven), mono: true },
              { key: "Protected (left alone)", value: p.protected.join(", "), mono: true },
              {
                key: "Classes not covered by any probe",
                value:
                  p.uncovered.length === 0
                    ? "none"
                    : `${p.uncovered.map(humanize).join(", ")} — no probe looked for these at all`,
              },
              {
                key: "Reservations",
                value: `${p.released_reservations} released · ${p.retained_reservations} retained (an allocation is released only when its object is proved gone)`,
              },
            ]}
          />
        )}
      />

      <SourcedPanel
        heading="Teardown evidence recorded by the control plane"
        record={live(`GET /api/v1/ranges/${range.id}/teardown-evidence`, evidence.data ?? [])}
        intro="This panel is live. It is the range API's own teardown record, and it uses the same three-valued vocabulary as the Proxmox residue prover above."
        render={(rows) => (
          <DataPanel
            state={evidence}
            isEmpty={() => rows.length === 0}
            empty={
              <EmptyState title="No teardown evidence">
                This range has not been destroyed, so the control plane has recorded no teardown
                evidence for it.
              </EmptyState>
            }
          >
            {() => (
              <CyberTable
                label="Teardown evidence"
                head={["Recorded", "Verdict", "Probe", "Expected", "Removed", "Present", "Unproven", "Reason"]}
                caption={`${rows.length} record${rows.length === 1 ? "" : "s"} · probe_reachable false means removal and the existence check share a failure mode — absence NOT proved`}
              >
                {rows.map((e) => (
                  <tr key={e.id} className={e.verdict === "unproven" ? "pmx-row-unproven" : undefined}>
                    <td className="muted mono">{e.observed_at.slice(0, 19).replace("T", " ")}</td>
                    <td>
                      <StatusBadge state={e.verdict} domain="range-operation" />
                    </td>
                    <td className={e.probe_reachable ? "muted" : "pmx-unproven"}>
                      {e.probe_reachable ? "reachable" : "unreachable"}
                    </td>
                    <td className="muted mono">{e.expected_count}</td>
                    <td className="muted mono">{e.removed_confirmed}</td>
                    <td className="muted mono">{e.still_present}</td>
                    <td className="muted mono">{e.unproven_count}</td>
                    <td className="muted">
                      {e.reason ?? "—"}
                      <div className="pmx-detail mono">{shortId(e.id)}</div>
                    </td>
                  </tr>
                ))}
              </CyberTable>
            )}
          </DataPanel>
        )}
      />
      </ProxmoxSection>
    </div>
  );
}
