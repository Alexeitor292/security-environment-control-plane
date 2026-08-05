import "../range.css";
import "./proxmox.css";

import {
  CyberButton,
  CyberCard,
  CyberTable,
  HashChip,
  KeyValueList,
  MetricTile,
  SafetyNotice,
} from "../../../components/ui";
import { useRange } from "../RangeLayout";
import { ProxmoxSection } from "./ProxmoxSection";
import { SourcedPanel } from "./SourcedPanel";
import {
  applyAuthorizationStateFixture,
  authoritativeStateFixture,
  destroyPlanFixture,
  planApprovalStateFixture,
  planDocumentFixture,
  readinessFixture,
  workerIdentityFixture,
} from "./proxmox-fixtures";
import { EXECUTION_STATUS_NOT_APPLIED } from "./proxmox-types";
import {
  APPLY_AND_DESTROY_ARE_SEPARATE_NOTE,
  APPLY_APPROVAL_IS_NOT_APPLY_NOTE,
  APPLY_AUTHORIZATION_HELP,
  APPLY_AUTHORIZATION_LABEL,
  APPLY_AUTHORIZATION_TONE,
  AUTHORIZATION_IS_SERVER_SIDE_NOTE,
  PLAN_APPROVAL_LABEL,
  PLAN_APPROVAL_TONE,
  PLAN_NOT_APPLIED_NOTE,
  TRISTATE_LABEL,
  TRISTATE_TONE,
  applyPreconditionRows,
  assertSeparateAuthorizations,
  changeCounts,
  humanize,
  mutationAvailability,
  planHashRows,
  planIsUnapplied,
  readinessSatisfied,
} from "./proxmox-view";

/**
 * Plan review and apply approval.
 *
 * OFFLINE. The plan document is built by the worker (`plan_document.build_plan_document`) and the
 * apply gate runs on the worker at claim time (`proxmox_apply_gate.evaluate_apply_gate`). Neither
 * has an HTTP surface, so no approval control here can post anything, and none pretends to.
 *
 * Three things this screen must never do, in order of how badly they would go wrong:
 *
 *  1. Imply the plan has run. `EXECUTION STATUS: NOT APPLIED` is rendered from the document, at the
 *     top, in the largest tile, unsoftened.
 *  2. Imply that approving is applying. Approval records a decision; the gate authorizes, later,
 *     against the hashes, and can still refuse.
 *  3. Bleed into the destroy authorization. The destroy hash is shown here ONLY to demonstrate it
 *     is a different hash, under a heading that says so, with no destroy control anywhere on the
 *     page.
 */
export function ProxmoxPlanReview() {
  const { range, lifecycle } = useRange();

  const doc = planDocumentFixture.value;
  const counts = changeCounts(doc);
  const unapplied = planIsUnapplied(doc);
  const approval = planApprovalStateFixture.value;
  const authorization = applyAuthorizationStateFixture.value;
  const preconditions = applyPreconditionRows(authoritativeStateFixture.value);

  // Refuses to render rather than risk showing one plan's hash under the other's label. A blank
  // screen is recoverable; an operator approving a destroy against a hash they think they already
  // reviewed is not.
  assertSeparateAuthorizations(doc.change_set_hash, destroyPlanFixture.value.change_set_hash);

  // Offered from the recorded lifecycle state only — and the reason is rendered either way, so an
  // operator never has to infer a security property from a control that is not there.
  const approveAvailability = mutationAvailability(
    lifecycle.recorded,
    ["draft"],
    "Recording a plan-approval decision",
  );

  return (
    <div className="rng">
      <ProxmoxSection>
      {/* First thing on the page, above every hash and every count. */}
      <SafetyNotice role="alert" tone="warn">
        {PLAN_NOT_APPLIED_NOTE}
      </SafetyNotice>

      <div className="rng-grid">
        <div className="ui-metric pmx-execution-status">
          <div className="ui-metric__label">Execution status</div>
          <div className="ui-metric__value pmx-not-applied">
            {unapplied ? EXECUTION_STATUS_NOT_APPLIED : doc.execution_status}
          </div>
          <div className="ui-metric__detail">
            Read from the plan document, not inferred from the range state.
          </div>
        </div>
        <MetricTile
          label="Plan approval"
          value={PLAN_APPROVAL_LABEL[approval]}
          detail="A recorded decision about the plan"
          tone={PLAN_APPROVAL_TONE[approval] === "ok" ? "ok" : PLAN_APPROVAL_TONE[approval] === "danger" ? "danger" : "warn"}
        />
        <MetricTile
          label="Apply authorization"
          value={APPLY_AUTHORIZATION_LABEL[authorization]}
          detail={APPLY_AUTHORIZATION_HELP[authorization]}
          tone={
            APPLY_AUTHORIZATION_TONE[authorization] === "ok"
              ? "ok"
              : APPLY_AUTHORIZATION_TONE[authorization] === "danger"
                ? "danger"
                : APPLY_AUTHORIZATION_TONE[authorization] === "warn"
                  ? "warn"
                  : "default"
          }
        />
      </div>

      <SafetyNotice role="note" tone="warn">
        {APPLY_APPROVAL_IS_NOT_APPLY_NOTE}
      </SafetyNotice>

      <SourcedPanel
        heading="Plan document"
        record={planDocumentFixture}
        intro={`Range ${range.name} · document version ${doc.version}`}
        render={(d) => (
          <>
            <KeyValueList
              items={[
                { key: "Execution status", value: d.execution_status, mono: true },
                { key: "Generated at", value: d.generated_at, mono: true },
                { key: "Contract version", value: d.version, mono: true },
              ]}
            />
            <CyberTable
              label="Plan hashes"
              head={["Hash", "Value"]}
              caption="Three separate hashes because the apply gate refuses on each independently — a mismatch needs to say which one moved."
            >
              {planHashRows(d).map((h) => (
                <tr key={h.key}>
                  <td>{h.label}</td>
                  <td>
                    <HashChip value={h.hash} digits={16} />
                  </td>
                </tr>
              ))}
            </CyberTable>
          </>
        )}
      />

      <SourcedPanel
        heading="Intended change"
        record={planDocumentFixture}
        intro="What the plan says it would do if it ran. It has not run."
        render={(d) => (
          <>
            <div className="rng-grid">
              <MetricTile label="To create" value={counts.create} detail="resources" />
              <MetricTile label="To update" value={counts.update} detail="resources" />
              <MetricTile
                label="To destroy"
                value={counts.destroy}
                detail="resources in the APPLY plan"
                tone={counts.destroy > 0 ? "warn" : "default"}
              />
            </div>
            <CyberTable
              label="Planned resource addresses"
              head={["Action", "Address"]}
              caption={`${d.create_addresses.length + d.update_addresses.length + d.delete_addresses.length} addresses · nothing here exists yet`}
            >
              {d.create_addresses.map((a) => (
                <tr key={`c:${a}`}>
                  <td>
                    <span className="badge ok">create</span>
                  </td>
                  <td className="mono">{a}</td>
                </tr>
              ))}
              {d.update_addresses.map((a) => (
                <tr key={`u:${a}`}>
                  <td>
                    <span className="badge accent">update</span>
                  </td>
                  <td className="mono">{a}</td>
                </tr>
              ))}
              {d.delete_addresses.map((a) => (
                <tr key={`d:${a}`}>
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
        heading="Apply-gate preconditions"
        record={authoritativeStateFixture}
        intro="What the apply gate reads before it authorizes anything. Each is three-valued: an unstated precondition is not a satisfied one, and it is not a denial either."
        render={() => (
          <CyberTable
            label="Apply preconditions"
            head={["Precondition", "State"]}
            caption="The gate treats anything but yes as unsatisfied and refuses. 'Not stated' is shown as itself because nobody-said and told-us-no are different facts."
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

      <SourcedPanel
        heading="Worker binding"
        record={workerIdentityFixture}
        intro="The plan is bound to one worker identity and one release. A different worker claiming it is refused with proxmox.apply.worker_identity_mismatch."
        render={(w) => (
          <KeyValueList
            items={[
              { key: "Worker id", value: w.worker_id, mono: true },
              { key: "Role", value: w.role, mono: true },
              { key: "Release", value: w.release, mono: true },
              { key: "Queue", value: w.queue, mono: true },
            ]}
          />
        )}
      />

      <SourcedPanel
        heading="Competition readiness"
        record={readinessFixture}
        intro="Assessed against the compiled workload plan. Note flags_delivered_out_of_band: no flag value appears in a desired state, a plan document, or any response this browser can read."
        render={(findings) => (
          <CyberTable
            label="Readiness findings"
            head={["Requirement", "Met", "Detail"]}
            caption={
              readinessSatisfied(findings)
                ? "All requirements met in the compiled plan."
                : "One or more requirements are not met."
            }
          >
            {findings.map((f) => (
              <tr key={f.requirement}>
                <td className="mono">{humanize(f.requirement)}</td>
                <td>
                  <span className={`badge ${f.met ? "ok" : "danger"}`}>{f.met ? "met" : "not met"}</span>
                </td>
                <td className="muted">{f.detail}</td>
              </tr>
            ))}
          </CyberTable>
        )}
      />

      <CyberCard heading="Plan-approval decision" headingLevel={2}>
        <SafetyNotice role="note" tone="info">
          {AUTHORIZATION_IS_SERVER_SIDE_NOTE}
        </SafetyNotice>
        <p className="rng-sub">{approveAvailability.reason}</p>
        <div className="pmx-actions">
          <CyberButton type="button" variant="primary" disabled title={NO_ENDPOINT_TITLE}>
            Approve plan
          </CyberButton>
          <CyberButton type="button" variant="danger" disabled title={NO_ENDPOINT_TITLE}>
            Reject plan
          </CyberButton>
        </div>
        <p className="rng-sub">
          Both controls are inert in this build: no endpoint accepts a Proxmox plan-approval
          decision, so there is nothing for them to post. They are shown because the decision is
          part of the flow and its place in the sequence is what is under review. Approving would
          record a decision — it would still not start apply.
        </p>
      </CyberCard>

      <CyberCard heading="Destroy authorization is not part of this decision" headingLevel={2}>
        <SafetyNotice role="note" tone="warn">
          {APPLY_AND_DESTROY_ARE_SEPARATE_NOTE}
        </SafetyNotice>
        <CyberTable
          label="Apply and destroy hashes side by side"
          head={["Plan", "Change-set hash"]}
          caption="Shown together once, here, only to make the difference visible. There is no destroy control on this page."
        >
          <tr>
            <td>Apply plan (this page)</td>
            <td>
              <HashChip value={doc.change_set_hash} digits={16} />
            </td>
          </tr>
          <tr>
            <td>Destroy plan (Teardown tab)</td>
            <td>
              <HashChip value={destroyPlanFixture.value.change_set_hash} digits={16} />
            </td>
          </tr>
        </CyberTable>
      </CyberCard>
      </ProxmoxSection>
    </div>
  );
}

const NO_ENDPOINT_TITLE =
  "No endpoint accepts a Proxmox plan-approval decision in this build. Disabling is not the boundary — the server authorizes every mutation independently.";
