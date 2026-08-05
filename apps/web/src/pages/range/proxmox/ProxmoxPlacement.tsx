import "../range.css";
import "./proxmox.css";

import { useMemo } from "react";

import { api } from "../../../api/client";
import {
  CyberCard,
  CyberTable,
  DataPanel,
  EmptyState,
  HashChip,
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
  DISCOVERY_FRESHNESS_NOTE,
  FRESHNESS_LABEL,
  FRESHNESS_TONE,
  NO_BINDING_NOTE,
  PLACEMENT_INTRO,
  WORKER_IDENTITY_NOTE,
  eligibilityRows,
  formatAge,
  healthyWorkers,
  latestDiscovery,
  targetRows,
  workerRows,
} from "./placement-view";
import { PROXMOX_SURFACE_NOTE } from "./proxmox-view";

/**
 * Placement — target, worker, enrollment, discovery and eligibility.
 *
 * This is the ONE Proxmox surface that is wired to live endpoints end to end, because everything
 * it shows already had an HTTP surface before the Proxmox work landed: targets and their inventory
 * snapshots (`/api/v1/targets/...`), worker enrollment (`/api/v1/enrollment`), published worker key
 * material and discovery enrollments (`/api/v1/target-discovery/...`).
 *
 * Every panel is stamped with the exact path that produced it. Nothing here is a fixture, and the
 * absence of an offline banner on this page is itself the claim being made.
 */
export function ProxmoxPlacement() {
  const { range } = useRange();

  const targets = useAsync(() => api.listTargets(), []);
  const enrollments = useAsync(() => api.listEnrollments({ limit: 50 }), []);
  const workerNodes = useAsync(() => api.listWorkerNodes(), []);
  const discoveryEnrollments = useAsync(() => api.listDiscoveryEnrollments(), []);

  const pveTargets = useMemo(
    () => (targets.data ? targetRows(targets.data) : []),
    [targets.data],
  );
  const firstTargetId = pveTargets.length > 0 ? pveTargets[0].id : null;

  // Snapshots are per-target, so the freshness panel reads the first registered Proxmox target.
  // With no target there is no request to make and the panel says so rather than showing nothing.
  const snapshots = useAsync(
    () => (firstTargetId === null ? Promise.resolve([]) : api.listSnapshots(firstTargetId)),
    [firstTargetId],
  );

  const workers = useMemo(
    () => workerRows(enrollments.data?.items ?? [], workerNodes.data ?? []),
    [enrollments.data, workerNodes.data],
  );
  const healthy = useMemo(() => healthyWorkers(workers), [workers]);
  const eligibility = useMemo(
    () => (discoveryEnrollments.data ? eligibilityRows(discoveryEnrollments.data) : []),
    [discoveryEnrollments.data],
  );
  // A single reading taken once per render pass, passed in explicitly, so the age shown is a
  // property of this render and not a number that drifts while nobody re-read the server.
  const discovery = useMemo(
    () => latestDiscovery(snapshots.data ?? [], new Date().toISOString()),
    [snapshots.data],
  );

  return (
    <div className="rng">
      <ProxmoxSection>
      <SafetyNotice role="note" tone="info">
        {PROXMOX_SURFACE_NOTE}
      </SafetyNotice>

      <p className="rng-sub">{PLACEMENT_INTRO}</p>

      <div className="rng-grid">
        <MetricTile
          label="Registered Proxmox targets"
          value={targets.data === null ? "—" : pveTargets.length}
          detail={targets.data === null ? "Target list unavailable." : "plugin_name = proxmox"}
        />
        <MetricTile
          label="Healthy workers"
          value={enrollments.data === null ? "—" : `${healthy.length} of ${workers.length}`}
          detail={
            enrollments.data === null
              ? "Enrollment list unavailable."
              : "Only a healthy enrollment can take work"
          }
          tone={enrollments.data !== null && healthy.length > 0 ? "ok" : "default"}
        />
        <MetricTile
          label="Discovery"
          value={discovery === null ? "—" : FRESHNESS_LABEL[discovery.freshness]}
          detail={discovery === null ? "No snapshot recorded." : formatAge(discovery.ageSeconds)}
          tone={
            discovery === null
              ? "default"
              : discovery.freshness === "fresh"
                ? "ok"
                : discovery.freshness === "stale" || discovery.freshness === "failed"
                  ? "danger"
                  : "warn"
          }
        />
      </div>

      <SafetyNotice role="note" tone="warn">
        {NO_BINDING_NOTE}
      </SafetyNotice>

      <SourcedPanel
        heading="Proxmox targets"
        record={live("GET /api/v1/targets", pveTargets)}
        intro={`This range is recorded against provider "${range.provider}".`}
        render={(rows) => (
          <DataPanel
            state={targets}
            isEmpty={() => rows.length === 0}
            empty={
              <EmptyState title="No Proxmox target registered">
                No execution target with plugin_name &ldquo;proxmox&rdquo; exists in your
                organization. Register one on the provider targets page before a Proxmox range can
                be placed.
              </EmptyState>
            }
          >
            {() => (
              <CyberTable
                label="Registered Proxmox targets"
                head={["Target", "Status", "Config hash", "Credential", "Registered"]}
                caption={`${rows.length} target${rows.length === 1 ? "" : "s"} · a credential reference is an opaque pointer, never a secret`}
              >
                {rows.map((t) => (
                  <tr key={t.id}>
                    <td>
                      {t.displayName}
                      <span className="muted mono"> {shortId(t.id)}</span>
                    </td>
                    <td>
                      <StatusBadge state={t.status} domain="target" />
                    </td>
                    <td>
                      <HashChip value={t.configHash} />
                    </td>
                    <td className="muted">
                      {t.hasCredentialRef ? "reference held" : "none recorded"}
                    </td>
                    <td className="muted mono">{t.createdAt.slice(0, 10)}</td>
                  </tr>
                ))}
              </CyberTable>
            )}
          </DataPanel>
        )}
      />

      <SourcedPanel
        heading="Workers and enrollment"
        record={live("GET /api/v1/enrollment + /api/v1/target-discovery/read-only-bootstrap/worker-nodes", workers)}
        intro={WORKER_IDENTITY_NOTE}
        render={(rows) => (
          <DataPanel
            state={enrollments}
            isEmpty={() => rows.length === 0}
            empty={
              <EmptyState title="No worker enrolled">
                No enrollment and no published worker key material. A Proxmox range cannot be
                deployed until a worker is enrolled and healthy.
              </EmptyState>
            }
          >
            {() => (
              <CyberTable
                label="Workers"
                head={["Worker", "Enrollment state", "Release", "Key fingerprint", "Site", "Updated"]}
                caption={`${rows.length} worker record${rows.length === 1 ? "" : "s"} · state is the control plane's, not this browser's`}
              >
                {rows.map((w) => (
                  <tr key={w.key}>
                    <td>
                      {w.nodeLabel ?? "—"}
                      <span className="muted mono">
                        {" "}
                        {w.workerInstallationId === null ? "" : shortId(w.workerInstallationId)}
                      </span>
                    </td>
                    <td>
                      {w.enrollmentState === null ? (
                        // Published keys with no enrollment. Its own state: not healthy, and not
                        // a failure either.
                        <span className="muted">not enrolled</span>
                      ) : (
                        <StatusBadge state={w.enrollmentState} domain="enrollment" />
                      )}
                      {w.refusalReason !== null && (
                        <div className="muted pmx-detail">{w.refusalReason}</div>
                      )}
                    </td>
                    <td>
                      {w.releaseFingerprint === null ? (
                        <span className="muted">—</span>
                      ) : (
                        <HashChip value={w.releaseFingerprint} />
                      )}
                    </td>
                    <td>
                      {w.workerKeyFingerprint === null && w.sshKeyFingerprint === null ? (
                        <span className="muted">—</span>
                      ) : (
                        <HashChip value={(w.workerKeyFingerprint ?? w.sshKeyFingerprint) as string} />
                      )}
                    </td>
                    <td className="muted">{w.siteLabel ?? "—"}</td>
                    <td className="muted mono">
                      {w.updatedAt === null ? "—" : w.updatedAt.slice(0, 19).replace("T", " ")}
                    </td>
                  </tr>
                ))}
              </CyberTable>
            )}
          </DataPanel>
        )}
      />

      <SourcedPanel
        heading="Discovery freshness"
        record={live(
          firstTargetId === null
            ? "GET /api/v1/targets/{target_id}/snapshots"
            : `GET /api/v1/targets/${firstTargetId}/snapshots`,
          discovery,
        )}
        intro={DISCOVERY_FRESHNESS_NOTE}
        render={(row) =>
          row === null ? (
            <EmptyState title="No discovery snapshot">
              {firstTargetId === null
                ? "No Proxmox target is registered, so no snapshot could have been taken."
                : "This target has never been discovered. Nothing is known about its nodes, storages or templates."}
            </EmptyState>
          ) : (
            <CyberTable
              label="Latest discovery snapshot"
              head={["Snapshot", "Status", "Freshness", "Completed", "Plugin version"]}
              caption="A snapshot that never completed is not stale — it is unproven, and shown as its own state."
            >
              <tr>
                <td className="mono">{shortId(row.snapshotId)}</td>
                <td>
                  <StatusBadge state={row.status} />
                </td>
                <td>
                  <span className={`badge ${FRESHNESS_TONE[row.freshness]}`}>
                    {FRESHNESS_LABEL[row.freshness]}
                  </span>
                  {row.error !== null && row.error !== "" && (
                    <div className="muted pmx-detail">{row.error}</div>
                  )}
                </td>
                <td className="muted mono">
                  {row.completedAt === null
                    ? "never"
                    : `${row.completedAt.slice(0, 19).replace("T", " ")} (${formatAge(row.ageSeconds)})`}
                </td>
                <td className="muted mono">{row.pluginVersion}</td>
              </tr>
            </CyberTable>
          )
        }
      />

      <SourcedPanel
        heading="Eligibility"
        record={live("GET /api/v1/target-discovery", eligibility)}
        intro="Eligibility is a recorded decision about a target, with the plan hash it was decided against. When the active plan hash moves past the approved one, the decision no longer covers what is there now."
        render={(rows) => (
          <DataPanel
            state={discoveryEnrollments}
            isEmpty={() => rows.length === 0}
            empty={
              <EmptyState title="No discovery enrollment">
                No target has been submitted for discovery and eligibility review.
              </EmptyState>
            }
          >
            {() => (
              <CyberTable
                label="Discovery eligibility"
                head={["Target", "Status", "Decision", "Active plan", "Approved plan", "Approved"]}
                caption={`${rows.length} enrollment${rows.length === 1 ? "" : "s"}`}
              >
                {rows.map((e) => (
                  <tr key={e.enrollmentId}>
                    <td>
                      {e.displayName}
                      <span className="muted mono"> {shortId(e.targetId)}</span>
                    </td>
                    <td>
                      <StatusBadge state={e.status} domain="discovery" />
                    </td>
                    <td className="muted">
                      {e.decisionCode === "" ? "—" : e.decisionCode}
                      {e.failureCode !== null && e.failureCode !== "" && (
                        <div className="pmx-detail">{e.failureCode}</div>
                      )}
                    </td>
                    <td>
                      {e.activePlanHash === "" ? (
                        <span className="muted">—</span>
                      ) : (
                        <HashChip value={e.activePlanHash} />
                      )}
                    </td>
                    <td>
                      {e.approvedPlanHash === "" ? (
                        <span className="muted">none</span>
                      ) : (
                        <HashChip value={e.approvedPlanHash} />
                      )}
                      {e.planHashDiverged && (
                        <div className="pmx-detail">
                          <span className="badge warn">plan moved since approval</span>
                        </div>
                      )}
                    </td>
                    <td className="muted mono">
                      {e.approvedAt === null ? "—" : e.approvedAt.slice(0, 10)}
                    </td>
                  </tr>
                ))}
              </CyberTable>
            )}
          </DataPanel>
        )}
      />

      <CyberCard heading="What this page does not show" headingLevel={2}>
        <p className="rng-sub">
          The compiled topology, the OpenTofu plan, the apply and destroy gates and the verification
          report are all held by the worker and have no HTTP surface. Their tabs render a labelled
          offline example so the design can be reviewed; none of it is a reading of a cluster.
        </p>
      </CyberCard>
      </ProxmoxSection>
    </div>
  );
}
