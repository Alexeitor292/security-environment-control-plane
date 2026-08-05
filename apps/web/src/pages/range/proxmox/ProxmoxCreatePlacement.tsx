import "./proxmox.css";

import { useMemo } from "react";

import { api } from "../../../api/client";
import {
  CyberTable,
  DataPanel,
  EmptyState,
  HashChip,
  SafetyNotice,
  StatusBadge,
  shortId,
} from "../../../components/ui";
import { useAsync } from "../../../hooks";
import { SourcedPanel } from "./SourcedPanel";
import { live } from "./provenance";
import { NO_BINDING_NOTE, healthyWorkers, targetRows, workerRows } from "./placement-view";

export const CREATE_PLACEMENT_INTRO =
  "This blueprint runs on Proxmox. Before creating it, this is what the control plane currently has to run it on.";

/**
 * The target-selection step of the Proxmox create flow — as far as the backend contract permits.
 *
 * It shows the registered Proxmox targets and the enrolled workers, live, so the operator can see
 * whether a Proxmox range could run at all before creating one. What it deliberately does NOT do is
 * offer a selection: `RangeCreate` accepts `template_slug` and an optional `name` and nothing else,
 * so a target picker here would be a control that discards the operator's choice on submit. A
 * control that silently drops its input is worse than no control, and far worse than a sentence
 * explaining why there is none.
 *
 * When the create contract grows a target binding, this component is where the picker goes.
 */
export function ProxmoxCreatePlacement() {
  const targets = useAsync(() => api.listTargets(), []);
  const enrollments = useAsync(() => api.listEnrollments({ limit: 50 }), []);
  const workerNodes = useAsync(() => api.listWorkerNodes(), []);

  const pveTargets = useMemo(
    () => (targets.data ? targetRows(targets.data) : []),
    [targets.data],
  );
  const workers = useMemo(
    () => workerRows(enrollments.data?.items ?? [], workerNodes.data ?? []),
    [enrollments.data, workerNodes.data],
  );
  const healthy = useMemo(() => healthyWorkers(workers), [workers]);

  return (
    <>
      <p className="rng-sub">{CREATE_PLACEMENT_INTRO}</p>

      <SafetyNotice role="note" tone="warn">
        {NO_BINDING_NOTE}
      </SafetyNotice>

      <SourcedPanel
        heading="Available Proxmox targets"
        headingLevel={3}
        record={live("GET /api/v1/targets", pveTargets)}
        render={(rows) => (
          <DataPanel
            state={targets}
            isEmpty={() => rows.length === 0}
            empty={
              <EmptyState title="No Proxmox target registered">
                Creating this range would record a draft, but there is no registered Proxmox target
                for it to be placed on.
              </EmptyState>
            }
          >
            {() => (
              <CyberTable
                label="Available Proxmox targets"
                head={["Target", "Status", "Config hash"]}
                caption={`${rows.length} registered target${rows.length === 1 ? "" : "s"} · placement is decided server-side`}
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
                  </tr>
                ))}
              </CyberTable>
            )}
          </DataPanel>
        )}
      />

      <SourcedPanel
        heading="Workers that could run it"
        headingLevel={3}
        record={live("GET /api/v1/enrollment", healthy)}
        render={(rows) => (
          <DataPanel
            state={enrollments}
            isEmpty={() => rows.length === 0}
            empty={
              <EmptyState title="No healthy worker">
                No enrollment is in the healthy state. A Proxmox range created now would sit in
                draft with nothing able to deploy it.
              </EmptyState>
            }
          >
            {() => (
              <CyberTable
                label="Healthy workers"
                head={["Worker", "State", "Release"]}
                caption={`${rows.length} healthy of ${workers.length} known · only a healthy enrollment can take work`}
              >
                {rows.map((w) => (
                  <tr key={w.key}>
                    <td className="mono">
                      {w.nodeLabel ?? (w.workerInstallationId === null ? "—" : shortId(w.workerInstallationId))}
                    </td>
                    <td>
                      <StatusBadge state={w.enrollmentState ?? "invited"} domain="enrollment" />
                    </td>
                    <td>
                      {w.releaseFingerprint === null ? (
                        <span className="muted">—</span>
                      ) : (
                        <HashChip value={w.releaseFingerprint} />
                      )}
                    </td>
                  </tr>
                ))}
              </CyberTable>
            )}
          </DataPanel>
        )}
      />
    </>
  );
}
