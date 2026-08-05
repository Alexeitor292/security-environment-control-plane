import "./range.css";

import { useMemo } from "react";

import { api } from "../../api/client";
import {
  CyberCard,
  CyberTable,
  DataPanel,
  EmptyState,
  MetricTile,
  SafetyNotice,
  StatusBadge,
  shortId,
} from "../../components/ui";
import { useAsync } from "../../hooks";
import { useRange } from "./RangeLayout";
import { RANGE_PHASE_LABEL, hasLiveInfrastructure } from "./range-lifecycle";
import {
  ACCESS_IS_OBSERVED_NOTE,
  VULNERABLE_SOFTWARE_NOTE,
  accessRows,
  reachabilityText,
  resourceRows,
} from "./range-view";

/**
 * Page 4 — Range Overview, including how to reach the targets.
 *
 * `access[]` comes straight off the range and is the point of the whole product: a URL an operator
 * can click. `reachable` is the server's OBSERVED value — a target that answered. It is never
 * inferred from the container existing, and a target the server never probed is shown as "not
 * checked" rather than as unreachable, because those are different facts.
 */
export function RangeOverview() {
  const { range, lifecycle } = useRange();

  // Re-read when the range changes so a completed deploy fills these in without a manual refresh.
  const resources = useAsync(
    () => api.listRangeResources(range.id),
    [range.id, range.updated_at],
  );

  const access = useMemo(() => accessRows(range), [range]);
  const rows = useMemo(
    () => (resources.data ? resourceRows(resources.data) : []),
    [resources.data],
  );
  const live = hasLiveInfrastructure(lifecycle.phase);
  const reachable = access.filter((a) => a.reachable).length;

  return (
    <div className="rng">
      <div className="rng-grid">
        <MetricTile
          label="State"
          value={RANGE_PHASE_LABEL[lifecycle.phase]}
          detail={`recorded: ${lifecycle.recorded}`}
        />
        <MetricTile
          label="Reachable targets"
          value={access.length === 0 ? "—" : `${reachable} of ${access.length}`}
          detail={
            access.length === 0
              ? "No access details recorded in this state."
              : "Observed by the server, not inferred"
          }
          tone={access.length > 0 && reachable === access.length ? "ok" : "default"}
        />
        <MetricTile
          label="Resources"
          value={resources.data === null ? "—" : rows.length}
          detail={
            resources.data === null
              ? "Resource list unavailable."
              : "Containers and networks this range owns"
          }
        />
      </div>

      <CyberCard heading="Access" headingLevel={2}>
        <SafetyNotice role="note" tone="info">
          {ACCESS_IS_OBSERVED_NOTE}
        </SafetyNotice>

        {!live && access.length === 0 && (
          <SafetyNotice role="status" tone="warn">
            This range is {RANGE_PHASE_LABEL[lifecycle.phase].toLowerCase()}. The server records
            access details only while a range is ready or active.
          </SafetyNotice>
        )}

        {access.length === 0 ? (
          <EmptyState title="No access details">
            Nothing to reach in this state. Deploy the range to get target URLs.
          </EmptyState>
        ) : (
          <CyberTable
            label="Access targets"
            head={["Target", "URL", "Port", "Observed", "Last checked"]}
            caption={`${access.length} target${access.length === 1 ? "" : "s"} · "responded" means the server got an actual response`}
          >
            {access.map((a) => (
              <tr key={a.componentKey}>
                <td>{a.name}</td>
                <td>
                  {/* A real link to a real local service. rel=noreferrer on an intentionally
                      vulnerable target so its pages cannot see where the operator came from. */}
                  <a href={a.url} target="_blank" rel="noreferrer noopener" className="mono">
                    {a.url}
                  </a>
                </td>
                <td className="muted mono">{a.port}</td>
                <td>
                  <StatusBadge
                    state={a.observedAt === null ? "unproven" : a.reachable ? "verified" : "failed"}
                    domain="range-operation"
                  />
                  <span className="muted"> {reachabilityText(a)}</span>
                </td>
                <td className="muted mono">
                  {a.observedAt === null ? "never" : a.observedAt.slice(11, 19)}
                </td>
              </tr>
            ))}
          </CyberTable>
        )}
      </CyberCard>

      <CyberCard heading="Resources" headingLevel={2}>
        <DataPanel
          state={resources}
          isEmpty={() => rows.length === 0}
          empty={
            <EmptyState title="No resources recorded">
              Resources are created when the range is deployed.
            </EmptyState>
          }
        >
          {() => (
            <CyberTable
              label="Range resources"
              head={["Kind", "Name", "State", "Image", "Host port"]}
              caption={`${rows.length} resource${rows.length === 1 ? "" : "s"} owned by this range`}
            >
              {rows.map((r) => (
                <tr key={r.id}>
                  <td className="muted">{r.kind}</td>
                  <td className="mono" title={r.externalId ?? undefined}>
                    {r.name}
                  </td>
                  <td>
                    <StatusBadge state={r.state} domain="range-operation" />
                  </td>
                  <td className="muted mono" title={r.imageDigest ?? undefined}>
                    {r.image === null ? "—" : r.image}
                    {r.imageDigest !== null && (
                      <span className="muted"> ({shortId(r.imageDigest)})</span>
                    )}
                  </td>
                  <td className="muted mono">{r.hostPort === null ? "—" : r.hostPort}</td>
                </tr>
              ))}
            </CyberTable>
          )}
        </DataPanel>
      </CyberCard>

      <SafetyNotice role="note" tone="warn">
        {VULNERABLE_SOFTWARE_NOTE}
      </SafetyNotice>
    </div>
  );
}
