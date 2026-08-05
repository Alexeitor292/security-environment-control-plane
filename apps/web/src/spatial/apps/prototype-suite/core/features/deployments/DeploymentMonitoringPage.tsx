import { useMemo } from 'react'
import { Activity, GitCompareArrows } from 'lucide-react'
import {
  CapabilityNotice,
  Card,
  DataTable,
  KeyValueGrid,
  MetricRow,
  MetricTile,
  StatusBadge,
} from '../../components'
import type { Column } from '../../components'
import { useDeploymentWorkspace } from '../../layouts/DeploymentWorkspaceLayout'
import type { DeploymentResource, HealthState } from '../../models/types'

/** Security/scoring rows surface first — they watch everything else. */
const KIND_PRIORITY: Record<string, number> = {
  'security-tool': 0,
  'scoring-service': 1,
}

const DRIFT_DETAIL: Record<string, string[]> = {
  'dep-soak-aws': [
    'soak-dc-1 (i-0soakdc01): instance status checks failing since 11:32 UTC — observed state no longer matches the applied plan.',
    'Repair workflow retrying (attempt 2/5); pre-repair capture recorded in the evidence store.',
  ],
  'dep-purple-gcp': [
    'attack-orchestrator (gce/attack-1): Caldera chain-set configuration differs from scenario version 1.1.0.',
    'Chain Set B phase transition failed readiness checks on 07-16 as a result.',
  ],
}

export default function DeploymentMonitoringPage() {
  const { deployment } = useDeploymentWorkspace()

  const counts = useMemo(() => {
    const c: Record<HealthState, number> = { healthy: 0, degraded: 0, unhealthy: 0, unknown: 0 }
    for (const r of deployment.resources) c[r.health] += 1
    return c
  }, [deployment.resources])

  const ordered = useMemo(
    () =>
      [...deployment.resources].sort(
        (a, b) => (KIND_PRIORITY[a.kind] ?? 2) - (KIND_PRIORITY[b.kind] ?? 2),
      ),
    [deployment.resources],
  )

  const securityTools = deployment.resources.filter(
    (r) => r.kind === 'security-tool' || r.kind === 'scoring-service',
  )
  const driftLines = DRIFT_DETAIL[deployment.id]

  const columns: Column<DeploymentResource>[] = [
    {
      key: 'name',
      header: 'Resource',
      render: (r) => <span className="u-mono u-small">{r.name}</span>,
    },
    {
      key: 'kind',
      header: 'Kind',
      render: (r) => <span className="u-small">{r.kind.replace(/-/g, ' ')}</span>,
    },
    { key: 'health', header: 'Health', render: (r) => <StatusBadge state={r.health} /> },
    {
      key: 'detail',
      header: 'Signal (mock)',
      render: (r) => <span className="u-secondary u-xs">{r.detail ?? '—'}</span>,
    },
  ]

  return (
    <div className="u-page">
      <CapabilityNotice capKey="deployments.drift" />
      <p className="u-muted u-xs">
        All monitoring figures on this page are mock fixtures — no live telemetry pipeline exists.
      </p>

      <MetricRow>
        <MetricTile
          label="Healthy"
          value={counts.healthy}
          tone={
            counts.healthy === deployment.resources.length && counts.healthy > 0 ? 'ok' : undefined
          }
          detail={`of ${deployment.resources.length} resources (mock)`}
        />
        <MetricTile
          label="Degraded"
          value={counts.degraded}
          tone={counts.degraded > 0 ? 'warn' : undefined}
          detail="mock health rollup"
        />
        <MetricTile
          label="Unhealthy"
          value={counts.unhealthy}
          tone={counts.unhealthy > 0 ? 'error' : undefined}
          detail="mock health rollup"
        />
        <MetricTile label="Unknown" value={counts.unknown} detail="not yet reporting (mock)" />
      </MetricRow>

      <Card
        heading="Per-resource health"
        actions={<span className="u-muted u-xs">security & scoring rows first</span>}
      >
        <DataTable
          columns={columns}
          rows={ordered}
          rowKey={(r) => r.id}
          label="Per-resource health"
          emptyTitle="No realized resources"
          emptyBody="This deployment is plan-only — nothing reports health yet."
        />
      </Card>

      <div
        className="u-grid"
        style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))' }}
      >
        <Card
          heading="Monitoring coverage"
          actions={<Activity size={14} aria-hidden className="u-muted" />}
        >
          {securityTools.length === 0 ? (
            <p className="u-secondary u-small">
              No security-tool or scoring resources in this deployment — no agent coverage to
              report.
            </p>
          ) : (
            <KeyValueGrid
              columns={1}
              items={securityTools.map((r) => ({
                key: r.name,
                value: (
                  <span className="u-row">
                    <StatusBadge state={r.health} />
                    <span className="u-secondary u-xs">{r.detail ?? 'no coverage detail'}</span>
                  </span>
                ),
              }))}
            />
          )}
          <p className="u-muted u-xs" style={{ marginTop: 'var(--sp-2)' }}>
            Agent counts are mock — SECP-004 (Wazuh/telemetry) is not implemented.
          </p>
        </Card>

        <Card
          heading="Drift"
          actions={<GitCompareArrows size={14} aria-hidden className="u-muted" />}
        >
          {deployment.drift && driftLines ? (
            <>
              <StatusBadge state="degraded" label="drift detected" tone="warn" />
              <ul
                style={{ margin: 'var(--sp-2) 0 0', paddingLeft: 18 }}
                className="u-small u-secondary"
              >
                {driftLines.map((line) => (
                  <li key={line}>{line}</li>
                ))}
              </ul>
            </>
          ) : deployment.drift ? (
            <p className="u-secondary u-small">
              Drift flagged for this deployment; no per-resource comparison detail in the mock
              fixtures.
            </p>
          ) : (
            <p className="u-secondary u-small">
              No drift detected (mock) — observed inventory matches scenario version{' '}
              {deployment.scenarioVersion}.
            </p>
          )}
          <p className="u-muted u-xs" style={{ marginTop: 'var(--sp-2)' }}>
            Drift comparison against desired state is a design concept; only read-only inventory
            snapshots exist today.
          </p>
        </Card>
      </div>
    </div>
  )
}
