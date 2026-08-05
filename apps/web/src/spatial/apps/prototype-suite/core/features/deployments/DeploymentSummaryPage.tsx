import { Link } from 'react-router-dom'
import { AlertTriangle } from 'lucide-react'
import {
  AlertsList,
  CapabilityNotice,
  CapabilityTag,
  Card,
  KeyValueGrid,
  LoadingState,
  MetricRow,
  MetricTile,
  ProviderBadge,
  StatusBadge,
} from '../../components'
import { useQuery } from '../../integrations/AdapterContext'
import { useDeploymentWorkspace } from '../../layouts/DeploymentWorkspaceLayout'
import type { ResourceKind } from '../../models/types'

const fmt = (t?: string) => (t ? `${t.slice(0, 10)} ${t.slice(11, 16)} UTC` : '—')

const KIND_LABEL: Record<ResourceKind, string> = {
  vm: 'VMs',
  container: 'containers',
  network: 'networks',
  firewall: 'firewalls',
  storage: 'storage',
  gateway: 'gateways',
  'security-tool': 'security tools',
  'scoring-service': 'scoring services',
}

export default function DeploymentSummaryPage() {
  const { deployment } = useDeploymentWorkspace()
  const scenarioQ = useQuery((a) => a.getScenario(deployment.scenarioId), [deployment.scenarioId])
  const eventQ = useQuery(
    (a) => (deployment.eventId ? a.getEvent(deployment.eventId) : Promise.resolve(undefined)),
    [deployment.eventId],
  )
  const targetsQ = useQuery((a) => a.listTargets())
  const runsQ = useQuery(
    (a) => a.listWorkflowRuns({ deploymentId: deployment.id }),
    [deployment.id],
  )
  const alertsQ = useQuery((a) => a.listAlerts())

  const resources = deployment.resources
  const networks = resources.filter((r) => r.kind === 'network')
  const healthy = resources.filter((r) => r.health === 'healthy')
  const healthyPct =
    resources.length > 0 ? Math.round((healthy.length / resources.length) * 100) : undefined
  const target = (targetsQ.data ?? []).find((t) => t.id === deployment.targetId)
  const runs = runsQ.data ?? []
  const activeRuns = runs.filter(
    (r) => r.status === 'running' || r.status === 'retrying' || r.status === 'awaiting-approval',
  )
  const relatedAlerts = (alertsQ.data ?? []).filter((a) => a.deploymentId === deployment.id)

  const byKind = new Map<ResourceKind, number>()
  for (const r of resources) byKind.set(r.kind, (byKind.get(r.kind) ?? 0) + 1)
  const capacitySummary =
    resources.length === 0
      ? 'No realized resources yet (plan only)'
      : [...byKind.entries()].map(([kind, n]) => `${n} ${KIND_LABEL[kind]}`).join(' · ')

  return (
    <div className="u-page">
      <CapabilityNotice capKey="deployments.lifecycle" />

      <MetricRow>
        <MetricTile
          label="Resources"
          value={resources.length}
          detail="realized in this deployment"
        />
        <MetricTile label="Networks" value={networks.length} detail="segments / VPCs" />
        <MetricTile
          label="Healthy"
          value={healthyPct !== undefined ? `${healthyPct}%` : '—'}
          tone={
            healthyPct === undefined
              ? undefined
              : healthyPct === 100
                ? 'ok'
                : healthyPct >= 80
                  ? 'warn'
                  : 'error'
          }
          detail={
            resources.length > 0
              ? `${healthy.length}/${resources.length} resources`
              : 'nothing provisioned'
          }
        />
        <MetricTile
          label="Cost to date"
          value={deployment.estimatedCostPerHour > 0 ? `$${deployment.costToDate.toFixed(0)}` : '—'}
          detail="mock figure — cost tracking is planned"
        />
      </MetricRow>

      <Card heading="Deployment record">
        <KeyValueGrid
          columns={3}
          items={[
            {
              key: 'Scenario version',
              value: (
                <Link to={`/scenarios/${deployment.scenarioId}`}>
                  {scenarioQ.data
                    ? `${scenarioQ.data.name} v${deployment.scenarioVersion}`
                    : `v${deployment.scenarioVersion}`}
                </Link>
              ),
            },
            {
              key: 'Event',
              value: eventQ.data ? (
                <Link to={`/events/${eventQ.data.id}`}>{eventQ.data.name}</Link>
              ) : (
                '—'
              ),
            },
            {
              key: 'Provider',
              value: (
                <span className="u-row">
                  <ProviderBadge provider={deployment.provider} />
                  <span className="u-muted u-xs">{deployment.region}</span>
                </span>
              ),
            },
            {
              key: 'Execution target',
              value: (
                <Link to="/infrastructure/targets">
                  {target ? target.name : deployment.targetId}
                </Link>
              ),
            },
            {
              key: 'State / health',
              value: (
                <span className="u-row">
                  <StatusBadge state={deployment.state} />
                  <StatusBadge state={deployment.health} />
                </span>
              ),
            },
            {
              key: 'Drift',
              value: deployment.drift ? (
                <span
                  className="c-badge c-badge--warn"
                  title="Observed state differs from the pinned scenario version"
                >
                  <AlertTriangle size={12} aria-hidden /> drift detected
                </span>
              ) : (
                <span className="u-secondary u-small">none detected</span>
              ),
            },
            {
              key: 'Cost (est vs observed)',
              value: (
                <span className="u-row">
                  <span>
                    {deployment.estimatedCostPerHour > 0
                      ? `$${deployment.estimatedCostPerHour.toFixed(1)}/h est · $${deployment.costToDate.toFixed(1)} to date`
                      : '—'}
                  </span>
                  <CapabilityTag status="planned" />
                </span>
              ),
            },
            { key: 'Capacity', value: <span className="u-small">{capacitySummary}</span> },
            { key: 'Created', value: fmt(deployment.createdAt), mono: true },
            { key: 'Expires', value: fmt(deployment.expiresAt), mono: true },
            { key: 'Owner', value: deployment.owner, mono: true },
            {
              key: 'Last operation',
              value: <span className="u-small">{deployment.lastOperation}</span>,
            },
          ]}
        />
      </Card>

      <div
        className="u-grid"
        style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))' }}
      >
        <Card heading="Current workflow runs">
          {runsQ.loading ? (
            <LoadingState lines={3} />
          ) : runs.length === 0 ? (
            <p className="u-secondary u-small">No workflow runs recorded for this deployment.</p>
          ) : (
            <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
              {(activeRuns.length > 0 ? activeRuns : runs).map((r) => (
                <li key={r.id} style={{ padding: '6px 0' }}>
                  <div className="u-spread">
                    <span className="u-small">{r.name}</span>
                    <StatusBadge state={r.status} />
                  </div>
                  <p className="u-muted u-xs u-mono">
                    {fmt(r.startedAt)} · {r.taskQueue} ·{' '}
                    {r.steps.filter((s) => s.status === 'complete').length}/{r.steps.length} steps
                  </p>
                </li>
              ))}
            </ul>
          )}
          <p className="u-muted u-xs" style={{ marginTop: 'var(--sp-2)' }}>
            Full step detail on the Operations tab.
          </p>
        </Card>

        <Card heading="Recent related alerts">
          {alertsQ.loading ? <LoadingState lines={3} /> : <AlertsList alerts={relatedAlerts} />}
        </Card>
      </div>
    </div>
  )
}
