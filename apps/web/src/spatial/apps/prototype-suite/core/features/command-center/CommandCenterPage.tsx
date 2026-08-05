import { Link } from 'react-router-dom'
import { CalendarClock, ShieldCheck } from 'lucide-react'
import {
  AlertsList,
  Card,
  CardGrid,
  ErrorState,
  LoadingState,
  MetricRow,
  MetricTile,
  PageHeader,
  ProviderBadge,
  StatusBadge,
} from '../../components'
import { useQuery } from '../../integrations/AdapterContext'
import type { Provider } from '../../models/types'
import { EventCard } from '../events/EventCard'

const UPCOMING_ACTIVITY = [
  { id: 'up-1', time: '2026-07-18 14:00 UTC', label: 'Aurora Cup — Verification phase expected' },
  { id: 'up-2', time: '2026-07-18 20:00 UTC', label: 'Q3 Ransomware Drill — recovery drill ends' },
  { id: 'up-3', time: '2026-07-19 10:00 UTC', label: 'aurora-soak-test — scheduled destruction' },
  {
    id: 'up-4',
    time: '2026-07-25 08:00 UTC',
    label: 'University CTF Qualifier — staging deployment apply',
  },
  {
    id: 'up-5',
    time: '2026-07-25 00:00 UTC',
    label: 'Azure service principal — credential rotation due',
  },
  { id: 'up-6', time: '2026-07-27 09:00 UTC', label: 'University CTF Qualifier — event start' },
]

export default function CommandCenterPage() {
  const eventsQ = useQuery((a) => a.listEvents())
  const deploymentsQ = useQuery((a) => a.listDeployments())
  const teamsQ = useQuery((a) => a.listTeams())
  const alertsQ = useQuery((a) => a.listAlerts())
  const approvalsQ = useQuery((a) => a.listApprovals())
  const targetsQ = useQuery((a) => a.listTargets())
  const scenariosQ = useQuery((a) => a.listScenarios())

  if (eventsQ.loading || deploymentsQ.loading) {
    return (
      <div className="u-page">
        <LoadingState lines={6} />
      </div>
    )
  }
  if (eventsQ.error || !eventsQ.data || !deploymentsQ.data) {
    return (
      <div className="u-page">
        <ErrorState message={eventsQ.error ?? 'Mock data unavailable.'} />
      </div>
    )
  }

  const events = eventsQ.data
  const deployments = deploymentsQ.data
  const activeEvents = events.filter((e) => e.status === 'active' || e.status === 'paused')
  const runningDeployments = deployments.filter(
    (d) => d.state === 'running' || d.state === 'provisioning' || d.state === 'degraded',
  )
  const alerts = alertsQ.data ?? []
  const criticalAlerts = alerts.filter((a) => a.severity === 'critical' && !a.acknowledged)
  const pendingApprovals = (approvalsQ.data ?? []).filter((a) => a.status === 'pending')
  const teams = teamsQ.data ?? []
  const connectedTeams = teams.filter((t) => t.connection === 'connected')
  const targets = targetsQ.data ?? []
  const capacityWorst = targets.reduce((max, t) => Math.max(max, t.capacity.usedPercent), 0)

  const byProvider = new Map<Provider, typeof deployments>()
  for (const d of deployments) {
    byProvider.set(d.provider, [...(byProvider.get(d.provider) ?? []), d])
  }

  return (
    <div className="u-page">
      <PageHeader
        title="Command Center"
        description="Organization-wide view: what is running, what needs attention, and what happens next. All data is mock."
      />

      <MetricRow>
        <MetricTile
          label="Active events"
          value={activeEvents.length}
          detail={`${events.length} total`}
        />
        <MetricTile
          label="Running deployments"
          value={runningDeployments.length}
          detail={`${deployments.length} in portfolio`}
        />
        <MetricTile
          label="Connected teams"
          value={teamsQ.data ? `${connectedTeams.length}/${teams.length}` : '—'}
          detail="across active events"
        />
        <MetricTile
          label="Critical alerts"
          value={criticalAlerts.length}
          tone={criticalAlerts.length > 0 ? 'error' : 'ok'}
          detail="unacknowledged"
        />
        <MetricTile
          label="Pending approvals"
          value={pendingApprovals.length}
          tone={pendingApprovals.length > 0 ? 'info' : undefined}
          detail="decided on owning surfaces"
        />
        <MetricTile
          label="Capacity headroom"
          value={targetsQ.data ? `${100 - capacityWorst}%` : '—'}
          tone={capacityWorst > 80 ? 'warn' : undefined}
          detail={targetsQ.data ? 'worst target: Main Proxmox' : 'targets unavailable'}
        />
      </MetricRow>

      <section aria-label="Active events">
        <div className="u-spread" style={{ marginBottom: 'var(--sp-2)' }}>
          <h2 className="u-small" style={{ textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Active events
          </h2>
          <Link to="/events" className="u-small">
            All events →
          </Link>
        </div>
        <CardGrid min={360}>
          {activeEvents.map((event) => (
            <EventCard
              key={event.id}
              event={event}
              scenario={scenariosQ.data?.find((s) => s.id === event.scenarioId)}
              deployments={deployments.filter((d) => d.eventId === event.id)}
            />
          ))}
        </CardGrid>
      </section>

      <div
        className="u-grid"
        style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))' }}
      >
        <Card
          heading="Needs attention"
          actions={
            <Link to="/events" className="u-xs">
              triage
            </Link>
          }
        >
          <AlertsList alerts={alerts} compact />
        </Card>

        <Card
          heading="Deployment portfolio"
          actions={
            <Link to="/deployments" className="u-xs">
              open
            </Link>
          }
        >
          <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
            {[...byProvider.entries()].map(([provider, list]) => (
              <li key={provider} className="u-spread" style={{ padding: '6px 0' }}>
                <ProviderBadge provider={provider} />
                <span
                  className="u-row u-small"
                  style={{ flexWrap: 'wrap', justifyContent: 'flex-end' }}
                >
                  {list.map((d) => (
                    <Link key={d.id} to={`/deployments/${d.id}`} title={d.name}>
                      <StatusBadge state={d.state} />
                    </Link>
                  ))}
                </span>
              </li>
            ))}
          </ul>
          <p className="u-muted u-xs" style={{ marginTop: 'var(--sp-2)' }}>
            Cloud providers are not implemented in the platform today — portfolio shown with mock
            data.
          </p>
        </Card>

        <Card
          heading="Pending approvals"
          actions={<ShieldCheck size={14} aria-hidden className="u-muted" />}
        >
          {pendingApprovals.length === 0 ? (
            <p className="u-secondary u-small">Nothing awaiting decision.</p>
          ) : (
            <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
              {pendingApprovals.map((a) => (
                <li key={a.id} style={{ padding: '6px 0' }}>
                  <div className="u-spread">
                    <strong className="u-small">{a.title}</strong>
                    <StatusBadge
                      state={a.riskLevel}
                      label={`risk: ${a.riskLevel}`}
                      tone={a.riskLevel === 'high' || a.riskLevel === 'critical' ? 'error' : 'warn'}
                    />
                  </div>
                  <p className="u-muted u-xs">{a.scope}</p>
                </li>
              ))}
            </ul>
          )}
          <p className="u-muted u-xs">Approvals are decided on the owning surface, never here.</p>
        </Card>

        <Card
          heading="Upcoming activity"
          actions={<CalendarClock size={14} aria-hidden className="u-muted" />}
        >
          <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
            {UPCOMING_ACTIVITY.map((item) => (
              <li key={item.id} style={{ padding: '5px 0' }} className="u-small">
                <span className="u-muted u-xs u-mono" style={{ display: 'block' }}>
                  {item.time}
                </span>
                {item.label}
              </li>
            ))}
          </ul>
        </Card>
      </div>
    </div>
  )
}
