import { Link } from 'react-router-dom'
import { CalendarClock, Megaphone } from 'lucide-react'
import {
  AlertsList,
  Card,
  ErrorState,
  KeyValueGrid,
  LoadingState,
  MetricRow,
  MetricTile,
  ProviderBadge,
  StatusBadge,
  Timeline,
} from '../../components'
import type { TimelineEntry } from '../../components'
import { useQuery } from '../../integrations/AdapterContext'
import { useEventWorkspace } from '../../layouts/EventWorkspaceLayout'

/**
 * Static mock reference clock (matches the fixture dataset, never Date.now()):
 * all countdown strings are derived against 2026-07-18T13:00Z.
 */
const REF_NOW = '2026-07-18T13:00:00Z'

function spanFrom(iso: string): string {
  const diff = Math.abs(Date.parse(iso) - Date.parse(REF_NOW))
  const hours = Math.floor(diff / 3_600_000)
  const mins = Math.floor((diff % 3_600_000) / 60_000)
  return `${hours}h ${mins.toString().padStart(2, '0')}m`
}

function fmt(iso: string): string {
  return iso.slice(0, 16).replace('T', ' ') + ' UTC'
}

export default function EventOverviewPage() {
  const { event } = useEventWorkspace()
  const teamsQ = useQuery((a) => a.listTeams(event.id), [event.id])
  const deploymentsQ = useQuery((a) => a.listDeployments())
  const alertsQ = useQuery((a) => a.listAlerts())
  const auditQ = useQuery((a) => a.listAuditEvents())

  if (teamsQ.loading || deploymentsQ.loading) {
    return (
      <div className="u-page">
        <LoadingState lines={6} />
      </div>
    )
  }
  if (!teamsQ.data || !deploymentsQ.data) {
    return (
      <div className="u-page">
        <ErrorState message={teamsQ.error ?? deploymentsQ.error ?? 'Mock data unavailable.'} />
      </div>
    )
  }

  const teams = teamsQ.data
  const eventDeployments = deploymentsQ.data.filter((d) => event.deploymentIds.includes(d.id))
  const eventAlerts = (alertsQ.data ?? []).filter((a) => a.eventId === event.id)

  const connectedTeams = teams.filter((t) => t.connection === 'connected').length
  const healthyDeployments = eventDeployments.filter((d) => d.health === 'healthy').length
  const healthyGateways = teams.filter((t) => t.gatewayHealth === 'healthy').length
  const scoringDeployment = eventDeployments.find((d) =>
    d.resources.some((r) => r.kind === 'scoring-service'),
  )

  const countdown =
    event.status === 'upcoming'
      ? { value: spanFrom(event.startsAt), detail: `until start (${fmt(event.startsAt)})` }
      : event.status === 'completed' || event.status === 'archived'
        ? { value: '—', detail: `ended ${fmt(event.endsAt)}` }
        : { value: spanFrom(event.endsAt), detail: `until end (${fmt(event.endsAt)})` }

  // Client-side filter: audit resources mentioning this event, its deployments, or its teams.
  const needles = [event.id, ...event.deploymentIds, ...event.teamIds]
  const activity: TimelineEntry[] = (auditQ.data ?? [])
    .filter((a) =>
      needles.some((n) => a.resource.includes(n) || a.resource.includes(n.replace('team-', ''))),
    )
    .slice(0, 8)
    .map((a) => ({
      id: a.id,
      time: fmt(a.time),
      title: (
        <span className="u-small">
          <span className="u-mono">{a.action}</span> · {a.actor}
        </span>
      ),
      detail: a.resource,
      tone: a.outcome === 'success' ? 'ok' : 'error',
    }))

  return (
    <div className="u-page">
      <MetricRow>
        <MetricTile
          label="Team readiness"
          value={teams.length > 0 ? `${connectedTeams}/${teams.length}` : '—'}
          tone={teams.length === 0 ? undefined : connectedTeams < teams.length ? 'warn' : 'ok'}
          detail={teams.length > 0 ? 'teams fully connected' : 'no teams provisioned yet'}
        />
        <MetricTile
          label="Deployment readiness"
          value={
            eventDeployments.length > 0 ? `${healthyDeployments}/${eventDeployments.length}` : '—'
          }
          tone={
            eventDeployments.length === 0
              ? undefined
              : healthyDeployments < eventDeployments.length
                ? 'warn'
                : 'ok'
          }
          detail={eventDeployments.length > 0 ? 'deployments healthy' : 'nothing deployed yet'}
        />
        <MetricTile
          label="Access readiness"
          value={teams.length > 0 ? `${healthyGateways}/${teams.length}` : '—'}
          tone={teams.length === 0 ? undefined : healthyGateways < teams.length ? 'warn' : 'ok'}
          detail={teams.length > 0 ? 'team gateways healthy' : 'no gateways issued'}
        />
        <MetricTile
          label="Scoring readiness"
          value={
            !event.scoringEnabled ? '—' : scoringDeployment ? scoringDeployment.health : 'pending'
          }
          tone={
            !event.scoringEnabled
              ? undefined
              : scoringDeployment?.health === 'healthy'
                ? 'ok'
                : 'warn'
          }
          detail={
            !event.scoringEnabled
              ? 'scoring disabled for this event'
              : scoringDeployment
                ? `${scoringDeployment.name} (mock scores)`
                : 'scoring stack not deployed'
          }
        />
        <MetricTile
          label={event.status === 'upcoming' ? 'Starts in' : 'Time remaining'}
          value={countdown.value}
          detail={`${countdown.detail} · vs ${REF_NOW.slice(11, 16)} UTC mock clock`}
        />
      </MetricRow>

      <div
        className="u-grid"
        style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))' }}
      >
        <Card
          heading="Schedule & rules"
          actions={<CalendarClock size={14} aria-hidden className="u-muted" />}
        >
          <KeyValueGrid
            columns={2}
            items={[
              { key: 'Starts', value: fmt(event.startsAt) },
              { key: 'Ends', value: fmt(event.endsAt) },
              { key: 'Type', value: event.type.replace(/-/g, ' ') },
              { key: 'Scenario version', value: `v${event.scenarioVersion}`, mono: true },
            ]}
          />
          {event.rules.length > 0 ? (
            <ul
              style={{ margin: 'var(--sp-2) 0 0', paddingLeft: 18 }}
              className="u-small u-secondary"
            >
              {event.rules.map((r) => (
                <li key={r}>{r}</li>
              ))}
            </ul>
          ) : (
            <p className="u-secondary u-small" style={{ marginTop: 'var(--sp-2)' }}>
              No rules recorded for this event.
            </p>
          )}
        </Card>

        <Card heading="Outstanding issues">
          <AlertsList alerts={eventAlerts} />
        </Card>

        <Card
          heading="Deployments"
          actions={
            <Link to="/deployments" className="u-xs">
              portfolio
            </Link>
          }
        >
          {eventDeployments.length === 0 ? (
            <p className="u-secondary u-small">No deployments linked to this event yet.</p>
          ) : (
            <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
              {eventDeployments.map((d) => (
                <li key={d.id} className="u-spread" style={{ padding: '6px 0' }}>
                  <span className="u-small">
                    <Link to={`/deployments/${d.id}`}>{d.name}</Link>
                    <span className="u-muted u-xs" style={{ display: 'block' }}>
                      {d.resources.length} resources · {d.region}
                    </span>
                  </span>
                  <span className="u-row">
                    <ProviderBadge provider={d.provider} />
                    <StatusBadge state={d.state} />
                    <StatusBadge state={d.health} />
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card
          heading="Announcements"
          actions={<Megaphone size={14} aria-hidden className="u-muted" />}
        >
          {event.announcements.length === 0 ? (
            <p className="u-secondary u-small">No announcements yet.</p>
          ) : (
            <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
              {event.announcements.map((ann) => (
                <li key={ann.id} style={{ padding: '5px 0' }} className="u-small">
                  <span className="u-muted u-xs u-mono" style={{ display: 'block' }}>
                    {ann.time.slice(11, 16)} UTC · {ann.author}
                  </span>
                  {ann.message}
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card heading="Recent operator activity">
          {activity.length === 0 ? (
            <p className="u-secondary u-small">No audit activity recorded for this event.</p>
          ) : (
            <Timeline entries={activity} />
          )}
          <p className="u-muted u-xs" style={{ marginTop: 'var(--sp-2)' }}>
            Filtered client-side from the audit ledger (implemented capability) by event,
            deployment, and team identifiers.
          </p>
        </Card>
      </div>
    </div>
  )
}
