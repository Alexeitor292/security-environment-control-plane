import {
  CapabilityNotice,
  Card,
  CardGrid,
  EmptyState,
  ErrorState,
  KeyValueGrid,
  LoadingState,
  Scoreboard,
  StatusBadge,
} from '../../components'
import { useQuery } from '../../integrations/AdapterContext'
import { useEventWorkspace } from '../../layouts/EventWorkspaceLayout'

const SCORING_MODEL = [
  {
    component: 'Defense',
    detail:
      'Hardening checks against each team’s scored systems: patched services, closed misconfigurations, surviving injects.',
  },
  {
    component: 'Availability',
    detail:
      'Periodic uptime checks on scored services. Downtime — including operator resets — costs points.',
  },
  {
    component: 'Attack',
    detail:
      'Flags captured from opponent zones once the attack phase opens routes; submitted via the scoreboard portal.',
  },
  {
    component: 'Penalties',
    detail:
      'Deductions for rule violations and approved resets, applied by event operators with an audit trail.',
  },
]

export default function EventScoringPage() {
  const { event } = useEventWorkspace()
  const scoresQ = useQuery((a) => a.listScores(event.id), [event.id])
  const teamsQ = useQuery((a) => a.listTeams(event.id), [event.id])

  if (scoresQ.loading || teamsQ.loading) {
    return (
      <div className="u-page">
        <LoadingState lines={6} />
      </div>
    )
  }
  if (!scoresQ.data || !teamsQ.data) {
    return (
      <div className="u-page">
        <ErrorState message={scoresQ.error ?? teamsQ.error ?? 'Mock data unavailable.'} />
      </div>
    )
  }

  const scores = scoresQ.data
  const teams = teamsQ.data

  return (
    <div className="u-page">
      <CapabilityNotice capKey="events.scoring" />

      {scores.length === 0 ? (
        <EmptyState
          title="No scores for this event"
          body={
            event.scoringEnabled
              ? 'Scoring is enabled but no standings exist in the mock data yet.'
              : 'Scoring is disabled for this event.'
          }
        />
      ) : (
        <>
          <Card
            heading="Standings"
            actions={<span className="u-muted u-xs">mock data · SECP-004</span>}
          >
            <Scoreboard scores={scores} teams={teams} detailed />
          </Card>

          <section aria-label="Per-team breakdown">
            <h2
              className="u-small"
              style={{
                textTransform: 'uppercase',
                letterSpacing: '0.06em',
                marginBottom: 'var(--sp-2)',
              }}
            >
              Per-team breakdown
            </h2>
            <CardGrid min={280}>
              {scores.map((s) => {
                const team = teams.find((t) => t.id === s.teamId)
                return (
                  <Card
                    key={s.teamId}
                    heading={
                      <span
                        className="c-matrix__team"
                        style={{ ['--team' as string]: team?.color }}
                      >
                        {team?.name ?? s.teamId}
                      </span>
                    }
                    actions={
                      <span className="u-row">
                        <span className="u-muted u-xs">#{s.rank}</span>
                        <StatusBadge
                          state={s.trend}
                          label={
                            s.trend === 'up' ? 'rising' : s.trend === 'down' ? 'falling' : 'steady'
                          }
                          tone={s.trend === 'up' ? 'ok' : s.trend === 'down' ? 'warn' : 'neutral'}
                        />
                      </span>
                    }
                  >
                    <KeyValueGrid
                      columns={2}
                      items={[
                        { key: 'Total', value: <strong>{s.total.toLocaleString()}</strong> },
                        { key: 'Defense', value: s.defense.toLocaleString() },
                        { key: 'Availability', value: s.availability.toLocaleString() },
                        { key: 'Attack', value: s.attack.toLocaleString() },
                        {
                          key: 'Penalties',
                          value: (
                            <span
                              style={
                                s.penalties < 0
                                  ? { color: 'var(--status-error, #f87171)' }
                                  : undefined
                              }
                            >
                              {s.penalties.toLocaleString()}
                            </span>
                          ),
                        },
                        {
                          key: 'Connection',
                          value: team ? <StatusBadge state={team.connection} /> : '—',
                        },
                      ]}
                    />
                  </Card>
                )
              })}
            </CardGrid>
          </section>
        </>
      )}

      <Card heading="Scoring model">
        <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
          {SCORING_MODEL.map((m) => (
            <li key={m.component} style={{ padding: '5px 0' }} className="u-small">
              <strong>{m.component}</strong>
              <span className="u-secondary" style={{ display: 'block' }}>
                {m.detail}
              </span>
            </li>
          ))}
        </ul>
        <p className="u-muted u-xs" style={{ marginTop: 'var(--sp-2)' }}>
          Total = defense + availability + attack + penalties. The scoring pipeline
          (Wazuh/CTFd/telemetry, SECP-004) is not implemented — every figure on this page is mock
          fixture data.
        </p>
      </Card>
    </div>
  )
}
