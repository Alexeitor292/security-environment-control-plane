import { Link, useNavigate } from 'react-router-dom'
import { Radio, Users } from 'lucide-react'
import {
  Button,
  Card,
  KeyValueGrid,
  PhaseTimeline,
  ProviderBadge,
  StatusBadge,
} from '../../components'
import type { Deployment, EventItem, Scenario } from '../../models/types'

/**
 * Replaceable slot: event card (Command Center + Events list).
 */
export function EventCard({
  event,
  scenario,
  deployments,
}: {
  event: EventItem
  scenario?: Scenario
  deployments: Deployment[]
}) {
  const navigate = useNavigate()
  const providers = [...new Set(deployments.map((d) => d.provider))]
  const upcoming = event.status === 'upcoming'

  return (
    <Card
      heading={
        <Link to={`/events/${event.id}`} className="u-row">
          {event.name}
        </Link>
      }
      actions={
        <>
          <StatusBadge state={event.status} />
          <StatusBadge state={event.health} />
        </>
      }
    >
      <div className="u-grid" style={{ gap: 'var(--sp-3)' }}>
        {event.phases.length > 1 && <PhaseTimeline phases={event.phases} />}
        <KeyValueGrid
          columns={3}
          items={[
            {
              key: 'Teams',
              value: (
                <span className="u-row">
                  <Users size={13} aria-hidden /> {event.teamIds.length || '—'}
                </span>
              ),
            },
            {
              key: 'Scenario',
              value: scenario ? `${scenario.name} v${event.scenarioVersion}` : '—',
            },
            { key: 'Deployments', value: deployments.length },
            {
              key: 'Connectivity',
              value: (
                <span className="u-row">
                  <Radio size={13} aria-hidden />
                  {event.totalParticipants > 0
                    ? `${event.connectedParticipants}/${event.totalParticipants}`
                    : '—'}
                </span>
              ),
            },
            {
              key: upcoming ? 'Starts' : 'Ends',
              value:
                (upcoming ? event.startsAt : event.endsAt).slice(0, 16).replace('T', ' ') + ' UTC',
            },
            {
              key: 'Providers',
              value: (
                <span className="u-row" style={{ flexWrap: 'wrap' }}>
                  {providers.length > 0
                    ? providers.map((p) => <ProviderBadge key={p} provider={p} />)
                    : '—'}
                </span>
              ),
            },
          ]}
        />
        <div className="u-row">
          <Button
            variant="primary"
            size="sm"
            onClick={() => navigate(`/events/${event.id}/control-room`)}
          >
            Open Control Room
          </Button>
          <Button variant="ghost" size="sm" onClick={() => navigate(`/events/${event.id}`)}>
            Overview
          </Button>
        </div>
      </div>
    </Card>
  )
}
