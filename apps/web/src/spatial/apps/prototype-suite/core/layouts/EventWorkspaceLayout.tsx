import { Outlet, useOutletContext, useParams } from 'react-router-dom'
import { PhaseTimeline, StatusBadge, WorkspaceTabs } from '../components'
import { ErrorState, LoadingState } from '../components/States'
import { useQuery } from '../integrations/AdapterContext'
import type { EventItem } from '../models/types'

export interface EventWorkspaceContext {
  event: EventItem
}

export function useEventWorkspace(): EventWorkspaceContext {
  return useOutletContext<EventWorkspaceContext>()
}

/**
 * Replaceable slot: event workspace frame — event header, phase strip, and
 * contextual tabs. Child routes receive the event via outlet context.
 */
export function EventWorkspaceLayout() {
  const { eventId = '' } = useParams()
  const { data: event, loading, error } = useQuery((a) => a.getEvent(eventId), [eventId])

  if (loading)
    return (
      <div className="u-page">
        <LoadingState lines={4} />
      </div>
    )
  if (error || !event)
    return (
      <div className="u-page">
        <ErrorState message={error ?? `Event ${eventId} not found in mock data.`} />
      </div>
    )

  const base = `/events/${event.id}`
  const activePhase = event.phases.find((p) => p.status === 'active')

  return (
    <div className="l-workspace">
      <header className="l-workspace__head">
        <div className="u-row" style={{ flexWrap: 'wrap' }}>
          <h1>{event.name}</h1>
          <StatusBadge state={event.status} />
          <StatusBadge state={event.health} />
          {activePhase && (
            <span className="u-secondary u-small">
              Phase: <strong>{activePhase.name}</strong>
            </span>
          )}
        </div>
        {event.phases.length > 1 && (
          <div className="l-workspace__phases">
            <PhaseTimeline phases={event.phases} />
          </div>
        )}
        <WorkspaceTabs
          tabs={[
            { to: base, label: 'Overview', end: true },
            { to: `${base}/control-room`, label: 'Control Room' },
            { to: `${base}/topology`, label: 'Topology' },
            { to: `${base}/teams`, label: 'Teams & Access' },
            { to: `${base}/operations`, label: 'Operations' },
            { to: `${base}/scoring`, label: 'Scoring' },
            { to: `${base}/reports`, label: 'Reports' },
          ]}
        />
      </header>
      <Outlet context={{ event } satisfies EventWorkspaceContext} />
    </div>
  )
}
