import { Link } from 'react-router-dom'
import { AlertTriangle } from 'lucide-react'
import { Card, KeyValueGrid, ProviderBadge, StatusBadge } from '../../components'
import type { Deployment, EventItem, Scenario } from '../../models/types'

/** Replaceable slot: deployment card (portfolio grid). */
export function DeploymentCard({
  deployment,
  event,
  scenario,
}: {
  deployment: Deployment
  event?: EventItem
  scenario?: Scenario
}) {
  return (
    <Card
      heading={
        <Link to={`/deployments/${deployment.id}`} className="u-mono">
          {deployment.name}
        </Link>
      }
      actions={
        <>
          <StatusBadge state={deployment.state} />
          {deployment.drift && (
            <span
              className="c-badge c-badge--warn"
              title="Observed state differs from scenario version"
            >
              <AlertTriangle size={12} aria-hidden /> drift
            </span>
          )}
        </>
      }
    >
      <KeyValueGrid
        columns={3}
        items={[
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
            key: 'Scenario',
            value: scenario
              ? `${scenario.name} v${deployment.scenarioVersion}`
              : deployment.scenarioVersion,
          },
          {
            key: 'Event',
            value: event ? <Link to={`/events/${event.id}`}>{event.name}</Link> : '—',
          },
          { key: 'Health', value: <StatusBadge state={deployment.health} /> },
          {
            key: 'Cost to date',
            value:
              deployment.estimatedCostPerHour > 0
                ? `$${deployment.costToDate.toFixed(0)} · $${deployment.estimatedCostPerHour.toFixed(1)}/h`
                : '—',
          },
          { key: 'Owner', value: deployment.owner.split('@')[0] },
        ]}
      />
      <p className="u-muted u-xs" style={{ marginTop: 'var(--sp-2)' }}>
        {deployment.lastOperation}
      </p>
    </Card>
  )
}
