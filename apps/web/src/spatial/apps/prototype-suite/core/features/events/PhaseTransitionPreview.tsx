import { ArrowRight, CheckCircle2, XCircle } from 'lucide-react'
import { Drawer, KeyValueGrid, StatusBadge } from '../../components'
import { Button } from '../../components'
import type { CompetitionPhase, EventItem } from '../../models/types'

/**
 * Replaceable slot: phase-transition preview.
 *
 * A phase transition is a controlled operation, never a toggle: the preview
 * shows exactly what would change, the readiness checks, and the required
 * approvals. The prototype's confirm action only closes the drawer.
 */
export function PhaseTransitionPreview({
  open,
  event,
  from,
  to,
  onClose,
}: {
  open: boolean
  event: EventItem
  from: CompetitionPhase
  to: CompetitionPhase
  onClose: () => void
}) {
  const readiness = [
    { name: 'All team gateways healthy', pass: false, detail: 'Team Violet VPN degraded' },
    { name: 'Deployments healthy', pass: false, detail: 'scoring-agent-pool degraded' },
    { name: 'Scoring service reachable', pass: true },
    { name: 'Hardening checklists submitted', pass: true, detail: '6/6 teams' },
    { name: 'Firewall policy compiled', pass: true },
    { name: 'Vulnerability packs armed (dormant)', pass: true },
  ]

  const changeGroups: { title: string; items: string[] }[] = [
    { title: 'Routes that would change', items: to.changes.routes },
    { title: 'Firewall policy changes', items: to.changes.firewall },
    { title: 'Vulnerabilities activated', items: to.changes.vulnerabilities },
    { title: 'Scoring changes', items: to.changes.scoring },
    { title: 'Access changes', items: to.changes.access },
  ].filter((g) => g.items.length > 0)

  return (
    <Drawer
      open={open}
      onClose={onClose}
      title="Phase transition preview"
      footer={
        <div className="u-spread">
          <span className="u-muted u-xs">Prototype preview — nothing is executed.</span>
          <div className="u-row">
            <Button variant="ghost" size="sm" onClick={onClose}>
              Cancel
            </Button>
            <Button
              variant="primary"
              size="sm"
              disabled
              title="Disabled in prototype: transition requires the approval-gated workflow"
            >
              Request transition
            </Button>
          </div>
        </div>
      }
    >
      <div className="c-inspector">
        <div className="u-row" style={{ flexWrap: 'wrap' }}>
          <StatusBadge state="active" label={from.name} />
          <ArrowRight size={14} aria-hidden className="u-muted" />
          <StatusBadge state="pending" label={to.name} tone="info" />
        </div>

        <KeyValueGrid
          columns={1}
          items={[
            { key: 'Event', value: event.name },
            { key: 'Teams affected', value: `${event.teamIds.length} teams` },
            {
              key: 'Expected workflow',
              value: 'phase-transition (approval-gated, worker-executed)',
            },
            { key: 'Required approvals', value: 'Event director + platform operator' },
          ]}
        />

        <section>
          <h4
            className="u-xs u-muted"
            style={{ textTransform: 'uppercase', letterSpacing: '0.06em' }}
          >
            Readiness checks
          </h4>
          <ul style={{ listStyle: 'none', margin: '6px 0 0', padding: 0 }}>
            {readiness.map((check) => (
              <li
                key={check.name}
                className="u-row u-small"
                style={{ padding: '3px 0', alignItems: 'flex-start' }}
              >
                {check.pass ? (
                  <CheckCircle2
                    size={14}
                    aria-hidden
                    style={{ color: 'var(--status-ok)', flexShrink: 0 }}
                  />
                ) : (
                  <XCircle
                    size={14}
                    aria-hidden
                    style={{ color: 'var(--status-error)', flexShrink: 0 }}
                  />
                )}
                <span>
                  {check.name}
                  {check.detail && <span className="u-muted u-xs"> — {check.detail}</span>}
                </span>
              </li>
            ))}
          </ul>
        </section>

        {changeGroups.map((group) => (
          <section key={group.title}>
            <h4
              className="u-xs u-muted"
              style={{ textTransform: 'uppercase', letterSpacing: '0.06em' }}
            >
              {group.title}
            </h4>
            <ul style={{ margin: '6px 0 0', paddingLeft: 18 }} className="u-small u-secondary">
              {group.items.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </section>
        ))}
      </div>
    </Drawer>
  )
}
