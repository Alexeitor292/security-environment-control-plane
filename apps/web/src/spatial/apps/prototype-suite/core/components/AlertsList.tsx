import { AlertTriangle, Bell, Check, Info, OctagonAlert } from 'lucide-react'
import { clsx } from 'clsx'
import type { AlertItem } from '../models/types'
import { useAppState } from '../app/AppStateContext'
import { Button } from './Button'
import { EmptyState } from './States'

const SEVERITY_ICON = {
  critical: <OctagonAlert size={14} aria-hidden />,
  warning: <AlertTriangle size={14} aria-hidden />,
  info: <Info size={14} aria-hidden />,
}

/**
 * Replaceable slot: alert list with mock acknowledgement (local state only).
 */
export function AlertsList({
  alerts,
  compact = false,
}: {
  alerts: AlertItem[]
  compact?: boolean
}) {
  const { acknowledgedAlerts, acknowledgeAlert } = useAppState()

  const visible = alerts.filter((a) => !a.acknowledged || acknowledgedAlerts.includes(a.id))
  if (alerts.length === 0) {
    return <EmptyState title="No alerts" body="Nothing needs attention right now." />
  }

  return (
    <ul className="c-alerts">
      {visible.map((alert) => {
        const acked = alert.acknowledged || acknowledgedAlerts.includes(alert.id)
        return (
          <li
            key={alert.id}
            className={clsx('c-alerts__row', `is-${alert.severity}`, acked && 'is-acked')}
          >
            <span className="c-alerts__icon">{SEVERITY_ICON[alert.severity]}</span>
            <div className="c-alerts__text">
              <div className="u-spread">
                <strong className="u-small">{alert.title}</strong>
                <time className="u-muted u-xs">{alert.time.slice(11, 16)} UTC</time>
              </div>
              {!compact && <p className="u-secondary u-xs">{alert.detail}</p>}
              <span className="u-muted u-xs u-mono">{alert.source}</span>
            </div>
            <div className="c-alerts__act">
              {acked ? (
                <span className="u-muted u-xs u-row">
                  <Check size={12} aria-hidden /> ack
                </span>
              ) : (
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => acknowledgeAlert(alert.id)}
                  icon={<Bell size={12} aria-hidden />}
                >
                  Ack
                </Button>
              )}
            </div>
          </li>
        )
      })}
    </ul>
  )
}
