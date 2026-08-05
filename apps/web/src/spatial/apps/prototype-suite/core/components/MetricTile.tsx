import { clsx } from 'clsx'
import type { ReactNode } from 'react'
import type { StatusTone } from './StatusBadge'

export interface MetricTileProps {
  label: string
  value: ReactNode
  detail?: string
  tone?: StatusTone
}

/**
 * Replaceable slot: metric summary tile. When a source is unavailable, pass
 * value "—" and a truthful detail — never a fabricated number.
 */
export function MetricTile({ label, value, detail, tone }: MetricTileProps) {
  return (
    <div className={clsx('c-metric', tone && `c-metric--${tone}`)}>
      <span className="c-metric__label">{label}</span>
      <span className="c-metric__value">{value}</span>
      {detail && <span className="c-metric__detail">{detail}</span>}
    </div>
  )
}

export function MetricRow({ children }: { children: ReactNode }) {
  return <div className="c-metricrow">{children}</div>
}
