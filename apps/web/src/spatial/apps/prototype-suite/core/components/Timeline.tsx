import type { ReactNode } from 'react'
import { clsx } from 'clsx'
import type { StatusTone } from './StatusBadge'

export interface TimelineEntry {
  id: string
  time: string
  title: ReactNode
  detail?: ReactNode
  tone?: StatusTone
}

/** Replaceable slot: vertical activity timeline. */
export function Timeline({ entries }: { entries: TimelineEntry[] }) {
  return (
    <ol className="c-timeline">
      {entries.map((entry) => (
        <li key={entry.id} className="c-timeline__entry">
          <span
            className={clsx('c-timeline__node', entry.tone && `c-timeline__node--${entry.tone}`)}
          />
          <div className="c-timeline__content">
            <div className="u-spread">
              <span className="c-timeline__title">{entry.title}</span>
              <time className="u-muted u-xs">{entry.time}</time>
            </div>
            {entry.detail && <div className="u-secondary u-small">{entry.detail}</div>}
          </div>
        </li>
      ))}
    </ol>
  )
}
