import { Check, ChevronRight } from 'lucide-react'
import { clsx } from 'clsx'
import type { CompetitionPhase } from '../models/types'

/**
 * Replaceable slot: horizontal competition-phase indicator.
 * Phase state is shown by icon + weight, never color alone.
 */
export function PhaseTimeline({
  phases,
  onSelect,
  selectedId,
}: {
  phases: CompetitionPhase[]
  onSelect?: (phase: CompetitionPhase) => void
  selectedId?: string
}) {
  const ordered = [...phases].sort((a, b) => a.order - b.order)
  return (
    <ol className="c-phases">
      {ordered.map((phase, i) => (
        <li key={phase.id} className="c-phases__item">
          {i > 0 && <ChevronRight size={13} aria-hidden className="c-phases__sep" />}
          <button
            type="button"
            className={clsx(
              'c-phases__pill',
              `is-${phase.status}`,
              phase.id === selectedId && 'is-selected',
            )}
            onClick={onSelect ? () => onSelect(phase) : undefined}
            disabled={!onSelect}
            aria-current={phase.status === 'active' ? 'step' : undefined}
          >
            {phase.status === 'complete' && <Check size={11} aria-hidden />}
            {phase.status === 'active' && <span className="c-phases__live" aria-hidden />}
            <span>{phase.name}</span>
          </button>
        </li>
      ))}
    </ol>
  )
}
