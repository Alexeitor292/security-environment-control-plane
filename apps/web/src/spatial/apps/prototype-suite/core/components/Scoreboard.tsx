import { Minus, TrendingDown, TrendingUp } from 'lucide-react'
import type { ScoreEntry, Team } from '../models/types'
import { DataTable } from './DataTable'

const TREND_ICON = {
  up: <TrendingUp size={13} aria-hidden />,
  down: <TrendingDown size={13} aria-hidden />,
  flat: <Minus size={13} aria-hidden />,
}

/** Replaceable slot: compact scoreboard (mock scoring data only). */
export function Scoreboard({
  scores,
  teams,
  detailed = false,
}: {
  scores: ScoreEntry[]
  teams: Team[]
  detailed?: boolean
}) {
  const teamName = (id: string) => teams.find((t) => t.id === id)?.name ?? id
  const teamColor = (id: string) => teams.find((t) => t.id === id)?.color

  return (
    <DataTable
      label="Scoreboard"
      columns={[
        { key: 'rank', header: '#', width: '2.5rem', render: (s: ScoreEntry) => s.rank },
        {
          key: 'team',
          header: 'Team',
          render: (s: ScoreEntry) => (
            <span className="c-matrix__team" style={{ ['--team' as string]: teamColor(s.teamId) }}>
              {teamName(s.teamId)}
            </span>
          ),
        },
        {
          key: 'total',
          header: 'Total',
          align: 'right',
          render: (s: ScoreEntry) => <strong>{s.total.toLocaleString()}</strong>,
        },
        ...(detailed
          ? [
              {
                key: 'defense',
                header: 'Defense',
                align: 'right' as const,
                render: (s: ScoreEntry) => s.defense.toLocaleString(),
              },
              {
                key: 'availability',
                header: 'Availability',
                align: 'right' as const,
                render: (s: ScoreEntry) => s.availability.toLocaleString(),
              },
              {
                key: 'attack',
                header: 'Attack',
                align: 'right' as const,
                render: (s: ScoreEntry) => s.attack.toLocaleString(),
              },
              {
                key: 'penalties',
                header: 'Penalties',
                align: 'right' as const,
                render: (s: ScoreEntry) => s.penalties.toLocaleString(),
              },
            ]
          : []),
        {
          key: 'trend',
          header: 'Trend',
          align: 'right',
          render: (s: ScoreEntry) => (
            <span title={s.trend}>
              {TREND_ICON[s.trend]}
              <span className="sr-only">{s.trend}</span>
            </span>
          ),
        },
      ]}
      rows={scores}
      rowKey={(s) => s.teamId}
    />
  )
}
