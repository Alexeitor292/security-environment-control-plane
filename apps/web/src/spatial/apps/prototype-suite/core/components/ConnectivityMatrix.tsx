import { Check, Minus, X } from 'lucide-react'
import type { Team } from '../models/types'

export type MatrixCell = 'open' | 'blocked' | 'self'

export interface ConnectivityMatrixProps {
  teams: Team[]
  /** cell(from, to) — what network policy allows between team zones. */
  cell: (from: Team, to: Team) => MatrixCell
  caption?: string
}

/**
 * Replaceable slot: team-to-team connectivity matrix. Icons + titles carry
 * the meaning; the team hue is a secondary cue.
 */
export function ConnectivityMatrix({ teams, cell, caption }: ConnectivityMatrixProps) {
  return (
    <div
      className="c-table__scroll"
      tabIndex={0}
      role="region"
      aria-label="Team connectivity matrix"
    >
      <table className="c-matrix">
        {caption && <caption className="u-muted u-xs">{caption}</caption>}
        <thead>
          <tr>
            <th scope="col">
              <span className="u-xs u-muted">from \ to</span>
            </th>
            {teams.map((t) => (
              <th key={t.id} scope="col">
                <span className="c-matrix__team" style={{ ['--team' as string]: t.color }}>
                  {t.name}
                </span>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {teams.map((from) => (
            <tr key={from.id}>
              <th scope="row">
                <span className="c-matrix__team" style={{ ['--team' as string]: from.color }}>
                  {from.name}
                </span>
              </th>
              {teams.map((to) => {
                const value = cell(from, to)
                return (
                  <td key={to.id} className={`c-matrix__cell is-${value}`}>
                    {value === 'self' && <Minus size={12} aria-hidden />}
                    {value === 'open' && <Check size={12} aria-hidden />}
                    {value === 'blocked' && <X size={12} aria-hidden />}
                    <span className="sr-only">
                      {from.name} → {to.name}: {value}
                    </span>
                  </td>
                )
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
