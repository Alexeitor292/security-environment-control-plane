import type { ReactNode } from 'react'
import { EmptyState } from './States'

export interface Column<T> {
  key: string
  header: string
  render: (row: T) => ReactNode
  width?: string
  align?: 'left' | 'right'
}

export interface DataTableProps<T> {
  columns: Column<T>[]
  rows: T[]
  rowKey: (row: T) => string
  onRowClick?: (row: T) => void
  selectedKey?: string
  emptyTitle?: string
  emptyBody?: string
  label?: string
}

/**
 * Replaceable slot: data table. Presentational only — sorting/pagination are
 * left to the future component kit; the prototype filters upstream.
 */
export function DataTable<T>({
  columns,
  rows,
  rowKey,
  onRowClick,
  selectedKey,
  emptyTitle = 'Nothing here yet',
  emptyBody,
  label,
}: DataTableProps<T>) {
  if (rows.length === 0) {
    return <EmptyState title={emptyTitle} body={emptyBody} />
  }
  return (
    <div className="c-table__scroll" role="region" aria-label={label} tabIndex={0}>
      <table className="c-table">
        <thead>
          <tr>
            {columns.map((col) => (
              <th key={col.key} style={{ width: col.width, textAlign: col.align }}>
                {col.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const key = rowKey(row)
            const clickable = Boolean(onRowClick)
            return (
              <tr
                key={key}
                className={key === selectedKey ? 'is-selected' : undefined}
                data-clickable={clickable || undefined}
                onClick={clickable ? () => onRowClick?.(row) : undefined}
                onKeyDown={
                  clickable
                    ? (e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.preventDefault()
                          onRowClick?.(row)
                        }
                      }
                    : undefined
                }
                tabIndex={clickable ? 0 : undefined}
              >
                {columns.map((col) => (
                  <td key={col.key} style={{ textAlign: col.align }}>
                    {col.render(row)}
                  </td>
                ))}
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
