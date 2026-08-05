import { clsx } from 'clsx'
import type { ReactNode } from 'react'

export interface KeyValueItem {
  key: string
  value: ReactNode
  mono?: boolean
}

/** Replaceable slot: definition-list grid for object metadata. */
export function KeyValueGrid({
  items,
  columns = 2,
}: {
  items: KeyValueItem[]
  columns?: 1 | 2 | 3
}) {
  return (
    <dl className={clsx('c-kv', `c-kv--${columns}`)}>
      {items.map((item) => (
        <div key={item.key} className="c-kv__item">
          <dt>{item.key}</dt>
          <dd className={clsx(item.mono && 'u-mono')}>{item.value}</dd>
        </div>
      ))}
    </dl>
  )
}
