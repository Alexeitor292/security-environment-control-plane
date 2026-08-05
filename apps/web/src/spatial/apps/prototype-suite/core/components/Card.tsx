import { clsx } from 'clsx'
import type { HTMLAttributes, ReactNode } from 'react'

export interface CardProps extends HTMLAttributes<HTMLDivElement> {
  heading?: ReactNode
  actions?: ReactNode
  padded?: boolean
}

/** Replaceable slot: panel card. */
export function Card({ heading, actions, padded = true, className, children, ...rest }: CardProps) {
  return (
    <section className={clsx('c-card', className)} {...rest}>
      {(heading || actions) && (
        <header className="c-card__head">
          {heading && <h3>{heading}</h3>}
          {actions && <div className="c-card__actions">{actions}</div>}
        </header>
      )}
      <div className={clsx('c-card__body', padded && 'c-card__body--padded')}>{children}</div>
    </section>
  )
}

export function CardGrid({
  min = 280,
  children,
  className,
}: {
  min?: number
  children: ReactNode
  className?: string
}) {
  return (
    <div
      className={clsx('c-cardgrid', className)}
      style={{ gridTemplateColumns: `repeat(auto-fill, minmax(${min}px, 1fr))` }}
    >
      {children}
    </div>
  )
}
