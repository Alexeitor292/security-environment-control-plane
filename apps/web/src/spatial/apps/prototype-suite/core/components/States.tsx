import { AlertOctagon, Inbox } from 'lucide-react'
import type { ReactNode } from 'react'
import { Button } from './Button'

/** Replaceable slots: empty / loading / error states. */

export function EmptyState({
  title,
  body,
  action,
}: {
  title: string
  body?: string
  action?: ReactNode
}) {
  return (
    <div className="c-state">
      <Inbox size={22} aria-hidden className="u-muted" />
      <strong>{title}</strong>
      {body && <p className="u-secondary u-small">{body}</p>}
      {action}
    </div>
  )
}

export function LoadingState({ lines = 3 }: { lines?: number }) {
  return (
    <div className="c-skeleton" aria-hidden>
      {Array.from({ length: lines }, (_, i) => (
        <div key={i} className="c-skeleton__line" style={{ width: `${88 - i * 14}%` }} />
      ))}
    </div>
  )
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="c-state c-state--error" role="alert">
      <AlertOctagon size={22} aria-hidden />
      <strong>Something went wrong</strong>
      <p className="u-secondary u-small">{message}</p>
      {onRetry && (
        <Button variant="secondary" size="sm" onClick={onRetry}>
          Retry
        </Button>
      )}
    </div>
  )
}
