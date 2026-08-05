import { X } from 'lucide-react'
import { useEffect, useRef } from 'react'
import type { ReactNode } from 'react'
import { Button } from './Button'

export interface DrawerProps {
  open: boolean
  title: ReactNode
  onClose: () => void
  children: ReactNode
  footer?: ReactNode
}

/**
 * Replaceable slot: right-side drawer. Used for inspectors, previews, and
 * operational detail (progressive-disclosure level 2).
 */
export function Drawer({ open, title, onClose, children, footer }: DrawerProps) {
  const panelRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKey)
    panelRef.current?.focus()
    return () => document.removeEventListener('keydown', onKey)
  }, [open, onClose])

  if (!open) return null

  return (
    <div className="c-drawer" role="presentation">
      <div className="c-drawer__backdrop" onClick={onClose} />
      <div
        className="c-drawer__panel"
        role="dialog"
        aria-modal="true"
        aria-label={typeof title === 'string' ? title : undefined}
        tabIndex={-1}
        ref={panelRef}
      >
        <header className="c-drawer__head">
          <h3>{title}</h3>
          <Button variant="ghost" size="sm" onClick={onClose} aria-label="Close">
            <X size={14} aria-hidden />
          </Button>
        </header>
        <div className="c-drawer__body">{children}</div>
        {footer && <footer className="c-drawer__foot">{footer}</footer>}
      </div>
    </div>
  )
}
