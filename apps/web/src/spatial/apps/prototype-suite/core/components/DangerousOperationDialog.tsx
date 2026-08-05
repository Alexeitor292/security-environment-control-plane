import { AlertTriangle, ShieldAlert } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { Button } from './Button'
import { CapabilityTag } from './CapabilityNotice'

export interface DangerousOperationDialogProps {
  open: boolean
  title: string
  operation: string
  /** What would change — routes, firewall rules, teams affected, etc. */
  preview: ReactNode
  requiredApprovals?: string[]
  onClose: () => void
}

/**
 * Replaceable slot: dangerous-operation preview-and-confirm dialog.
 *
 * PROTOTYPE CONTRACT: the confirm button never executes anything. It records
 * a local acknowledgement and closes. Real implementations must route
 * through the platform's approval-gated workflow — never a direct toggle.
 */
export function DangerousOperationDialog({
  open,
  title,
  operation,
  preview,
  requiredApprovals = [],
  onClose,
}: DangerousOperationDialogProps) {
  const [acknowledged, setAcknowledged] = useState(false)
  const [confirmed, setConfirmed] = useState(false)
  const panelRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) {
      setAcknowledged(false)
      setConfirmed(false)
      return
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKey)
    panelRef.current?.focus()
    return () => document.removeEventListener('keydown', onKey)
  }, [open, onClose])

  if (!open) return null

  return (
    <div className="c-dialog" role="presentation">
      <div className="c-dialog__backdrop" onClick={onClose} />
      <div
        className="c-dialog__panel c-dialog__panel--danger"
        role="alertdialog"
        aria-modal="true"
        aria-label={title}
        tabIndex={-1}
        ref={panelRef}
      >
        <header className="c-dialog__head">
          <ShieldAlert size={16} aria-hidden className="c-dialog__dangericon" />
          <h3>{title}</h3>
          <CapabilityTag status="ui-only" />
        </header>
        {confirmed ? (
          <div className="c-dialog__body">
            <p className="u-secondary">
              Prototype acknowledgement recorded. In the real platform, <strong>{operation}</strong>{' '}
              would now enter the approval-gated workflow — no state has changed.
            </p>
          </div>
        ) : (
          <div className="c-dialog__body">
            <p className="u-secondary u-small">
              Review exactly what <strong>{operation}</strong> would change before confirming.
            </p>
            <div className="c-dialog__preview">{preview}</div>
            {requiredApprovals.length > 0 && (
              <div className="c-dialog__approvals">
                <span className="u-xs u-muted">Required approvals</span>
                <ul>
                  {requiredApprovals.map((a) => (
                    <li key={a}>{a}</li>
                  ))}
                </ul>
              </div>
            )}
            <label className="c-dialog__ack">
              <input
                type="checkbox"
                checked={acknowledged}
                onChange={(e) => setAcknowledged(e.target.checked)}
              />
              <span>I reviewed the changes above (prototype acknowledgement)</span>
            </label>
          </div>
        )}
        <footer className="c-dialog__foot">
          <Button variant="ghost" onClick={onClose}>
            {confirmed ? 'Close' : 'Cancel'}
          </Button>
          {!confirmed && (
            <Button
              variant="danger"
              disabled={!acknowledged}
              onClick={() => setConfirmed(true)}
              icon={<AlertTriangle size={13} aria-hidden />}
            >
              Confirm (prototype — no effect)
            </Button>
          )}
        </footer>
      </div>
    </div>
  )
}
