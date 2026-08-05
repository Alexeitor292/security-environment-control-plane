import type { ReactNode } from 'react'
import { clsx } from 'clsx'
import { FlaskConical, Lock, Radio, Sparkles, Wrench } from 'lucide-react'
import type { CapabilityStatus } from '../models/types'
import { capability } from '../mocks/capabilities'

/**
 * Capability-truth surfaces. These keep the prototype honest: any page or
 * control representing behavior the platform does not have today carries one
 * of these markers (see docs/07_CAPABILITY_TRUTH_MATRIX.md).
 */

const STATUS_META: Record<CapabilityStatus, { label: string; className: string; icon: ReactNode }> =
  {
    implemented: { label: 'Implemented', className: 'ok', icon: <Wrench size={12} aria-hidden /> },
    simulated: {
      label: 'Simulated',
      className: 'sim',
      icon: <FlaskConical size={12} aria-hidden />,
    },
    'read-only': { label: 'Read-only', className: 'sim', icon: <Radio size={12} aria-hidden /> },
    'plan-only': { label: 'Plan-only', className: 'sim', icon: <Radio size={12} aria-hidden /> },
    sealed: { label: 'Sealed', className: 'sealed', icon: <Lock size={12} aria-hidden /> },
    partial: { label: 'Partial', className: 'sim', icon: <Wrench size={12} aria-hidden /> },
    'ui-only': { label: 'UI only', className: 'planned', icon: <Sparkles size={12} aria-hidden /> },
    planned: { label: 'Planned', className: 'planned', icon: <Sparkles size={12} aria-hidden /> },
    'not-found': {
      label: 'Not in repo',
      className: 'planned',
      icon: <Sparkles size={12} aria-hidden />,
    },
  }

export function CapabilityTag({ status }: { status: CapabilityStatus }) {
  const meta = STATUS_META[status]
  return (
    <span className={clsx('c-captag', `c-captag--${meta.className}`)}>
      {meta.icon}
      {meta.label}
    </span>
  )
}

/**
 * Replaceable slot: planned/sealed-capability notice banner.
 * Pass a key from the capability registry; the banner renders the grounded
 * status, label, and evidence note.
 */
export function CapabilityNotice({ capKey }: { capKey: string }) {
  const fact = capability(capKey)
  const meta = STATUS_META[fact.status]
  return (
    <aside className={clsx('c-capnotice', `c-capnotice--${meta.className}`)} role="note">
      <div className="c-capnotice__head">
        <CapabilityTag status={fact.status} />
        <strong>{fact.label}</strong>
      </div>
      <p>{fact.note}</p>
    </aside>
  )
}
