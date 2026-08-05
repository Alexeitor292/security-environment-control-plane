import { ChevronRight } from 'lucide-react'
import { useState } from 'react'
import type { ReactNode } from 'react'
import { clsx } from 'clsx'
import { useAppState } from '../app/AppStateContext'

export interface AccordionSectionProps {
  title: string
  hint?: string
  defaultOpen?: boolean
  children: ReactNode
}

/** Replaceable slot: collapsible section (collapsed by default). */
export function AccordionSection({
  title,
  hint,
  defaultOpen = false,
  children,
}: AccordionSectionProps) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className={clsx('c-accordion', open && 'is-open')}>
      <button
        type="button"
        className="c-accordion__head"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
      >
        <ChevronRight size={14} aria-hidden className="c-accordion__chev" />
        <span>{title}</span>
        {hint && <span className="c-accordion__hint">{hint}</span>}
      </button>
      {open && <div className="c-accordion__body">{children}</div>}
    </div>
  )
}

/**
 * Expert-level section (progressive-disclosure level 3): renders only when
 * the Advanced Controls toggle is on. Visibility is a display preference —
 * it never grants authorization; the backend remains the permission boundary.
 */
export function AdvancedSection({ title, hint, children }: AccordionSectionProps) {
  const { advancedMode } = useAppState()
  if (!advancedMode) return null
  return (
    <AccordionSection title={title} hint={hint ?? 'Advanced'}>
      {children}
    </AccordionSection>
  )
}
