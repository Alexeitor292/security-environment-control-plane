import { Wrench } from 'lucide-react'
import { clsx } from 'clsx'
import { useAppState } from '../app/AppStateContext'

/**
 * Replaceable slot: Advanced Controls switch (progressive-disclosure level 3).
 * Display preference only — never grants authorization.
 */
export function AdvancedToggle() {
  const { advancedMode, setAdvancedMode } = useAppState()
  return (
    <button
      type="button"
      className={clsx('c-advtoggle', advancedMode && 'is-on')}
      aria-pressed={advancedMode}
      onClick={() => setAdvancedMode(!advancedMode)}
      title="Show expert-level sections (display preference only — permissions unchanged)"
    >
      <Wrench size={13} aria-hidden />
      {/* Label collapses to `.sr-only` on narrow viewports; the on/off state
          stays visible so the control never becomes ambiguous. */}
      <span className="c-advtoggle__label">Advanced</span>
      <span className="c-advtoggle__state">{advancedMode ? 'on' : 'off'}</span>
    </button>
  )
}
