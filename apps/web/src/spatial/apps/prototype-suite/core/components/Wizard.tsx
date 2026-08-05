import { Check } from 'lucide-react'
import { clsx } from 'clsx'
import type { ReactNode } from 'react'
import { Button } from './Button'

export interface WizardStep {
  key: string
  title: string
  render: () => ReactNode
}

export interface WizardProps {
  steps: WizardStep[]
  activeIndex: number
  onNavigate: (index: number) => void
  finishLabel?: string
  onFinish?: () => void
  aside?: ReactNode
}

/**
 * Replaceable slot: multi-step wizard frame (step rail + content + footer
 * navigation). Prototype-only: completing a wizard never creates anything.
 */
export function Wizard({
  steps,
  activeIndex,
  onNavigate,
  finishLabel = 'Finish',
  onFinish,
  aside,
}: WizardProps) {
  const step = steps[activeIndex]
  const last = activeIndex === steps.length - 1

  return (
    <div className={clsx('c-wizard', aside && 'c-wizard--with-aside')}>
      <ol className="c-wizard__rail" aria-label="Wizard steps">
        {steps.map((s, i) => {
          const state = i < activeIndex ? 'complete' : i === activeIndex ? 'current' : 'pending'
          return (
            <li key={s.key}>
              <button
                type="button"
                className={clsx('c-wizard__step', `is-${state}`)}
                onClick={() => onNavigate(i)}
                aria-current={state === 'current' ? 'step' : undefined}
              >
                <span className="c-wizard__num" aria-hidden>
                  {state === 'complete' ? <Check size={11} /> : i + 1}
                </span>
                <span>{s.title}</span>
              </button>
            </li>
          )
        })}
      </ol>
      <div className="c-wizard__content">
        <h2 className="c-wizard__title">{step.title}</h2>
        <div className="c-wizard__body">{step.render()}</div>
        <footer className="c-wizard__foot">
          <Button
            variant="ghost"
            disabled={activeIndex === 0}
            onClick={() => onNavigate(activeIndex - 1)}
          >
            Back
          </Button>
          {last ? (
            <Button variant="primary" onClick={onFinish}>
              {finishLabel}
            </Button>
          ) : (
            <Button variant="primary" onClick={() => onNavigate(activeIndex + 1)}>
              Continue
            </Button>
          )}
        </footer>
      </div>
      {aside && <aside className="c-wizard__aside">{aside}</aside>}
    </div>
  )
}
