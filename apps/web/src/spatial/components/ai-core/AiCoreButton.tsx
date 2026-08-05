import { useMemo, useState, type ReactNode } from 'react'
import { GradientOrb } from './GradientOrb'
import './AiCoreButton.css'

interface AiCoreButtonProps {
  active?: boolean
  label?: string
  title?: string
  className?: string
  onClick?: () => void
  children?: ReactNode
}

export function AiCoreButton({
  active = false,
  label = 'AI Core',
  title = 'Open command center',
  className = '',
  onClick,
  children,
}: AiCoreButtonProps) {
  const [hovered, setHovered] = useState(false)

  const engaged = hovered || active

  const orbConfig = useMemo(
    () => ({
      background: 'transparent',

      hue: 0,

      /*
       * Hover wakes up the internal energy,
       * but never rotates the whole orb.
       */
      energySpeed: engaged ? 0.46 : 0.3,

      noiseScale: engaged ? 0.74 : 0.68,

      innerRadius: engaged ? 0.115 : 0.13,

      glowStrength: engaged ? 1.08 : 0.76,

      edgeSoftness: engaged ? 0.03 : 0.04,
    }),
    [engaged],
  )

  return (
    <button
      className={[
        'ai-core-button',

        active ? 'ai-core-button--active' : '',

        hovered ? 'ai-core-button--hovered' : '',

        className,
      ]
        .filter(Boolean)
        .join(' ')}
      type="button"
      aria-label={title}
      aria-pressed={active}
      onClick={onClick}
      onPointerEnter={() => {
        setHovered(true)
      }}
      onPointerLeave={() => {
        setHovered(false)
      }}
    >
      <span className="ai-core-button__orb-shell" aria-hidden="true">
        <span className="ai-core-button__orb">
          <GradientOrb config={orbConfig} />
        </span>
      </span>

      <span className="ai-core-button__label">
        <span className="ai-core-button__status">
          <span className="ai-core-button__status-dot" />

          {active ? 'Core active' : 'Core ready'}
        </span>

        <strong>{label}</strong>

        <span className="ai-core-button__hint">{children ?? 'Open command center'}</span>
      </span>
    </button>
  )
}
