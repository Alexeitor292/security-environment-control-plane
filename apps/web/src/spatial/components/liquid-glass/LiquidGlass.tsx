import { type CSSProperties, type MouseEventHandler, type ReactNode } from 'react'
import './LiquidGlass.css'

interface LiquidGlassProps {
  children: ReactNode
  className?: string
  contentClassName?: string
  style?: CSSProperties
  as?: 'div' | 'button' | 'a'
  href?: string
  target?: string
  type?: 'button' | 'submit' | 'reset'
  disabled?: boolean
  onClick?: MouseEventHandler<HTMLDivElement | HTMLButtonElement | HTMLAnchorElement>
}

export function LiquidGlassFilter() {
  return (
    <svg className="liquid-glass-filter" aria-hidden="true" focusable="false">
      <defs>
        <filter
          id="secp-liquid-glass-distortion"
          x="-20%"
          y="-20%"
          width="140%"
          height="140%"
          colorInterpolationFilters="sRGB"
        >
          <feTurbulence
            type="fractalNoise"
            baseFrequency="0.008 0.014"
            numOctaves="2"
            seed="17"
            result="noise"
          />

          <feGaussianBlur in="noise" stdDeviation="1.6" result="softNoise" />

          <feDisplacementMap
            in="SourceGraphic"
            in2="softNoise"
            scale="22"
            xChannelSelector="R"
            yChannelSelector="B"
            result="distorted"
          />

          <feSpecularLighting
            in="softNoise"
            surfaceScale="3"
            specularConstant="0.58"
            specularExponent="42"
            lightingColor="#d9f7ff"
            result="specular"
          >
            <fePointLight x="-180" y="-140" z="240" />
          </feSpecularLighting>

          <feComposite in="specular" in2="SourceAlpha" operator="in" result="maskedSpecular" />

          <feBlend in="distorted" in2="maskedSpecular" mode="screen" />
        </filter>
      </defs>
    </svg>
  )
}

export function LiquidGlass({
  children,
  className = '',
  contentClassName = '',
  style,
  as = 'div',
  href,
  target = '_blank',
  type = 'button',
  disabled = false,
  onClick,
}: LiquidGlassProps) {
  const classes = ['liquid-glass', className].filter(Boolean).join(' ')

  const content = (
    <>
      <span className="liquid-glass__backdrop" aria-hidden="true" />

      <span className="liquid-glass__distortion" aria-hidden="true" />

      <span className="liquid-glass__tint" aria-hidden="true" />

      <span className="liquid-glass__shine" aria-hidden="true" />

      <span className="liquid-glass__edge" aria-hidden="true" />

      <span className={['liquid-glass__content', contentClassName].filter(Boolean).join(' ')}>
        {children}
      </span>
    </>
  )

  if (as === 'button') {
    return (
      <button
        className={classes}
        style={style}
        type={type}
        disabled={disabled}
        onClick={onClick as MouseEventHandler<HTMLButtonElement>}
      >
        {content}
      </button>
    )
  }

  if (as === 'a') {
    return (
      <a
        className={classes}
        style={style}
        href={href}
        target={target}
        rel={target === '_blank' ? 'noopener noreferrer' : undefined}
        onClick={onClick as MouseEventHandler<HTMLAnchorElement>}
      >
        {content}
      </a>
    )
  }

  return (
    <div className={classes} style={style} onClick={onClick as MouseEventHandler<HTMLDivElement>}>
      {content}
    </div>
  )
}

export default LiquidGlass
