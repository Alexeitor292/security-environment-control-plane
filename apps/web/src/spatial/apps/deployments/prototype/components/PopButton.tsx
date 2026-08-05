/**
 * PopButton — the shared tactile button primitive for the whole application.
 *
 * Adapted from Vengeance UI's "Pop Button"
 *   docs:     https://www.vengenceui.com/components/pop-button
 *   registry: https://www.vengenceui.com/r/pop-button.json
 *   retrieved 2026-07-20
 *
 * PRESERVED from the source: the raised resting position, the layered lower
 * edge built from stacked `box-shadow` rings, the physical depth, the downward
 * hover displacement, the deeper pressed displacement, the shadow collapsing as
 * the button travels down, the fast `cubic-bezier(0,0,0.58,1)` response, and a
 * native `<button>` element.
 *
 * ADAPTED: the reference's pink palette (`#fff0f0` / `#b18597` / `#f9c4d2`),
 * uppercase type, `px-8 py-5` marketing dimensions and `rounded-xl` radius are
 * all replaced by SECP tokens at control-room density. See `pop-button.css`.
 *
 * This is the primitive; `Button` renders through it, so migrating a call site
 * usually means changing nothing at all.
 */
import { clsx } from 'clsx'
import { Loader2 } from 'lucide-react'
import { forwardRef } from 'react'
import type { ButtonHTMLAttributes, ReactNode } from 'react'
import './pop-button.css'

export type PopVariant =
  'primary' | 'secondary' | 'neutral' | 'danger' | 'warning' | 'success' | 'ghost-pop' | 'icon'

export type PopSize = 'xs' | 'sm' | 'md' | 'lg'

export interface PopButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: PopVariant
  size?: PopSize
  /** Leading icon node; rendered before the label. */
  icon?: ReactNode
  /** Shows a spinner, marks the control busy and blocks activation. */
  loading?: boolean
  /**
   * Opt in to a >=44x44px pointer target without changing the rendered box.
   * Defaults to `true` for the icon-only variant, which is the case most at
   * risk of being too small to hit.
   */
  wideHitArea?: boolean
  children?: ReactNode
}

export const PopButton = forwardRef<HTMLButtonElement, PopButtonProps>(function PopButton(
  {
    variant = 'secondary',
    size = 'md',
    icon,
    loading = false,
    wideHitArea,
    type = 'button',
    className,
    disabled,
    children,
    ...rest
  },
  ref,
) {
  const expandHit = wideHitArea ?? variant === 'icon'
  return (
    <button
      ref={ref}
      // `type` is threaded through untouched so submit buttons keep submitting.
      type={type}
      className={clsx(
        'pop-btn',
        `pop-btn--${variant}`,
        `pop-btn--${size}`,
        expandHit && 'pop-btn--hit',
        className,
      )}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      {...rest}
    >
      {loading ? <Loader2 className="pop-btn__spinner c-spin" size={14} aria-hidden /> : icon}
      {children}
    </button>
  )
})
