import { forwardRef } from 'react'
import type { ButtonHTMLAttributes, ReactNode } from 'react'
import { PopButton } from './PopButton'
import type { PopSize, PopVariant } from './PopButton'

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger'
  size?: 'sm' | 'md'
  icon?: ReactNode
  /** Shows a spinner and blocks activation. */
  loading?: boolean
}

const VARIANT: Record<NonNullable<ButtonProps['variant']>, PopVariant> = {
  primary: 'primary',
  secondary: 'secondary',
  ghost: 'ghost-pop',
  danger: 'danger',
}

const SIZE: Record<NonNullable<ButtonProps['size']>, PopSize> = {
  sm: 'sm',
  md: 'md',
}

/**
 * Replaceable slot: base button.
 *
 * The public API is unchanged — same variants, sizes, `icon`, and every native
 * button attribute (`type`, `disabled`, `form`, handlers, refs) passes straight
 * through. Underneath it now renders the shared Pop Button primitive, which is
 * how the Vengeance treatment reached the whole application without touching
 * ~60 call sites individually. Controls that must NOT look pressable (status
 * badges, nav links, tabs, chips, breadcrumbs, phase steps) do not use this
 * component and were deliberately left alone — see docs/13.
 */
export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = 'secondary', size = 'md', ...rest },
  ref,
) {
  return <PopButton ref={ref} variant={VARIANT[variant]} size={SIZE[size]} {...rest} />
})
