import { clsx } from 'clsx'
import {
  AlertTriangle,
  Ban,
  CheckCircle2,
  CircleDashed,
  CircleDot,
  CircleHelp,
  Clock,
  Info,
  Loader2,
  TriangleAlert,
  XCircle,
} from 'lucide-react'
import type { ReactNode } from 'react'

export type StatusTone =
  | 'ok'
  | 'warn'
  | 'error'
  | 'info'
  | 'neutral'
  | 'progress'
  | 'degraded'
  | 'planned'
  | 'unknown'
  | 'disabled'

const TONE_ICON: Record<StatusTone, ReactNode> = {
  ok: <CheckCircle2 size={12} aria-hidden />,
  warn: <AlertTriangle size={12} aria-hidden />,
  error: <XCircle size={12} aria-hidden />,
  info: <Info size={12} aria-hidden />,
  neutral: <CircleDashed size={12} aria-hidden />,
  progress: <Loader2 size={12} aria-hidden className="c-spin" />,
  degraded: <TriangleAlert size={12} aria-hidden />,
  planned: <Clock size={12} aria-hidden />,
  unknown: <CircleHelp size={12} aria-hidden />,
  disabled: <Ban size={12} aria-hidden />,
}

/**
 * Maps domain states to tones. Unrecognised states resolve to `unknown` —
 * never to a healthy default — mirroring the source repo's status-tone rule.
 * `degraded`, `planned` and `unknown` are their own tones (rather than being
 * folded into warn/neutral) so a dimmed display can still tell "partially
 * serving" from "warning", and "not built yet" from "we don't know".
 */
const STATE_TONE: Record<string, StatusTone> = {
  healthy: 'ok',
  ok: 'ok',
  online: 'ok',
  running: 'ok',
  active: 'ok',
  connected: 'ok',
  valid: 'ok',
  validated: 'ok',
  completed: 'ok',
  complete: 'ok',
  approved: 'info',
  success: 'ok',
  activated: 'ok',
  degraded: 'degraded',
  partial: 'degraded',
  expiring: 'warn',
  warning: 'warn',
  paused: 'warn',
  pending: 'neutral',
  draft: 'neutral',
  upcoming: 'neutral',
  planned: 'planned',
  'not-implemented': 'planned',
  unknown: 'unknown',
  indeterminate: 'unknown',
  archived: 'neutral',
  registered: 'neutral',
  disabled: 'disabled',
  inactive: 'disabled',
  unhealthy: 'error',
  offline: 'error',
  failed: 'error',
  error: 'error',
  revoked: 'error',
  expired: 'error',
  disconnected: 'error',
  denied: 'error',
  rejected: 'error',
  destroyed: 'error',
  sealed: 'error',
  provisioning: 'progress',
  resetting: 'progress',
  destroying: 'progress',
  retrying: 'progress',
  draining: 'progress',
  'awaiting-approval': 'info',
  'plan-only': 'info',
  'read-only': 'info',
  preflight: 'neutral',
  cancelled: 'neutral',
}

export function toneForState(state: string): StatusTone {
  return Object.prototype.hasOwnProperty.call(STATE_TONE, state) ? STATE_TONE[state] : 'unknown'
}

export interface StatusBadgeProps {
  state: string
  label?: string
  tone?: StatusTone
}

/**
 * Replaceable slot: status badge. Color-blind safe by construction — every
 * tone pairs a distinct icon with a text label; color is never the only cue.
 */
export function StatusBadge({ state, label, tone }: StatusBadgeProps) {
  const resolved = tone ?? toneForState(state)
  return (
    <span className={clsx('c-badge', `c-badge--${resolved}`)}>
      {TONE_ICON[resolved]}
      <span>{label ?? state.replace(/-/g, ' ')}</span>
    </span>
  )
}

/** Small dot-only variant for dense grids; still labeled via title + sr text. */
export function StatusDot({ state, label }: { state: string; label?: string }) {
  const resolved = toneForState(state)
  const text = label ?? state
  return (
    <span className={clsx('c-dot', `c-dot--${resolved}`)} title={text}>
      <CircleDot size={10} aria-hidden />
      <span className="sr-only">{text}</span>
    </span>
  )
}
