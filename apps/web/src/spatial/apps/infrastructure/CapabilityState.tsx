import type { CapabilityStatus } from '../../data'

interface CapabilityStateProps {
  status: CapabilityStatus
  label?: string
}

export function CapabilityState({ status, label }: CapabilityStateProps) {
  return (
    <span className={['capability-state', `capability-state--${status}`].join(' ')}>
      {label ?? status}
    </span>
  )
}
