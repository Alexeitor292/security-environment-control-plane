import type { Provider } from '../models/types'

const PROVIDER_LABEL: Record<Provider, string> = {
  aws: 'AWS',
  azure: 'Azure',
  gcp: 'GCP',
  proxmox: 'Proxmox',
  kubernetes: 'Kubernetes',
  vmware: 'VMware',
}

/**
 * Replaceable slot: provider chip. Neutral text-first design — the label is
 * always present; the hue is a secondary cue only (color-blind safe).
 */
export function ProviderBadge({ provider }: { provider: Provider }) {
  return (
    <span className="c-provider" data-provider={provider}>
      <span className="c-provider__swatch" aria-hidden />
      {PROVIDER_LABEL[provider]}
    </span>
  )
}

export function providerLabel(provider: Provider): string {
  return PROVIDER_LABEL[provider]
}
