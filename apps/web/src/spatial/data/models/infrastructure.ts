export type Provider = 'aws' | 'azure' | 'gcp' | 'proxmox' | 'kubernetes' | 'vmware'

export type HealthState = 'healthy' | 'degraded' | 'unhealthy' | 'unknown'

export type CapabilityStatus =
  | 'implemented'
  | 'simulated'
  | 'read-only'
  | 'plan-only'
  | 'sealed'
  | 'partial'
  | 'ui-only'
  | 'planned'
  | 'not-found'

export type CredentialStatus = 'valid' | 'expiring' | 'expired' | 'missing'

export type OnboardingState = 'registered' | 'preflight' | 'plan-only' | 'activated'

export interface InfraTarget {
  id: string
  name: string
  provider: Provider
  location: string
  health: HealthState
  capacity: {
    usedPercent: number
    detail: string
  }
  costStatus: 'ok' | 'warning' | 'over-budget' | 'n/a'
  workerId?: string
  credentialStatus: CredentialStatus
  capabilities: string[]
  deploymentCount: number
  lastDiscovery?: string
  onboardingState: OnboardingState
}

export interface WorkerNode {
  id: string
  name: string
  status: 'online' | 'offline' | 'draining'
  taskQueues: string[]
  lastHeartbeat: string
  version: string
  targetIds: string[]
}

export interface ProviderSummary {
  provider: Provider
  label: string
  targetCount: number
  healthyCount: number
  capabilityStatus: CapabilityStatus
  discovery: CapabilityStatus
  planning: CapabilityStatus
  execution: CapabilityStatus
}

export interface InventoryItem {
  id: string
  name: string
  kind: 'vm' | 'container' | 'network' | 'storage' | 'node' | 'cluster' | 'gateway'
  targetId: string
  provider: Provider
  health: HealthState
  detail: string
}

export interface CapabilityFact {
  key: string
  status: CapabilityStatus
  label: string
  note: string
}
