import { capabilityFacts } from '../fixtures/capabilities'
import { inventory, targets, workers } from '../fixtures/infrastructure'
import type { CapabilityFact, InfraTarget, Provider, ProviderSummary } from '../models'

const providerLabels: Record<Provider, string> = {
  aws: 'Amazon Web Services',
  azure: 'Microsoft Azure',
  gcp: 'Google Cloud',
  proxmox: 'Proxmox',
  kubernetes: 'Kubernetes',
  vmware: 'VMware',
}

export function getTargets() {
  return targets
}

export function getWorkers() {
  return workers
}

export function getInventory() {
  return inventory
}

export function getTargetById(targetId: string) {
  return targets.find((target) => target.id === targetId)
}

export function getWorkerById(workerId?: string) {
  return workers.find((worker) => worker.id === workerId)
}

export function getTargetInventory(targetId: string) {
  return inventory.filter((item) => item.targetId === targetId)
}

export function getCapabilityFact(key: string): CapabilityFact {
  return (
    capabilityFacts.find((fact) => fact.key === key) ?? {
      key,
      status: 'planned',
      label: 'Proposed capability',
      note: 'This surface is a product design without confirmed backend support.',
    }
  )
}

export function getInfrastructureSummary() {
  return {
    targets: targets.length,
    activated: targets.filter((target) => target.onboardingState === 'activated').length,
    healthy: targets.filter((target) => target.health === 'healthy').length,
    degraded: targets.filter((target) => target.health === 'degraded').length,
    workersOnline: workers.filter((worker) => worker.status === 'online').length,
    workersTotal: workers.length,
    deployments: targets.reduce((total, target) => total + target.deploymentCount, 0),
    expiringCredentials: targets.filter((target) => target.credentialStatus === 'expiring').length,
  }
}

export function getProviderSummaries(): ProviderSummary[] {
  const providers = Array.from(new Set(targets.map((target) => target.provider)))

  return providers.map((provider) => {
    const providerTargets = targets.filter((target) => target.provider === provider)

    const isCloud = provider === 'aws' || provider === 'azure' || provider === 'gcp'

    return {
      provider,
      label: providerLabels[provider],
      targetCount: providerTargets.length,
      healthyCount: providerTargets.filter((target) => target.health === 'healthy').length,
      capabilityStatus: isCloud ? 'not-found' : provider === 'proxmox' ? 'partial' : 'planned',
      discovery: provider === 'proxmox' ? 'read-only' : isCloud ? 'simulated' : 'partial',
      planning: provider === 'proxmox' ? 'plan-only' : isCloud ? 'simulated' : 'planned',
      execution: provider === 'proxmox' ? 'sealed' : isCloud ? 'not-found' : 'planned',
    }
  })
}

export function getPlacementCandidates() {
  return [...targets].sort((left: InfraTarget, right: InfraTarget) => {
    const leftPenalty = left.health === 'healthy' ? 0 : 100

    const rightPenalty = right.health === 'healthy' ? 0 : 100

    return left.capacity.usedPercent + leftPenalty - (right.capacity.usedPercent + rightPenalty)
  })
}
