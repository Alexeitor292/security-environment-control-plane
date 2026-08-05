/**
 * SECP UX Prototype — product domain model.
 *
 * These types define the product objects the prototype is organized around
 * (see docs/02_PRODUCT_MODEL.md). They are deliberately backend-agnostic:
 * the mock adapter in src/integrations implements them from fixture data,
 * and a future SECP API adapter can implement the same interfaces.
 */

export type Provider = 'aws' | 'azure' | 'gcp' | 'proxmox' | 'kubernetes' | 'vmware'

export type HealthState = 'healthy' | 'degraded' | 'unhealthy' | 'unknown'

/**
 * Capability-truth classification (docs/07_CAPABILITY_TRUTH_MATRIX.md).
 * Every prototype surface that represents platform behavior carries one of
 * these so the UI never implies an unavailable capability is operational.
 */
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

/* ------------------------------------------------------------------ */
/* Scenario                                                            */
/* ------------------------------------------------------------------ */

export type ScenarioDifficulty = 'intro' | 'intermediate' | 'advanced' | 'expert'
export type ValidationStatus = 'validated' | 'pending' | 'failed' | 'draft'

export interface ScenarioVersion {
  version: string
  createdAt: string
  changelog: string
  immutable: boolean
  validation: ValidationStatus
}

export interface Scenario {
  id: string
  name: string
  purpose: string
  difficulty: ScenarioDifficulty
  teamRange: [number, number]
  estimatedResources: { vms: number; containers: number; networks: number }
  estimatedCostPerHour: number
  supportedProviders: Provider[]
  requiredPlugins: string[]
  currentVersion: string
  validation: ValidationStatus
  tags: string[]
  updatedAt: string
  versions: ScenarioVersion[]
}

/* ------------------------------------------------------------------ */
/* Event & competition phases                                          */
/* ------------------------------------------------------------------ */

export type EventType =
  'competition' | 'training' | 'purple-team' | 'ir-rehearsal' | 'demo' | 'validation'

export type EventStatus = 'upcoming' | 'active' | 'paused' | 'completed' | 'archived'

export type PhaseStatus = 'complete' | 'active' | 'pending'

export interface CompetitionPhase {
  id: string
  name: string
  order: number
  status: PhaseStatus
  description: string
  startedAt?: string
  endedAt?: string
  /** What flips when this phase becomes active — shown in transition previews. */
  changes: {
    routes: string[]
    firewall: string[]
    vulnerabilities: string[]
    scoring: string[]
    access: string[]
  }
}

export interface EventAnnouncement {
  id: string
  time: string
  author: string
  message: string
}

export interface EventItem {
  id: string
  name: string
  description: string
  type: EventType
  status: EventStatus
  scenarioId: string
  scenarioVersion: string
  phases: CompetitionPhase[]
  teamIds: string[]
  deploymentIds: string[]
  startsAt: string
  endsAt: string
  health: HealthState
  connectedParticipants: number
  totalParticipants: number
  rules: string[]
  announcements: EventAnnouncement[]
  scoringEnabled: boolean
}

/* ------------------------------------------------------------------ */
/* Teams, participants, access                                         */
/* ------------------------------------------------------------------ */

export type ConnectionState = 'connected' | 'partial' | 'disconnected'

export interface Participant {
  id: string
  name: string
  email: string
  role: 'captain' | 'member' | 'observer'
  teamId: string
  lastSeen?: string
}

export type AccessProfileStatus = 'active' | 'pending' | 'revoked' | 'expired'

/** Gateway-agnostic access profile; WireGuard is the first implementation. */
export interface AccessProfile {
  id: string
  teamId: string
  participantId: string
  gateway: 'wireguard' | 'openvpn' | 'guacamole' | 'ssh-cert'
  status: AccessProfileStatus
  endpoint: string
  /** Public metadata only — the prototype never carries private keys. */
  publicKeyFingerprint: string
  issuedAt: string
  lastHandshake?: string
  deviceCount: number
}

export interface Team {
  id: string
  eventId: string
  name: string
  /** Hue used on topology + matrix; always paired with the team label. */
  color: string
  memberIds: string[]
  subnet: string
  systems: string[]
  connection: ConnectionState
  connectedDevices: number
  gatewayHealth: HealthState
  vpnEndpoint: string
  allowedRoutes: string[]
  restrictions: string[]
  objectives: string[]
}

/* ------------------------------------------------------------------ */
/* Deployment                                                          */
/* ------------------------------------------------------------------ */

export type DeploymentState =
  | 'planned'
  | 'provisioning'
  | 'running'
  | 'degraded'
  | 'failed'
  | 'resetting'
  | 'destroying'
  | 'destroyed'

export type ResourceKind =
  | 'vm'
  | 'container'
  | 'network'
  | 'firewall'
  | 'storage'
  | 'gateway'
  | 'security-tool'
  | 'scoring-service'

export interface DeploymentResource {
  id: string
  name: string
  kind: ResourceKind
  ip?: string
  providerRef: string
  health: HealthState
  teamId?: string
  detail?: string
}

export interface Deployment {
  id: string
  name: string
  scenarioId: string
  scenarioVersion: string
  eventId?: string
  targetId: string
  provider: Provider
  region: string
  state: DeploymentState
  health: HealthState
  drift: boolean
  costToDate: number
  estimatedCostPerHour: number
  createdAt: string
  expiresAt?: string
  owner: string
  lastOperation: string
  resources: DeploymentResource[]
  workflowRunIds: string[]
}

/* ------------------------------------------------------------------ */
/* Infrastructure                                                      */
/* ------------------------------------------------------------------ */

export type CredentialStatus = 'valid' | 'expiring' | 'expired' | 'missing'

export interface InfraTarget {
  id: string
  name: string
  provider: Provider
  location: string
  health: HealthState
  capacity: { usedPercent: number; detail: string }
  costStatus: 'ok' | 'warning' | 'over-budget' | 'n/a'
  workerId?: string
  credentialStatus: CredentialStatus
  capabilities: string[]
  deploymentCount: number
  lastDiscovery?: string
  onboardingState: 'registered' | 'preflight' | 'plan-only' | 'activated'
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

export interface IntegrationInfo {
  id: string
  name: string
  category:
    | 'cloud'
    | 'virtualization'
    | 'orchestration'
    | 'identity'
    | 'secrets'
    | 'storage'
    | 'monitoring'
    | 'automation'
  status: CapabilityStatus
  detail: string
}

/* ------------------------------------------------------------------ */
/* Operations: workflows, approvals, alerts, audit, evidence           */
/* ------------------------------------------------------------------ */

export type WorkflowStatus =
  'running' | 'completed' | 'failed' | 'retrying' | 'awaiting-approval' | 'cancelled'

export interface WorkflowStep {
  name: string
  status: 'complete' | 'active' | 'pending' | 'failed'
  detail?: string
}

export interface WorkflowRun {
  id: string
  name: string
  kind:
    | 'deploy'
    | 'destroy'
    | 'reset'
    | 'discovery'
    | 'phase-transition'
    | 'plan'
    | 'credential-rotation'
    | 'report'
  status: WorkflowStatus
  startedAt: string
  finishedAt?: string
  deploymentId?: string
  eventId?: string
  taskQueue: string
  steps: WorkflowStep[]
}

export type ApprovalStatus = 'pending' | 'approved' | 'rejected' | 'expired'

export interface Approval {
  id: string
  title: string
  operation: string
  requestedBy: string
  status: ApprovalStatus
  riskLevel: 'low' | 'medium' | 'high' | 'critical'
  createdAt: string
  scope: string
}

export type AlertSeverity = 'critical' | 'warning' | 'info'

export interface AlertItem {
  id: string
  severity: AlertSeverity
  title: string
  detail: string
  source: string
  time: string
  acknowledged: boolean
  eventId?: string
  deploymentId?: string
}

export interface AuditEvent {
  id: string
  time: string
  actor: string
  action: string
  resource: string
  outcome: 'success' | 'denied' | 'failed'
  origin: string
}

export interface EvidenceRecord {
  id: string
  time: string
  kind: 'plan' | 'apply-receipt' | 'discovery-snapshot' | 'reset-receipt' | 'capture'
  subject: string
  sha256: string
  store: string
}

/* ------------------------------------------------------------------ */
/* Scoring & reports                                                   */
/* ------------------------------------------------------------------ */

export interface ScoreEntry {
  teamId: string
  rank: number
  total: number
  defense: number
  availability: number
  attack: number
  penalties: number
  trend: 'up' | 'down' | 'flat'
}

export type ReportCategory =
  | 'event-summary'
  | 'after-action'
  | 'technical'
  | 'executive'
  | 'scoring'
  | 'participant'
  | 'utilization'
  | 'cost'
  | 'control-validation'
  | 'audit-export'

export interface ReportDef {
  id: string
  category: ReportCategory
  title: string
  description: string
  eventId?: string
  generatedAt?: string
}

/* ------------------------------------------------------------------ */
/* Identity & secrets (metadata only)                                  */
/* ------------------------------------------------------------------ */

export interface UserAccount {
  id: string
  name: string
  email: string
  roles: string[]
  organization: string
  lastLogin?: string
  kind: 'human' | 'service'
}

export interface SecretRef {
  id: string
  name: string
  purpose: string
  provider: Provider | 'platform'
  boundTarget?: string
  credentialType: string
  dynamic: boolean
  leaseExpires?: string
  rotationSchedule: string
  lastRotation?: string
  consumer: string
  health: 'ok' | 'expiring' | 'error'
}

/* ------------------------------------------------------------------ */
/* Topology                                                            */
/* ------------------------------------------------------------------ */

export type TopologyNodeKind =
  | 'subnet'
  | 'router'
  | 'firewall'
  | 'server'
  | 'workstation'
  | 'identity'
  | 'security-tool'
  | 'scoring'
  | 'gateway'
  | 'database'
  | 'web'
  | 'vulnerable-app'

export interface TopologyNode {
  id: string
  label: string
  kind: TopologyNodeKind
  teamId?: string
  ip?: string
  subnet?: string
  status: HealthState
  /** Draft layout position; a future auto-layout (ELK) replaces this. */
  x: number
  y: number
  meta?: Record<string, string>
}

export interface TopologyEdge {
  id: string
  source: string
  target: string
  kind: 'link' | 'route' | 'attack-path' | 'monitoring'
  label?: string
}

export interface TopologyGraph {
  nodes: TopologyNode[]
  edges: TopologyEdge[]
}
