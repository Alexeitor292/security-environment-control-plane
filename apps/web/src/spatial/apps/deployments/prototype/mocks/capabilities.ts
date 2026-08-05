import type { CapabilityStatus } from '../models/types'

/**
 * Capability-truth registry.
 *
 * Every entry is grounded in the source repository's own ledger
 * (docs/STATUS.md at commit ae7f902c) and the ADR series. Pages use these
 * keys to render Planned / Sealed / Simulated notices so the prototype
 * never implies an unavailable capability is operational.
 * See docs/07_CAPABILITY_TRUTH_MATRIX.md for the full evidence table.
 *
 * Reconciled against the final landed PR5E commit a9e9a27d
 * (docs/10_PR5E_FINAL_RECONCILIATION.md): that delta touches only
 * apps/management + docs — no apps/api or apps/web change — so every fact
 * below is unchanged. PR5E hardened an already production-sealed
 * management-plane foundation; no new capability became operational.
 */
export interface CapabilityFact {
  status: CapabilityStatus
  label: string
  note: string
}

export const capabilities: Record<string, CapabilityFact> = {
  'events.model': {
    status: 'planned',
    label: 'Events are a proposed product concept',
    note: 'The repo has no competition/event entity. The nearest implemented concept is the Exercise (simulated lifecycle, SECP-001). This workspace is a forward-looking design over that foundation.',
  },
  'events.phases': {
    status: 'planned',
    label: 'Competition phases are proposed',
    note: 'No phase model exists in the repo. Phase transitions are designed here as approval-gated controlled operations, matching the platform’s many-small-gates architecture.',
  },
  'events.control-room': {
    status: 'planned',
    label: 'Control Room is a design proposal',
    note: 'Emergency controls (freeze, isolate, suspend) have no backend today. All controls here are non-functional previews with confirm-style interactions.',
  },
  'events.scoring': {
    status: 'planned',
    label: 'Scoring is not implemented',
    note: 'SECP-004 (Wazuh/CTFd/telemetry/scoring) is not-implemented per docs/STATUS.md. All scores shown are mock data.',
  },
  'teams.model': {
    status: 'partial',
    label: 'Teams exist; team operations are proposed',
    note: 'Teams and per-team instances/subnets are real (simulated lifecycle, per-team CIDR reservations). Member management, connectivity status, and access operations are proposed.',
  },
  'access.gateway': {
    status: 'not-found',
    label: 'Access gateways are not in the repo',
    note: 'No VPN/WireGuard concept exists anywhere in the source repository. This workspace is a new gateway-agnostic design; WireGuard is the intended first implementation.',
  },
  'scenarios.library': {
    status: 'implemented',
    label: 'Scenario library is real (as Environment Templates)',
    note: 'Templates + immutable environment versions with content hashes are implemented (simulated execution only).',
  },
  'scenarios.builder': {
    status: 'partial',
    label: 'Builder core is real; rich palette is proposed',
    note: 'A React Flow + ELK topology workspace with durable revisions, validation, and approval exists. Node kinds today: attacker/target/sensor/network. The richer asset palette shown here is proposed.',
  },
  'scenarios.validation': {
    status: 'implemented',
    label: 'Definition validation is real',
    note: 'Server-side definition validation and topology validation exist. Deeper deployment validation checks are proposed.',
  },
  'scenarios.vulnerabilities': {
    status: 'planned',
    label: 'Vulnerability packs are not implemented',
    note: 'SECP-003 (content/vulnerability packs) is not-implemented. A YAML example (weak-ssh) exists as documentation only.',
  },
  'deployments.lifecycle': {
    status: 'simulated',
    label: 'Deployment lifecycle is simulated',
    note: 'The simulator is the only complete deployment lifecycle; its effects are database records, not real infrastructure (docs/STATUS.md).',
  },
  'deployments.plan': {
    status: 'implemented',
    label: 'Plans + approval gates are real',
    note: 'Deterministic plans and explicit approval with pinned content hashes are implemented. Approval records a decision; it is a separate step from carrying the plan out.',
  },
  'deployments.apply': {
    status: 'partial',
    label: 'Provisioning support varies by provider',
    note: 'The simulator implements the full lifecycle against database records. Provider-backed provisioning exists for Proxmox. Whether an apply can run, and under what authorization, is determined by the control plane and is not shown here.',
  },
  'deployments.reset': {
    status: 'simulated',
    label: 'Reset/destroy are simulated',
    note: 'Reset/destroy work end-to-end against the simulator only. SECP-002C (real reconciliation/reset/destroy) is not-implemented.',
  },
  'deployments.drift': {
    status: 'planned',
    label: 'Drift detection is proposed',
    note: 'Read-only inventory snapshots exist; drift comparison against desired state is a design concept here.',
  },
  'deployments.cost': {
    status: 'planned',
    label: 'Cost tracking is proposed',
    note: 'No cost model exists in the repo. All cost figures are mock data.',
  },
  'infrastructure.targets': {
    status: 'implemented',
    label: 'Target registration + onboarding are real (fake preflight)',
    note: 'Execution targets, immutable boundaries, onboarding lifecycle, and approvals are implemented; preflight evidence is fake-only and the live-evidence seal is in force.',
  },
  'infrastructure.discovery': {
    status: 'read-only',
    label: 'Discovery collects inventory without modifying it',
    note: 'A worker-owned discovery path collects inventory; candidate plans derived from it are review material rather than an execution artifact. Whether the live path is available depends on the activation chain configured for the target.',
  },
  'infrastructure.placement': {
    status: 'planned',
    label: 'Placement policies are proposed',
    note: 'No placement engine exists. Per-resource placement across targets is a forward-looking design.',
  },
  'infrastructure.workers': {
    status: 'partial',
    label: 'Workers are real; this console is proposed',
    note: 'Worker processes, task queues, and worker-only execution are implemented. A worker operations console does not exist yet.',
  },
  'infrastructure.cloud': {
    status: 'not-found',
    label: 'Cloud providers are not implemented',
    note: 'AWS/Azure/GCP/Kubernetes plugins do not exist (SECP-006 future work). All cloud deployments shown are mock data.',
  },
  'reports.generation': {
    status: 'planned',
    label: 'Reporting is not implemented',
    note: 'Audit records and change-sets are real; after-action/executive/scoring reports are not-implemented (SECP-004/artifacts partially-implemented).',
  },
  'platform.identity': {
    status: 'partial',
    label: 'OIDC auth is real; identity administration is proposed',
    note: 'OIDC bearer + PKCE auth is implemented; authorization is DB-owned. There is no identity-lifecycle UI/API today.',
  },
  'platform.secrets': {
    status: 'partial',
    label: 'Opaque references only; values resolve worker-side',
    note: 'The control plane holds opaque references. Resolving a reference to a value is a worker-side concern and has no interface in this application.',
  },
  'platform.workflows': {
    status: 'partial',
    label: 'Workflow runs are real; this console is proposed',
    note: 'Durable workflow dispatch (inline default + Temporal path + transactional outbox) is implemented. The Jobs/Schedules UI was an intentionally disabled placeholder.',
  },
  'platform.audit': {
    status: 'implemented',
    label: 'Audit ledger is real',
    note: 'Immutable audit events for every mutation, with recorded refusals, are implemented.',
  },
  'platform.evidence': {
    status: 'partial',
    label: 'Evidence records are real; storage browsing is proposed',
    note: 'Hash-bound preflight/discovery/readiness evidence exists. MinIO-backed artifact browsing is aspirational.',
  },
  'platform.organizations': {
    status: 'partial',
    label: 'Org-scoped RBAC is real; org administration is proposed',
    note: 'Organizations and permissions are enforced in the backend; there is no org/team management UI today.',
  },
  'platform.settings': {
    status: 'planned',
    label: 'Platform settings are proposed',
    note: 'The existing UI ships Settings as a truthfully disabled nav stub.',
  },
  'platform.retention': {
    status: 'planned',
    label: 'Retention & backup are proposed',
    note: 'Backup/restore and retention policies are SECP-006 future work.',
  },
}

export function capability(key: string): CapabilityFact {
  return (
    capabilities[key] ?? {
      status: 'planned',
      label: 'Proposed capability',
      note: 'This surface is a design proposal without backend support.',
    }
  )
}
