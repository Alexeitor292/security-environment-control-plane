import type { CapabilityFact } from '../models'

export const capabilityFacts: CapabilityFact[] = [
  {
    key: 'infrastructure.targets',
    status: 'implemented',
    label: 'Target registration and onboarding are real',
    note: 'Execution targets, immutable boundaries, onboarding lifecycle, and approvals are implemented. Preflight evidence remains fake-only.',
  },
  {
    key: 'infrastructure.discovery',
    status: 'read-only',
    label: 'Discovery is read-only and sealed by default',
    note: 'Controlled worker-owned discovery exists behind explicit gates. Candidate plans are non-executable.',
  },
  {
    key: 'infrastructure.placement',
    status: 'planned',
    label: 'Placement policies are proposed',
    note: 'No placement engine exists yet. The current view is a product design using fixture capacity data.',
  },
  {
    key: 'infrastructure.workers',
    status: 'partial',
    label: 'Workers are real; this operations console is proposed',
    note: 'Worker processes and task queues exist. Full worker administration is not yet implemented.',
  },
  {
    key: 'infrastructure.cloud',
    status: 'not-found',
    label: 'Cloud provider execution is not implemented',
    note: 'AWS, Azure, and GCP data shown in this prototype is fixture data. No provider plugin is active.',
  },
  {
    key: 'deployments.apply',
    status: 'sealed',
    label: 'Real provisioning remains sealed',
    note: 'Plan-only behavior exists, but apply and destroy are not enabled against real infrastructure.',
  },
]
