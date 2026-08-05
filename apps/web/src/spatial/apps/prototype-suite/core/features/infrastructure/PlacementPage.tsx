import { useState } from 'react'
import {
  AdvancedSection,
  Button,
  CapabilityNotice,
  CapabilityTag,
  Card,
  DataTable,
  ErrorState,
  LoadingState,
  ProviderBadge,
} from '../../components'
import type { Column } from '../../components'
import { useQuery } from '../../integrations/AdapterContext'
import type { Provider } from '../../models/types'

/**
 * Capacity & Placement — entirely a design proposal. No placement engine
 * exists in the platform; the policy selection is local UI state only.
 */

const POLICIES: { key: string; label: string; detail: string }[] = [
  {
    key: 'automatic',
    label: 'Automatic',
    detail: 'Platform picks a target using capacity, cost, and capability fit.',
  },
  {
    key: 'lowest-cost',
    label: 'Lowest estimated cost',
    detail: 'Prefer the target with the lowest estimated hourly cost.',
  },
  {
    key: 'preferred-provider',
    label: 'Preferred provider',
    detail: 'Prefer a named provider (e.g. Proxmox first), fall back by capacity.',
  },
  {
    key: 'specific-region',
    label: 'Specific region',
    detail: 'Constrain placement to a named region (e.g. us-west-2).',
  },
  {
    key: 'local-only',
    label: 'Local-only',
    detail: 'On-prem virtualization targets only; never cloud.',
  },
  { key: 'cloud-only', label: 'Cloud-only', detail: 'Cloud targets only; never on-prem.' },
  {
    key: 'hybrid',
    label: 'Hybrid',
    detail: 'Split placement: team zones on-prem, public services in cloud.',
  },
  {
    key: 'high-availability',
    label: 'High availability',
    detail: 'Spread replicas across at least two targets or providers.',
  },
  {
    key: 'data-residency',
    label: 'Data-residency constrained',
    detail: 'Keep data-holding resources inside a named jurisdiction.',
  },
]

interface PlacementExample {
  resource: string
  provider: Provider
  target: string
  rationale: string
}

const PLACEMENT_EXAMPLES: PlacementExample[] = [
  {
    resource: 'Team environments',
    provider: 'proxmox',
    target: 'Main Proxmox Cluster (tgt-proxmox-main)',
    rationale: 'Low latency to participants; no per-hour cost',
  },
  {
    resource: 'Public scoring service',
    provider: 'aws',
    target: 'AWS Production Account (tgt-aws-prod)',
    rationale: 'Public reachability and autoscaling',
  },
  {
    resource: 'Central monitoring',
    provider: 'gcp',
    target: 'GCP Cyber-Range Project (tgt-gcp-range)',
    rationale: 'Managed logging capacity',
  },
  {
    resource: 'Evidence backup',
    provider: 'azure',
    target: 'Azure Training Subscription (tgt-azure-training)',
    rationale: 'Separate provider for durability',
  },
]

function CapacityBar({ usedPercent, detail }: { usedPercent: number; detail: string }) {
  const warn = usedPercent > 80
  return (
    <div className={`inf-capbar${warn ? ' inf-capbar--warn' : ''}`}>
      <div className="inf-capbar__track" role="img" aria-label={`${usedPercent}% capacity used`}>
        <div className="inf-capbar__fill" style={{ width: `${usedPercent}%` }} />
      </div>
      <span className="inf-capbar__label">
        {usedPercent}% · {detail}
      </span>
    </div>
  )
}

export default function PlacementPage() {
  const targetsQ = useQuery((a) => a.listTargets())
  const [policy, setPolicy] = useState('automatic')

  if (targetsQ.loading) {
    return (
      <div className="u-page">
        <LoadingState lines={6} />
      </div>
    )
  }
  if (targetsQ.error || !targetsQ.data) {
    return (
      <div className="u-page">
        <ErrorState message={targetsQ.error ?? 'Mock data unavailable.'} />
      </div>
    )
  }

  const targets = targetsQ.data

  const exampleColumns: Column<PlacementExample>[] = [
    {
      key: 'resource',
      header: 'Resource group',
      render: (r) => <strong className="u-small">{r.resource}</strong>,
    },
    { key: 'provider', header: 'Provider', render: (r) => <ProviderBadge provider={r.provider} /> },
    {
      key: 'target',
      header: 'Target',
      render: (r) => <span className="u-small u-mono">{r.target}</span>,
    },
    {
      key: 'rationale',
      header: 'Rationale',
      render: (r) => <span className="u-secondary u-xs">{r.rationale}</span>,
    },
  ]

  return (
    <div className="u-page">
      <CapabilityNotice capKey="infrastructure.placement" />
      <p className="u-secondary u-small" style={{ margin: 0 }}>
        Where should each part of a deployment run? This page drafts the placement-policy vocabulary
        and shows real per-target capacity from the fixture set. Everything here is planned — no
        placement engine exists, and the selection below is a local UI draft only.
      </p>

      <div
        className="u-grid"
        style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))' }}
      >
        <Card
          heading="Placement policy"
          actions={
            <Button
              size="sm"
              disabled
              title="Planned — no placement engine exists; the selection is not saved"
            >
              Save policy
            </Button>
          }
        >
          <fieldset className="inf-policy">
            <legend className="sr-only">Placement policy</legend>
            {POLICIES.map((p) => (
              <label key={p.key} className={policy === p.key ? 'is-selected' : undefined}>
                <input
                  type="radio"
                  name="placement-policy"
                  value={p.key}
                  checked={policy === p.key}
                  onChange={() => setPolicy(p.key)}
                />
                <span className="u-small">
                  {p.label}
                  <span className="u-muted u-xs" style={{ display: 'block' }}>
                    {p.detail}
                  </span>
                </span>
              </label>
            ))}
          </fieldset>
          <p className="u-muted u-xs" style={{ marginTop: 'var(--sp-2)' }}>
            Proposed vocabulary — policies would resolve to a concrete target per resource at plan
            time, and the chosen placement would be pinned into the approved plan.
          </p>
        </Card>

        <Card heading="Capacity overview">
          <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
            {targets.map((t) => (
              <li key={t.id} className="u-spread" style={{ padding: '6px 0', gap: 'var(--sp-3)' }}>
                <span className="u-row u-small" style={{ minWidth: 0, flexWrap: 'wrap' }}>
                  <ProviderBadge provider={t.provider} />
                  <span>{t.name}</span>
                </span>
                <CapacityBar usedPercent={t.capacity.usedPercent} detail={t.capacity.detail} />
              </li>
            ))}
          </ul>
          <p className="u-muted u-xs" style={{ marginTop: 'var(--sp-2)' }}>
            Fixture capacity figures. Cloud quotas and cost tracking are proposed; Proxmox numbers
            mirror the capacity alert threshold (warn above 80%).
          </p>
        </Card>
      </div>

      <AdvancedSection title="Per-resource placement (proposed example)" hint="Advanced · proposed">
        <div className="u-row" style={{ marginBottom: 'var(--sp-2)' }}>
          <CapabilityTag status="planned" />
          <span className="u-muted u-xs">
            Illustrative split of one event across four targets — nothing computes or applies this
            today.
          </span>
        </div>
        <DataTable
          columns={exampleColumns}
          rows={PLACEMENT_EXAMPLES}
          rowKey={(r) => r.resource}
          label="Proposed per-resource placement example"
        />
      </AdvancedSection>
    </div>
  )
}
