import {
  Button,
  CapabilityNotice,
  CapabilityTag,
  Card,
  DataTable,
  ErrorState,
  LoadingState,
  ProviderBadge,
  StatusBadge,
} from '../../components'
import type { Column } from '../../components'
import { useQuery } from '../../integrations/AdapterContext'
import type { EvidenceRecord, InfraTarget } from '../../models/types'

/**
 * Inventory & Discovery — read-only posture. A controlled worker-owned
 * read-only discovery path exists behind an 8-gate chain; candidate plans
 * are non-executable, and no real endpoint has been contacted.
 */

function fmtUtc(iso?: string): string {
  return iso ? `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC` : 'never'
}

interface MockResource {
  target: string
  targetId: string
  resourceId: string
  type: string
  observedAt: string
}

/** Illustrative observed-resource rows; observed_at mirrors each target's fixture lastDiscovery. */
const MOCK_INVENTORY: MockResource[] = [
  {
    target: 'Main Proxmox Cluster',
    targetId: 'tgt-proxmox-main',
    resourceId: 'qemu/141 (web-5)',
    type: 'vm',
    observedAt: '2026-07-18T12:45:00Z',
  },
  {
    target: 'Main Proxmox Cluster',
    targetId: 'tgt-proxmox-main',
    resourceId: 'vmbr0',
    type: 'bridge',
    observedAt: '2026-07-18T12:45:00Z',
  },
  {
    target: 'Main Proxmox Cluster',
    targetId: 'tgt-proxmox-main',
    resourceId: 'local-lvm',
    type: 'storage-pool',
    observedAt: '2026-07-18T12:45:00Z',
  },
  {
    target: 'AWS Production Account',
    targetId: 'tgt-aws-prod',
    resourceId: 'vpc-0a3f19e2',
    type: 'vpc',
    observedAt: '2026-07-18T11:30:00Z',
  },
  {
    target: 'AWS Production Account',
    targetId: 'tgt-aws-prod',
    resourceId: 'i-04b2c9d1',
    type: 'ec2-instance',
    observedAt: '2026-07-18T11:30:00Z',
  },
  {
    target: 'GCP Cyber-Range Project',
    targetId: 'tgt-gcp-range',
    resourceId: 'instances/score-check-1',
    type: 'compute-instance',
    observedAt: '2026-07-18T11:00:00Z',
  },
  {
    target: 'Azure Training Subscription',
    targetId: 'tgt-azure-training',
    resourceId: 'rg-training/obs-vm-1',
    type: 'virtual-machine',
    observedAt: '2026-07-17T22:15:00Z',
  },
  {
    target: 'Local Kubernetes Dev Cluster',
    targetId: 'tgt-k8s-local',
    resourceId: 'ns/web101-stage',
    type: 'namespace',
    observedAt: '2026-07-18T12:00:00Z',
  },
]

const DISCOVERY_STEPS = [
  'An operator enqueues a discovery request — queue-only, never direct execution.',
  'A worker bound to the target picks the task up; the control plane never contacts endpoints.',
  'The collector performs GET-only reads against the provider API (read-only by construction).',
  'The live path is sealed by default behind an 8-gate activation chain; today only fake-mode collection runs.',
  'Observations are hashed and recorded as discovery-snapshot evidence.',
  'Candidate plans derived from observations are non-executable — review material only.',
]

export default function InventoryPage() {
  const targetsQ = useQuery((a) => a.listTargets())
  const evidenceQ = useQuery((a) => a.listEvidence())

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
  const discoveryEvidence = (evidenceQ.data ?? []).filter((e) => e.kind === 'discovery-snapshot')

  const postureColumns: Column<InfraTarget>[] = [
    {
      key: 'target',
      header: 'Target',
      render: (t) => (
        <div>
          <strong className="u-small">{t.name}</strong>
          <span className="u-muted u-xs u-mono" style={{ display: 'block' }}>
            {t.id}
          </span>
        </div>
      ),
    },
    { key: 'provider', header: 'Provider', render: (t) => <ProviderBadge provider={t.provider} /> },
    {
      key: 'onboarding',
      header: 'Onboarding',
      render: (t) => <StatusBadge state={t.onboardingState} />,
    },
    {
      key: 'discover',
      header: 'Discover capability',
      render: (t) =>
        t.capabilities.includes('discover') ? (
          <StatusBadge state="advertised" tone="ok" />
        ) : (
          <StatusBadge state="not-advertised" tone="neutral" label="not advertised" />
        ),
    },
    {
      key: 'last',
      header: 'Last discovery',
      render: (t) => <span className="u-xs u-mono">{fmtUtc(t.lastDiscovery)}</span>,
    },
  ]

  const inventoryColumns: Column<MockResource>[] = [
    {
      key: 'target',
      header: 'Target',
      render: (r) => (
        <div>
          <span className="u-small">{r.target}</span>
          <span className="u-muted u-xs u-mono" style={{ display: 'block' }}>
            {r.targetId}
          </span>
        </div>
      ),
    },
    {
      key: 'id',
      header: 'Resource id',
      render: (r) => <span className="u-small u-mono">{r.resourceId}</span>,
    },
    { key: 'type', header: 'Type', render: (r) => <span className="inf-chip">{r.type}</span> },
    {
      key: 'observed',
      header: 'observed_at',
      render: (r) => <span className="u-xs u-mono">{fmtUtc(r.observedAt)}</span>,
    },
  ]

  const evidenceColumns: Column<EvidenceRecord>[] = [
    {
      key: 'time',
      header: 'Time',
      render: (e) => <span className="u-xs u-mono">{fmtUtc(e.time)}</span>,
    },
    {
      key: 'subject',
      header: 'Subject',
      render: (e) => <span className="u-small">{e.subject}</span>,
    },
    {
      key: 'sha',
      header: 'SHA-256',
      render: (e) => <span className="u-xs u-mono">{e.sha256}</span>,
    },
    {
      key: 'store',
      header: 'Store',
      render: (e) => <span className="u-xs u-mono">{e.store}</span>,
    },
  ]

  return (
    <div className="u-page">
      <CapabilityNotice capKey="infrastructure.discovery" />
      <p className="u-secondary u-small" style={{ margin: 0 }}>
        What the platform has observed on each target, and how it observed it. Discovery is strictly
        read-only: requests are enqueued, executed by workers, and produce hash-bound evidence —
        never changes.
      </p>

      <Card
        heading="Discovery posture by target"
        actions={
          <Button
            size="sm"
            disabled
            title="Enqueue-only; the live discovery path is sealed behind an 8-gate activation chain — not wired in this prototype"
          >
            Run discovery
          </Button>
        }
      >
        <DataTable
          columns={postureColumns}
          rows={targets}
          rowKey={(t) => t.id}
          label="Discovery posture by target"
          emptyTitle="No targets registered"
        />
      </Card>

      <div
        className="u-grid"
        style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))' }}
      >
        <Card heading="How discovery works">
          <ol className="u-small u-secondary" style={{ margin: 0, paddingLeft: 18 }}>
            {DISCOVERY_STEPS.map((s) => (
              <li key={s} style={{ padding: '3px 0' }}>
                {s}
              </li>
            ))}
          </ol>
          <p className="u-muted u-xs" style={{ marginTop: 'var(--sp-2)' }}>
            No real endpoint has ever been contacted — the sealed live path has only run in fake
            mode.
          </p>
        </Card>

        <Card heading="Discovery evidence">
          {discoveryEvidence.length === 0 ? (
            <p className="u-secondary u-small" style={{ margin: 0 }}>
              No discovery-snapshot evidence recorded.
            </p>
          ) : (
            <DataTable
              columns={evidenceColumns}
              rows={discoveryEvidence}
              rowKey={(e) => e.id}
              label="Discovery evidence records"
            />
          )}
          <p className="u-muted u-xs" style={{ marginTop: 'var(--sp-2)' }}>
            Hash-bound discovery snapshots from the evidence ledger (kind: discovery-snapshot).
          </p>
        </Card>
      </div>

      <Card
        heading="Inventory snapshot"
        actions={
          <span className="u-row">
            <CapabilityTag status="ui-only" />
            <span className="u-muted u-xs">mock rows</span>
          </span>
        }
      >
        <DataTable
          columns={inventoryColumns}
          rows={MOCK_INVENTORY}
          rowKey={(r) => `${r.targetId}-${r.resourceId}`}
          label="Mock inventory snapshot"
        />
        <p className="u-muted u-xs" style={{ marginTop: 'var(--sp-2)' }}>
          Illustrative observed resources only — the platform&rsquo;s real snapshots exist solely
          for the simulator and fake-mode Proxmox collection.
        </p>
      </Card>
    </div>
  )
}
