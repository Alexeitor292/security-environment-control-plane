import {
  CapabilityNotice,
  CapabilityTag,
  Card,
  CardGrid,
  DataTable,
  ErrorState,
  LoadingState,
  StatusBadge,
} from '../../components'
import type { Column, StatusTone } from '../../components'
import { useQuery } from '../../integrations/AdapterContext'
import type { IntegrationInfo } from '../../models/types'

/**
 * Provider plugins. Grounded in the repo: the simulator is the only complete
 * lifecycle; the Proxmox plugin is read-only with sealed provisioning; cloud
 * plugins (AWS/Azure/GCP/Kubernetes) do not exist.
 */

const PROVIDER_NOTES: Record<string, string> = {
  'int-proxmox':
    'Advertises validate, health, discover, and status only. Every mutating operation (plan, apply, reset, destroy) is refused, and the refusal is audited. Live discovery is GET-only and sealed behind activation gates.',
  'int-aws':
    'Planned provider plugin (SECP-006 future work). AWS deployments in this prototype are mock data.',
  'int-azure':
    'Planned provider plugin (SECP-006 future work). Azure deployments in this prototype are mock data.',
  'int-gcp':
    'Planned provider plugin (SECP-006 future work). GCP deployments in this prototype are mock data.',
  'int-k8s':
    'Planned provider plugin; today Kubernetes appears only as a local/dev execution substrate.',
}

type OpSupport = 'simulated' | 'advertised' | 'refused' | 'planned'

interface TaxonomyRow {
  op: string
  simulator: OpSupport
  proxmox: OpSupport
  cloud: OpSupport
  note: string
}

const TAXONOMY: TaxonomyRow[] = [
  {
    op: 'validate',
    simulator: 'simulated',
    proxmox: 'advertised',
    cloud: 'planned',
    note: 'Definition + provider-config checks',
  },
  {
    op: 'plan',
    simulator: 'simulated',
    proxmox: 'refused',
    cloud: 'planned',
    note: 'Deterministic change-set; approval pins the content hash',
  },
  {
    op: 'apply',
    simulator: 'simulated',
    proxmox: 'refused',
    cloud: 'planned',
    note: 'Real provisioning sealed (OpenTofu subprocess hard-sealed)',
  },
  {
    op: 'discover',
    simulator: 'simulated',
    proxmox: 'advertised',
    cloud: 'planned',
    note: 'Read-only, GET-only inventory collection',
  },
  {
    op: 'reset',
    simulator: 'simulated',
    proxmox: 'refused',
    cloud: 'planned',
    note: 'Simulator-only today (SECP-002C not implemented)',
  },
  {
    op: 'destroy',
    simulator: 'simulated',
    proxmox: 'refused',
    cloud: 'planned',
    note: 'Simulator-only today (SECP-002C not implemented)',
  },
]

const SUPPORT_META: Record<OpSupport, { tone: StatusTone; label: string }> = {
  simulated: { tone: 'info', label: 'simulated' },
  advertised: { tone: 'ok', label: 'advertised' },
  refused: { tone: 'error', label: 'refused' },
  planned: { tone: 'neutral', label: 'planned' },
}

function SupportBadge({ support }: { support: OpSupport }) {
  const meta = SUPPORT_META[support]
  return <StatusBadge state={support} label={meta.label} tone={meta.tone} />
}

export default function ProvidersPage() {
  const integrationsQ = useQuery((a) => a.listIntegrations())

  if (integrationsQ.loading) {
    return (
      <div className="u-page">
        <LoadingState lines={5} />
      </div>
    )
  }
  if (integrationsQ.error || !integrationsQ.data) {
    return (
      <div className="u-page">
        <ErrorState message={integrationsQ.error ?? 'Mock data unavailable.'} />
      </div>
    )
  }

  const providers = integrationsQ.data.filter(
    (i) => i.category === 'cloud' || i.category === 'virtualization',
  )

  const taxonomyColumns: Column<TaxonomyRow>[] = [
    {
      key: 'op',
      header: 'Operation',
      render: (r) => <span className="u-mono u-small">{r.op}</span>,
    },
    {
      key: 'simulator',
      header: 'Simulator',
      render: (r) => <SupportBadge support={r.simulator} />,
    },
    {
      key: 'proxmox',
      header: 'Proxmox plugin',
      render: (r) => <SupportBadge support={r.proxmox} />,
    },
    { key: 'cloud', header: 'Cloud plugins', render: (r) => <SupportBadge support={r.cloud} /> },
    {
      key: 'note',
      header: 'Notes',
      render: (r) => <span className="u-secondary u-xs">{r.note}</span>,
    },
  ]

  const providerCard = (integration: IntegrationInfo) => (
    <Card
      key={integration.id}
      heading={integration.name}
      actions={
        <span className="u-row">
          <CapabilityTag status={integration.status} />
          {integration.id === 'int-proxmox' && <CapabilityTag status="sealed" />}
        </span>
      }
    >
      <p className="u-secondary u-small" style={{ margin: 0 }}>
        {integration.detail}
      </p>
      {PROVIDER_NOTES[integration.id] && (
        <p className="u-muted u-xs" style={{ marginTop: 'var(--sp-2)' }}>
          {PROVIDER_NOTES[integration.id]}
        </p>
      )}
    </Card>
  )

  return (
    <div className="u-page">
      <CapabilityNotice capKey="infrastructure.cloud" />
      <p className="u-secondary u-small" style={{ margin: 0 }}>
        Providers integrate through a versioned plugin contract (plugin API v1). A plugin declares
        which operations it advertises; the control plane refuses anything not advertised and
        records the refusal in the audit ledger. The simulator is the reference implementation of
        the contract.
      </p>

      <CardGrid min={320}>
        <Card
          heading="Simulator (reference plugin)"
          actions={
            <span className="u-row">
              <CapabilityTag status="implemented" />
              <CapabilityTag status="simulated" />
            </span>
          }
        >
          <p className="u-secondary u-small" style={{ margin: 0 }}>
            The only complete lifecycle in the platform: validate → plan → apply → discover → reset
            → destroy. Its effects are database records, not real infrastructure.
          </p>
          <p className="u-muted u-xs" style={{ marginTop: 'var(--sp-2)' }}>
            Reference implementation of plugin API v1 — new plugins are held to its contract and
            test suite.
          </p>
        </Card>
        {providers.map(providerCard)}
      </CardGrid>

      <Card heading="Capability taxonomy (plugin API v1)">
        <DataTable
          columns={taxonomyColumns}
          rows={TAXONOMY}
          rowKey={(r) => r.op}
          label="Plugin capability taxonomy"
        />
        <p className="u-muted u-xs" style={{ marginTop: 'var(--sp-2)' }}>
          The Proxmox plugin additionally advertises health and status probes. &ldquo;Refused&rdquo;
          means the plugin rejects the operation at the contract boundary and the control plane
          records an audited refusal — the operation is never attempted against a real endpoint.
        </p>
      </Card>
    </div>
  )
}
