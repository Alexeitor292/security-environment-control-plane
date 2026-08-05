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
 * Provider plugins.
 *
 * THIS PAGE DELIBERATELY ASSERTS NOTHING ABOUT WHAT ANY PROVIDER WILL REFUSE OR
 * PERMIT.
 *
 * It used to. It carried a hand-written table stating that for Proxmox every
 * mutating operation -- plan, apply, reset, destroy -- was `refused`, that
 * discovery was GET-only, and that refusals were audited. Nothing verified any
 * of that; it was frontend copy about a security control. By the time this was
 * migrated it had already gone stale: the Proxmox apply, destroy, verification
 * and residue-proof paths shipped in SECP-PROXMOX #105-#110, so the page was
 * telling operators that operations were refused while the endpoints to perform
 * them existed.
 *
 * The obvious repair -- source the table from `GET /api/v1/providers/capabilities`
 * -- is worse, not better. That endpoint returns a hardcoded constant
 * (`PROVISIONING_ENABLED = False`, "Proxmox provisioning is deferred") and is
 * stale in exactly the same way. Wiring the page to it would relocate the false
 * claim from the frontend to the backend and make it look observed, because a
 * claim sourced from an API reads as verified. That is a harder lie to catch.
 *
 * So every capability cell renders `unverified` until something actually
 * observes provider behaviour. This is not a hedge for tidiness. A fixture label
 * is an adequate caveat for a deployment count; it is NOT adequate for "every
 * mutating operation is refused", because an operator may act on that and the
 * error is in the direction where someone gets hurt. Under-claiming is
 * recoverable; over-claiming safety is not.
 *
 * Wiring lands in P7-D, once the capability endpoint reports observed capability
 * rather than a constant.
 */

const PROVIDER_NOTES: Record<string, string> = {
  'int-proxmox':
    'This page does not determine which operations the Proxmox plugin permits or refuses. That is a property of the running control plane, and nothing here observes it.',
  'int-aws':
    'No AWS provider plugin exists in this repository. AWS deployments shown in this prototype are fixture data.',
  'int-azure':
    'No Azure provider plugin exists in this repository. Azure deployments shown in this prototype are fixture data.',
  'int-gcp':
    'No GCP provider plugin exists in this repository. GCP deployments shown in this prototype are fixture data.',
  'int-k8s':
    'No Kubernetes provider plugin exists in this repository; Kubernetes appears only as a local/dev execution substrate.',
}

/**
 * The only value this column can honestly take today.
 *
 * Kept as a union rather than collapsed to a bare string so that adding an
 * observed value later is a typed change with a visible diff, rather than a
 * string quietly appearing in a cell.
 */
type OpSupport = 'unverified'

interface TaxonomyRow {
  op: string
  /** What the plugin contract defines. NOT what any provider does with it. */
  note: string
}

/**
 * The operations defined by plugin API v1.
 *
 * This list is a contract fact -- it is what `contracts/plugin-api` declares --
 * and is safe to state. What each provider DOES with each operation is a
 * runtime property and is not stated anywhere on this page.
 */
const TAXONOMY: TaxonomyRow[] = [
  { op: 'validate', note: 'Definition + provider-config checks' },
  { op: 'plan', note: 'Deterministic change-set; approval pins the content hash' },
  { op: 'apply', note: 'Provisioning against the provider' },
  { op: 'discover', note: 'Inventory collection' },
  { op: 'reset', note: 'Return resources to a known baseline' },
  { op: 'destroy', note: 'Tear resources down' },
]

const SUPPORT_META: Record<OpSupport, { tone: StatusTone; label: string }> = {
  // `unknown` tone, never `ok` and never `error`: the point is that this is not
  // determined. An `ok` would read as permitted and an `error` would read as
  // refused, and both would be assertions this page cannot make.
  unverified: { tone: 'unknown', label: 'not determined' },
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
      render: () => <SupportBadge support="unverified" />,
    },
    {
      key: 'proxmox',
      header: 'Proxmox plugin',
      render: () => <SupportBadge support="unverified" />,
    },
    { key: 'cloud', header: 'Cloud plugins', render: () => <SupportBadge support="unverified" /> },
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
        // No `sealed` tag for Proxmox. "Sealed" is a claim that provisioning
        // cannot happen, and this page has no way to observe whether that is
        // true -- it was not true by the time this was migrated.
        <span className="u-row">
          <CapabilityTag status={integration.status} />
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
        which operations it advertises. The simulator is the reference implementation of the
        contract.
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
            Implements the full contract lifecycle: validate → plan → apply → discover → reset →
            destroy.
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
          These are the operations the plugin contract defines. Whether a given provider permits or
          refuses any of them is a property of the running control plane, and this page does not
          observe it — so it is shown as <strong>not determined</strong> rather than guessed in
          either direction. Do not read a cell here as authorization to run an operation, or as an
          assurance that one cannot run.
        </p>
      </Card>
    </div>
  )
}
