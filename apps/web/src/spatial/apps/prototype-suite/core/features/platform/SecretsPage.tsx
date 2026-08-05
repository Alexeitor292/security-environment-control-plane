import { useState } from 'react'
import { RotateCcw } from 'lucide-react'
import {
  Button,
  CapabilityNotice,
  CapabilityTag,
  Card,
  CardGrid,
  DangerousOperationDialog,
  DataTable,
  ErrorState,
  LoadingState,
  ProviderBadge,
  StatusBadge,
} from '../../components'
import type { Column } from '../../components'
import { useQuery } from '../../integrations/AdapterContext'
import type { SecretRef } from '../../models/types'

function fmtUtc(iso?: string): string {
  return iso ? `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC` : '—'
}

const COLUMNS: Column<SecretRef>[] = [
  {
    key: 'name',
    header: 'Reference',
    render: (r) => <span className="u-mono u-xs">{r.name}</span>,
  },
  {
    key: 'purpose',
    header: 'Purpose',
    render: (r) => <span className="u-small">{r.purpose}</span>,
  },
  {
    key: 'provider',
    header: 'Provider',
    render: (r) =>
      r.provider === 'platform' ? (
        <span className="u-small">Platform</span>
      ) : (
        <ProviderBadge provider={r.provider} />
      ),
  },
  {
    key: 'target',
    header: 'Bound target',
    render: (r) =>
      r.boundTarget ? (
        <span className="u-mono u-xs">{r.boundTarget}</span>
      ) : (
        <span className="u-muted u-xs">—</span>
      ),
  },
  {
    key: 'type',
    header: 'Credential type',
    render: (r) => <span className="u-small">{r.credentialType}</span>,
  },
  {
    key: 'dynamic',
    header: 'Issuance',
    render: (r) => (
      <StatusBadge state={r.dynamic ? 'dynamic' : 'static'} tone={r.dynamic ? 'info' : 'neutral'} />
    ),
  },
  {
    key: 'rotation',
    header: 'Rotation',
    render: (r) =>
      r.dynamic ? (
        <span className="u-small">
          {r.rotationSchedule}
          <span className="u-muted u-xs" style={{ display: 'block' }}>
            lease expires {fmtUtc(r.leaseExpires)}
          </span>
        </span>
      ) : (
        <span className="u-small">
          {r.rotationSchedule}
          <span className="u-muted u-xs" style={{ display: 'block' }}>
            last {fmtUtc(r.lastRotation)}
          </span>
        </span>
      ),
  },
  {
    key: 'consumer',
    header: 'Consumer',
    render: (r) => <span className="u-xs">{r.consumer}</span>,
  },
  { key: 'health', header: 'Health', render: (r) => <StatusBadge state={r.health} /> },
]

export default function SecretsPage() {
  const secretsQ = useQuery((a) => a.listSecretRefs())
  const [rotateOpen, setRotateOpen] = useState(false)

  if (secretsQ.loading) {
    return (
      <div className="u-page">
        <LoadingState lines={5} />
      </div>
    )
  }
  if (secretsQ.error || !secretsQ.data) {
    return (
      <div className="u-page">
        <ErrorState message={secretsQ.error ?? 'Mock data unavailable.'} />
      </div>
    )
  }

  const refs = secretsQ.data
  const expiring = refs.filter((r) => r.health === 'expiring')

  return (
    <div className="u-page">
      <CapabilityNotice capKey="platform.secrets" />

      <p className="u-secondary u-small">
        The control plane stores <strong>opaque references and rotation metadata only</strong> — it
        never holds, displays, or transports secret values. There is nothing to reveal on this page
        by design.
      </p>

      <Card heading="Secret references">
        <DataTable columns={COLUMNS} rows={refs} rowKey={(r) => r.id} label="Secret references" />
        <p className="u-muted u-xs" style={{ marginTop: 'var(--sp-2)' }}>
          {refs.length} references · {expiring.length} expiring. Metadata is fixture data.
        </p>
      </Card>

      <CardGrid min={320}>
        <Card heading="Worker-only resolution">
          <p className="u-secondary u-small">
            References resolve to values <em>inside the worker</em> at the moment of use, scoped to
            the executing task, and are never returned to the control plane, logged, or persisted.
            The API and this UI handle only the reference names shown above.
          </p>
        </Card>

        <Card heading="OpenBao adapter" actions={<CapabilityTag status="sealed" />}>
          <p className="u-secondary u-small">
            An OpenBao resolver is committed in the source repository but sealed by default: no
            secret manager has ever been contacted. Until unsealed, workers resolve references from
            their local, operator-provisioned material only.
          </p>
        </Card>

        <Card
          heading="Rotation"
          actions={
            <Button
              size="sm"
              icon={<RotateCcw size={14} aria-hidden />}
              onClick={() => setRotateOpen(true)}
            >
              Request rotation…
            </Button>
          }
        >
          <p className="u-secondary u-small">
            Rotation is an approval-gated workflow, never an immediate action. The Azure service
            principal (expires 2026-07-25) already has a rotation request awaiting approval on the
            Workflow Engine page.
          </p>
        </Card>
      </CardGrid>

      <DangerousOperationDialog
        open={rotateOpen}
        title="Request credential rotation"
        operation="rotate azure-training/service-principal"
        requiredApprovals={['Platform admin']}
        onClose={() => setRotateOpen(false)}
        preview={
          <ul style={{ margin: 0, paddingLeft: 18 }} className="u-small u-secondary">
            <li>
              Issue a replacement service-principal secret (worker-side, value never surfaced)
            </li>
            <li>Verify consumer wrk-cloud-02 can resolve the new reference</li>
            <li>Revoke the outgoing secret after verification</li>
            <li>Record rotation receipt in the audit ledger</li>
          </ul>
        }
      />
    </div>
  )
}
