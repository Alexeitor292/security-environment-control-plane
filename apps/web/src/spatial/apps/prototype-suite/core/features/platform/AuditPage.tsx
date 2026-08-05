import { useMemo, useState } from 'react'
import { Download } from 'lucide-react'
import {
  Button,
  CapabilityNotice,
  Card,
  DataTable,
  Drawer,
  ErrorState,
  FilterBar,
  FilterSelect,
  KeyValueGrid,
  LoadingState,
  SearchField,
  StatusBadge,
} from '../../components'
import type { Column } from '../../components'
import { useQuery } from '../../integrations/AdapterContext'
import type { AuditEvent, EvidenceRecord } from '../../models/types'

function fmtUtc(iso?: string): string {
  return iso ? `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC` : '—'
}

const AUDIT_COLUMNS: Column<AuditEvent>[] = [
  {
    key: 'time',
    header: 'Time',
    render: (e) => <span className="u-mono u-xs">{fmtUtc(e.time)}</span>,
  },
  { key: 'actor', header: 'Actor', render: (e) => <span className="u-small">{e.actor}</span> },
  {
    key: 'action',
    header: 'Action',
    render: (e) => <span className="u-mono u-xs">{e.action}</span>,
  },
  {
    key: 'resource',
    header: 'Resource',
    render: (e) => <span className="u-small">{e.resource}</span>,
  },
  { key: 'outcome', header: 'Outcome', render: (e) => <StatusBadge state={e.outcome} /> },
  {
    key: 'origin',
    header: 'Origin',
    render: (e) => <span className="u-mono u-xs">{e.origin}</span>,
  },
]

const EVIDENCE_COLUMNS: Column<EvidenceRecord>[] = [
  {
    key: 'time',
    header: 'Time',
    render: (r) => <span className="u-mono u-xs">{fmtUtc(r.time)}</span>,
  },
  { key: 'kind', header: 'Kind', render: (r) => <span className="u-mono u-xs">{r.kind}</span> },
  {
    key: 'subject',
    header: 'Subject',
    render: (r) => <span className="u-small">{r.subject}</span>,
  },
  { key: 'sha', header: 'SHA-256', render: (r) => <span className="u-mono u-xs">{r.sha256}</span> },
  { key: 'store', header: 'Store', render: (r) => <span className="u-mono u-xs">{r.store}</span> },
]

export default function AuditPage() {
  const auditQ = useQuery((a) => a.listAuditEvents())
  const evidenceQ = useQuery((a) => a.listEvidence())
  const [outcome, setOutcome] = useState('all')
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<AuditEvent | undefined>()

  const filtered = useMemo(() => {
    let list = auditQ.data ?? []
    if (outcome !== 'all') list = list.filter((e) => e.outcome === outcome)
    if (search.trim()) {
      const q = search.toLowerCase()
      list = list.filter(
        (e) =>
          e.actor.toLowerCase().includes(q) ||
          e.action.toLowerCase().includes(q) ||
          e.resource.toLowerCase().includes(q),
      )
    }
    return list
  }, [auditQ.data, outcome, search])

  if (auditQ.loading) {
    return (
      <div className="u-page">
        <LoadingState lines={6} />
      </div>
    )
  }
  if (auditQ.error || !auditQ.data) {
    return (
      <div className="u-page">
        <ErrorState message={auditQ.error ?? 'Mock data unavailable.'} />
      </div>
    )
  }

  return (
    <div className="u-page">
      <CapabilityNotice capKey="platform.audit" />

      <Card
        heading="Audit ledger"
        actions={
          <Button
            size="sm"
            variant="ghost"
            icon={<Download size={14} aria-hidden />}
            disabled
            title="Disabled: audit-export reporting is planned (see Reports)"
          >
            Export
          </Button>
        }
      >
        <FilterBar>
          <FilterSelect
            label="Outcome"
            value={outcome}
            onChange={setOutcome}
            options={[
              { value: 'all', label: 'All outcomes' },
              { value: 'success', label: 'Success' },
              { value: 'denied', label: 'Denied' },
              { value: 'failed', label: 'Failed' },
            ]}
          />
          <SearchField
            value={search}
            onChange={setSearch}
            placeholder="Search actor, action, resource…"
          />
        </FilterBar>
        <DataTable
          columns={AUDIT_COLUMNS}
          rows={filtered}
          rowKey={(e) => e.id}
          onRowClick={setSelected}
          selectedKey={selected?.id}
          label="Audit events"
          emptyTitle="No audit events match"
          emptyBody="Adjust the outcome filter or search."
        />
        <p className="u-muted u-xs" style={{ marginTop: 'var(--sp-2)' }}>
          Every mutation is recorded — including refusals (denied outcomes are first-class records,
          not silent drops). Entries shown are fixture data.
        </p>
      </Card>

      <section aria-label="Evidence records">
        <CapabilityNotice capKey="platform.evidence" />
        <Card heading="Evidence records">
          {evidenceQ.loading ? (
            <LoadingState lines={3} />
          ) : (
            <DataTable
              columns={EVIDENCE_COLUMNS}
              rows={evidenceQ.data ?? []}
              rowKey={(r) => r.id}
              label="Evidence records"
              emptyTitle="No evidence records"
            />
          )}
          <p className="u-muted u-xs" style={{ marginTop: 'var(--sp-2)' }}>
            Records are hash-bound: the SHA-256 pins the artifact content at capture time. Browsing
            the underlying store is proposed, not implemented.
          </p>
        </Card>
      </section>

      <Drawer
        open={Boolean(selected)}
        title="Operator-safe view"
        onClose={() => setSelected(undefined)}
      >
        {selected && (
          <div className="c-inspector">
            <KeyValueGrid
              columns={1}
              items={[
                { key: 'Record id', value: selected.id, mono: true },
                { key: 'Time', value: fmtUtc(selected.time), mono: true },
                { key: 'Actor', value: selected.actor },
                { key: 'Action', value: selected.action, mono: true },
                { key: 'Resource', value: selected.resource, mono: true },
                { key: 'Outcome', value: <StatusBadge state={selected.outcome} /> },
                { key: 'Origin', value: selected.origin, mono: true },
              ]}
            />
            <p className="u-muted u-xs">
              Fields shown are allowlisted for operator viewing. Raw payloads, internal identifiers,
              and anything secret-adjacent never leave the server.
            </p>
          </div>
        )}
      </Drawer>
    </div>
  )
}
