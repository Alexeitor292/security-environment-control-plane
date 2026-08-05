import { useMemo, useState } from 'react'
import { Download } from 'lucide-react'
import {
  Button,
  CapabilityNotice,
  Card,
  DataTable,
  Drawer,
  FilterBar,
  FilterSelect,
  KeyValueGrid,
  LoadingState,
  SearchField,
  StatusBadge,
} from '../../components'
import type { Column } from '../../components'
import { useQuery } from '../../integrations/AdapterContext'
import type { EvidenceRecord } from '../../models/types'
import { liveReader } from '../../../../../../api/control-plane-reader'
import {
  auditRows,
  NOT_SUPPLIED,
  type AuditRowView,
} from '../../../../../integrations/audit-projection'
import { PermissionGate } from '../../../../../integrations/principal'
import { QueryStateView } from '../../../../../integrations/QueryStateView'
import { useReaderQuery } from '../../../../../integrations/use-reader-query'

function fmtUtc(iso?: string): string {
  return iso ? `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC` : '—'
}

/** Stable identity for "no rows loaded", so the memos below keep their deps honest. */
const EMPTY_ROWS: readonly AuditRowView[] = []

/**
 * The word comes from the server; the colour comes from the design system.
 *
 * THE DISTINCTION THAT COST A DEFECT, kept here because the deleted symbol is
 * the only trace of it left. The projection used to export a `toned` flag that
 * answered "is this one of the three values the MIGRATED DOMAIN TYPE allows" --
 * a fact about `models/types.ts` under a name that reads as "can this surface
 * display it". This page asked it the second way to pick a badge colour, so
 * `revoked` and `expired` rendered in the neutral "we don't know" badge although
 * `STATE_TONE` has always classified both as errors. Grey with a question mark,
 * in a ledger where `failed` is red: under-claimed severity, which is the
 * direction someone gets hurt.
 *
 * `toneForState` is the right oracle because its own documented rule is that an
 * unrecognised state resolves to `unknown` and never to a healthy default --
 * error for `revoked`/`expired`/`denied`/`failed`, ok for `success`, neutral for
 * `refused`/`failure`, the two nothing has ever been told about.
 *
 * `label` is passed explicitly so the word survives untouched: the badge's own
 * default would run `state.replace(/-/g, ' ')` over it.
 */
function OutcomeBadge({ outcome }: { outcome: string }) {
  return <StatusBadge state={outcome} label={outcome} />
}

const AUDIT_COLUMNS: Column<AuditRowView>[] = [
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
  {
    key: 'outcome',
    header: 'Outcome',
    render: (e) => <OutcomeBadge outcome={e.outcome} />,
  },
  // NO `origin` COLUMN. The control plane does not publish the field, so every
  // cell would read "not supplied" -- a sixth of the table width spent repeating
  // one static fact, narrowing the five columns that carry real data. The
  // absence is stated once in the card footnote, where it is a standing property
  // of the surface, and once per record in the drawer, where a reader asking
  // about ONE record is in a position to want it. Dropping the column without
  // either would make the field silently missing rather than visibly considered.
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
  // LIVE: `GET /api/v1/audit`, projected without inventing. The server requires
  // `audit:read` -- resolved from `topology.list_audit_events`, which calls
  // `actor.require(Permission.audit_read)`, not guessed from the route name.
  const auditQ = useReaderQuery<AuditRowView>({
    requires: ['audit:read'],
    provenance: 'live',
    run: async () => auditRows(await liveReader.listAuditEvents()),
  })

  // FIXTURE: evidence is range-scoped (`listEvidence(rangeId)`) and no org-wide
  // route exists, so this half cannot go live from a page with no range in
  // scope. It stays on the mock adapter and the page badge absorbs to fixture.
  const evidenceQ = useQuery((a) => a.listEvidence())
  const [outcome, setOutcome] = useState('all')
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<AuditRowView | undefined>()

  // Memoised for identity, not for cost: the bare conditional produced a fresh
  // `[]` on every render, so both memos below re-ran every time and the linter
  // was right to say their dependency lists meant nothing.
  const loaded = useMemo(
    () => (auditQ.status === 'ready' ? auditQ.rows : EMPTY_ROWS),
    [auditQ],
  )

  /**
   * Options come from the rows CURRENTLY LOADED, and the control says so.
   *
   * A hardcoded list offered three of seven outcomes. Deriving from loaded data
   * is the same defect with a moving edge -- a `revoked` row further down the
   * ledger gives no `revoked` option here. Neither is a filter over the ledger,
   * so the label states what it actually covers. The real fix is a facet
   * endpoint, which does not exist and is recorded as `no-endpoint`.
   */
  const outcomeOptions = useMemo(() => {
    const present = [...new Set(loaded.map((e) => e.outcome))].sort()
    return [
      { value: 'all', label: 'All loaded outcomes' },
      ...present.map((o) => ({ value: o, label: o })),
    ]
  }, [loaded])

  const filtered = useMemo(() => {
    let list: readonly AuditRowView[] = loaded
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
  }, [loaded, outcome, search])

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
            options={outcomeOptions}
          />
          <SearchField
            value={search}
            onChange={setSearch}
            placeholder="Search actor, action, resource…"
          />
        </FilterBar>
        <PermissionGate requires={['audit:read']} surface="The audit ledger">
          <QueryStateView
            state={auditQ}
            surface="The audit ledger"
            emptyTitle="No audit events recorded"
            emptyBody="The control plane returned no entries."
          >
            {() => (
              <DataTable
                columns={AUDIT_COLUMNS}
                rows={[...filtered]}
                rowKey={(e) => e.id}
                onRowClick={setSelected}
                selectedKey={selected?.id}
                label="Audit events"
                emptyTitle="No audit events match"
                emptyBody="Adjust the outcome filter or search."
              />
            )}
          </QueryStateView>
        </PermissionGate>
        <p className="u-muted u-xs" style={{ marginTop: 'var(--sp-2)' }}>
          Every mutation is recorded — including refusals, which are first-class records rather
          than silent drops. Entries are read live from the control plane. Outcomes are shown
          exactly as recorded: the ledger uses more values than this surface has colours for, and
          an unfamiliar one is displayed as itself rather than mapped to the nearest familiar one.
          The outcome filter covers the entries currently loaded, not the whole ledger. The control
          plane does not record an origin for audit entries, so that field is not shown here and
          reads as not supplied on each record.
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
                {
                  key: 'Outcome',
                  value: <OutcomeBadge outcome={selected.outcome} />,
                },
                {
                  key: 'Origin',
                  value:
                    selected.origin === NOT_SUPPLIED
                      ? 'not supplied by the control plane'
                      : String(selected.origin),
                },
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
