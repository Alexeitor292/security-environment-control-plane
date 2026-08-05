import { useState } from 'react'
import { Link } from 'react-router-dom'
import { ExternalLink } from 'lucide-react'
import {
  Button,
  CapabilityNotice,
  CapabilityTag,
  Card,
  CardGrid,
  DataTable,
  Drawer,
  ErrorState,
  KeyValueGrid,
  LoadingState,
  StatusBadge,
} from '../../components'
import type { Column, KeyValueItem } from '../../components'
import { useQuery } from '../../integrations/AdapterContext'
import type { WorkflowRun } from '../../models/types'

function fmtUtc(iso?: string): string {
  return iso ? `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC` : '—'
}

/** Mock queue depths — no live engine metrics exist in the prototype. */
const QUEUES = [
  { name: 'control-plane', depth: 2, note: 'phase transitions, rotations, approvals' },
  { name: 'proxmox-provision', depth: 0, note: 'apply / reset on Proxmox targets' },
  { name: 'proxmox-discovery', depth: 0, note: 'read-only inventory collection' },
  { name: 'cloud-provision', depth: 3, note: 'wrk-cloud-02 offline — Azure jobs waiting' },
]

const PROPOSED_SCHEDULES = [
  { id: 'sch-discovery', name: 'Read-only discovery', cadence: 'Every 6 h per activated target' },
  { id: 'sch-rotation', name: 'Credential rotation review', cadence: 'Weekly · Mon 09:00 UTC' },
]

export default function WorkflowsPage() {
  const runsQ = useQuery((a) => a.listWorkflowRuns())
  const workersQ = useQuery((a) => a.listWorkers())
  const [selected, setSelected] = useState<WorkflowRun | undefined>()

  if (runsQ.loading) {
    return (
      <div className="u-page">
        <LoadingState lines={6} />
      </div>
    )
  }
  if (runsQ.error || !runsQ.data) {
    return (
      <div className="u-page">
        <ErrorState message={runsQ.error ?? 'Mock data unavailable.'} />
      </div>
    )
  }

  const runs = runsQ.data
  const workers = workersQ.data ?? []
  const retrying = runs.filter((r) => r.status === 'retrying')
  const failed = runs.filter((r) => r.status === 'failed')

  const columns: Column<WorkflowRun>[] = [
    { key: 'name', header: 'Run', render: (r) => <strong className="u-small">{r.name}</strong> },
    { key: 'kind', header: 'Kind', render: (r) => <span className="u-mono u-xs">{r.kind}</span> },
    { key: 'status', header: 'Status', render: (r) => <StatusBadge state={r.status} /> },
    {
      key: 'started',
      header: 'Started',
      render: (r) => <span className="u-mono u-xs">{fmtUtc(r.startedAt)}</span>,
    },
    {
      key: 'finished',
      header: 'Finished',
      render: (r) => <span className="u-mono u-xs">{fmtUtc(r.finishedAt)}</span>,
    },
    {
      key: 'queue',
      header: 'Task queue',
      render: (r) => <span className="u-mono u-xs">{r.taskQueue}</span>,
    },
    {
      key: 'subject',
      header: 'Subject',
      render: (r) => (
        <span className="u-row u-xs" style={{ flexWrap: 'wrap', gap: 4 }}>
          {r.deploymentId && (
            <Link
              className="u-mono"
              to={`/deployments/${r.deploymentId}`}
              onClick={(e) => e.stopPropagation()}
            >
              {r.deploymentId}
            </Link>
          )}
          {r.eventId && (
            <Link
              className="u-mono"
              to={`/events/${r.eventId}`}
              onClick={(e) => e.stopPropagation()}
            >
              {r.eventId}
            </Link>
          )}
          {!r.deploymentId && !r.eventId && <span className="u-muted">—</span>}
        </span>
      ),
    },
  ]

  const drawerItems: KeyValueItem[] = selected
    ? [
        { key: 'Run id', value: selected.id, mono: true },
        { key: 'Kind', value: selected.kind },
        { key: 'Status', value: <StatusBadge state={selected.status} /> },
        { key: 'Task queue', value: selected.taskQueue, mono: true },
        { key: 'Started', value: fmtUtc(selected.startedAt) },
        { key: 'Finished', value: fmtUtc(selected.finishedAt) },
        ...(selected.deploymentId
          ? [
              {
                key: 'Deployment',
                value: (
                  <Link className="u-mono u-small" to={`/deployments/${selected.deploymentId}`}>
                    {selected.deploymentId}
                  </Link>
                ),
              },
            ]
          : []),
        ...(selected.eventId
          ? [
              {
                key: 'Event',
                value: (
                  <Link className="u-mono u-small" to={`/events/${selected.eventId}`}>
                    {selected.eventId}
                  </Link>
                ),
              },
            ]
          : []),
      ]
    : []

  return (
    <div className="u-page">
      <CapabilityNotice capKey="platform.workflows" />

      <Card heading="Workflow runs">
        <DataTable
          columns={columns}
          rows={runs}
          rowKey={(r) => r.id}
          onRowClick={setSelected}
          selectedKey={selected?.id}
          label="Workflow runs"
        />
        <p className="u-muted u-xs" style={{ marginTop: 'var(--sp-2)' }}>
          Click a run for its step list. Runs are fixture data mirroring the platform's durable
          dispatch (inline default + Temporal path + transactional outbox).
        </p>
      </Card>

      <CardGrid min={300}>
        <Card heading="Task queues">
          <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
            {QUEUES.map((q) => {
              const serving = workers.filter(
                (w) => w.status === 'online' && w.taskQueues.includes(q.name),
              )
              return (
                <li key={q.name} className="u-spread u-small" style={{ padding: '5px 0' }}>
                  <span>
                    <span className="u-mono">{q.name}</span>
                    <span className="u-muted u-xs" style={{ display: 'block' }}>
                      {q.note}
                    </span>
                  </span>
                  <span className="u-row">
                    <span className="u-muted u-xs">{serving.length} serving</span>
                    <StatusBadge
                      state={q.depth > 0 ? 'pending' : 'ok'}
                      label={`depth ${q.depth}`}
                      tone={q.depth > 0 ? 'warn' : 'ok'}
                    />
                  </span>
                </li>
              )
            })}
          </ul>
          <p className="u-muted u-xs" style={{ marginTop: 'var(--sp-2)' }}>
            Queue depths are mock values — no live engine metrics in the prototype.
          </p>
        </Card>

        <Card
          heading="Workers"
          actions={
            <Link to="/infrastructure/workers" className="u-xs">
              worker console →
            </Link>
          }
        >
          {workers.length === 0 ? (
            <p className="u-secondary u-small">Worker data unavailable.</p>
          ) : (
            <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
              {workers.map((w) => (
                <li key={w.id} className="u-spread u-small" style={{ padding: '4px 0' }}>
                  <span className="u-mono">{w.name}</span>
                  <span className="u-row">
                    <span className="u-muted u-xs">{w.taskQueues.join(', ')}</span>
                    <StatusBadge state={w.status} />
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card heading="Schedules" actions={<CapabilityTag status="planned" />}>
          <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
            {PROPOSED_SCHEDULES.map((s) => (
              <li key={s.id} className="u-spread u-small" style={{ padding: '4px 0' }}>
                <span>{s.name}</span>
                <span className="u-muted u-xs">{s.cadence}</span>
              </li>
            ))}
          </ul>
          <p className="u-muted u-xs" style={{ marginTop: 'var(--sp-2)' }}>
            Proposed schedules only — the Jobs/Schedules surface in the source repo is an
            intentionally disabled placeholder.
          </p>
        </Card>

        <Card heading="Failure & recovery posture">
          <p className="u-secondary u-small">
            {retrying.length} run{retrying.length === 1 ? '' : 's'} retrying · {failed.length}{' '}
            failed. Failed activities retry with backoff (see the aurora-soak-test repair, attempt
            2/5). Runs that exhaust retries surface an explicit{' '}
            <span className="u-mono u-xs">recovery_required</span> state for an operator decision —
            recovery is a deliberate step, never a silent retry loop.
          </p>
        </Card>
      </CardGrid>

      <div className="u-row">
        <Button
          size="sm"
          variant="ghost"
          icon={<ExternalLink size={14} aria-hidden />}
          disabled
          title="Temporal Web UI — engine diagnostics stay out of primary navigation"
        >
          Open engine diagnostics
        </Button>
      </div>

      <Drawer
        open={Boolean(selected)}
        title={selected?.name ?? ''}
        onClose={() => setSelected(undefined)}
      >
        {selected && (
          <div className="c-inspector">
            <KeyValueGrid columns={1} items={drawerItems} />
            <section>
              <h4
                className="u-xs u-muted"
                style={{ textTransform: 'uppercase', letterSpacing: '0.06em' }}
              >
                Steps
              </h4>
              <ul style={{ listStyle: 'none', margin: '6px 0 0', padding: 0 }}>
                {selected.steps.map((step) => (
                  <li
                    key={step.name}
                    className="u-spread u-small"
                    style={{ padding: '4px 0', alignItems: 'flex-start' }}
                  >
                    <span>
                      {step.name}
                      {step.detail && (
                        <span className="u-muted u-xs" style={{ display: 'block' }}>
                          {step.detail}
                        </span>
                      )}
                    </span>
                    <StatusBadge state={step.status} />
                  </li>
                ))}
              </ul>
            </section>
            <p className="u-muted u-xs">
              Step history is fixture data. Retry, cancel, and signal controls are deliberately
              absent here — operations belong to the owning deployment or event surface.
            </p>
          </div>
        )}
      </Drawer>
    </div>
  )
}
