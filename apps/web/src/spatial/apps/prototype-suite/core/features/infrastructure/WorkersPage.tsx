import { useState } from 'react'
import { AlertTriangle } from 'lucide-react'
import {
  Button,
  CapabilityNotice,
  DataTable,
  Drawer,
  ErrorState,
  KeyValueGrid,
  LoadingState,
  MetricRow,
  MetricTile,
  ProviderBadge,
  StatusBadge,
} from '../../components'
import type { Column } from '../../components'
import { useQuery } from '../../integrations/AdapterContext'
import type { WorkerNode } from '../../models/types'

/**
 * Worker fleet console. Workers, task queues, and worker-only execution are
 * real in the platform; this operations console is a proposed surface.
 */

function fmtUtc(iso?: string): string {
  return iso ? `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC` : '—'
}

export default function WorkersPage() {
  const workersQ = useQuery((a) => a.listWorkers())
  const targetsQ = useQuery((a) => a.listTargets())
  const [selected, setSelected] = useState<WorkerNode | undefined>()

  if (workersQ.loading) {
    return (
      <div className="u-page">
        <LoadingState lines={5} />
      </div>
    )
  }
  if (workersQ.error || !workersQ.data) {
    return (
      <div className="u-page">
        <ErrorState message={workersQ.error ?? 'Mock data unavailable.'} />
      </div>
    )
  }

  const workers = workersQ.data
  const targets = targetsQ.data ?? []
  const targetsOf = (w: WorkerNode) => targets.filter((t) => w.targetIds.includes(t.id))
  const online = workers.filter((w) => w.status === 'online')
  const offline = workers.filter((w) => w.status === 'offline')
  const queueCount = new Set(workers.flatMap((w) => w.taskQueues)).size
  const unservedTargets = targets.filter((t) => {
    const w = workers.find((x) => x.id === t.workerId)
    return !w || w.status !== 'online'
  })

  const columns: Column<WorkerNode>[] = [
    {
      key: 'name',
      header: 'Worker',
      render: (w) =>
        w.status === 'offline' ? (
          <span className="u-row">
            <AlertTriangle
              size={13}
              aria-hidden
              style={{ color: 'var(--status-error)', flexShrink: 0 }}
            />
            <span className="inf-offline-name u-mono u-small">{w.name}</span>
          </span>
        ) : (
          <span className="u-mono u-small">{w.name}</span>
        ),
    },
    { key: 'status', header: 'Status', render: (w) => <StatusBadge state={w.status} /> },
    {
      key: 'queues',
      header: 'Task queues',
      render: (w) => (
        <div className="inf-chips">
          {w.taskQueues.map((q) => (
            <span key={q} className="inf-chip">
              {q}
            </span>
          ))}
        </div>
      ),
    },
    {
      key: 'heartbeat',
      header: 'Last heartbeat',
      render: (w) => (
        <span className={`u-xs u-mono${w.status === 'offline' ? ' inf-offline-name' : ''}`}>
          {fmtUtc(w.lastHeartbeat)}
        </span>
      ),
    },
    {
      key: 'version',
      header: 'Version',
      render: (w) => <span className="u-xs u-mono">{w.version}</span>,
    },
    {
      key: 'targets',
      header: 'Targets served',
      render: (w) => (
        <span className="u-small">
          {targetsOf(w).length > 0
            ? targetsOf(w)
                .map((t) => t.name)
                .join(', ')
            : '—'}
        </span>
      ),
    },
  ]

  return (
    <div className="u-page">
      <CapabilityNotice capKey="infrastructure.workers" />
      <p className="u-secondary u-small" style={{ margin: 0 }}>
        Workers are the only processes that touch provider APIs: secret references resolve
        worker-side and plans/applies run worker-side. The control plane only enqueues work onto
        task queues. This console over the fleet is proposed.
      </p>

      <MetricRow>
        <MetricTile
          label="Workers online"
          value={`${online.length}/${workers.length}`}
          tone={offline.length > 0 ? 'warn' : 'ok'}
          detail={
            offline.length > 0
              ? `${offline.map((w) => w.name).join(', ')} offline`
              : 'all reporting'
          }
        />
        <MetricTile label="Task queues" value={queueCount} detail="declared across the fleet" />
        <MetricTile
          label="Targets without an online worker"
          value={unservedTargets.length}
          tone={unservedTargets.length > 0 ? 'error' : 'ok'}
          detail={
            unservedTargets.length > 0
              ? unservedTargets.map((t) => t.name).join(', ')
              : 'all targets served'
          }
        />
      </MetricRow>

      <DataTable
        columns={columns}
        rows={workers}
        rowKey={(w) => w.id}
        onRowClick={setSelected}
        selectedKey={selected?.id}
        label="Worker fleet"
        emptyTitle="No workers registered"
      />

      {selected && (
        <Drawer
          open
          title={selected.name}
          onClose={() => setSelected(undefined)}
          footer={
            <div className="u-spread">
              <span className="u-muted u-xs">Prototype — nothing executes.</span>
              <div className="u-row">
                <Button
                  size="sm"
                  disabled
                  title="No worker control API exists today — restart is an operations-console proposal"
                >
                  Restart worker
                </Button>
                <Button
                  size="sm"
                  disabled
                  title="Draining (finish in-flight tasks, stop polling queues) is proposed; no backend endpoint exists"
                >
                  Drain worker
                </Button>
              </div>
            </div>
          }
        >
          <div className="c-inspector">
            <div className="u-row" style={{ flexWrap: 'wrap' }}>
              <StatusBadge state={selected.status} />
              <span className="u-xs u-mono u-muted">v{selected.version}</span>
            </div>

            <KeyValueGrid
              columns={2}
              items={[
                { key: 'Worker id', value: selected.id, mono: true },
                { key: 'Last heartbeat', value: fmtUtc(selected.lastHeartbeat), mono: true },
                { key: 'Version', value: selected.version, mono: true },
                { key: 'Bound targets', value: selected.targetIds.length },
              ]}
            />

            <section>
              <h4
                className="u-xs u-muted"
                style={{ textTransform: 'uppercase', letterSpacing: '0.06em' }}
              >
                Task queues
              </h4>
              <div className="inf-chips" style={{ marginTop: 6 }}>
                {selected.taskQueues.map((q) => (
                  <span key={q} className="inf-chip">
                    {q}
                  </span>
                ))}
              </div>
            </section>

            <section>
              <h4
                className="u-xs u-muted"
                style={{ textTransform: 'uppercase', letterSpacing: '0.06em' }}
              >
                Bound targets
              </h4>
              {targetsOf(selected).length === 0 ? (
                <p className="u-secondary u-small" style={{ margin: '6px 0 0' }}>
                  No targets bound.
                </p>
              ) : (
                <ul style={{ listStyle: 'none', margin: '6px 0 0', padding: 0 }}>
                  {targetsOf(selected).map((t) => (
                    <li key={t.id} className="u-spread u-small" style={{ padding: '4px 0' }}>
                      <span className="u-row">
                        <ProviderBadge provider={t.provider} />
                        <span>{t.name}</span>
                      </span>
                      <StatusBadge state={t.health} />
                    </li>
                  ))}
                </ul>
              )}
            </section>

            <section>
              <h4
                className="u-xs u-muted"
                style={{ textTransform: 'uppercase', letterSpacing: '0.06em' }}
              >
                Execution model
              </h4>
              <p className="u-secondary u-small" style={{ margin: '6px 0 0' }}>
                Worker-only execution: secret references resolve only inside workers, and
                plans/applies run worker-side. The control plane holds opaque references, never
                provider credentials, and never contacts targets directly.
              </p>
            </section>
          </div>
        </Drawer>
      )}
    </div>
  )
}
