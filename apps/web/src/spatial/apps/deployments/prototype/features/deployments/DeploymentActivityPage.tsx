import { useMemo } from 'react'
import { Card, LoadingState, Timeline } from '../../components'
import type { StatusTone, TimelineEntry } from '../../components'
import { useQuery } from '../../integrations/AdapterContext'
import { useDeploymentWorkspace } from '../../layouts/DeploymentWorkspaceLayout'
import type { WorkflowStatus } from '../../models/types'

const fmt = (t: string) => `${t.slice(0, 10)} ${t.slice(11, 16)} UTC`

const RUN_TONE: Record<WorkflowStatus, StatusTone> = {
  running: 'progress',
  completed: 'ok',
  failed: 'error',
  retrying: 'progress',
  'awaiting-approval': 'info',
  cancelled: 'neutral',
}

interface Dated {
  at: string
  entry: TimelineEntry
}

export default function DeploymentActivityPage() {
  const { deployment } = useDeploymentWorkspace()
  const runsQ = useQuery(
    (a) => a.listWorkflowRuns({ deploymentId: deployment.id }),
    [deployment.id],
  )
  const auditQ = useQuery((a) => a.listAuditEvents())
  const evidenceQ = useQuery((a) => a.listEvidence())

  const entries = useMemo<TimelineEntry[]>(() => {
    const matches = (text: string) => text.includes(deployment.id) || text.includes(deployment.name)
    const dated: Dated[] = []

    for (const r of runsQ.data ?? []) {
      const at = r.finishedAt ?? r.startedAt
      dated.push({
        at,
        entry: {
          id: `run-${r.id}`,
          time: fmt(at),
          title: r.name,
          tone: RUN_TONE[r.status],
          detail: (
            <span>
              Workflow {r.status.replace(/-/g, ' ')} ·{' '}
              {r.steps.filter((s) => s.status === 'complete').length}/{r.steps.length} steps ·{' '}
              <span className="u-mono u-xs">{r.taskQueue}</span>
            </span>
          ),
        },
      })
    }

    for (const e of (auditQ.data ?? []).filter((e) => matches(e.resource))) {
      dated.push({
        at: e.time,
        entry: {
          id: `aud-${e.id}`,
          time: fmt(e.time),
          title: (
            <span>
              <span className="u-mono">{e.action}</span> — {e.actor}
            </span>
          ),
          tone: e.outcome === 'success' ? 'ok' : 'error',
          detail: (
            <span className="u-mono u-xs">
              {e.resource} · {e.outcome} · origin {e.origin}
            </span>
          ),
        },
      })
    }

    for (const e of (evidenceQ.data ?? []).filter((e) => matches(e.subject))) {
      dated.push({
        at: e.time,
        entry: {
          id: `ev-${e.id}`,
          time: fmt(e.time),
          title: `Evidence recorded: ${e.kind.replace(/-/g, ' ')}`,
          tone: 'info',
          detail: (
            <span className="u-mono u-xs">
              {e.subject} · {e.sha256}
            </span>
          ),
        },
      })
    }

    return dated.sort((a, b) => b.at.localeCompare(a.at)).map((d) => d.entry)
  }, [runsQ.data, auditQ.data, evidenceQ.data, deployment.id, deployment.name])

  if (runsQ.loading || auditQ.loading || evidenceQ.loading) {
    return (
      <div className="u-page">
        <LoadingState lines={6} />
      </div>
    )
  }

  return (
    <div className="u-page">
      <Card
        heading="Deployment activity"
        actions={
          <span className="u-muted u-xs">
            workflow runs · audit ledger · evidence (mock fixtures)
          </span>
        }
      >
        {entries.length === 0 ? (
          <p className="u-secondary u-small">
            No recorded activity for this deployment in the mock fixtures.
          </p>
        ) : (
          <Timeline entries={entries} />
        )}
        <p className="u-muted u-xs" style={{ marginTop: 'var(--sp-2)' }}>
          Newest first. The audit ledger itself is an implemented platform capability; the entries
          shown here are fixture data.
        </p>
      </Card>
    </div>
  )
}
