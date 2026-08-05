import { ShieldCheck } from 'lucide-react'
import {
  AccordionSection,
  CapabilityNotice,
  Card,
  CardGrid,
  EmptyState,
  ErrorState,
  KeyValueGrid,
  LoadingState,
  StatusBadge,
  Timeline,
} from '../../components'
import type { TimelineEntry } from '../../components'
import { useQuery } from '../../integrations/AdapterContext'
import { useEventWorkspace } from '../../layouts/EventWorkspaceLayout'

function fmt(iso: string): string {
  return iso.slice(0, 16).replace('T', ' ') + ' UTC'
}

export default function EventOperationsPage() {
  const { event } = useEventWorkspace()
  const runsQ = useQuery((a) => a.listWorkflowRuns({ eventId: event.id }), [event.id])
  const approvalsQ = useQuery((a) => a.listApprovals())
  const evidenceQ = useQuery((a) => a.listEvidence())

  if (runsQ.loading) {
    return (
      <div className="u-page">
        <LoadingState lines={6} />
      </div>
    )
  }
  if (!runsQ.data) {
    return (
      <div className="u-page">
        <ErrorState message={runsQ.error ?? 'Mock data unavailable.'} />
      </div>
    )
  }

  const runs = runsQ.data
  const needles = [event.id, ...event.deploymentIds, event.name]
  const relevantApprovals = (approvalsQ.data ?? []).filter((a) =>
    needles.some((n) => a.scope.includes(n) || a.title.includes(n)),
  )
  const pendingApprovals = relevantApprovals.filter((a) => a.status === 'pending')
  const decidedApprovals = relevantApprovals.filter((a) => a.status !== 'pending')
  const evidence = (evidenceQ.data ?? []).filter((e) => needles.some((n) => e.subject.includes(n)))

  const resetHistory: TimelineEntry[] = runs
    .filter((r) => r.kind === 'reset')
    .map((r) => ({
      id: r.id,
      time: fmt(r.startedAt),
      title: <span className="u-small">{r.name}</span>,
      detail: r.finishedAt ? `finished ${fmt(r.finishedAt)}` : 'in progress',
      tone: r.status === 'completed' ? 'ok' : r.status === 'failed' ? 'error' : 'progress',
    }))

  return (
    <div className="u-page">
      <CapabilityNotice capKey="deployments.reset" />

      <section aria-label="Workflow runs">
        <h2
          className="u-small"
          style={{
            textTransform: 'uppercase',
            letterSpacing: '0.06em',
            marginBottom: 'var(--sp-2)',
          }}
        >
          Workflow runs for this event
        </h2>
        {runs.length === 0 ? (
          <EmptyState title="No workflow runs" body="No operations have targeted this event yet." />
        ) : (
          <CardGrid min={340}>
            {runs.map((run) => (
              <Card key={run.id} heading={run.name} actions={<StatusBadge state={run.status} />}>
                <KeyValueGrid
                  columns={3}
                  items={[
                    { key: 'Kind', value: run.kind.replace(/-/g, ' ') },
                    { key: 'Queue', value: run.taskQueue, mono: true },
                    {
                      key: 'Started',
                      value: run.startedAt.slice(5, 16).replace('T', ' ') + ' UTC',
                    },
                  ]}
                />
                <ul style={{ listStyle: 'none', margin: 'var(--sp-2) 0 0', padding: 0 }}>
                  {run.steps.map((step) => (
                    <li key={step.name} className="u-spread u-small" style={{ padding: '3px 0' }}>
                      <span>
                        {step.name}
                        {step.detail && <span className="u-muted u-xs"> — {step.detail}</span>}
                      </span>
                      <StatusBadge state={step.status} />
                    </li>
                  ))}
                </ul>
              </Card>
            ))}
          </CardGrid>
        )}
      </section>

      <div
        className="u-grid"
        style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))' }}
      >
        <Card
          heading="Pending approvals"
          actions={<ShieldCheck size={14} aria-hidden className="u-muted" />}
        >
          {pendingApprovals.length === 0 ? (
            <p className="u-secondary u-small">Nothing awaiting decision for this event.</p>
          ) : (
            <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
              {pendingApprovals.map((a) => (
                <li key={a.id} style={{ padding: '6px 0' }}>
                  <div className="u-spread">
                    <strong className="u-small">{a.title}</strong>
                    <StatusBadge
                      state={a.riskLevel}
                      label={`risk: ${a.riskLevel}`}
                      tone={a.riskLevel === 'high' || a.riskLevel === 'critical' ? 'error' : 'warn'}
                    />
                  </div>
                  <p className="u-secondary u-xs">{a.operation}</p>
                  <p className="u-muted u-xs">
                    {a.scope} · requested by {a.requestedBy}
                  </p>
                </li>
              ))}
            </ul>
          )}
          {decidedApprovals.length > 0 && (
            <ul style={{ listStyle: 'none', margin: 'var(--sp-2) 0 0', padding: 0 }}>
              {decidedApprovals.map((a) => (
                <li key={a.id} className="u-spread u-small" style={{ padding: '4px 0' }}>
                  <span className="u-secondary">{a.title}</span>
                  <StatusBadge state={a.status} />
                </li>
              ))}
            </ul>
          )}
          <p className="u-muted u-xs" style={{ marginTop: 'var(--sp-2)' }}>
            Approval is a decision only — it never executes anything (implemented platform rule).
          </p>
        </Card>

        <Card heading="Reset history">
          {resetHistory.length === 0 ? (
            <p className="u-secondary u-small">No resets have been run for this event.</p>
          ) : (
            <Timeline entries={resetHistory} />
          )}
          <p className="u-muted u-xs" style={{ marginTop: 'var(--sp-2)' }}>
            Resets are operator-approved controlled operations; competition rules apply availability
            penalties. Reset/destroy run end-to-end against the simulator only.
          </p>
        </Card>
      </div>

      <AccordionSection title="Evidence records" hint={`${evidence.length} for this event`}>
        {evidence.length === 0 ? (
          <p className="u-secondary u-small">No evidence records reference this event.</p>
        ) : (
          <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
            {evidence.map((e) => (
              <li
                key={e.id}
                style={{ padding: '6px 0', borderBottom: '1px solid var(--border-subtle)' }}
              >
                <div className="u-spread">
                  <span className="u-small">
                    <StatusBadge state={e.kind.replace(/-/g, ' ')} tone="info" /> {e.subject}
                  </span>
                  <time className="u-muted u-xs">{fmt(e.time)}</time>
                </div>
                <p className="u-muted u-xs u-mono">
                  sha256 {e.sha256} · {e.store}
                </p>
              </li>
            ))}
          </ul>
        )}
        <p className="u-muted u-xs" style={{ marginTop: 'var(--sp-2)' }}>
          Hash-bound evidence records are real platform capability; artifact browsing is proposed.
        </p>
      </AccordionSection>
    </div>
  )
}
