import { FileText } from 'lucide-react'
import {
  Button,
  CapabilityNotice,
  Card,
  CardGrid,
  EmptyState,
  ErrorState,
  LoadingState,
  StatusBadge,
} from '../../components'
import { useQuery } from '../../integrations/AdapterContext'
import type { ReportCategory } from '../../models/types'
import { useEventWorkspace } from '../../layouts/EventWorkspaceLayout'

const GENERATE_TITLE = 'Reporting is not implemented — SECP-004'

/** Standard per-event report types offered for generation (all disabled). */
const STANDARD_TYPES: { category: ReportCategory; label: string; desc: string }[] = [
  {
    category: 'event-summary',
    label: 'Event summary',
    desc: 'Rolling summary of phases, teams, deployments, and incidents.',
  },
  {
    category: 'after-action',
    label: 'After-action report',
    desc: 'Timeline, findings, and recommendations after the event closes.',
  },
  {
    category: 'scoring',
    label: 'Final scoring',
    desc: 'Final standings with per-phase breakdown.',
  },
  {
    category: 'participant',
    label: 'Participant packets',
    desc: 'Individual performance summaries for each participant.',
  },
  {
    category: 'technical',
    label: 'Technical report',
    desc: 'Detection coverage, incidents, and infrastructure notes.',
  },
]

export default function EventReportsPage() {
  const { event } = useEventWorkspace()
  const reportsQ = useQuery((a) => a.listReports())

  if (reportsQ.loading) {
    return (
      <div className="u-page">
        <LoadingState lines={5} />
      </div>
    )
  }
  if (!reportsQ.data) {
    return (
      <div className="u-page">
        <ErrorState message={reportsQ.error ?? 'Mock data unavailable.'} />
      </div>
    )
  }

  const eventReports = reportsQ.data.filter((r) => r.eventId === event.id)

  return (
    <div className="u-page">
      <CapabilityNotice capKey="reports.generation" />

      <section aria-label="Reports for this event">
        <h2
          className="u-small"
          style={{
            textTransform: 'uppercase',
            letterSpacing: '0.06em',
            marginBottom: 'var(--sp-2)',
          }}
        >
          Reports for {event.name}
        </h2>
        {eventReports.length === 0 ? (
          <EmptyState
            title="No reports for this event"
            body="Nothing has been generated. Report definitions below show what would be available."
          />
        ) : (
          <CardGrid min={320}>
            {eventReports.map((r) => (
              <Card
                key={r.id}
                heading={
                  <span className="u-row">
                    <FileText size={14} aria-hidden className="u-muted" /> {r.title}
                  </span>
                }
                actions={<StatusBadge state={r.category.replace(/-/g, ' ')} tone="info" />}
              >
                <p className="u-secondary u-small">{r.description}</p>
                <p className="u-muted u-xs" style={{ margin: 'var(--sp-2) 0' }}>
                  {r.generatedAt
                    ? `Generated ${r.generatedAt.slice(0, 16).replace('T', ' ')} UTC (mock metadata)`
                    : 'Not generated — definition only'}
                </p>
                <div className="u-row">
                  <Button size="sm" variant="secondary" disabled title={GENERATE_TITLE}>
                    {r.generatedAt ? 'Regenerate' : 'Generate'}
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    disabled
                    title="Prototype: report artifacts are mock metadata — there is nothing to download"
                  >
                    Download
                  </Button>
                </div>
              </Card>
            ))}
          </CardGrid>
        )}
      </section>

      <section aria-label="Generate a new report">
        <h2
          className="u-small"
          style={{
            textTransform: 'uppercase',
            letterSpacing: '0.06em',
            marginBottom: 'var(--sp-2)',
          }}
        >
          Generate a new report
        </h2>
        <CardGrid min={280}>
          {STANDARD_TYPES.map((t) => (
            <Card key={t.category} heading={t.label} actions={<StatusBadge state="planned" />}>
              <p className="u-secondary u-small">{t.desc}</p>
              <Button
                size="sm"
                variant="secondary"
                disabled
                title={GENERATE_TITLE}
                style={{ marginTop: 'var(--sp-2)' }}
              >
                Generate
              </Button>
            </Card>
          ))}
        </CardGrid>
        <p className="u-muted u-xs" style={{ marginTop: 'var(--sp-2)' }}>
          Audit records and change-sets are real platform capability and would feed these reports;
          the generation pipeline itself is not implemented (SECP-004).
        </p>
      </section>
    </div>
  )
}
