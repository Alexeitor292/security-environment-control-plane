import {
  Button,
  CapabilityNotice,
  Card,
  CardGrid,
  ErrorState,
  LoadingState,
  PageHeader,
  StatusBadge,
} from '../../components'
import { useQuery } from '../../integrations/AdapterContext'
import type { ReportCategory, ReportDef } from '../../models/types'

const DISABLED_TITLE = 'Reporting is not implemented — SECP-004/artifacts partially-implemented'

const CATEGORIES: { key: ReportCategory; label: string; blurb: string }[] = [
  {
    key: 'event-summary',
    label: 'Event summary',
    blurb: 'Rolling overview of an event: phases, teams, deployments, incidents.',
  },
  {
    key: 'after-action',
    label: 'After-action',
    blurb: 'Post-event timeline, findings, and recommendations.',
  },
  {
    key: 'technical',
    label: 'Technical',
    blurb: 'Detection coverage, attack-chain detail, tuning actions.',
  },
  {
    key: 'executive',
    label: 'Executive',
    blurb: 'Program-level outcomes and readiness for leadership.',
  },
  {
    key: 'scoring',
    label: 'Scoring',
    blurb: 'Final standings with per-phase and per-check breakdowns.',
  },
  {
    key: 'participant',
    label: 'Participant',
    blurb: 'Individual performance packets for participants.',
  },
  {
    key: 'utilization',
    label: 'Utilization',
    blurb: 'Capacity and usage across infrastructure targets.',
  },
  {
    key: 'cost',
    label: 'Cost',
    blurb: 'Spend by event, deployment, and provider.',
  },
  {
    key: 'control-validation',
    label: 'Control validation',
    blurb: 'Security-control coverage evidence from validation labs.',
  },
  {
    key: 'audit-export',
    label: 'Audit export',
    blurb: 'Signed exports of the audit trail and evidence hashes.',
  },
]

function ReportRow({ report }: { report: ReportDef }) {
  return (
    <li className="u-spread" style={{ padding: '5px 0', gap: 'var(--sp-2)' }}>
      <span className="u-small" style={{ minWidth: 0 }}>
        {report.title}
        {report.generatedAt ? (
          <span className="u-muted u-xs u-mono" style={{ display: 'block' }}>
            generated {report.generatedAt.slice(0, 16).replace('T', ' ')} UTC
          </span>
        ) : (
          <span style={{ display: 'block', marginTop: 2 }}>
            <StatusBadge state="live" label="live" tone="info" />
          </span>
        )}
      </span>
      <Button size="sm" variant="ghost" disabled title={DISABLED_TITLE}>
        View
      </Button>
    </li>
  )
}

export default function ReportsPage() {
  const reportsQ = useQuery((a) => a.listReports())

  if (reportsQ.loading) {
    return (
      <div className="u-page">
        <LoadingState lines={6} />
      </div>
    )
  }
  if (reportsQ.error || !reportsQ.data) {
    return (
      <div className="u-page">
        <ErrorState message={reportsQ.error ?? 'Mock data unavailable.'} />
      </div>
    )
  }

  const reports = reportsQ.data

  return (
    <div className="u-page">
      <PageHeader
        title="Reports"
        capabilityStatus="planned"
        description="Draft report catalog: ten proposed categories over the platform's real audit records and change-sets. Report generation itself does not exist yet; every entry below is mock."
      />
      <CapabilityNotice capKey="reports.generation" />

      <CardGrid min={320}>
        {CATEGORIES.map((cat) => {
          const inCategory = reports.filter((r) => r.category === cat.key)
          return (
            <Card
              key={cat.key}
              heading={cat.label}
              actions={
                <Button size="sm" disabled title={DISABLED_TITLE}>
                  Generate
                </Button>
              }
            >
              <p className="u-muted u-xs" style={{ marginTop: 0 }}>
                {cat.blurb}
              </p>
              {inCategory.length === 0 ? (
                <p className="u-secondary u-small" style={{ margin: 0 }}>
                  No mock reports in this category.
                </p>
              ) : (
                <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
                  {inCategory.map((r) => (
                    <ReportRow key={r.id} report={r} />
                  ))}
                </ul>
              )}
            </Card>
          )
        })}
      </CardGrid>
    </div>
  )
}
