import { Link } from 'react-router-dom'
import {
  CapabilityTag,
  Card,
  CardGrid,
  ErrorState,
  LoadingState,
  MetricRow,
  MetricTile,
} from '../../components'
import { useQuery } from '../../integrations/AdapterContext'
import type { CapabilityStatus } from '../../models/types'

interface SectionLink {
  to: string
  title: string
  description: string
  status: CapabilityStatus
}

const SECTIONS: SectionLink[] = [
  {
    to: '/platform/organizations',
    title: 'Organizations & Teams',
    description:
      'Administrative organizations, members, and service identities. Org-scoped RBAC is enforced in the backend; the management UI is proposed.',
    status: 'partial',
  },
  {
    to: '/platform/identity',
    title: 'Identity & Access',
    description:
      'Users, roles, sessions, and effective permissions. OIDC auth is real; identity administration is proposed.',
    status: 'partial',
  },
  {
    to: '/platform/secrets',
    title: 'Secrets & Credentials',
    description:
      'Secret references and rotation metadata. Values resolve worker-side only; the OpenBao adapter is committed but sealed.',
    status: 'sealed',
  },
  {
    to: '/platform/workflows',
    title: 'Workflow Engine',
    description:
      'Durable workflow runs, task queues, and schedules. Dispatch is real; this operations console is proposed.',
    status: 'partial',
  },
  {
    to: '/platform/integrations',
    title: 'Integrations',
    description:
      'The implementation registry behind the product concepts — each entry carries its grounded capability status.',
    status: 'partial',
  },
  {
    to: '/platform/audit',
    title: 'Audit & Evidence',
    description:
      'Immutable audit ledger (including recorded refusals) and hash-bound evidence records.',
    status: 'implemented',
  },
  {
    to: '/platform/settings',
    title: 'Settings',
    description:
      'General, display, safety, and API policy. The source repo ships Settings as a truthfully disabled stub.',
    status: 'planned',
  },
  {
    to: '/platform/retention',
    title: 'Retention & Backup',
    description:
      'Evidence/audit retention, backups, and destroyed-environment residue policy — all proposed (SECP-006).',
    status: 'planned',
  },
]

export default function PlatformOverviewPage() {
  const usersQ = useQuery((a) => a.listUsers())
  const integrationsQ = useQuery((a) => a.listIntegrations())
  const approvalsQ = useQuery((a) => a.listApprovals())
  const workersQ = useQuery((a) => a.listWorkers())

  if (usersQ.loading || integrationsQ.loading) {
    return (
      <div className="u-page">
        <LoadingState lines={5} />
      </div>
    )
  }
  if (usersQ.error || !usersQ.data) {
    return (
      <div className="u-page">
        <ErrorState message={usersQ.error ?? 'Mock data unavailable.'} />
      </div>
    )
  }

  const users = usersQ.data
  const integrations = integrationsQ.data ?? []
  const present = integrations.filter(
    (i) =>
      i.status === 'implemented' ||
      i.status === 'partial' ||
      i.status === 'read-only' ||
      i.status === 'plan-only',
  )
  const pendingApprovals = (approvalsQ.data ?? []).filter((a) => a.status === 'pending')
  const workers = workersQ.data ?? []
  const workersOnline = workers.filter((w) => w.status === 'online')

  return (
    <div className="u-page">
      <p className="u-secondary u-small">
        Platform administration is deliberately separated from daily event operations: nothing on
        these pages is needed to run an event. Each section below carries its grounded capability
        status — most administration surfaces are proposed UI over an implemented backend boundary.
      </p>

      <MetricRow>
        <MetricTile
          label="Users"
          value={users.length}
          detail={`${users.filter((u) => u.kind === 'service').length} service identities`}
        />
        <MetricTile
          label="Integrations"
          value={`${present.length}/${integrations.length}`}
          detail="implemented or partially present"
        />
        <MetricTile
          label="Pending approvals"
          value={pendingApprovals.length}
          tone={pendingApprovals.length > 0 ? 'info' : undefined}
          detail="decided on owning surfaces"
        />
        <MetricTile
          label="Workers online"
          value={workersQ.data ? `${workersOnline.length}/${workers.length}` : '—'}
          tone={workersOnline.length < workers.length ? 'warn' : 'ok'}
          detail="task-queue executors"
        />
      </MetricRow>

      <CardGrid min={300}>
        {SECTIONS.map((s) => (
          <Card
            key={s.to}
            heading={<Link to={s.to}>{s.title}</Link>}
            actions={<CapabilityTag status={s.status} />}
          >
            <p className="u-secondary u-small">{s.description}</p>
          </Card>
        ))}
      </CardGrid>
    </div>
  )
}
