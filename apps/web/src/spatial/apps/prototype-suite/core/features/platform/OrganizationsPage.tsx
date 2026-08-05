import { Link } from 'react-router-dom'
import { Plus, UserPlus } from 'lucide-react'
import {
  Button,
  CapabilityNotice,
  Card,
  DataTable,
  ErrorState,
  LoadingState,
} from '../../components'
import type { Column } from '../../components'
import { useQuery } from '../../integrations/AdapterContext'
import type { UserAccount } from '../../models/types'

function fmtUtc(iso?: string): string {
  return iso ? `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC` : '—'
}

const MEMBER_COLUMNS: Column<UserAccount>[] = [
  { key: 'name', header: 'Name', render: (u) => <strong className="u-small">{u.name}</strong> },
  { key: 'email', header: 'Email', render: (u) => <span className="u-mono u-xs">{u.email}</span> },
  {
    key: 'roles',
    header: 'Roles',
    render: (u) => (
      <span className="p-chips">
        {u.roles.map((r) => (
          <span key={r} className={'p-chip' + (r.startsWith('service:') ? ' p-chip--service' : '')}>
            {r}
          </span>
        ))}
      </span>
    ),
  },
  {
    key: 'kind',
    header: 'Kind',
    render: (u) => (
      <span className={'p-chip' + (u.kind === 'service' ? ' p-chip--service' : '')}>{u.kind}</span>
    ),
  },
  {
    key: 'lastLogin',
    header: 'Last login',
    render: (u) => (
      <span className="u-mono u-xs">
        {u.kind === 'service' ? 'n/a (service)' : fmtUtc(u.lastLogin)}
      </span>
    ),
  },
]

export default function OrganizationsPage() {
  const usersQ = useQuery((a) => a.listUsers())

  if (usersQ.loading) {
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
  const orgNames = [...new Set(users.map((u) => u.organization))]

  return (
    <div className="u-page">
      <CapabilityNotice capKey="platform.organizations" />

      <div className="u-spread">
        <p className="u-secondary u-small" style={{ margin: 0 }}>
          Administrative organizations scope users, roles, and resources. Membership shown here is
          fixture data; the backend enforces org-scoped permissions on every request.
        </p>
        <Button
          size="sm"
          icon={<Plus size={14} aria-hidden />}
          disabled
          title="Prototype: organization administration has no backend (proposed)"
        >
          Create organization
        </Button>
      </div>

      {orgNames.map((org) => {
        const members = users.filter((u) => u.organization === org)
        return (
          <Card
            key={org}
            heading={org}
            actions={
              <Button
                size="sm"
                variant="ghost"
                icon={<UserPlus size={14} aria-hidden />}
                disabled
                title="Prototype: member management has no backend (proposed)"
              >
                Invite member
              </Button>
            }
          >
            <DataTable
              columns={MEMBER_COLUMNS}
              rows={members}
              rowKey={(u) => u.id}
              label={`${org} members`}
              emptyTitle="No members"
            />
            <p className="u-muted u-xs" style={{ marginTop: 'var(--sp-2)' }}>
              {members.filter((m) => m.kind === 'human').length} humans ·{' '}
              {members.filter((m) => m.kind === 'service').length} service identities
            </p>
          </Card>
        )
      })}

      <Card heading="Where are teams?">
        <p className="u-secondary u-small">
          Competition teams (Team Crimson, Team Cobalt, …) are <em>event</em> objects: they live
          inside their event workspace under <Link to="/events">Events</Link> → Teams &amp; Access,
          alongside rosters, subnets, and gateway status. The organizations on this page are
          administrative groupings for platform users only — the two are intentionally separate
          concepts.
        </p>
      </Card>
    </div>
  )
}
