import { useState } from 'react'
import {
  CapabilityNotice,
  CapabilityTag,
  Card,
  CardGrid,
  DataTable,
  ErrorState,
  FilterSelect,
  LoadingState,
} from '../../components'
import type { Column } from '../../components'
import { useQuery } from '../../integrations/AdapterContext'
import type { UserAccount } from '../../models/types'

function fmtUtc(iso?: string): string {
  return iso ? `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC` : '—'
}

const ROLE_DESCRIPTIONS: { role: string; description: string }[] = [
  {
    role: 'platform-admin',
    description:
      'Platform-wide administration; decides platform-scope approvals (target activation, rotation).',
  },
  {
    role: 'event-director',
    description: 'Owns events end-to-end; decides event-scope approvals such as phase transitions.',
  },
  {
    role: 'operator',
    description:
      'Day-to-day deployment and infrastructure operations; requests (never self-approves) resets.',
  },
  { role: 'ir-lead', description: 'Runs incident-response rehearsals; reads capture evidence.' },
  {
    role: 'service:*',
    description:
      'Non-human identities (scheduler, workers) with narrowly scoped, non-interactive permissions.',
  },
]

/** Static mock — real effective permissions are computed by the backend only. */
const ROLE_PERMISSIONS: Record<string, string[]> = {
  'platform-admin': [
    'platform:administer — organizations, settings, retention (proposed surfaces)',
    'approvals:decide (platform scope) — target activation, credential rotation',
    'audit:read — full operator-safe ledger',
  ],
  'event-director': [
    'events:manage — phases, announcements, emergency controls for owned events',
    'approvals:decide (event scope) — phase transitions, team resets',
    'teams:manage — rosters and access profiles for owned events',
  ],
  operator: [
    'deployments:operate — plan, reset-request, workflow visibility',
    'infrastructure:read — targets, workers, inventory',
    'alerts:acknowledge',
  ],
  'ir-lead': [
    'events:manage — IR rehearsal events only',
    'evidence:read — capture and receipt records',
  ],
  'service:scheduler': ['workflows:dispatch — scheduled discovery and rotation requests'],
  'service:worker': [
    'taskqueues:poll — assigned queues only',
    'secrets:resolve — worker-side only, never returned to the control plane',
  ],
}

const MOCK_SESSIONS = [
  { id: 'ses-1', user: 'ops-oncall', started: '2026-07-18T12:44:00Z', origin: '198.51.100.31' },
  { id: 'ses-2', user: 'm.chen', started: '2026-07-18T12:28:00Z', origin: '198.51.100.24' },
  { id: 'ses-3', user: 'j.rivera', started: '2026-07-18T11:55:00Z', origin: '198.51.100.18' },
  { id: 'ses-4', user: 'p.admin', started: '2026-07-18T10:02:00Z', origin: '198.51.100.7' },
]

const USER_COLUMNS: Column<UserAccount>[] = [
  { key: 'name', header: 'Name', render: (u) => <strong className="u-small">{u.name}</strong> },
  { key: 'email', header: 'Email', render: (u) => <span className="u-mono u-xs">{u.email}</span> },
  {
    key: 'kind',
    header: 'Kind',
    render: (u) => (
      <span className={'p-chip' + (u.kind === 'service' ? ' p-chip--service' : '')}>{u.kind}</span>
    ),
  },
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
    key: 'org',
    header: 'Organization',
    render: (u) => <span className="u-small">{u.organization}</span>,
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

export default function IdentityPage() {
  const usersQ = useQuery((a) => a.listUsers())
  const [selectedId, setSelectedId] = useState('')

  if (usersQ.loading) {
    return (
      <div className="u-page">
        <LoadingState lines={6} />
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
  const services = users.filter((u) => u.kind === 'service')
  const selected = users.find((u) => u.id === selectedId) ?? users[0]
  const permissions = selected
    ? selected.roles.flatMap((r) => ROLE_PERMISSIONS[r] ?? [`${r} — no mock mapping`])
    : []

  return (
    <div className="u-page">
      <CapabilityNotice capKey="platform.identity" />

      <Card heading="Users">
        <DataTable columns={USER_COLUMNS} rows={users} rowKey={(u) => u.id} label="Users" />
      </Card>

      <CardGrid min={320}>
        <Card heading="Roles & permissions">
          <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
            {ROLE_DESCRIPTIONS.map((r) => (
              <li key={r.role} style={{ padding: '5px 0' }} className="u-small">
                <span className="p-chip">{r.role}</span>
                <span className="u-secondary" style={{ display: 'block', marginTop: 2 }}>
                  {r.description}
                </span>
              </li>
            ))}
          </ul>
          <p className="u-muted u-xs" style={{ marginTop: 'var(--sp-2)' }}>
            Authorization is DB-owned: the backend derives permissions from its own records on every
            request. Roles carried on tokens grant nothing by themselves.
          </p>
        </Card>

        <Card heading="Sessions" actions={<CapabilityTag status="ui-only" />}>
          <DataTable
            columns={[
              {
                key: 'user',
                header: 'User',
                render: (s) => <span className="u-small">{s.user}</span>,
              },
              {
                key: 'started',
                header: 'Started',
                render: (s) => <span className="u-mono u-xs">{fmtUtc(s.started)}</span>,
              },
              {
                key: 'origin',
                header: 'Origin',
                render: (s) => <span className="u-mono u-xs">{s.origin}</span>,
              },
            ]}
            rows={MOCK_SESSIONS}
            rowKey={(s) => s.id}
            label="Sessions (mock)"
          />
          <p className="u-muted u-xs" style={{ marginTop: 'var(--sp-2)' }}>
            Mock session data — no session-listing API exists today.
          </p>
        </Card>

        <Card heading="Service identities">
          <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
            {services.map((s) => (
              <li key={s.id} className="u-spread u-small" style={{ padding: '5px 0' }}>
                <span className="u-mono">{s.name}</span>
                <span className="p-chips">
                  {s.roles.map((r) => (
                    <span key={r} className="p-chip p-chip--service">
                      {r}
                    </span>
                  ))}
                </span>
              </li>
            ))}
          </ul>
          <p className="u-muted u-xs" style={{ marginTop: 'var(--sp-2)' }}>
            Non-interactive identities. Workers poll their task queues; they are never reachable
            from the control plane.
          </p>
        </Card>

        <Card heading="Effective permissions viewer">
          <FilterSelect
            label="User"
            value={selected?.id ?? ''}
            onChange={setSelectedId}
            options={users.map((u) => ({ value: u.id, label: u.name }))}
          />
          {selected && (
            <ul
              style={{ margin: 'var(--sp-2) 0 0', paddingLeft: 18 }}
              className="u-small u-secondary"
            >
              {permissions.map((p) => (
                <li key={p}>{p}</li>
              ))}
            </ul>
          )}
          <p className="u-muted u-xs" style={{ marginTop: 'var(--sp-2)' }}>
            Static mock derivation for illustration — the backend is the authoritative permission
            boundary; nothing this viewer shows grants access.
          </p>
        </Card>

        <Card
          heading="Event, deployment & infrastructure access"
          actions={<CapabilityTag status="planned" />}
        >
          <p className="u-secondary u-small">
            Per-event, per-deployment, and per-target access grants (who can operate which scope)
            are a proposed design. Today scope enforcement exists only as backend org-scoped RBAC.
          </p>
        </Card>

        <Card heading="Approval authority" actions={<CapabilityTag status="planned" />}>
          <p className="u-secondary u-small">
            A declarative mapping of which roles may decide which approval kinds (event-scope vs
            platform-scope) is proposed. Approvals themselves are implemented and audited; authority
            configuration is not.
          </p>
        </Card>

        <Card heading="Identity provider">
          <ul style={{ listStyle: 'none', margin: 0, padding: 0 }} className="u-small">
            <li className="u-spread" style={{ padding: '4px 0' }}>
              <span>OIDC bearer + browser PKCE</span>
              <CapabilityTag status="implemented" />
            </li>
            <li className="u-spread" style={{ padding: '4px 0' }}>
              <span>Keycloak (bundled for development)</span>
              <CapabilityTag status="implemented" />
            </li>
            <li className="u-spread" style={{ padding: '4px 0' }}>
              <span>Production IdP (externally operated federation)</span>
              <CapabilityTag status="planned" />
            </li>
          </ul>
          <p className="u-muted u-xs" style={{ marginTop: 'var(--sp-2)' }}>
            Implementation names appear only here and on Integrations — navigation and everyday
            surfaces use the product concept (Identity &amp; Access).
          </p>
        </Card>
      </CardGrid>
    </div>
  )
}
