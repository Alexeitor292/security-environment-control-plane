import { useState } from 'react'
import { KeyRound, ShieldOff, UserX } from 'lucide-react'
import {
  Button,
  CapabilityNotice,
  DangerousOperationDialog,
  DataTable,
  Drawer,
  ErrorState,
  KeyValueGrid,
  LoadingState,
  StatusBadge,
} from '../../components'
import { useQuery } from '../../integrations/AdapterContext'
import type { AccessProfile, Team } from '../../models/types'
import { useEventWorkspace } from '../../layouts/EventWorkspaceLayout'

type DangerKind = 'revoke' | 'suspend' | 'rotate'

const DISABLED_ACTIONS: { label: string; title: string }[] = [
  {
    label: 'Invite member',
    title:
      'Prototype: member management is proposed (teams.model partial) — invitations are not wired',
  },
  {
    label: 'Issue profile',
    title: 'Prototype: profile issuance is not wired — access gateways are not in the repo',
  },
  {
    label: 'Reissue profile',
    title: 'Prototype: profile reissue is not wired — access gateways are not in the repo',
  },
  {
    label: 'Add device',
    title: 'Prototype: device enrollment is not wired — access gateways are not in the repo',
  },
  {
    label: 'Test connectivity',
    title: 'Prototype: connectivity probes are not wired — no gateway backend exists',
  },
  {
    label: 'View instructions',
    title: 'Prototype: connection instructions are not generated — no gateway backend exists',
  },
]

function TeamDetail({ team }: { team: Team }) {
  const membersQ = useQuery((a) => a.listParticipants(team.id), [team.id])
  const profilesQ = useQuery((a) => a.listAccessProfiles(team.id), [team.id])

  const memberName = (participantId: string) =>
    membersQ.data?.find((m) => m.id === participantId)?.name ?? participantId

  return (
    <div className="c-inspector">
      <KeyValueGrid
        columns={2}
        items={[
          { key: 'Subnet', value: team.subnet, mono: true },
          { key: 'VPN endpoint', value: team.vpnEndpoint, mono: true },
          { key: 'Connection', value: <StatusBadge state={team.connection} /> },
          { key: 'Gateway health', value: <StatusBadge state={team.gatewayHealth} /> },
          { key: 'Connected devices', value: team.connectedDevices },
          { key: 'Systems', value: team.systems.join(', '), mono: true },
        ]}
      />

      <section>
        <h4
          className="u-xs u-muted"
          style={{ textTransform: 'uppercase', letterSpacing: '0.06em' }}
        >
          Members
        </h4>
        {membersQ.loading ? (
          <LoadingState lines={3} />
        ) : (membersQ.data ?? []).length === 0 ? (
          <p className="u-secondary u-small">No participants registered.</p>
        ) : (
          <ul style={{ listStyle: 'none', margin: '6px 0 0', padding: 0 }}>
            {(membersQ.data ?? []).map((m) => (
              <li key={m.id} className="u-spread u-small" style={{ padding: '4px 0' }}>
                <span>
                  {m.name}
                  <span className="u-muted u-xs" style={{ display: 'block' }}>
                    {m.email}
                  </span>
                </span>
                <span className="u-row">
                  {m.role === 'captain' && <StatusBadge state="captain" tone="info" />}
                  <span className="u-muted u-xs">
                    {m.lastSeen ? `seen ${m.lastSeen.slice(11, 16)} UTC` : 'never seen'}
                  </span>
                </span>
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
          Access profiles
        </h4>
        <p className="u-muted u-xs">
          Public metadata only — private keys never exist in the control plane, so there is nothing
          to display here beyond fingerprints.
        </p>
        {profilesQ.loading ? (
          <LoadingState lines={3} />
        ) : (profilesQ.data ?? []).length === 0 ? (
          <p className="u-secondary u-small">No access profiles issued.</p>
        ) : (
          <ul style={{ listStyle: 'none', margin: '6px 0 0', padding: 0 }}>
            {(profilesQ.data ?? []).map((p: AccessProfile) => (
              <li
                key={p.id}
                style={{ padding: '6px 0', borderBottom: '1px solid var(--border-subtle)' }}
              >
                <div className="u-spread">
                  <strong className="u-small">{memberName(p.participantId)}</strong>
                  <span className="u-row">
                    <span className="u-muted u-xs">{p.gateway}</span>
                    <StatusBadge state={p.status} />
                  </span>
                </div>
                <KeyValueGrid
                  columns={2}
                  items={[
                    { key: 'Endpoint', value: p.endpoint, mono: true },
                    { key: 'Key fingerprint', value: p.publicKeyFingerprint, mono: true },
                    {
                      key: 'Last handshake',
                      value: p.lastHandshake ? `${p.lastHandshake.slice(11, 16)} UTC` : 'never',
                    },
                    { key: 'Devices', value: p.deviceCount },
                  ]}
                />
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
          Allowed routes
        </h4>
        <ul style={{ margin: '6px 0 0', paddingLeft: 18 }} className="u-small u-mono">
          {team.allowedRoutes.map((r) => (
            <li key={r}>{r}</li>
          ))}
        </ul>
      </section>

      <section>
        <h4
          className="u-xs u-muted"
          style={{ textTransform: 'uppercase', letterSpacing: '0.06em' }}
        >
          Restrictions
        </h4>
        <ul style={{ margin: '6px 0 0', paddingLeft: 18 }} className="u-small u-secondary">
          {team.restrictions.map((r) => (
            <li key={r}>{r}</li>
          ))}
        </ul>
      </section>

      <section>
        <h4
          className="u-xs u-muted"
          style={{ textTransform: 'uppercase', letterSpacing: '0.06em' }}
        >
          Objectives
        </h4>
        <ul style={{ margin: '6px 0 0', paddingLeft: 18 }} className="u-small u-secondary">
          {team.objectives.map((o) => (
            <li key={o}>{o}</li>
          ))}
        </ul>
      </section>
    </div>
  )
}

export default function TeamsAccessPage() {
  const { event } = useEventWorkspace()
  const teamsQ = useQuery((a) => a.listTeams(event.id), [event.id])
  const [selected, setSelected] = useState<Team | undefined>()
  const [danger, setDanger] = useState<{ kind: DangerKind; team: Team } | undefined>()

  if (teamsQ.loading) {
    return (
      <div className="u-page">
        <LoadingState lines={6} />
      </div>
    )
  }
  if (!teamsQ.data) {
    return (
      <div className="u-page">
        <ErrorState message={teamsQ.error ?? 'Mock data unavailable.'} />
      </div>
    )
  }

  const teams = teamsQ.data

  const dangerMeta: Record<DangerKind, { title: string; operation: string; preview: string[] }> = {
    revoke: {
      title: `Revoke access — ${danger?.team.name ?? ''}`,
      operation: `revoke all ${danger?.team.memberIds.length ?? 0} access profiles for ${danger?.team.name ?? ''}`,
      preview: [
        `Mark all ${danger?.team.memberIds.length ?? 0} profiles revoked`,
        'Terminate active gateway sessions for this team',
        'Team stays offline until profiles are reissued',
      ],
    },
    suspend: {
      title: `Suspend access — ${danger?.team.name ?? ''}`,
      operation: `suspend participant access for ${danger?.team.name ?? ''}`,
      preview: [
        'Temporarily disable all team profiles (keys retained)',
        'Terminate active sessions; reconnects rejected while suspended',
        'Operators retain management access',
      ],
    },
    rotate: {
      title: `Rotate gateway keys — ${danger?.team.name ?? ''}`,
      operation: `rotate gateway key material for ${danger?.team.name ?? ''}`,
      preview: [
        'Generate new gateway key pairs worker-side (this interface handles references, not key values)',
        'All public-key fingerprints change',
        'Participants must re-import connection profiles',
      ],
    },
  }

  return (
    <div className="u-page">
      <CapabilityNotice capKey="access.gateway" />

      <DataTable
        label="Teams"
        rows={teams}
        rowKey={(t) => t.id}
        onRowClick={setSelected}
        selectedKey={selected?.id}
        emptyTitle="No teams yet"
        emptyBody="Teams are provisioned when the event's deployments are created."
        columns={[
          {
            key: 'name',
            header: 'Team',
            render: (t) => (
              <span className="c-matrix__team" style={{ ['--team' as string]: t.color }}>
                {t.name}
              </span>
            ),
          },
          { key: 'members', header: 'Members', align: 'right', render: (t) => t.memberIds.length },
          {
            key: 'subnet',
            header: 'Subnet',
            render: (t) => <span className="u-mono u-xs">{t.subnet}</span>,
          },
          { key: 'systems', header: 'Systems', align: 'right', render: (t) => t.systems.length },
          {
            key: 'connection',
            header: 'Connection',
            render: (t) => <StatusBadge state={t.connection} />,
          },
          {
            key: 'gateway',
            header: 'Gateway',
            render: (t) => <StatusBadge state={t.gatewayHealth} />,
          },
          {
            key: 'endpoint',
            header: 'VPN endpoint',
            render: (t) => <span className="u-mono u-xs">{t.vpnEndpoint}</span>,
          },
          { key: 'devices', header: 'Devices', align: 'right', render: (t) => t.connectedDevices },
        ]}
      />
      <p className="u-muted u-xs">
        Select a team row for members, access profiles, routes, and prototype access operations.
      </p>

      <Drawer
        open={Boolean(selected)}
        title={
          selected ? (
            <span className="c-matrix__team" style={{ ['--team' as string]: selected.color }}>
              {selected.name}
            </span>
          ) : (
            'Team'
          )
        }
        onClose={() => setSelected(undefined)}
        footer={
          selected && (
            <div className="u-grid" style={{ gap: 'var(--sp-2)' }}>
              <div className="u-row" style={{ flexWrap: 'wrap' }}>
                <Button
                  size="sm"
                  variant="danger"
                  icon={<UserX size={13} aria-hidden />}
                  onClick={() => setDanger({ kind: 'revoke', team: selected })}
                >
                  Revoke access
                </Button>
                <Button
                  size="sm"
                  variant="danger"
                  icon={<ShieldOff size={13} aria-hidden />}
                  onClick={() => setDanger({ kind: 'suspend', team: selected })}
                >
                  Suspend
                </Button>
                <Button
                  size="sm"
                  variant="danger"
                  icon={<KeyRound size={13} aria-hidden />}
                  onClick={() => setDanger({ kind: 'rotate', team: selected })}
                >
                  Rotate keys
                </Button>
              </div>
              <div className="u-row" style={{ flexWrap: 'wrap' }}>
                {DISABLED_ACTIONS.map((a) => (
                  <Button key={a.label} size="sm" variant="ghost" disabled title={a.title}>
                    {a.label}
                  </Button>
                ))}
              </div>
            </div>
          )
        }
      >
        {selected && <TeamDetail team={selected} />}
      </Drawer>

      {danger && (
        <DangerousOperationDialog
          open
          title={dangerMeta[danger.kind].title}
          operation={dangerMeta[danger.kind].operation}
          requiredApprovals={['Event director', 'Platform operator']}
          onClose={() => setDanger(undefined)}
          preview={
            <ul style={{ margin: 0, paddingLeft: 18 }} className="u-small u-secondary">
              {dangerMeta[danger.kind].preview.map((p) => (
                <li key={p}>{p}</li>
              ))}
            </ul>
          }
        />
      )}
    </div>
  )
}
