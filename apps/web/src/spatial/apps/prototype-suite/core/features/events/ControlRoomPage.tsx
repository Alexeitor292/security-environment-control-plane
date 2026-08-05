import type { ReactNode } from 'react'
import { useMemo, useState } from 'react'
import {
  Megaphone,
  OctagonPause,
  Pause,
  RefreshCcw,
  Shield,
  Snowflake,
  UserX,
  Video,
} from 'lucide-react'
import {
  AlertsList,
  Button,
  Card,
  CapabilityNotice,
  ConnectivityMatrix,
  DangerousOperationDialog,
  ErrorState,
  LoadingState,
  MetricRow,
  MetricTile,
  PhaseTimeline,
  Scoreboard,
  StatusBadge,
} from '../../components'
import type { MatrixCell } from '../../components'
import { useQuery } from '../../integrations/AdapterContext'
import type { Team } from '../../models/types'
import { useEventWorkspace } from '../../layouts/EventWorkspaceLayout'
import { PhaseTransitionPreview } from './PhaseTransitionPreview'

interface EmergencyControl {
  key: string
  label: string
  icon: ReactNode
  operation: string
  preview: string[]
  approvals: string[]
}

export default function ControlRoomPage() {
  const { event } = useEventWorkspace()
  const teamsQ = useQuery((a) => a.listTeams(event.id), [event.id])
  const deploymentsQ = useQuery((a) => a.listDeployments())
  const alertsQ = useQuery((a) => a.listAlerts())
  const scoresQ = useQuery((a) => a.listScores(event.id), [event.id])
  const runsQ = useQuery((a) => a.listWorkflowRuns({ eventId: event.id }), [event.id])

  const [previewOpen, setPreviewOpen] = useState(false)
  const [control, setControl] = useState<EmergencyControl | undefined>()
  const [isolateTeam, setIsolateTeam] = useState<Team | undefined>()

  const activePhase = event.phases.find((p) => p.status === 'active')
  const nextPhase = useMemo(() => {
    if (!activePhase) return undefined
    return [...event.phases]
      .sort((a, b) => a.order - b.order)
      .find((p) => p.order > activePhase.order)
  }, [event.phases, activePhase])

  if (teamsQ.loading || deploymentsQ.loading) {
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
  const eventDeployments = (deploymentsQ.data ?? []).filter((d) =>
    event.deploymentIds.includes(d.id),
  )
  const eventAlerts = (alertsQ.data ?? []).filter((a) => a.eventId === event.id)
  const runs = (runsQ.data ?? []).filter(
    (r) => r.status === 'running' || r.status === 'awaiting-approval' || r.status === 'retrying',
  )

  // During hardening, inter-team traffic is blocked; attack phase would open it.
  const matrixCell = (from: Team, to: Team): MatrixCell => (from.id === to.id ? 'self' : 'blocked')

  const emergencyControls: EmergencyControl[] = [
    {
      key: 'freeze',
      label: 'Freeze competition traffic',
      icon: <Snowflake size={14} aria-hidden />,
      operation: 'freeze all participant traffic',
      preview: [
        'Deny all participant → environment traffic at the core firewall',
        'Keep operator/management access unchanged',
        'Pause availability scoring while frozen',
      ],
      approvals: ['Event director'],
    },
    {
      key: 'cross-team',
      label: 'Disable cross-team access',
      icon: <Shield size={14} aria-hidden />,
      operation: 'close all inter-team routes',
      preview: ['Remove team ↔ opponent DMZ routes', 'Restore hardening-phase firewall policy'],
      approvals: ['Event director'],
    },
    {
      key: 'suspend-access',
      label: 'Suspend participant access',
      icon: <UserX size={14} aria-hidden />,
      operation: 'suspend all participant VPN sessions',
      preview: [
        'Disable all participant access profiles',
        'Terminate active gateway sessions',
        'Operators retain access',
      ],
      approvals: ['Event director', 'Platform operator'],
    },
    {
      key: 'pause-scoring',
      label: 'Pause scoring',
      icon: <Pause size={14} aria-hidden />,
      operation: 'pause all scoring checks',
      preview: ['Stop availability + attack scoring', 'Scoreboard frozen at current standings'],
      approvals: ['Event director'],
    },
    {
      key: 'capture',
      label: 'Capture evidence',
      icon: <Video size={14} aria-hidden />,
      operation: 'capture environment evidence snapshots',
      preview: ['Snapshot all team zones (read-only)', 'Hash and store evidence records'],
      approvals: ['Platform operator'],
    },
    {
      key: 'reset',
      label: 'Initiate controlled reset',
      icon: <RefreshCcw size={14} aria-hidden />,
      operation: 'controlled reset of a team zone',
      preview: [
        'Roll back selected systems to known-good baseline',
        'Availability penalty applies per event rules',
        'Evidence captured before reset',
      ],
      approvals: ['Event director', 'Platform operator'],
    },
  ]

  return (
    <div className="u-page">
      <CapabilityNotice capKey="events.control-room" />

      <MetricRow>
        <MetricTile
          label="Participants online"
          value={`${event.connectedParticipants}/${event.totalParticipants}`}
          tone={event.connectedParticipants < event.totalParticipants ? 'warn' : 'ok'}
          detail="via team gateways"
        />
        <MetricTile
          label="Deployment health"
          value={
            eventDeployments.filter((d) => d.health === 'healthy').length +
            '/' +
            eventDeployments.length
          }
          tone={eventDeployments.some((d) => d.health !== 'healthy') ? 'warn' : 'ok'}
          detail="healthy deployments"
        />
        <MetricTile
          label="Live alerts"
          value={eventAlerts.filter((a) => !a.acknowledged).length}
          tone={
            eventAlerts.some((a) => a.severity === 'critical' && !a.acknowledged)
              ? 'error'
              : undefined
          }
          detail="for this event"
        />
        <MetricTile
          label="Operations underway"
          value={runs.length}
          detail="running or awaiting approval"
        />
      </MetricRow>

      <Card
        heading="Competition phase"
        actions={
          nextPhase && (
            <Button variant="primary" size="sm" onClick={() => setPreviewOpen(true)}>
              Preview transition → {nextPhase.name}
            </Button>
          )
        }
      >
        <PhaseTimeline phases={event.phases} />
        {activePhase && (
          <p className="u-secondary u-small" style={{ marginTop: 'var(--sp-2)' }}>
            <strong>{activePhase.name}</strong> — {activePhase.description}
          </p>
        )}
      </Card>

      <div
        className="u-grid"
        style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))' }}
      >
        <Card heading="Team connectivity">
          <ConnectivityMatrix
            teams={teams}
            cell={matrixCell}
            caption="Inter-team traffic policy for the current phase (hardening: all blocked)."
          />
          <ul style={{ listStyle: 'none', margin: 'var(--sp-2) 0 0', padding: 0 }}>
            {teams.map((t) => (
              <li key={t.id} className="u-spread u-small" style={{ padding: '3px 0' }}>
                <span className="c-matrix__team" style={{ ['--team' as string]: t.color }}>
                  {t.name}
                </span>
                <span className="u-row">
                  <span className="u-muted u-xs">{t.connectedDevices} devices</span>
                  <StatusBadge state={t.connection} />
                </span>
              </li>
            ))}
          </ul>
        </Card>

        <Card heading="Live alerts">
          <AlertsList alerts={eventAlerts} />
        </Card>

        <Card heading="Scoreboard preview">
          {event.scoringEnabled && scoresQ.data && scoresQ.data.length > 0 ? (
            <Scoreboard scores={scoresQ.data} teams={teams} />
          ) : (
            <p className="u-secondary u-small">Scoring is not enabled for this event.</p>
          )}
          <p className="u-muted u-xs" style={{ marginTop: 'var(--sp-2)' }}>
            Mock standings — scoring is not implemented in the platform (SECP-004).
          </p>
        </Card>

        <Card heading="Current operations">
          {runs.length === 0 ? (
            <p className="u-secondary u-small">No operations underway.</p>
          ) : (
            <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
              {runs.map((r) => (
                <li key={r.id} className="u-spread u-small" style={{ padding: '5px 0' }}>
                  <span>{r.name}</span>
                  <StatusBadge state={r.status} />
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card
          heading="Announcements"
          actions={<Megaphone size={14} aria-hidden className="u-muted" />}
        >
          {event.announcements.length === 0 ? (
            <p className="u-secondary u-small">No announcements yet.</p>
          ) : (
            <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
              {event.announcements.map((ann) => (
                <li key={ann.id} style={{ padding: '5px 0' }} className="u-small">
                  <span className="u-muted u-xs u-mono" style={{ display: 'block' }}>
                    {ann.time.slice(11, 16)} UTC · {ann.author}
                  </span>
                  {ann.message}
                </li>
              ))}
            </ul>
          )}
          <Button
            variant="ghost"
            size="sm"
            disabled
            title="Prototype: announcement publishing is not wired"
          >
            New announcement
          </Button>
        </Card>

        <Card
          heading="Emergency controls"
          actions={<OctagonPause size={14} aria-hidden className="u-muted" />}
        >
          <p className="u-muted u-xs" style={{ marginBottom: 'var(--sp-2)' }}>
            Every control opens a preview-and-confirm dialog. Nothing executes in the prototype.
          </p>
          <div className="u-grid" style={{ gridTemplateColumns: '1fr 1fr', gap: 'var(--sp-2)' }}>
            {emergencyControls.map((c) => (
              <Button
                key={c.key}
                variant="danger"
                size="sm"
                icon={c.icon}
                onClick={() => setControl(c)}
              >
                {c.label}
              </Button>
            ))}
            <Button
              variant="danger"
              size="sm"
              icon={<UserX size={14} aria-hidden />}
              onClick={() =>
                setIsolateTeam(teams.find((t) => t.connection === 'partial') ?? teams[0])
              }
            >
              Isolate team…
            </Button>
          </div>
        </Card>
      </div>

      {nextPhase && activePhase && (
        <PhaseTransitionPreview
          open={previewOpen}
          event={event}
          from={activePhase}
          to={nextPhase}
          onClose={() => setPreviewOpen(false)}
        />
      )}

      {control && (
        <DangerousOperationDialog
          open
          title={control.label}
          operation={control.operation}
          requiredApprovals={control.approvals}
          onClose={() => setControl(undefined)}
          preview={
            <ul style={{ margin: 0, paddingLeft: 18 }} className="u-small u-secondary">
              {control.preview.map((p) => (
                <li key={p}>{p}</li>
              ))}
            </ul>
          }
        />
      )}

      {isolateTeam && (
        <DangerousOperationDialog
          open
          title={`Isolate ${isolateTeam.name}`}
          operation={`isolate team ${isolateTeam.name} from all networks`}
          requiredApprovals={['Event director', 'Platform operator']}
          onClose={() => setIsolateTeam(undefined)}
          preview={
            <ul style={{ margin: 0, paddingLeft: 18 }} className="u-small u-secondary">
              <li>Deny all traffic to/from {isolateTeam.subnet}</li>
              <li>Suspend {isolateTeam.memberIds.length} participant access profiles</li>
              <li>Keep systems running for evidence capture</li>
              <li>Availability scoring pauses for this team only</li>
            </ul>
          }
        />
      )}
    </div>
  )
}
