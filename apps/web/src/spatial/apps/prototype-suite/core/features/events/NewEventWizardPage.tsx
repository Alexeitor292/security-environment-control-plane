import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { CheckCircle2 } from 'lucide-react'
import {
  Button,
  CapabilityNotice,
  CapabilityTag,
  ErrorState,
  KeyValueGrid,
  LoadingState,
  PageHeader,
  StatusBadge,
  Wizard,
} from '../../components'
import type { WizardStep } from '../../components'
import { useQuery } from '../../integrations/AdapterContext'
import type { EventType } from '../../models/types'

const EVENT_TYPES: { key: EventType; label: string; desc: string }[] = [
  {
    key: 'competition',
    label: 'Competition',
    desc: 'Scored attack/defense with phases and a scoreboard.',
  },
  {
    key: 'training',
    label: 'Training',
    desc: 'Guided lab with objectives; no competitive scoring.',
  },
  {
    key: 'purple-team',
    label: 'Purple team',
    desc: 'Joint red/blue detection sprint with telemetry scoring.',
  },
  {
    key: 'ir-rehearsal',
    label: 'IR rehearsal',
    desc: 'Incident-response drill in a sealed enclave.',
  },
  { key: 'demo', label: 'Demonstration', desc: 'Short-lived showcase environment.' },
  { key: 'validation', label: 'Validation', desc: 'Continuous control/detection validation run.' },
]

const PLACEMENTS: { key: string; label: string; desc: string }[] = [
  {
    key: 'automatic',
    label: 'Automatic',
    desc: 'Platform picks targets by capacity, health, and policy.',
  },
  {
    key: 'lowest-cost',
    label: 'Lowest cost',
    desc: 'Prefer the cheapest eligible target per deployment.',
  },
  {
    key: 'preferred-provider',
    label: 'Preferred provider',
    desc: 'Pin all deployments to one provider.',
  },
  {
    key: 'specific-region',
    label: 'Specific region',
    desc: 'Constrain placement to a named region.',
  },
  {
    key: 'local-only',
    label: 'Local only',
    desc: 'On-prem targets only (Proxmox / local Kubernetes).',
  },
  { key: 'hybrid', label: 'Hybrid', desc: 'Team zones on-prem; scoring and observers in cloud.' },
]

const GATEWAYS: { key: string; label: string; desc: string; planned: boolean }[] = [
  {
    key: 'wireguard',
    label: 'WireGuard',
    desc: 'First implementation target for participant access.',
    planned: false,
  },
  { key: 'openvpn', label: 'OpenVPN', desc: 'Planned alternative gateway.', planned: true },
  {
    key: 'guacamole',
    label: 'Guacamole (browser)',
    desc: 'Planned clientless browser access.',
    planned: true,
  },
  {
    key: 'ssh-cert',
    label: 'SSH certificates',
    desc: 'Planned certificate-based shell access.',
    planned: true,
  },
]

const SCORING_MODELS: { key: string; label: string; desc: string }[] = [
  {
    key: 'attack-defense',
    label: 'Attack/defense composite',
    desc: 'Defense + availability + attack − penalties.',
  },
  { key: 'availability', label: 'Availability only', desc: 'Uptime checks on scored services.' },
  {
    key: 'detection',
    label: 'Detection scoring',
    desc: 'Chain-step detection coverage (purple team).',
  },
  { key: 'none', label: 'No scoring', desc: 'Run the event without a scoreboard.' },
]

const DEFAULT_PHASES = [
  { name: 'Preparation', desc: 'Environments deployed, access issued, scoreboard hidden.' },
  { name: 'Team hardening', desc: 'Teams harden their zones; cross-team traffic blocked.' },
  { name: 'Verification', desc: 'Operators verify readiness before opening attack traffic.' },
  { name: 'Attack phase', desc: 'Cross-team routes open; offensive scoring begins.' },
  { name: 'Final scoring', desc: 'Attack traffic frozen; final availability sweep.' },
  { name: 'Frozen', desc: 'Environments preserved for evidence capture and review.' },
  { name: 'Complete', desc: 'Event closed; reports generated; teardown scheduled.' },
]

const TEAM_NAME_POOL = [
  'Crimson',
  'Cobalt',
  'Amber',
  'Emerald',
  'Violet',
  'Slate',
  'Onyx',
  'Coral',
  'Jade',
  'Umber',
  'Ivory',
  'Zinc',
]

function OptionCard({
  name,
  value,
  label,
  desc,
  selected,
  disabled,
  disabledTitle,
  extra,
  onSelect,
}: {
  name: string
  value: string
  label: string
  desc: string
  selected: boolean
  disabled?: boolean
  disabledTitle?: string
  extra?: React.ReactNode
  onSelect: (value: string) => void
}) {
  return (
    <label
      className={`ev-opt${selected ? ' is-selected' : ''}${disabled ? ' is-disabled' : ''}`}
      title={disabled ? disabledTitle : undefined}
    >
      <input
        type="radio"
        name={name}
        value={value}
        checked={selected}
        disabled={disabled}
        onChange={() => onSelect(value)}
      />
      <span>
        <strong>{label}</strong>
        <span className="u-secondary u-xs">{desc}</span>
        {extra}
      </span>
    </label>
  )
}

export default function NewEventWizardPage() {
  const scenariosQ = useQuery((a) => a.listScenarios())

  const [stepIndex, setStepIndex] = useState(0)
  const [eventType, setEventType] = useState<EventType>('competition')
  const [scenarioId, setScenarioId] = useState<string | undefined>()
  const [teamCount, setTeamCount] = useState(6)
  const [placement, setPlacement] = useState('automatic')
  const [startAt, setStartAt] = useState('2026-07-27T09:00')
  const [endAt, setEndAt] = useState('2026-07-27T18:00')
  const [gateway, setGateway] = useState('wireguard')
  const [profilesPerTeam, setProfilesPerTeam] = useState(5)
  const [scoringModel, setScoringModel] = useState('attack-defense')
  const [created, setCreated] = useState(false)

  const scenario = scenariosQ.data?.find((s) => s.id === scenarioId)
  const teamNames = useMemo(
    () => Array.from({ length: teamCount }, (_, i) => TEAM_NAME_POOL[i] ?? `Team ${i + 1}`),
    [teamCount],
  )

  const reviewItems = [
    { key: 'Event type', value: EVENT_TYPES.find((t) => t.key === eventType)?.label ?? eventType },
    {
      key: 'Scenario',
      value: scenario ? `${scenario.name} v${scenario.currentVersion}` : 'Not selected',
    },
    {
      key: 'Scenario validation',
      value: scenario ? <StatusBadge state={scenario.validation} /> : '—',
    },
    {
      key: 'Teams',
      value: `${teamCount} (${teamNames.slice(0, 4).join(', ')}${teamCount > 4 ? ', …' : ''})`,
    },
    { key: 'Placement', value: PLACEMENTS.find((p) => p.key === placement)?.label ?? placement },
    { key: 'Schedule', value: `${startAt.replace('T', ' ')} → ${endAt.replace('T', ' ')} UTC` },
    { key: 'Phases', value: `${DEFAULT_PHASES.length} (default competition chain)` },
    { key: 'Access gateway', value: GATEWAYS.find((g) => g.key === gateway)?.label ?? gateway },
    { key: 'Profiles per team', value: profilesPerTeam },
    {
      key: 'Scoring model',
      value: SCORING_MODELS.find((m) => m.key === scoringModel)?.label ?? scoringModel,
    },
    {
      key: 'Estimated cost',
      value: scenario
        ? `~$${scenario.estimatedCostPerHour.toFixed(2)}/hr (mock — cost tracking is proposed)`
        : '—',
    },
  ]

  const steps: WizardStep[] = [
    {
      key: 'type',
      title: 'Event type',
      render: () => (
        <div className="u-grid">
          <p className="u-secondary u-small">
            The type sets defaults for phases, scoring, and access — everything stays editable
            later.
          </p>
          <div className="ev-optgrid" role="radiogroup" aria-label="Event type">
            {EVENT_TYPES.map((t) => (
              <OptionCard
                key={t.key}
                name="event-type"
                value={t.key}
                label={t.label}
                desc={t.desc}
                selected={eventType === t.key}
                onSelect={(v) => setEventType(v as EventType)}
              />
            ))}
          </div>
        </div>
      ),
    },
    {
      key: 'scenario',
      title: 'Scenario selection',
      render: () => {
        if (scenariosQ.loading) return <LoadingState lines={4} />
        if (scenariosQ.error || !scenariosQ.data)
          return <ErrorState message={scenariosQ.error ?? 'Mock data unavailable.'} />
        return (
          <div className="u-grid">
            <p className="u-secondary u-small">
              Events pin a validated, immutable scenario version. Draft or failed-validation
              versions cannot be scheduled.
            </p>
            <div className="ev-optgrid" role="radiogroup" aria-label="Scenario">
              {scenariosQ.data.map((s) => (
                <OptionCard
                  key={s.id}
                  name="scenario"
                  value={s.id}
                  label={`${s.name} v${s.currentVersion}`}
                  desc={s.purpose}
                  selected={scenarioId === s.id}
                  onSelect={setScenarioId}
                  extra={
                    <span className="u-row u-xs" style={{ marginTop: 4, flexWrap: 'wrap' }}>
                      <StatusBadge state={s.validation} />
                      <span className="u-muted">
                        ~${s.estimatedCostPerHour.toFixed(2)}/hr · teams {s.teamRange[0]}–
                        {s.teamRange[1]}
                      </span>
                    </span>
                  }
                />
              ))}
            </div>
          </div>
        )
      },
    },
    {
      key: 'teams',
      title: 'Team count',
      render: () => (
        <div className="u-grid">
          <label className="ev-field">
            <span>Number of teams</span>
            <input
              type="number"
              min={1}
              max={12}
              value={teamCount}
              onChange={(e) => setTeamCount(Math.max(1, Math.min(12, Number(e.target.value) || 1)))}
            />
          </label>
          {scenario && (teamCount < scenario.teamRange[0] || teamCount > scenario.teamRange[1]) && (
            <p className="u-small" style={{ color: 'var(--status-warn, #fbbf24)' }}>
              {scenario.name} supports {scenario.teamRange[0]}–{scenario.teamRange[1]} teams.
            </p>
          )}
          <div>
            <span className="u-xs u-muted">Team name preview (editable after creation)</span>
            <div className="ev-chiprow" style={{ marginTop: 6 }}>
              {teamNames.map((n) => (
                <span key={n} className="ev-chip">
                  {n}
                </span>
              ))}
            </div>
          </div>
          <p className="u-muted u-xs">
            Each team receives an isolated zone with its own subnet reservation, matching the
            platform&apos;s per-team CIDR model.
          </p>
        </div>
      ),
    },
    {
      key: 'placement',
      title: 'Deployment placement',
      render: () => (
        <div className="u-grid">
          <CapabilityNotice capKey="infrastructure.placement" />
          <div className="ev-optgrid" role="radiogroup" aria-label="Placement policy">
            {PLACEMENTS.map((p) => (
              <OptionCard
                key={p.key}
                name="placement"
                value={p.key}
                label={p.label}
                desc={p.desc}
                selected={placement === p.key}
                onSelect={setPlacement}
              />
            ))}
          </div>
          <p className="u-muted u-xs">
            The placement engine is planned — this choice records intent only; no placement is
            computed in the prototype.
          </p>
        </div>
      ),
    },
    {
      key: 'schedule',
      title: 'Schedule',
      render: () => (
        <div className="u-grid">
          <div className="u-row" style={{ flexWrap: 'wrap', alignItems: 'flex-end' }}>
            <label className="ev-field">
              <span>Starts (UTC)</span>
              <input
                type="datetime-local"
                value={startAt}
                onChange={(e) => setStartAt(e.target.value)}
              />
            </label>
            <label className="ev-field">
              <span>Ends (UTC)</span>
              <input
                type="datetime-local"
                value={endAt}
                onChange={(e) => setEndAt(e.target.value)}
              />
            </label>
          </div>
          <p className="u-muted u-xs">
            Prototype-only inputs. In the real platform, scheduling would drive deployment
            lead-times, credential leases, and teardown windows.
          </p>
        </div>
      ),
    },
    {
      key: 'phases',
      title: 'Competition phases',
      render: () => (
        <div className="u-grid">
          <CapabilityNotice capKey="events.phases" />
          <ol style={{ listStyle: 'none', margin: 0, padding: 0 }}>
            {DEFAULT_PHASES.map((p, i) => (
              <li
                key={p.name}
                className="u-spread"
                style={{ padding: '6px 0', borderBottom: '1px solid var(--border-subtle)' }}
              >
                <span className="u-small">
                  <span className="u-muted u-mono u-xs" style={{ marginRight: 8 }}>
                    {i + 1}
                  </span>
                  <strong>{p.name}</strong>
                  <span className="u-secondary u-xs" style={{ display: 'block', marginLeft: 22 }}>
                    {p.desc}
                  </span>
                </span>
                <span className="u-row">
                  <Button
                    size="sm"
                    variant="ghost"
                    disabled
                    title="Prototype: phase editing is not wired (phases are proposed, SECP events model)"
                  >
                    Edit
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    disabled
                    title="Prototype: phase reordering is not wired (phases are proposed, SECP events model)"
                  >
                    Reorder
                  </Button>
                </span>
              </li>
            ))}
          </ol>
          <p className="u-muted u-xs">
            Default 7-phase competition chain. Each transition is designed as an approval-gated
            controlled operation with a full change preview — never a toggle.
          </p>
        </div>
      ),
    },
    {
      key: 'access',
      title: 'Participant access',
      render: () => (
        <div className="u-grid">
          <div className="ev-optgrid" role="radiogroup" aria-label="Access gateway">
            {GATEWAYS.map((g) => (
              <OptionCard
                key={g.key}
                name="gateway"
                value={g.key}
                label={g.label}
                desc={g.desc}
                selected={gateway === g.key}
                disabled={g.planned}
                disabledTitle="Planned gateway — WireGuard is the intended first implementation"
                onSelect={setGateway}
                extra={
                  g.planned ? (
                    <span style={{ display: 'block', marginTop: 4 }}>
                      <CapabilityTag status="planned" />
                    </span>
                  ) : undefined
                }
              />
            ))}
          </div>
          <label className="ev-field">
            <span>Access profiles per team</span>
            <input
              type="number"
              min={1}
              max={20}
              value={profilesPerTeam}
              onChange={(e) =>
                setProfilesPerTeam(Math.max(1, Math.min(20, Number(e.target.value) || 1)))
              }
            />
          </label>
          <p className="u-muted u-xs">
            Profiles carry public metadata only (endpoint, key fingerprint, handshake). Private keys
            never touch the control plane.
          </p>
        </div>
      ),
    },
    {
      key: 'scoring',
      title: 'Scoring',
      render: () => (
        <div className="u-grid">
          <CapabilityNotice capKey="events.scoring" />
          <div className="ev-optgrid" role="radiogroup" aria-label="Scoring model">
            {SCORING_MODELS.map((m) => (
              <OptionCard
                key={m.key}
                name="scoring"
                value={m.key}
                label={m.label}
                desc={m.desc}
                selected={scoringModel === m.key}
                onSelect={setScoringModel}
              />
            ))}
          </div>
        </div>
      ),
    },
    {
      key: 'review',
      title: 'Review',
      render: () => (
        <div className="u-grid">
          <p className="u-secondary u-small">
            Everything below is local wizard state — nothing has been sent anywhere.
          </p>
          <KeyValueGrid columns={2} items={reviewItems} />
        </div>
      ),
    },
    {
      key: 'create',
      title: 'Create',
      render: () => (
        <div className="u-grid">
          {created ? (
            <div className="ev-confirm" role="status">
              <span className="u-row" style={{ color: 'var(--status-ok, #4ade80)' }}>
                <CheckCircle2 size={16} aria-hidden />
                <strong>Prototype confirmation — nothing was created</strong>
              </span>
              <p className="u-secondary u-small">
                In the real platform, this would create the event record, generate per-team
                deployment plans, and queue them for approval. This prototype keeps all wizard state
                in the browser and persists nothing.
              </p>
              <p className="u-secondary u-small">
                Explore the existing mock events instead: <Link to="/events">Events list</Link>.
              </p>
            </div>
          ) : (
            <div className="ev-confirm">
              <strong className="u-small">Ready to create (prototype)</strong>
              <KeyValueGrid
                columns={2}
                items={reviewItems.filter((i) =>
                  ['Event type', 'Scenario', 'Teams', 'Schedule', 'Scoring model'].includes(i.key),
                )}
              />
              <p className="u-muted u-xs">
                Use the “Create event (prototype)” button below. It records a local confirmation
                only — no event, deployment, or access profile is created.
              </p>
            </div>
          )}
        </div>
      ),
    },
  ]

  return (
    <div className="u-page">
      <PageHeader
        title="New event"
        capabilityStatus="planned"
        description="Guided event setup: type, scenario, teams, placement, schedule, phases, access, and scoring. A clickable draft — finishing never persists anything."
      />
      <CapabilityNotice capKey="events.model" />

      <Wizard
        steps={steps}
        activeIndex={stepIndex}
        onNavigate={(i) => setStepIndex(Math.max(0, Math.min(steps.length - 1, i)))}
        finishLabel="Create event (prototype)"
        onFinish={() => setCreated(true)}
        aside={
          <div className="u-grid" style={{ gap: 'var(--sp-2)' }}>
            <h3
              className="u-xs u-muted"
              style={{ textTransform: 'uppercase', letterSpacing: '0.06em' }}
            >
              Selections
            </h3>
            <KeyValueGrid
              columns={1}
              items={[
                { key: 'Type', value: EVENT_TYPES.find((t) => t.key === eventType)?.label ?? '—' },
                { key: 'Scenario', value: scenario?.name ?? '—' },
                { key: 'Teams', value: teamCount },
                { key: 'Gateway', value: GATEWAYS.find((g) => g.key === gateway)?.label ?? '—' },
                {
                  key: 'Scoring',
                  value: SCORING_MODELS.find((m) => m.key === scoringModel)?.label ?? '—',
                },
              ]}
            />
            <p className="u-muted u-xs">All wizard state is local. Nothing is saved.</p>
          </div>
        }
      />
    </div>
  )
}
