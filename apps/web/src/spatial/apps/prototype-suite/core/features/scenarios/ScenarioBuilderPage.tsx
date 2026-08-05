import type { ReactNode } from 'react'
import { useMemo, useState } from 'react'
import {
  Bug,
  Crosshair,
  Database,
  Fingerprint,
  Flame,
  Globe,
  KeyRound,
  Monitor,
  Network,
  Route,
  Server,
  Shield,
  Trophy,
  Users,
} from 'lucide-react'
import {
  CapabilityNotice,
  ConnectivityMatrix,
  EmptyState,
  ErrorState,
  LoadingState,
  ResourceInspector,
  Tabs,
  TopologyCanvas,
  TopologyLegend,
} from '../../components'
import { useQuery } from '../../integrations/AdapterContext'
import type { TopologyNode } from '../../models/types'
import { useScenarioWorkspace } from '../../layouts/ScenarioWorkspaceLayout'

/**
 * Packet Tracer-inspired builder frame: left palette, central canvas with
 * conceptual views, right inspector. The canvas is read-only in this draft;
 * the production builder should reuse the source repo's topology-workspace
 * core (reducer, ELK layout, validation) behind this same frame.
 */

const PALETTE: { category: string; items: { label: string; icon: ReactNode }[] }[] = [
  {
    category: 'Networks',
    items: [
      { label: 'Team subnet', icon: <Network size={13} aria-hidden /> },
      { label: 'Shared subnet', icon: <Network size={13} aria-hidden /> },
      { label: 'Router', icon: <Route size={13} aria-hidden /> },
      { label: 'Firewall', icon: <Flame size={13} aria-hidden /> },
      { label: 'Team boundary', icon: <Users size={13} aria-hidden /> },
    ],
  },
  {
    category: 'Compute',
    items: [
      { label: 'Windows server', icon: <Server size={13} aria-hidden /> },
      { label: 'Linux server', icon: <Server size={13} aria-hidden /> },
      { label: 'Web server', icon: <Globe size={13} aria-hidden /> },
      { label: 'Database', icon: <Database size={13} aria-hidden /> },
      { label: 'Kali workstation', icon: <Monitor size={13} aria-hidden /> },
    ],
  },
  {
    category: 'Identity',
    items: [{ label: 'Active Directory', icon: <Fingerprint size={13} aria-hidden /> }],
  },
  {
    category: 'Security',
    items: [
      { label: 'Wazuh server', icon: <Shield size={13} aria-hidden /> },
      { label: 'Wazuh agent', icon: <Shield size={13} aria-hidden /> },
      { label: 'Security Onion', icon: <Shield size={13} aria-hidden /> },
      { label: 'SIEM', icon: <Shield size={13} aria-hidden /> },
      { label: 'Vulnerable application', icon: <Bug size={13} aria-hidden /> },
    ],
  },
  {
    category: 'Competition',
    items: [{ label: 'Scoring agent', icon: <Trophy size={13} aria-hidden /> }],
  },
  {
    category: 'Access',
    items: [{ label: 'WireGuard gateway', icon: <KeyRound size={13} aria-hidden /> }],
  },
]

const VIEWS = [
  { key: 'logical', label: 'Logical topology' },
  { key: 'placement', label: 'Provider placement' },
  { key: 'zones', label: 'Security zones' },
  { key: 'attack', label: 'Attack paths' },
  { key: 'monitoring', label: 'Monitoring coverage' },
  { key: 'matrix', label: 'Connectivity matrix' },
]

const TEAM_COLORS: Record<string, string> = {
  'team-crimson': '#f87171',
  'team-cobalt': '#60a5fa',
  'team-amber': '#fbbf24',
  'team-emerald': '#4ade80',
  'team-violet': '#c084fc',
  'team-slate': '#94a3b8',
}

export default function ScenarioBuilderPage() {
  const { scenario } = useScenarioWorkspace()
  const topologyQ = useQuery((a) => a.getTopology(scenario.id), [scenario.id])
  const teamsQ = useQuery((a) => a.listTeams('evt-aurora-cup'))
  const [view, setView] = useState('logical')
  const [selected, setSelected] = useState<TopologyNode | undefined>()

  const edgeKinds = useMemo(() => {
    switch (view) {
      case 'attack':
        return ['link', 'route', 'attack-path'] as const
      case 'monitoring':
        return ['link', 'monitoring'] as const
      default:
        return ['link', 'route'] as const
    }
  }, [view])

  if (topologyQ.loading) {
    return (
      <div className="u-page">
        <LoadingState lines={6} />
      </div>
    )
  }
  if (topologyQ.error) {
    return (
      <div className="u-page">
        <ErrorState message={topologyQ.error} />
      </div>
    )
  }

  const graph = topologyQ.data

  return (
    <div className="u-page" style={{ maxWidth: 'none' }}>
      <CapabilityNotice capKey="scenarios.builder" />

      <div className="sb-frame">
        <aside className="sb-palette" aria-label="Asset palette">
          <h3
            className="u-xs u-muted"
            style={{ textTransform: 'uppercase', letterSpacing: '0.06em' }}
          >
            Palette
          </h3>
          {PALETTE.map((group) => (
            <div key={group.category} className="sb-palette__group">
              <span className="sb-palette__cat">{group.category}</span>
              {group.items.map((item) => (
                <button
                  key={item.label}
                  type="button"
                  className="sb-palette__item"
                  disabled
                  title="Prototype: drag-to-add is not wired in the draft builder"
                >
                  {item.icon}
                  <span>{item.label}</span>
                </button>
              ))}
            </div>
          ))}
          <p className="u-muted u-xs">
            Palette items are draft placeholders. Node kinds implemented in the repo today:
            attacker, target, sensor, network.
          </p>
        </aside>

        <section className="sb-canvas" aria-label="Scenario canvas">
          <Tabs tabs={VIEWS} active={view} onSelect={setView} />
          {view === 'matrix' ? (
            teamsQ.data && teamsQ.data.length > 0 ? (
              <div style={{ padding: 'var(--sp-3) 0' }}>
                <ConnectivityMatrix
                  teams={teamsQ.data}
                  cell={(a, b) => (a.id === b.id ? 'self' : 'blocked')}
                  caption="Declared inter-team policy for the hardening phase (mock)."
                />
              </div>
            ) : (
              <EmptyState title="No team data" body="Connectivity matrix requires team fixtures." />
            )
          ) : graph ? (
            <>
              <TopologyCanvas
                graph={graph}
                height={560}
                onSelectNode={setSelected}
                selectedNodeId={selected?.id}
                teamColors={TEAM_COLORS}
                visibleEdgeKinds={[...edgeKinds]}
              />
              <TopologyLegend />
              {view === 'placement' && (
                <p className="u-secondary u-small">
                  Provider placement view: team zones → Proxmox (dc-lab-1), scoring → AWS us-west-2.
                  Per-resource placement is a proposed capability.
                </p>
              )}
              {view === 'zones' && (
                <p className="u-secondary u-small">
                  Security zones view: each team zone is an isolation boundary; shared services sit
                  behind the core firewall. A declared zone is not verified isolation.
                </p>
              )}
            </>
          ) : (
            <EmptyState
              title="No topology for this scenario"
              body="This mock scenario has no canvas fixture. Aurora Breach and Web Breach 101 do."
            />
          )}
        </section>

        <aside className="sb-inspector" aria-label="Resource inspector">
          <h3
            className="u-xs u-muted"
            style={{ textTransform: 'uppercase', letterSpacing: '0.06em' }}
          >
            Inspector
          </h3>
          {selected ? (
            <ResourceInspector
              node={selected}
              teamName={selected.teamId
                ?.replace('team-', '')
                .replace(/^\w/, (c) => c.toUpperCase())}
            />
          ) : (
            <div className="c-state" style={{ padding: 'var(--sp-4) var(--sp-2)' }}>
              <Crosshair size={18} aria-hidden className="u-muted" />
              <p className="u-secondary u-small">Select a node on the canvas to inspect it.</p>
            </div>
          )}
        </aside>
      </div>
    </div>
  )
}
