import { useMemo, useState } from 'react'
import {
  Drawer,
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
import { useEventWorkspace } from '../../layouts/EventWorkspaceLayout'

const VIEWS = [
  { key: 'all', label: 'All' },
  { key: 'attack', label: 'Attack paths' },
  { key: 'monitoring', label: 'Monitoring' },
]

export default function EventTopologyPage() {
  const { event } = useEventWorkspace()
  const topologyQ = useQuery((a) => a.getTopology(event.scenarioId), [event.scenarioId])
  const teamsQ = useQuery((a) => a.listTeams(event.id), [event.id])
  const [view, setView] = useState('all')
  const [selected, setSelected] = useState<TopologyNode | undefined>()

  const teamColors = useMemo(() => {
    const map: Record<string, string> = {}
    for (const t of teamsQ.data ?? []) map[t.id] = t.color
    return map
  }, [teamsQ.data])

  const visibleEdgeKinds = useMemo(() => {
    switch (view) {
      case 'attack':
        return ['link', 'attack-path'] as Array<'link' | 'route' | 'attack-path' | 'monitoring'>
      case 'monitoring':
        return ['link', 'monitoring'] as Array<'link' | 'route' | 'attack-path' | 'monitoring'>
      default:
        return undefined
    }
  }, [view])

  if (topologyQ.loading || teamsQ.loading) {
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
  const selectedTeamName = selected?.teamId
    ? (teamsQ.data ?? []).find((t) => t.id === selected.teamId)?.name
    : undefined

  return (
    <div className="u-page" style={{ maxWidth: 'none' }}>
      <Tabs tabs={VIEWS} active={view} onSelect={setView} />

      {graph ? (
        <>
          <TopologyCanvas
            graph={graph}
            height={560}
            teamColors={teamColors}
            visibleEdgeKinds={visibleEdgeKinds}
            onSelectNode={setSelected}
            selectedNodeId={selected?.id}
          />
          <TopologyLegend />
          {view === 'attack' && (
            <p className="u-secondary u-small">
              Attack paths are declared, dormant routes that the attack phase would open — none are
              active during hardening.
            </p>
          )}
          {view === 'monitoring' && (
            <p className="u-secondary u-small">
              Monitoring edges show declared telemetry flows into the Wazuh manager; agent coverage
              is mock data.
            </p>
          )}
          <p className="u-muted u-xs">
            This canvas shows the <strong>declared</strong> topology of scenario{' '}
            <span className="u-mono">{event.scenarioId}</span> v{event.scenarioVersion}. The
            realized deployment can differ (drift, resets, repairs) — discovery snapshots on the
            deployment workspace are the source of truth for realized state.
          </p>
        </>
      ) : (
        <EmptyState
          title="No topology fixture for this scenario"
          body={`Scenario ${event.scenarioId} has no mock topology graph. Aurora Breach (scn-aurora) and Web Breach 101 (scn-web101) do.`}
        />
      )}

      <Drawer
        open={Boolean(selected)}
        title={selected ? selected.label : 'Resource'}
        onClose={() => setSelected(undefined)}
      >
        {selected && <ResourceInspector node={selected} teamName={selectedTeamName} />}
      </Drawer>
    </div>
  )
}
