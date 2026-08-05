import { useMemo, useState } from 'react'
import { AlertTriangle } from 'lucide-react'
import {
  Card,
  Drawer,
  EmptyState,
  KeyValueGrid,
  LoadingState,
  ResourceInspector,
  TopologyCanvas,
  TopologyLegend,
} from '../../components'
import { useQuery } from '../../integrations/AdapterContext'
import { useDeploymentWorkspace } from '../../layouts/DeploymentWorkspaceLayout'
import type { TopologyNode } from '../../models/types'

export default function DeploymentTopologyPage() {
  const { deployment } = useDeploymentWorkspace()
  const graphQ = useQuery((a) => a.getTopology(deployment.id), [deployment.id])
  const teamsQ = useQuery((a) => a.listTeams())

  const [selected, setSelected] = useState<TopologyNode | undefined>()

  const teamColors = useMemo(() => {
    const map: Record<string, string> = {}
    for (const t of teamsQ.data ?? []) map[t.id] = t.color
    return map
  }, [teamsQ.data])

  const teamName = (teamId?: string) => (teamsQ.data ?? []).find((t) => t.id === teamId)?.name

  if (graphQ.loading) {
    return (
      <div className="u-page">
        <LoadingState lines={6} />
      </div>
    )
  }

  if (!graphQ.data) {
    return (
      <div className="u-page">
        <EmptyState
          title="No topology canvas for this deployment"
          body="The prototype ships hand-placed canvas fixtures for dep-aurora-teams and dep-web101-stage only. Other deployments list their realized resources on the Resources tab."
        />
      </div>
    )
  }

  // Realized provider identifiers: a small sample of the deployment's resources.
  const refSample = deployment.resources.slice(0, 6)

  return (
    <div className="u-page">
      <Card
        heading="Realized topology"
        actions={<span className="u-muted u-xs">read-only · positions are draft fixtures</span>}
        padded={false}
      >
        <TopologyCanvas
          graph={graphQ.data}
          height={540}
          onSelectNode={setSelected}
          selectedNodeId={selected?.id}
          teamColors={teamColors}
        />
      </Card>
      <TopologyLegend />

      {deployment.drift && (
        <p className="u-small" role="note">
          <span className="c-badge c-badge--warn">
            <AlertTriangle size={12} aria-hidden /> drift
          </span>{' '}
          Observed state differs from scenario version {deployment.scenarioVersion} — the canvas
          shows the intended layout; see Monitoring for what drifted.
        </p>
      )}

      <Card
        heading="Realized identifiers"
        actions={
          <span className="u-muted u-xs">sample of {deployment.resources.length} resources</span>
        }
      >
        {refSample.length === 0 ? (
          <p className="u-secondary u-small">
            No realized resources yet — this deployment is plan-only.
          </p>
        ) : (
          <KeyValueGrid
            columns={3}
            items={refSample.map((r) => ({ key: r.name, value: r.providerRef, mono: true }))}
          />
        )}
        <p className="u-muted u-xs" style={{ marginTop: 'var(--sp-2)' }}>
          Provider references are mock fixtures — no real infrastructure exists behind them.
        </p>
      </Card>

      <Drawer
        open={Boolean(selected)}
        title={selected ? selected.label : ''}
        onClose={() => setSelected(undefined)}
      >
        {selected && <ResourceInspector node={selected} teamName={teamName(selected.teamId)} />}
      </Drawer>
    </div>
  )
}
