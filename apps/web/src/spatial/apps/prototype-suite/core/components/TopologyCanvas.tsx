import type { ReactNode } from 'react'
import { useMemo } from 'react'
import {
  Background,
  Controls,
  MiniMap,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
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
} from 'lucide-react'
import { clsx } from 'clsx'
import type { TopologyGraph, TopologyNode, TopologyNodeKind } from '../models/types'

const KIND_ICON: Record<TopologyNodeKind, ReactNode> = {
  subnet: <Network size={14} aria-hidden />,
  router: <Route size={14} aria-hidden />,
  firewall: <Flame size={14} aria-hidden />,
  server: <Server size={14} aria-hidden />,
  workstation: <Monitor size={14} aria-hidden />,
  identity: <Fingerprint size={14} aria-hidden />,
  'security-tool': <Shield size={14} aria-hidden />,
  scoring: <Trophy size={14} aria-hidden />,
  gateway: <KeyRound size={14} aria-hidden />,
  database: <Database size={14} aria-hidden />,
  web: <Globe size={14} aria-hidden />,
  'vulnerable-app': <Bug size={14} aria-hidden />,
}

type CanvasNode = Node<{ topo: TopologyNode; teamColor?: string }, 'secp'>

function SecpNode({ data, selected }: NodeProps<CanvasNode>) {
  const { topo, teamColor } = data
  return (
    <div
      className={clsx('c-topo-node', `is-${topo.status}`, selected && 'is-selected')}
      style={teamColor ? ({ ['--team' as string]: teamColor } as React.CSSProperties) : undefined}
    >
      <span className="c-topo-node__icon">{KIND_ICON[topo.kind] ?? <Crosshair size={14} />}</span>
      <span className="c-topo-node__text">
        <strong>{topo.label}</strong>
        <span className="u-mono u-xs u-muted">{topo.ip ?? topo.subnet ?? topo.kind}</span>
      </span>
    </div>
  )
}

const nodeTypes = { secp: SecpNode }

export interface TopologyCanvasProps {
  graph: TopologyGraph
  onSelectNode?: (node: TopologyNode | undefined) => void
  selectedNodeId?: string
  teamColors?: Record<string, string>
  height?: number | string
  /** Hide attack-path/monitoring overlays (conceptual views). */
  visibleEdgeKinds?: Array<'link' | 'route' | 'attack-path' | 'monitoring'>
}

/**
 * Replaceable slot: topology canvas.
 *
 * Read-only React Flow wrapper over hand-positioned mock graphs. The
 * production builder is expected to reuse the source repo's topology
 * workspace core (reducer + ELK auto-layout); this draft only establishes
 * the canvas frame, node language, and inspector wiring.
 */
export function TopologyCanvas({
  graph,
  onSelectNode,
  selectedNodeId,
  teamColors = {},
  height = 520,
  visibleEdgeKinds,
}: TopologyCanvasProps) {
  const nodes: CanvasNode[] = useMemo(
    () =>
      graph.nodes.map((n) => ({
        id: n.id,
        type: 'secp' as const,
        position: { x: n.x, y: n.y },
        selected: n.id === selectedNodeId,
        data: { topo: n, teamColor: n.teamId ? teamColors[n.teamId] : undefined },
      })),
    [graph.nodes, selectedNodeId, teamColors],
  )

  const edges: Edge[] = useMemo(
    () =>
      graph.edges
        .filter((e) => !visibleEdgeKinds || visibleEdgeKinds.includes(e.kind))
        .map((e) => ({
          id: e.id,
          source: e.source,
          target: e.target,
          label: e.label,
          className: `c-topo-edge c-topo-edge--${e.kind}`,
          // Edges are never animated: this is a plan/state preview, not
          // observed traffic (rule carried over from the source repo).
          animated: false,
        })),
    [graph.edges, visibleEdgeKinds],
  )

  return (
    <div className="c-topo" style={{ height }}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        fitView
        minZoom={0.2}
        maxZoom={2}
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable
        onNodeClick={(_, node) => onSelectNode?.((node as CanvasNode).data.topo)}
        onPaneClick={() => onSelectNode?.(undefined)}
        proOptions={{ hideAttribution: true }}
      >
        <Background gap={22} size={1} />
        <Controls showInteractive={false} />
        <MiniMap pannable zoomable className="c-topo__minimap" />
      </ReactFlow>
    </div>
  )
}

export function TopologyLegend() {
  return (
    <div className="c-topo-legend" aria-label="Topology legend">
      <span className="c-topo-legend__item">
        <span className="c-topo-legend__line is-link" aria-hidden /> link
      </span>
      <span className="c-topo-legend__item">
        <span className="c-topo-legend__line is-route" aria-hidden /> route
      </span>
      <span className="c-topo-legend__item">
        <span className="c-topo-legend__line is-attack-path" aria-hidden /> attack path (dormant)
      </span>
      <span className="c-topo-legend__item">
        <span className="c-topo-legend__line is-monitoring" aria-hidden /> monitoring
      </span>
    </div>
  )
}
