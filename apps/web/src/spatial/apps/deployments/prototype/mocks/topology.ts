import type { TopologyGraph, TopologyNode, TopologyEdge } from '../models/types'

/**
 * Mock topology graphs (fixture-only). Positions are hand-placed for the
 * draft; the production builder is expected to reuse ELK auto-layout.
 */

const auroraTeams = [
  { key: 'crimson', label: 'Crimson', index: 1 },
  { key: 'cobalt', label: 'Cobalt', index: 2 },
  { key: 'amber', label: 'Amber', index: 3 },
  { key: 'emerald', label: 'Emerald', index: 4 },
  { key: 'violet', label: 'Violet', index: 5 },
  { key: 'slate', label: 'Slate', index: 6 },
]

function auroraGraph(): TopologyGraph {
  const nodes: TopologyNode[] = [
    {
      id: 'wg-gateway',
      label: 'WireGuard Gateway',
      kind: 'gateway',
      ip: '10.0.10.5',
      subnet: '10.0.10.0/24',
      status: 'degraded',
      x: 560,
      y: 40,
      meta: { role: 'Participant access hub' },
    },
    {
      id: 'core-fw',
      label: 'Core Firewall',
      kind: 'firewall',
      ip: '10.0.10.2',
      subnet: '10.0.10.0/24',
      status: 'healthy',
      x: 560,
      y: 160,
      meta: { role: 'Phase policy enforcement' },
    },
    {
      id: 'core-router',
      label: 'Core Router',
      kind: 'router',
      ip: '10.0.10.1',
      subnet: '10.0.10.0/24',
      status: 'healthy',
      x: 560,
      y: 280,
      meta: { role: 'Inter-zone routing' },
    },
    {
      id: 'wazuh',
      label: 'Wazuh Manager',
      kind: 'security-tool',
      ip: '10.0.10.20',
      subnet: '10.0.10.0/24',
      status: 'healthy',
      x: 860,
      y: 160,
      meta: { role: 'Monitoring · 30 agents' },
    },
    {
      id: 'scoring',
      label: 'Scoring Service',
      kind: 'scoring',
      ip: 'aws:172.31.4.10',
      status: 'degraded',
      x: 260,
      y: 160,
      meta: { role: 'Scoreboard + availability checks', placement: 'AWS us-west-2' },
    },
  ]
  const edges: TopologyEdge[] = [
    { id: 'e-gw-fw', source: 'wg-gateway', target: 'core-fw', kind: 'link' },
    { id: 'e-fw-router', source: 'core-fw', target: 'core-router', kind: 'link' },
    { id: 'e-fw-wazuh', source: 'core-fw', target: 'wazuh', kind: 'link' },
    {
      id: 'e-fw-scoring',
      source: 'core-fw',
      target: 'scoring',
      kind: 'link',
      label: 'cross-provider',
    },
  ]

  auroraTeams.forEach((team, i) => {
    const col = i % 3
    const row = Math.floor(i / 3)
    const baseX = 150 + col * 400
    const baseY = 430 + row * 260
    const octet = 10 + team.index
    const subnetId = `subnet-${team.key}`
    nodes.push(
      {
        id: subnetId,
        label: `${team.label} Zone`,
        kind: 'subnet',
        subnet: `10.${octet}.0.0/24`,
        teamId: `team-${team.key}`,
        status: team.key === 'violet' ? 'degraded' : 'healthy',
        x: baseX,
        y: baseY,
      },
      {
        id: `dc-${team.key}`,
        label: `dc-${team.index}`,
        kind: 'identity',
        ip: `10.${octet}.0.10`,
        teamId: `team-${team.key}`,
        status: 'healthy',
        x: baseX - 110,
        y: baseY + 110,
        meta: { os: 'Windows Server 2022', role: 'AD DS' },
      },
      {
        id: `web-${team.key}`,
        label: `web-${team.index}`,
        kind: 'web',
        ip: `10.${octet}.0.20`,
        teamId: `team-${team.key}`,
        status: team.key === 'violet' ? 'degraded' : 'healthy',
        x: baseX + 10,
        y: baseY + 110,
        meta: { os: 'Ubuntu 24.04', role: 'DMZ web' },
      },
      {
        id: `kali-${team.key}`,
        label: `kali-${team.index}`,
        kind: 'workstation',
        ip: `10.${octet}.0.50`,
        teamId: `team-${team.key}`,
        status: 'healthy',
        x: baseX + 130,
        y: baseY + 110,
        meta: { os: 'Kali 2026.2', role: 'Attack workstation' },
      },
    )
    edges.push(
      { id: `e-router-${team.key}`, source: 'core-router', target: subnetId, kind: 'route' },
      { id: `e-${team.key}-dc`, source: subnetId, target: `dc-${team.key}`, kind: 'link' },
      { id: `e-${team.key}-web`, source: subnetId, target: `web-${team.key}`, kind: 'link' },
      { id: `e-${team.key}-kali`, source: subnetId, target: `kali-${team.key}`, kind: 'link' },
      { id: `e-wazuh-${team.key}`, source: 'wazuh', target: subnetId, kind: 'monitoring' },
    )
  })

  // Dormant attack paths (activate in attack phase) — representative pair only.
  edges.push(
    {
      id: 'ap-crimson-cobalt',
      source: 'kali-crimson',
      target: 'web-cobalt',
      kind: 'attack-path',
      label: 'attack phase only',
    },
    {
      id: 'ap-emerald-violet',
      source: 'kali-emerald',
      target: 'web-violet',
      kind: 'attack-path',
      label: 'attack phase only',
    },
  )

  return { nodes, edges }
}

const web101Graph: TopologyGraph = {
  nodes: [
    {
      id: 'w101-gw',
      label: 'Access Gateway',
      kind: 'gateway',
      ip: '10.80.0.1',
      status: 'unknown',
      x: 420,
      y: 40,
    },
    {
      id: 'w101-net',
      label: 'Lab Network',
      kind: 'subnet',
      subnet: '10.80.1.0/24',
      status: 'unknown',
      x: 420,
      y: 180,
    },
    {
      id: 'w101-web',
      label: 'vuln-web',
      kind: 'vulnerable-app',
      ip: '10.80.1.10',
      status: 'unknown',
      x: 260,
      y: 320,
      meta: { packs: 'weak-ssh, outdated-cms' },
    },
    {
      id: 'w101-db',
      label: 'db',
      kind: 'database',
      ip: '10.80.1.20',
      status: 'unknown',
      x: 420,
      y: 320,
    },
    {
      id: 'w101-kali',
      label: 'student-kali',
      kind: 'workstation',
      ip: '10.80.1.50',
      status: 'unknown',
      x: 580,
      y: 320,
    },
  ],
  edges: [
    { id: 'w101-e1', source: 'w101-gw', target: 'w101-net', kind: 'link' },
    { id: 'w101-e2', source: 'w101-net', target: 'w101-web', kind: 'link' },
    { id: 'w101-e3', source: 'w101-net', target: 'w101-db', kind: 'link' },
    { id: 'w101-e4', source: 'w101-net', target: 'w101-kali', kind: 'link' },
    {
      id: 'w101-ap',
      source: 'w101-kali',
      target: 'w101-web',
      kind: 'attack-path',
      label: 'objective',
    },
  ],
}

export const topologies: Record<string, TopologyGraph> = {
  'scn-aurora': auroraGraph(),
  'scn-web101': web101Graph,
  'dep-aurora-teams': auroraGraph(),
  'dep-web101-stage': web101Graph,
}
