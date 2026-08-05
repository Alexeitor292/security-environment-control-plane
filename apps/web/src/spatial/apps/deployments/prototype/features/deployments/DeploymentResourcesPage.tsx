import type { ReactNode } from 'react'
import { useMemo, useState } from 'react'
import { Box, Flame, HardDrive, KeyRound, Network, Server, Shield, Trophy } from 'lucide-react'
import {
  AccordionSection,
  Button,
  CapabilityTag,
  DataTable,
  Drawer,
  FilterBar,
  FilterSelect,
  KeyValueGrid,
  SearchField,
  StatusBadge,
} from '../../components'
import type { Column } from '../../components'
import { useQuery } from '../../integrations/AdapterContext'
import { useDeploymentWorkspace } from '../../layouts/DeploymentWorkspaceLayout'
import type { DeploymentResource, ResourceKind } from '../../models/types'

const KIND_ICON: Record<ResourceKind, ReactNode> = {
  vm: <Server size={13} aria-hidden />,
  container: <Box size={13} aria-hidden />,
  network: <Network size={13} aria-hidden />,
  firewall: <Flame size={13} aria-hidden />,
  storage: <HardDrive size={13} aria-hidden />,
  gateway: <KeyRound size={13} aria-hidden />,
  'security-tool': <Shield size={13} aria-hidden />,
  'scoring-service': <Trophy size={13} aria-hidden />,
}

export default function DeploymentResourcesPage() {
  const { deployment } = useDeploymentWorkspace()
  const teamsQ = useQuery((a) => a.listTeams())

  const [kind, setKind] = useState('all')
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<DeploymentResource | undefined>()

  const teamName = (teamId?: string) => (teamsQ.data ?? []).find((t) => t.id === teamId)?.name

  const presentKinds = useMemo(
    () => [...new Set(deployment.resources.map((r) => r.kind))],
    [deployment.resources],
  )

  const filtered = useMemo(() => {
    let list = deployment.resources
    if (kind !== 'all') list = list.filter((r) => r.kind === kind)
    if (search.trim()) {
      const q = search.toLowerCase()
      list = list.filter(
        (r) =>
          r.name.toLowerCase().includes(q) ||
          r.providerRef.toLowerCase().includes(q) ||
          (r.ip ?? '').toLowerCase().includes(q) ||
          (r.detail ?? '').toLowerCase().includes(q),
      )
    }
    return list
  }, [deployment.resources, kind, search])

  const columns: Column<DeploymentResource>[] = [
    {
      key: 'name',
      header: 'Name',
      render: (r) => <span className="u-mono u-small">{r.name}</span>,
    },
    {
      key: 'kind',
      header: 'Kind',
      render: (r) => (
        <span className="u-row u-small">
          {KIND_ICON[r.kind]}
          {r.kind.replace(/-/g, ' ')}
        </span>
      ),
    },
    {
      key: 'ip',
      header: 'Address',
      render: (r) => <span className="u-mono u-xs">{r.ip ?? '—'}</span>,
    },
    {
      key: 'ref',
      header: 'Provider ref',
      render: (r) => <span className="u-mono u-xs">{r.providerRef}</span>,
    },
    { key: 'health', header: 'Health', render: (r) => <StatusBadge state={r.health} /> },
    {
      key: 'team',
      header: 'Team',
      render: (r) => <span className="u-small">{teamName(r.teamId) ?? '—'}</span>,
    },
    {
      key: 'detail',
      header: 'Detail',
      render: (r) => <span className="u-secondary u-xs">{r.detail ?? ''}</span>,
    },
  ]

  return (
    <div className="u-page">
      <FilterBar>
        <FilterSelect
          label="Kind"
          value={kind}
          onChange={setKind}
          options={[
            { value: 'all', label: `All kinds (${deployment.resources.length})` },
            ...presentKinds.map((k) => ({ value: k, label: k.replace(/-/g, ' ') })),
          ]}
        />
        <SearchField value={search} onChange={setSearch} placeholder="Search name, ref, address…" />
      </FilterBar>

      <DataTable
        columns={columns}
        rows={filtered}
        rowKey={(r) => r.id}
        onRowClick={setSelected}
        selectedKey={selected?.id}
        label="Deployment resources"
        emptyTitle={
          deployment.resources.length === 0 ? 'No realized resources' : 'No resources match'
        }
        emptyBody={
          deployment.resources.length === 0
            ? 'This deployment is plan-only — nothing has been provisioned.'
            : 'Adjust the kind filter or search above.'
        }
      />

      <Drawer
        open={Boolean(selected)}
        title={selected ? selected.name : ''}
        onClose={() => setSelected(undefined)}
      >
        {selected && (
          <>
            <div className="u-spread" style={{ marginBottom: 'var(--sp-2)' }}>
              <StatusBadge state={selected.health} />
              <span className="u-muted u-xs u-mono">{selected.id}</span>
            </div>
            <KeyValueGrid
              columns={1}
              items={[
                {
                  key: 'Kind',
                  value: (
                    <span className="u-row u-small">
                      {KIND_ICON[selected.kind]}
                      {selected.kind.replace(/-/g, ' ')}
                    </span>
                  ),
                },
                ...(selected.ip ? [{ key: 'Address', value: selected.ip, mono: true }] : []),
                { key: 'Provider ref', value: selected.providerRef, mono: true },
                ...(selected.teamId
                  ? [{ key: 'Team', value: teamName(selected.teamId) ?? selected.teamId }]
                  : []),
                ...(selected.detail ? [{ key: 'Detail', value: selected.detail }] : []),
              ]}
            />

            <AccordionSection title="Console access" hint="planned">
              <p className="u-secondary u-small">
                Browser console / serial access to this resource is a proposed capability — no
                session broker exists today. <CapabilityTag status="planned" />
              </p>
              <Button
                size="sm"
                disabled
                title="Planned — no console broker exists in the platform today"
              >
                Open console
              </Button>
            </AccordionSection>
            <AccordionSection title="Snapshots" hint="planned">
              <p className="u-secondary u-small">
                Point-in-time snapshots and restore points would be listed here.{' '}
                <CapabilityTag status="planned" />
              </p>
              <Button size="sm" disabled title="Planned — snapshot lifecycle is not implemented">
                Create snapshot
              </Button>
            </AccordionSection>
          </>
        )}
      </Drawer>
    </div>
  )
}
