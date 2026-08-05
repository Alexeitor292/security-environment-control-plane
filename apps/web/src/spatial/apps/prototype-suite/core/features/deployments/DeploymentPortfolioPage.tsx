import { useMemo, useState } from 'react'
import {
  CapabilityNotice,
  CardGrid,
  EmptyState,
  ErrorState,
  FilterBar,
  FilterSelect,
  LoadingState,
  PageHeader,
  SearchField,
} from '../../components'
import { useQuery } from '../../integrations/AdapterContext'
import { DeploymentCard } from './DeploymentCard'

export default function DeploymentPortfolioPage() {
  const deploymentsQ = useQuery((a) => a.listDeployments())
  const eventsQ = useQuery((a) => a.listEvents())
  const scenariosQ = useQuery((a) => a.listScenarios())

  const [provider, setProvider] = useState('all')
  const [state, setState] = useState('all')
  const [eventFilter, setEventFilter] = useState('all')
  const [scenarioFilter, setScenarioFilter] = useState('all')
  const [search, setSearch] = useState('')

  const filtered = useMemo(() => {
    let list = deploymentsQ.data ?? []
    if (provider !== 'all') list = list.filter((d) => d.provider === provider)
    if (state !== 'all') list = list.filter((d) => d.state === state)
    if (eventFilter !== 'all')
      list = list.filter((d) => (eventFilter === 'none' ? !d.eventId : d.eventId === eventFilter))
    if (scenarioFilter !== 'all') list = list.filter((d) => d.scenarioId === scenarioFilter)
    if (search.trim()) {
      const q = search.toLowerCase()
      list = list.filter(
        (d) => d.name.toLowerCase().includes(q) || d.owner.toLowerCase().includes(q),
      )
    }
    return list
  }, [deploymentsQ.data, provider, state, eventFilter, scenarioFilter, search])

  if (deploymentsQ.loading) {
    return (
      <div className="u-page">
        <LoadingState lines={6} />
      </div>
    )
  }
  if (deploymentsQ.error || !deploymentsQ.data) {
    return (
      <div className="u-page">
        <ErrorState message={deploymentsQ.error ?? 'Mock data unavailable.'} />
      </div>
    )
  }

  return (
    <div className="u-page">
      <PageHeader
        title="Deployments"
        capabilityStatus="simulated"
        description="Running instances of immutable scenario versions. The platform's only complete lifecycle today is simulated; cloud rows are mock."
      />
      <CapabilityNotice capKey="deployments.lifecycle" />

      <FilterBar>
        <FilterSelect
          label="Provider"
          value={provider}
          onChange={setProvider}
          options={[
            { value: 'all', label: 'All providers' },
            { value: 'aws', label: 'AWS' },
            { value: 'azure', label: 'Azure' },
            { value: 'gcp', label: 'GCP' },
            { value: 'proxmox', label: 'Proxmox' },
            { value: 'kubernetes', label: 'Kubernetes' },
          ]}
        />
        <FilterSelect
          label="Lifecycle"
          value={state}
          onChange={setState}
          options={[
            { value: 'all', label: 'All states' },
            { value: 'planned', label: 'Planned' },
            { value: 'provisioning', label: 'Provisioning' },
            { value: 'running', label: 'Running' },
            { value: 'degraded', label: 'Degraded' },
            { value: 'failed', label: 'Failed' },
            { value: 'destroyed', label: 'Destroyed' },
          ]}
        />
        <FilterSelect
          label="Event"
          value={eventFilter}
          onChange={setEventFilter}
          options={[
            { value: 'all', label: 'All events' },
            { value: 'none', label: 'No event' },
            ...(eventsQ.data ?? []).map((e) => ({ value: e.id, label: e.name })),
          ]}
        />
        <FilterSelect
          label="Scenario"
          value={scenarioFilter}
          onChange={setScenarioFilter}
          options={[
            { value: 'all', label: 'All scenarios' },
            ...(scenariosQ.data ?? []).map((s) => ({ value: s.id, label: s.name })),
          ]}
        />
        <SearchField value={search} onChange={setSearch} placeholder="Search name or owner…" />
      </FilterBar>

      {filtered.length === 0 ? (
        <EmptyState title="No deployments match" body="Adjust the filters above." />
      ) : (
        <CardGrid min={340}>
          {filtered.map((d) => (
            <DeploymentCard
              key={d.id}
              deployment={d}
              event={(eventsQ.data ?? []).find((e) => e.id === d.eventId)}
              scenario={(scenariosQ.data ?? []).find((s) => s.id === d.scenarioId)}
            />
          ))}
        </CardGrid>
      )}
    </div>
  )
}
