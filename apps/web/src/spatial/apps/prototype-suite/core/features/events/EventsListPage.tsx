import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Plus } from 'lucide-react'
import {
  Button,
  CapabilityNotice,
  CardGrid,
  ErrorState,
  FilterBar,
  FilterSelect,
  LoadingState,
  PageHeader,
  SearchField,
  Tabs,
} from '../../components'
import { useQuery } from '../../integrations/AdapterContext'
import type { EventStatus } from '../../models/types'
import { EventCard } from './EventCard'

const STATUS_TABS: { key: EventStatus | 'all'; label: string }[] = [
  { key: 'all', label: 'All' },
  { key: 'upcoming', label: 'Upcoming' },
  { key: 'active', label: 'Active' },
  { key: 'paused', label: 'Paused' },
  { key: 'completed', label: 'Completed' },
  { key: 'archived', label: 'Archived' },
]

export default function EventsListPage() {
  const navigate = useNavigate()
  const eventsQ = useQuery((a) => a.listEvents())
  const scenariosQ = useQuery((a) => a.listScenarios())
  const deploymentsQ = useQuery((a) => a.listDeployments())
  const [statusTab, setStatusTab] = useState<string>('all')
  const [typeFilter, setTypeFilter] = useState('all')
  const [search, setSearch] = useState('')

  const filtered = useMemo(() => {
    let list = eventsQ.data ?? []
    if (statusTab !== 'all') list = list.filter((e) => e.status === statusTab)
    if (typeFilter !== 'all') list = list.filter((e) => e.type === typeFilter)
    if (search.trim()) {
      const q = search.toLowerCase()
      list = list.filter(
        (e) => e.name.toLowerCase().includes(q) || e.description.toLowerCase().includes(q),
      )
    }
    return list
  }, [eventsQ.data, statusTab, typeFilter, search])

  if (eventsQ.loading) {
    return (
      <div className="u-page">
        <LoadingState lines={6} />
      </div>
    )
  }
  if (eventsQ.error || !eventsQ.data) {
    return (
      <div className="u-page">
        <ErrorState message={eventsQ.error ?? 'Mock data unavailable.'} />
      </div>
    )
  }

  return (
    <div className="u-page">
      <PageHeader
        title="Events"
        capabilityStatus="planned"
        description="Competitions, exercises, rehearsals, and validation runs. The Event concept is proposed product language over the repo's implemented (simulated) Exercise lifecycle."
        actions={
          <Button
            variant="primary"
            icon={<Plus size={14} aria-hidden />}
            onClick={() => navigate('/events/new')}
          >
            New event
          </Button>
        }
      />
      <CapabilityNotice capKey="events.model" />

      <Tabs
        tabs={STATUS_TABS.map((t) => ({ key: t.key, label: t.label }))}
        active={statusTab}
        onSelect={setStatusTab}
      />

      <FilterBar>
        <FilterSelect
          label="Type"
          value={typeFilter}
          onChange={setTypeFilter}
          options={[
            { value: 'all', label: 'All types' },
            { value: 'competition', label: 'Competition' },
            { value: 'training', label: 'Training' },
            { value: 'purple-team', label: 'Purple team' },
            { value: 'ir-rehearsal', label: 'IR rehearsal' },
            { value: 'demo', label: 'Demonstration' },
            { value: 'validation', label: 'Validation' },
          ]}
        />
        <SearchField value={search} onChange={setSearch} placeholder="Search events…" />
      </FilterBar>

      {filtered.length === 0 ? (
        <ErrorStateFallback statusTab={statusTab} />
      ) : (
        <CardGrid min={360}>
          {filtered.map((event) => (
            <EventCard
              key={event.id}
              event={event}
              scenario={scenariosQ.data?.find((s) => s.id === event.scenarioId)}
              deployments={(deploymentsQ.data ?? []).filter((d) => d.eventId === event.id)}
            />
          ))}
        </CardGrid>
      )}
    </div>
  )
}

function ErrorStateFallback({ statusTab }: { statusTab: string }) {
  return (
    <div className="c-state">
      <strong>No {statusTab === 'all' ? '' : statusTab + ' '}events match</strong>
      <p className="u-secondary u-small">Adjust the filters, or create a new event.</p>
    </div>
  )
}
