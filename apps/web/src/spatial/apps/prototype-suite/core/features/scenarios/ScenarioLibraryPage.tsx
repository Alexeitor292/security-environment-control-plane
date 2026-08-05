import { useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Plus } from 'lucide-react'
import {
  Button,
  CapabilityNotice,
  Card,
  CardGrid,
  EmptyState,
  ErrorState,
  FilterBar,
  FilterSelect,
  KeyValueGrid,
  LoadingState,
  PageHeader,
  ProviderBadge,
  SearchField,
  StatusBadge,
} from '../../components'
import type { StatusTone } from '../../components'
import { useQuery } from '../../integrations/AdapterContext'
import type { Scenario, ScenarioDifficulty } from '../../models/types'

const DIFFICULTY_TONE: Record<ScenarioDifficulty, StatusTone> = {
  intro: 'ok',
  intermediate: 'info',
  advanced: 'warn',
  expert: 'error',
}

function ScenarioCard({ scenario }: { scenario: Scenario }) {
  return (
    <Card
      heading={<Link to={`/scenarios/${scenario.id}`}>{scenario.name}</Link>}
      actions={
        <>
          <StatusBadge state={scenario.difficulty} tone={DIFFICULTY_TONE[scenario.difficulty]} />
          <StatusBadge state={scenario.validation} />
        </>
      }
    >
      <div className="u-grid" style={{ gap: 'var(--sp-3)' }}>
        <p className="u-secondary u-small" style={{ margin: 0 }}>
          {scenario.purpose}
        </p>
        <KeyValueGrid
          columns={3}
          items={[
            { key: 'Teams', value: `${scenario.teamRange[0]}–${scenario.teamRange[1]}` },
            {
              key: 'Resources',
              value: `${scenario.estimatedResources.vms} VM · ${scenario.estimatedResources.containers} CT · ${scenario.estimatedResources.networks} net`,
            },
            { key: 'Est. cost', value: `$${scenario.estimatedCostPerHour.toFixed(2)}/h` },
            { key: 'Version', value: `v${scenario.currentVersion}`, mono: true },
            { key: 'Updated', value: scenario.updatedAt.slice(0, 10), mono: true },
            {
              key: 'Providers',
              value: (
                <span className="u-row" style={{ flexWrap: 'wrap' }}>
                  {scenario.supportedProviders.map((p) => (
                    <ProviderBadge key={p} provider={p} />
                  ))}
                </span>
              ),
            },
          ]}
        />
        <p className="u-muted u-xs u-mono" style={{ margin: 0 }}>
          plugins: {scenario.requiredPlugins.join(' · ')}
        </p>
        <p className="u-muted u-xs" style={{ margin: 0 }}>
          {scenario.tags.map((t) => `#${t}`).join('  ')}
        </p>
      </div>
    </Card>
  )
}

export default function ScenarioLibraryPage() {
  const navigate = useNavigate()
  const scenariosQ = useQuery((a) => a.listScenarios())
  const [difficulty, setDifficulty] = useState('all')
  const [provider, setProvider] = useState('all')
  const [search, setSearch] = useState('')

  const filtered = useMemo(() => {
    let list = scenariosQ.data ?? []
    if (difficulty !== 'all') list = list.filter((s) => s.difficulty === difficulty)
    if (provider !== 'all')
      list = list.filter((s) => s.supportedProviders.some((p) => p === provider))
    if (search.trim()) {
      const q = search.toLowerCase()
      list = list.filter(
        (s) =>
          s.name.toLowerCase().includes(q) ||
          s.purpose.toLowerCase().includes(q) ||
          s.tags.some((t) => t.toLowerCase().includes(q)),
      )
    }
    return list
  }, [scenariosQ.data, difficulty, provider, search])

  if (scenariosQ.loading) {
    return (
      <div className="u-page">
        <LoadingState lines={6} />
      </div>
    )
  }
  if (scenariosQ.error || !scenariosQ.data) {
    return (
      <div className="u-page">
        <ErrorState message={scenariosQ.error ?? 'Mock data unavailable.'} />
      </div>
    )
  }

  return (
    <div className="u-page">
      <PageHeader
        title="Scenarios"
        capabilityStatus="implemented"
        description="Reusable environment blueprints. Scenarios are real in the platform today as Environment Templates with immutable, content-hashed versions (execution is simulated)."
        actions={
          <Button
            variant="primary"
            icon={<Plus size={14} aria-hidden />}
            onClick={() => navigate('/scenarios/new')}
          >
            New scenario
          </Button>
        }
      />
      <CapabilityNotice capKey="scenarios.library" />

      <FilterBar>
        <FilterSelect
          label="Difficulty"
          value={difficulty}
          onChange={setDifficulty}
          options={[
            { value: 'all', label: 'All levels' },
            { value: 'intro', label: 'Intro' },
            { value: 'intermediate', label: 'Intermediate' },
            { value: 'advanced', label: 'Advanced' },
            { value: 'expert', label: 'Expert' },
          ]}
        />
        <FilterSelect
          label="Provider"
          value={provider}
          onChange={setProvider}
          options={[
            { value: 'all', label: 'All providers' },
            { value: 'proxmox', label: 'Proxmox' },
            { value: 'aws', label: 'AWS' },
            { value: 'azure', label: 'Azure' },
            { value: 'gcp', label: 'GCP' },
            { value: 'kubernetes', label: 'Kubernetes' },
            { value: 'vmware', label: 'VMware' },
          ]}
        />
        <SearchField value={search} onChange={setSearch} placeholder="Search name, purpose, tag…" />
      </FilterBar>

      {filtered.length === 0 ? (
        <EmptyState
          title="No scenarios match"
          body="Adjust the filters above, or create a new scenario."
        />
      ) : (
        <CardGrid min={360}>
          {filtered.map((s) => (
            <ScenarioCard key={s.id} scenario={s} />
          ))}
        </CardGrid>
      )}
    </div>
  )
}
