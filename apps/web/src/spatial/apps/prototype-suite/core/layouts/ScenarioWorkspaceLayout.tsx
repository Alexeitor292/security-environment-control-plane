import { Outlet, useOutletContext, useParams } from 'react-router-dom'
import { StatusBadge, WorkspaceTabs } from '../components'
import { ErrorState, LoadingState } from '../components/States'
import { useQuery } from '../integrations/AdapterContext'
import type { Scenario } from '../models/types'

export interface ScenarioWorkspaceContext {
  scenario: Scenario
}

export function useScenarioWorkspace(): ScenarioWorkspaceContext {
  return useOutletContext<ScenarioWorkspaceContext>()
}

/** Replaceable slot: scenario workspace frame. */
export function ScenarioWorkspaceLayout() {
  const { scenarioId = '' } = useParams()
  const {
    data: scenario,
    loading,
    error,
  } = useQuery((a) => a.getScenario(scenarioId), [scenarioId])

  if (loading)
    return (
      <div className="u-page">
        <LoadingState lines={4} />
      </div>
    )
  if (error || !scenario)
    return (
      <div className="u-page">
        <ErrorState message={error ?? `Scenario ${scenarioId} not found in mock data.`} />
      </div>
    )

  const base = `/scenarios/${scenario.id}`

  return (
    <div className="l-workspace">
      <header className="l-workspace__head">
        <div className="u-row" style={{ flexWrap: 'wrap' }}>
          <h1>{scenario.name}</h1>
          <span className="u-mono u-small u-muted">v{scenario.currentVersion}</span>
          <StatusBadge state={scenario.validation} />
        </div>
        <WorkspaceTabs
          tabs={[
            { to: base, label: 'Overview', end: true },
            { to: `${base}/builder`, label: 'Builder' },
            { to: `${base}/versions`, label: 'Versions' },
            { to: `${base}/validation`, label: 'Validation' },
          ]}
        />
      </header>
      <Outlet context={{ scenario } satisfies ScenarioWorkspaceContext} />
    </div>
  )
}
