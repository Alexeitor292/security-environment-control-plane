import { Outlet, useOutletContext, useParams } from 'react-router-dom'
import { ProviderBadge, StatusBadge, WorkspaceTabs } from '../components'
import { ErrorState, LoadingState } from '../components/States'
import { useQuery } from '../integrations/AdapterContext'
import type { Deployment } from '../models/types'

export interface DeploymentWorkspaceContext {
  deployment: Deployment
}

export function useDeploymentWorkspace(): DeploymentWorkspaceContext {
  return useOutletContext<DeploymentWorkspaceContext>()
}

/** Replaceable slot: deployment workspace frame. */
export function DeploymentWorkspaceLayout() {
  const { deploymentId = '' } = useParams()
  const {
    data: deployment,
    loading,
    error,
  } = useQuery((a) => a.getDeployment(deploymentId), [deploymentId])

  if (loading)
    return (
      <div className="u-page">
        <LoadingState lines={4} />
      </div>
    )
  if (error || !deployment)
    return (
      <div className="u-page">
        <ErrorState message={error ?? `Deployment ${deploymentId} not found in mock data.`} />
      </div>
    )

  const base = `/deployments/${deployment.id}`

  return (
    <div className="l-workspace">
      <header className="l-workspace__head">
        <div className="u-row" style={{ flexWrap: 'wrap' }}>
          <h1 className="u-mono">{deployment.name}</h1>
          <StatusBadge state={deployment.state} />
          <StatusBadge state={deployment.health} />
          <ProviderBadge provider={deployment.provider} />
          <span className="u-muted u-small">{deployment.region}</span>
        </div>
        <WorkspaceTabs
          tabs={[
            { to: base, label: 'Summary', end: true },
            { to: `${base}/topology`, label: 'Topology' },
            { to: `${base}/resources`, label: 'Resources' },
            { to: `${base}/operations`, label: 'Operations' },
            { to: `${base}/monitoring`, label: 'Monitoring' },
            { to: `${base}/activity`, label: 'Activity' },
            { to: `${base}/advanced`, label: 'Advanced' },
          ]}
        />
      </header>
      <Outlet context={{ deployment } satisfies DeploymentWorkspaceContext} />
    </div>
  )
}
