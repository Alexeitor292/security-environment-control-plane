import { Navigate, MemoryRouter, Route, Routes } from 'react-router-dom'
import { AppStateProvider } from './prototype/app/AppStateContext'
import { AdapterProvider } from './prototype/integrations/AdapterContext'
import { DeploymentWorkspaceLayout } from './prototype/layouts/DeploymentWorkspaceLayout'
import DeploymentPortfolioPage from './prototype/features/deployments/DeploymentPortfolioPage'
import DeploymentSummaryPage from './prototype/features/deployments/DeploymentSummaryPage'
import DeploymentTopologyPage from './prototype/features/deployments/DeploymentTopologyPage'
import DeploymentResourcesPage from './prototype/features/deployments/DeploymentResourcesPage'
import DeploymentOperationsPage from './prototype/features/deployments/DeploymentOperationsPage'
import DeploymentMonitoringPage from './prototype/features/deployments/DeploymentMonitoringPage'
import DeploymentActivityPage from './prototype/features/deployments/DeploymentActivityPage'
import DeploymentAdvancedPage from './prototype/features/deployments/DeploymentAdvancedPage'
import './DeploymentsApp.css'

function CrossApplicationRoute({ title }: { title: string }) {
  return (
    <div className="prototype-cross-route">
      <strong>{title}</strong>
      <span>This linked object belongs to another Spatial OS application.</span>
      <a href="/deployments">Return to Deployments</a>
    </div>
  )
}

export function DeploymentsApp({ initialEntry = '/deployments' }: { initialEntry?: string }) {
  return (
    <div className="secp-deployments-prototype">
      <AppStateProvider>
        <AdapterProvider>
          <MemoryRouter key={initialEntry} initialEntries={[initialEntry]}>
            <Routes>
              <Route path="/deployments" element={<DeploymentPortfolioPage />} />
              <Route path="/deployments/:deploymentId" element={<DeploymentWorkspaceLayout />}>
                <Route index element={<DeploymentSummaryPage />} />
                <Route path="topology" element={<DeploymentTopologyPage />} />
                <Route path="resources" element={<DeploymentResourcesPage />} />
                <Route path="operations" element={<DeploymentOperationsPage />} />
                <Route path="monitoring" element={<DeploymentMonitoringPage />} />
                <Route path="activity" element={<DeploymentActivityPage />} />
                <Route path="advanced" element={<DeploymentAdvancedPage />} />
              </Route>
              <Route
                path="/events/:eventId"
                element={<CrossApplicationRoute title="Cyber Range event" />}
              />
              <Route
                path="/scenarios/:scenarioId"
                element={<CrossApplicationRoute title="Scenario" />}
              />
              <Route path="*" element={<Navigate replace to="/deployments" />} />
            </Routes>
          </MemoryRouter>
        </AdapterProvider>
      </AppStateProvider>
    </div>
  )
}
