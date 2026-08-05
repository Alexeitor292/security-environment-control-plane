import { MemoryRouter, Navigate, Route, Routes } from 'react-router-dom'
import { AppStateProvider } from './core/app/AppStateContext'
import { AdapterProvider } from './core/integrations/AdapterContext'
import { DeploymentWorkspaceLayout } from './core/layouts/DeploymentWorkspaceLayout'
import { EventWorkspaceLayout } from './core/layouts/EventWorkspaceLayout'
import { InfrastructureLayout, PlatformLayout } from './core/layouts/SectionLayout'
import { ScenarioWorkspaceLayout } from './core/layouts/ScenarioWorkspaceLayout'
import CommandCenterPage from './core/features/command-center/CommandCenterPage'
import DeploymentActivityPage from './core/features/deployments/DeploymentActivityPage'
import DeploymentAdvancedPage from './core/features/deployments/DeploymentAdvancedPage'
import DeploymentMonitoringPage from './core/features/deployments/DeploymentMonitoringPage'
import DeploymentOperationsPage from './core/features/deployments/DeploymentOperationsPage'
import DeploymentPortfolioPage from './core/features/deployments/DeploymentPortfolioPage'
import DeploymentResourcesPage from './core/features/deployments/DeploymentResourcesPage'
import DeploymentSummaryPage from './core/features/deployments/DeploymentSummaryPage'
import DeploymentTopologyPage from './core/features/deployments/DeploymentTopologyPage'
import ControlRoomPage from './core/features/events/ControlRoomPage'
import EventOperationsPage from './core/features/events/EventOperationsPage'
import EventOverviewPage from './core/features/events/EventOverviewPage'
import EventReportsPage from './core/features/events/EventReportsPage'
import EventScoringPage from './core/features/events/EventScoringPage'
import EventTopologyPage from './core/features/events/EventTopologyPage'
import EventsListPage from './core/features/events/EventsListPage'
import NewEventWizardPage from './core/features/events/NewEventWizardPage'
import TeamsAccessPage from './core/features/events/TeamsAccessPage'
import InventoryPage from './core/features/infrastructure/InventoryPage'
import PlacementPage from './core/features/infrastructure/PlacementPage'
import ProvidersPage from './core/features/infrastructure/ProvidersPage'
import TargetsPage from './core/features/infrastructure/TargetsPage'
import WorkersPage from './core/features/infrastructure/WorkersPage'
import AuditPage from './core/features/platform/AuditPage'
import IdentityPage from './core/features/platform/IdentityPage'
import IntegrationsPage from './core/features/platform/IntegrationsPage'
import OrganizationsPage from './core/features/platform/OrganizationsPage'
import PlatformOverviewPage from './core/features/platform/PlatformOverviewPage'
import RetentionPage from './core/features/platform/RetentionPage'
import PlatformSettingsPage from './core/features/platform/SettingsPage'
import WorkflowsPage from './core/features/platform/WorkflowsPage'
import ReportsPage from './core/features/reports/ReportsPage'
import NewScenarioPage from './core/features/scenarios/NewScenarioPage'
import ScenarioBuilderPage from './core/features/scenarios/ScenarioBuilderPage'
import ScenarioLibraryPage from './core/features/scenarios/ScenarioLibraryPage'
import ScenarioOverviewPage from './core/features/scenarios/ScenarioOverviewPage'
import ScenarioValidationPage from './core/features/scenarios/ScenarioValidationPage'
import ScenarioVersionsPage from './core/features/scenarios/ScenarioVersionsPage'
import './core/PrototypeSuite.css'

interface PrototypeSuiteAppProps {
  initialEntry: string
  onAddInfrastructure?: () => void
}

export function PrototypeSuiteApp({ initialEntry, onAddInfrastructure }: PrototypeSuiteAppProps) {
  return (
    <div
      className="secp-prototype-suite"
      data-appearance="dark"
      data-surface-style="glass"
      data-accent-theme="cyan"
    >
      <AppStateProvider>
        <AdapterProvider>
          <MemoryRouter initialEntries={[initialEntry]}>
            <Routes>
              <Route path="/" element={<CommandCenterPage />} />

              <Route path="/events" element={<EventsListPage />} />
              <Route path="/events/new" element={<NewEventWizardPage />} />
              <Route path="/events/:eventId" element={<EventWorkspaceLayout />}>
                <Route index element={<EventOverviewPage />} />
                <Route path="control-room" element={<ControlRoomPage />} />
                <Route path="topology" element={<EventTopologyPage />} />
                <Route path="teams" element={<TeamsAccessPage />} />
                <Route path="operations" element={<EventOperationsPage />} />
                <Route path="scoring" element={<EventScoringPage />} />
                <Route path="reports" element={<EventReportsPage />} />
              </Route>

              <Route path="/scenarios" element={<ScenarioLibraryPage />} />
              <Route path="/scenarios/new" element={<NewScenarioPage />} />
              <Route path="/scenarios/:scenarioId" element={<ScenarioWorkspaceLayout />}>
                <Route index element={<ScenarioOverviewPage />} />
                <Route path="builder" element={<ScenarioBuilderPage />} />
                <Route path="versions" element={<ScenarioVersionsPage />} />
                <Route path="validation" element={<ScenarioValidationPage />} />
              </Route>

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
                path="/infrastructure/enroll"
                element={<Navigate replace to="/infrastructure/targets" />}
              />
              <Route
                path="/infrastructure"
                element={<InfrastructureLayout onAddInfrastructure={onAddInfrastructure} />}
              >
                <Route index element={<Navigate replace to="/infrastructure/targets" />} />
                <Route path="targets" element={<TargetsPage />} />
                <Route path="placement" element={<PlacementPage />} />
                <Route path="workers" element={<WorkersPage />} />
                <Route path="providers" element={<ProvidersPage />} />
                <Route path="inventory" element={<InventoryPage />} />
              </Route>

              <Route path="/reports" element={<ReportsPage />} />

              <Route path="/platform" element={<PlatformLayout />}>
                <Route index element={<PlatformOverviewPage />} />
                <Route path="organizations" element={<OrganizationsPage />} />
                <Route path="identity" element={<IdentityPage />} />
                <Route path="workflows" element={<WorkflowsPage />} />
                <Route path="integrations" element={<IntegrationsPage />} />
                <Route path="audit" element={<AuditPage />} />
                <Route path="settings" element={<PlatformSettingsPage />} />
                <Route path="retention" element={<RetentionPage />} />
              </Route>

              <Route path="*" element={<Navigate replace to={initialEntry} />} />
            </Routes>
          </MemoryRouter>
        </AdapterProvider>
      </AppStateProvider>
    </div>
  )
}
