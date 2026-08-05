import React from "react";
import ReactDOM from "react-dom/client";
import { RouterProvider, createBrowserRouter } from "react-router-dom";

import { App } from "./App";
import { AuthBoundary } from "./auth/AuthBoundary";
import { AuthCallback } from "./auth/AuthCallback";
import { AuthProvider } from "./auth/AuthProvider";
import { Approvals } from "./pages/Approvals";
import { AuditLog } from "./pages/AuditLog";
import { Dashboard } from "./pages/Dashboard";
import { DefinitionEditor } from "./pages/DefinitionEditor";
import { EnrollmentInventory } from "./pages/EnrollmentInventory";
import { EnvironmentPublication } from "./pages/EnvironmentPublication";
import { ExerciseDetail } from "./pages/ExerciseDetail";
import { Exercises } from "./pages/Exercises";
import { Login } from "./pages/Login";
import { OnboardingWizard } from "./pages/OnboardingWizard";
import { PlanApproval } from "./pages/PlanApproval";
import { ProviderTargets } from "./pages/ProviderTargets";
import { CompetitionControl } from "./pages/range/CompetitionControl";
import { CreateRange } from "./pages/range/CreateRange";
import { DeploymentProgress } from "./pages/range/DeploymentProgress";
import { RangeCatalog } from "./pages/range/RangeCatalog";
import { RangeLayout } from "./pages/range/RangeLayout";
import { RangeLifecycleActions } from "./pages/range/RangeLifecycleActions";
import { RangeOverview } from "./pages/range/RangeOverview";
import { RangeTimeline } from "./pages/range/RangeTimeline";
import { Scoreboard } from "./pages/range/Scoreboard";
import { TeamManagement } from "./pages/range/TeamManagement";
import { ReadOnlyBootstrap } from "./pages/ReadOnlyBootstrap";
import { ReadonlyPreflight } from "./pages/ReadonlyPreflight";
import { ResolverActivation } from "./pages/ResolverActivation";
import { StagingDeployment } from "./pages/StagingDeployment";
import { StagingLab } from "./pages/StagingLab";
import { TargetDiscovery } from "./pages/TargetDiscovery";
import { Templates } from "./pages/Templates";
import { WorkerEnrollment } from "./pages/WorkerEnrollment";
// The topology workspace (with the React Flow + ELK runtime) is code-split so
// the heavy canvas libraries load only when the workspace route is opened.
const TopologyView = React.lazy(() =>
  import("./pages/TopologyView").then((m) => ({ default: m.TopologyView })),
);
import "./design/tokens.css";
import "./styles.css";

const router = createBrowserRouter([
  // Public auth routes (ADR-018 / OIDC-B) render outside the protected shell.
  { path: "/login", element: <Login /> },
  { path: "/auth/callback", element: <AuthCallback /> },
  {
    path: "/",
    // Every application route is guarded: protected content renders only once authenticated.
    element: (
      <AuthBoundary>
        <App />
      </AuthBoundary>
    ),
    children: [
      { index: true, element: <Dashboard /> },
      { path: "templates", element: <Templates /> },
      { path: "templates/new", element: <DefinitionEditor /> },
      // ADR-016 PR D: contextual publication workflow. Entered from an approved topology document
      // (only the document id is authoritative from the URL); no global nav item.
      { path: "environment-publication/:documentId", element: <EnvironmentPublication /> },
      { path: "exercises", element: <Exercises /> },
      { path: "exercises/:exerciseId", element: <ExerciseDetail /> },
      { path: "exercises/:exerciseId/plan", element: <PlanApproval /> },
      {
        path: "exercises/:exerciseId/topology",
        element: (
          <React.Suspense fallback={<p className="muted">Loading workspace…</p>}>
            <TopologyView />
          </React.Suspense>
        ),
      },
      // RANGE surfaces. `/ranges/new` is declared BEFORE `/ranges/:rangeId` so the literal wins:
      // react-router ranks static segments above dynamic ones, but the explicit ordering also
      // documents the intent for anyone adding a sibling route later.
      { path: "ranges", element: <RangeCatalog /> },
      { path: "ranges/new", element: <CreateRange /> },
      {
        // One layout owns the range load and the lifecycle poll for all seven single-range tabs,
        // so the phase badge advances no matter which tab is open.
        path: "ranges/:rangeId",
        element: <RangeLayout />,
        children: [
          { index: true, element: <RangeOverview /> },
          { path: "deployment", element: <DeploymentProgress /> },
          { path: "competition", element: <CompetitionControl /> },
          { path: "teams", element: <TeamManagement /> },
          { path: "scoreboard", element: <Scoreboard /> },
          { path: "timeline", element: <RangeTimeline /> },
          { path: "lifecycle", element: <RangeLifecycleActions /> },
        ],
      },
      { path: "provider-targets", element: <ProviderTargets /> },
      { path: "onboarding", element: <OnboardingWizard /> },
      { path: "staging-labs", element: <StagingLab /> },
      { path: "staging-deployments", element: <StagingDeployment /> },
      { path: "read-only-bootstrap", element: <ReadOnlyBootstrap /> },
      { path: "target-discovery", element: <TargetDiscovery /> },
      { path: "readonly-preflight", element: <ReadonlyPreflight /> },
      { path: "resolver-activation", element: <ResolverActivation /> },
      { path: "approvals", element: <Approvals /> },
      // SECP-PR5H-B1: the supported worker-enrollment controller surface, split across two routes
      // because they are two different jobs with two different permissions.
      //
      // `worker-enrollment` is the create-and-hand-over surface: it needs enrollment:manage to be
      // useful, and its sidebar entry is gated on read OR manage — ANY rather than ALL is
      // load-bearing, because manage without read can still run the entire hand-off flow.
      //
      // `enrollment-inventory` is the organization-wide read, built on the list route. It is gated
      // on enrollment:read alone, since that is exactly what the list requires and manage does not
      // include it.
      { path: "worker-enrollment", element: <WorkerEnrollment /> },
      { path: "enrollment-inventory", element: <EnrollmentInventory /> },
      { path: "audit", element: <AuditLog /> },
    ],
  },
]);

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <AuthProvider>
      <RouterProvider router={router} />
    </AuthProvider>
  </React.StrictMode>,
);
