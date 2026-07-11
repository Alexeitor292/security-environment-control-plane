import React from "react";
import ReactDOM from "react-dom/client";
import { RouterProvider, createBrowserRouter } from "react-router-dom";

import { App } from "./App";
import { Approvals } from "./pages/Approvals";
import { AuditLog } from "./pages/AuditLog";
import { Dashboard } from "./pages/Dashboard";
import { DefinitionEditor } from "./pages/DefinitionEditor";
import { ExerciseDetail } from "./pages/ExerciseDetail";
import { Exercises } from "./pages/Exercises";
import { Login } from "./pages/Login";
import { OnboardingWizard } from "./pages/OnboardingWizard";
import { PlanApproval } from "./pages/PlanApproval";
import { ProviderTargets } from "./pages/ProviderTargets";
import { ReadOnlyBootstrap } from "./pages/ReadOnlyBootstrap";
import { ReadonlyPreflight } from "./pages/ReadonlyPreflight";
import { ResolverActivation } from "./pages/ResolverActivation";
import { StagingDeployment } from "./pages/StagingDeployment";
import { StagingLab } from "./pages/StagingLab";
import { TargetDiscovery } from "./pages/TargetDiscovery";
import { Templates } from "./pages/Templates";
// The topology workspace (with the React Flow + ELK runtime) is code-split so
// the heavy canvas libraries load only when the workspace route is opened.
const TopologyView = React.lazy(() =>
  import("./pages/TopologyView").then((m) => ({ default: m.TopologyView })),
);
import "./design/tokens.css";
import "./styles.css";

const router = createBrowserRouter([
  { path: "/login", element: <Login /> },
  {
    path: "/",
    element: <App />,
    children: [
      { index: true, element: <Dashboard /> },
      { path: "templates", element: <Templates /> },
      { path: "templates/new", element: <DefinitionEditor /> },
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
      { path: "provider-targets", element: <ProviderTargets /> },
      { path: "onboarding", element: <OnboardingWizard /> },
      { path: "staging-labs", element: <StagingLab /> },
      { path: "staging-deployments", element: <StagingDeployment /> },
      { path: "read-only-bootstrap", element: <ReadOnlyBootstrap /> },
      { path: "target-discovery", element: <TargetDiscovery /> },
      { path: "readonly-preflight", element: <ReadonlyPreflight /> },
      { path: "resolver-activation", element: <ResolverActivation /> },
      { path: "approvals", element: <Approvals /> },
      { path: "audit", element: <AuditLog /> },
    ],
  },
]);

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <RouterProvider router={router} />
  </React.StrictMode>,
);
