# Spatial frontend migration matrix

Route-by-route status of the spatial prototype migrated into `apps/web` (P7-C).

## How to read this, and how much to trust it

Every factual column here was produced by reading the migrated source or the
API source in this repository, not from recollection of either. Specifically:

| Column group | Derived from | Command class |
| --- | --- | --- |
| Route, page, components | The two `MemoryRouter` route tables in the migrated source | read of `PrototypeSuiteApp.tsx`, `DeploymentsApp.tsx` |
| Mock source, mock fields | `adapter.*` call sites per page | grep of `features/**/*Page.tsx` |
| Existing / missing endpoint | The **223 routes actually registered on the FastAPI app** | resolved `app.include_router(...)` in `apps/api/secp_api/main.py` back to each router module, then collected its decorators |
| States | Presence of `LoadingState` / `EmptyState` / `ErrorState` per page | grep per page file |

The endpoint column deserves the emphasis. It was built by walking
`include_router` calls and resolving each alias to its module, **not** by
grepping for route decorators across the tree. Those are different questions.
This repository has already been bitten by the difference: a backend module can
be merged, imported by tests and by the worker, fully green in CI, and still be
reachable by no HTTP client at all because nothing includes its router. A
decorator is not an endpoint. Only inclusion in the app is.

**What this document does not tell you.** It records what the migrated code
does today. It is not a claim that any screen is production-ready, and the
`API status` column is deliberately blunt about how much of this UI has no
backend at all.

---

## 0. The adapter surface — where the real gap is

All 33 data-bearing pages read through one interface, `ControlPlaneAdapter`
(22 methods). So the production-readiness question is not really 40 separate
questions; it is 22. This table is the load-bearing one, and the per-route
tables below inherit from it.

| Adapter method | Fixture source | Production resource | Registered endpoint today | Status |
| --- | --- | --- | --- | --- |
| `listTargets` | `mocks/infrastructure.ts` → `targets` | Provider targets | `GET /api/v1/targets` | **exact match** |
| `listAuditEvents` | `mocks/operations.ts` → `auditEvents` | Audit log | `GET /api/v1/audit` | **exact match** |
| `getTopology` | `mocks/topology.ts` → `topologies` | Topology graph | `GET /api/v1/exercises/{id}/topology`, `GET /api/v1/instances/{id}/topology`, `GET /api/v1/ranges/{id}/proxmox/topology` | **exists, shape differs** — three subject-specific routes vs. one `getTopology(subjectId)` |
| `listScores` | `mocks/governance.ts` → `scores` | Scoreboard | `GET /api/v1/ranges/{id}/scoreboard`, `GET /api/v1/competitions/{id}/scoreboard` | **exists, requires a range id** the prototype does not carry |
| `listTeams` | `mocks/events.ts` → `teams` | Teams | `GET /api/v1/ranges/{range_id}/teams` | **exists, scoped** — no org-wide team list |
| `listParticipants` | `mocks/events.ts` → `participants` | Team members | `GET /api/v1/ranges/{id}/teams/{team_id}/members` | **exists, doubly scoped** |
| `listWorkers` | `mocks/infrastructure.ts` → `workers` | Worker nodes | `GET /api/v1/target-discovery/read-only-bootstrap/worker-nodes`, `GET /api/v1/enrollment` | **exists, different model** — enrollment records, not a worker fleet view |
| `listEvents` / `getEvent` | `mocks/events.ts` → `events` | Ranges / exercises | `GET /api/v1/ranges`, `GET /api/v1/exercises` | **partial** — "event" is a prototype concept spanning both |
| `listDeployments` / `getDeployment` | `mocks/deployments.ts` | Deployments | `GET /api/v1/staging-deployments`, `GET /api/v1/exercises/{id}/instances` | **partial** — two different backend concepts |
| `listScenarios` / `getScenario` | `mocks/scenarios.ts` | Scenario library | `GET /api/v1/templates`, `GET /api/v1/templates/{id}/versions` | **partial** — templates+versions ≠ scenarios |
| `listWorkflowRuns` | `mocks/operations.ts` → `workflowRuns` | Operations | `GET /api/v1/ranges/{id}/operations`, `GET /api/v1/manifests/{id}/operations` | **partial, scoped** — no cross-cutting run list |
| `listIntegrations` | `mocks/infrastructure.ts` → `integrations` | Plugins | `GET /api/v1/plugins` | **partial** — plugin registry, not integration config |
| `listApprovals` | `mocks/operations.ts` → `approvals` | Pending approvals | *(none — approve/reject exist per-object; no list)* | **MISSING (list)** |
| `listAlerts` | `mocks/operations.ts` → `alerts` | Alerts | *(none)* | **MISSING** |
| `listEvidence` | `mocks/operations.ts` → `evidenceRecords` | Evidence | *(only `…/onboarding/{id}/evidence`, `…/ranges/{id}/teardown-evidence`)* | **MISSING (global list)** |
| `listReports` | `mocks/governance.ts` → `reports` | Reports | *(none)* | **MISSING** |
| `listUsers` | `mocks/governance.ts` → `users` | User accounts | *(only `GET /api/v1/me`)* | **MISSING** |
| `listSecretRefs` | `mocks/governance.ts` → `secretRefs` | Secret references | *(only plan-secret-*authorizations*)* | **MISSING** |
| `listAccessProfiles` | `mocks/events.ts` → `accessProfiles` | Access profiles | *(none)* | **MISSING** |

**Summary: 2 of 22 adapter methods map cleanly onto a registered endpoint.**
7 are missing outright; the remaining 13 have something adjacent that differs in
scope or model. Transport type status for all 22: **no generated client types
exist for the prototype's models** — `models/types.ts` is hand-written and
independent of `src/api/types.ts`. Reconciling the two is not in P7-C.

---

## 1. Routes — data and API status

The `prototype-suite` router (the app the shell mounts for Infrastructure,
Ranges, Scenarios, Reports and Platform) declares **42 `<Route path=…>`
entries** — 40 content paths, one redirect (`/infrastructure/enroll`) and the
catch-all — plus **5 `index` routes** that render a default child at a parent
path. The `deployments` sub-app declares 11 more with 1 index route. These
counts are pinned by `src/spatial/migration-completeness.test.ts`, so a route
disappearing is a test failure rather than a silent regression.

Adapter status is **fixture** for every row: the live adapter does not exist yet.

| Route | Page | Major components | Mock fields | Existing endpoint | Missing endpoint | API status |
| --- | --- | --- | --- | --- | --- | --- |
| `/` | CommandCenterPage | MetricTile, AlertsList, Card | events, scenarios, deployments, targets, teams, alerts, approvals | `/api/v1/targets` | alerts, approvals list | fixture |
| `/events` | EventsListPage | DataTable, FilterBar, PageHeader | events, scenarios, deployments | `/api/v1/ranges` | unified event list | partial |
| `/events/new` | NewEventWizardPage | Accordion, Button | scenarios | `/api/v1/templates` | — | partial |
| `/events/:eventId` | EventOverviewPage | KeyValueGrid, Timeline, MetricTile | teams, deployments, alerts, auditEvents | `/api/v1/ranges/{id}` | alerts | partial |
| `/events/:eventId/control-room` | ControlRoomPage | MetricTile, AlertsList, Timeline | teams, scores, alerts, deployments, workflowRuns | `/api/v1/ranges/{id}/scoreboard` | alerts | partial |
| `/events/:eventId/topology` | EventTopologyPage | TopologyCanvas (`@xyflow/react`) | topologies, teams | `/api/v1/ranges/{id}/proxmox/topology` | — | partial |
| `/events/:eventId/teams` | TeamsAccessPage | DataTable, Drawer | teams, participants, accessProfiles | `/api/v1/ranges/{id}/teams` | accessProfiles | partial |
| `/events/:eventId/operations` | EventOperationsPage | Timeline, DataTable | workflowRuns, approvals, evidence | `/api/v1/ranges/{id}/operations` | approvals list, evidence list | partial |
| `/events/:eventId/scoring` | EventScoringPage | DataTable, MetricTile | scores, teams | `/api/v1/ranges/{id}/scoreboard` | — | partial |
| `/events/:eventId/reports` | EventReportsPage | DataTable | reports | — | reports | **missing** |
| `/scenarios` | ScenarioLibraryPage | DataTable, FilterBar | scenarios | `/api/v1/templates` | — | partial |
| `/scenarios/new` | NewScenarioPage | form controls | *(none — local form state)* | `POST /api/v1/templates` | — | not wired |
| `/scenarios/:scenarioId` | ScenarioOverviewPage | KeyValueGrid, Card | events, deployments | `/api/v1/templates/{id}/versions` | — | partial |
| `/scenarios/:scenarioId/builder` | ScenarioBuilderPage | TopologyCanvas, ResourceInspector | topologies, teams | `/api/v1/topology-authoring/documents/{id}` | — | partial |
| `/scenarios/:scenarioId/versions` | ScenarioVersionsPage | DataTable | *(none — static)* | `/api/v1/templates/{id}/versions` | — | not wired |
| `/scenarios/:scenarioId/validation` | ScenarioValidationPage | Accordion | *(none — static)* | `POST /api/v1/definitions/validate` | — | not wired |
| `/deployments` | DeploymentPortfolioPage | DataTable, DeploymentCard, FilterBar | deployments, events, scenarios | `/api/v1/staging-deployments` | — | partial |
| `/deployments/:deploymentId` | DeploymentSummaryPage | KeyValueGrid, MetricTile | event, scenario, targets, alerts, workflowRuns | `/api/v1/staging-deployments/{id}` | alerts | partial |
| `/deployments/:deploymentId/topology` | DeploymentTopologyPage | TopologyCanvas | topologies, teams | `/api/v1/instances/{id}/topology` | — | partial |
| `/deployments/:deploymentId/resources` | DeploymentResourcesPage | DataTable, ResourceInspector | teams | `/api/v1/staging-deployments/{id}/resources` | — | partial |
| `/deployments/:deploymentId/operations` | DeploymentOperationsPage | Timeline | workflowRuns | `/api/v1/manifests/{id}/operations` | — | partial |
| `/deployments/:deploymentId/monitoring` | DeploymentMonitoringPage | MetricTile | *(none — static)* | — | metrics | **missing** |
| `/deployments/:deploymentId/activity` | DeploymentActivityPage | Timeline, DataTable | workflowRuns, auditEvents, evidence | `/api/v1/audit` | evidence list | partial |
| `/deployments/:deploymentId/advanced` | DeploymentAdvancedPage | AdvancedToggle, DangerousOperationDialog | targets, workers, secretRefs, evidence, workflowRuns | `/api/v1/targets` | secrets, evidence | partial |
| `/infrastructure` → `/targets` | *(redirect)* | — | — | — | — | n/a |
| `/infrastructure/enroll` → `/targets` | *(redirect)* | — | — | — | — | n/a |
| `/infrastructure/targets` | TargetsPage | DataTable, ProviderBadge, Drawer | targets, workers | **`GET /api/v1/targets`** | — | **wireable now** |
| `/infrastructure/placement` | PlacementPage | DataTable, KeyValueGrid | targets | `GET /api/v1/targets/{id}/reservations` | — | partial |
| `/infrastructure/workers` | WorkersPage | DataTable, StatusBadge | targets, workers | `/api/v1/enrollment` | fleet view | partial |
| `/infrastructure/providers` | ProvidersPage | DataTable, CapabilityNotice | integrations | `GET /api/v1/providers/capabilities` | — | partial — **see §4.1** |
| `/infrastructure/inventory` | InventoryPage | DataTable, FilterBar | targets, evidence | `/api/v1/targets/{id}/snapshots` | evidence list | partial |
| `/reports` | ReportsPage | DataTable, FilterBar | reports | — | reports | **missing** |
| `/platform` | PlatformOverviewPage | MetricTile, Card | users, workers, integrations, approvals | `/api/v1/plugins` | users, approvals | partial |
| `/platform/organizations` | OrganizationsPage | DataTable | users | — | organizations, users | **missing** |
| `/platform/identity` | IdentityPage | DataTable | users | `GET /api/v1/me` (self only) | user list | **missing** |
| `/platform/secrets` | SecretsPage | DataTable, StatusBadge | secretRefs | — | secrets | **missing** |
| `/platform/workflows` | WorkflowsPage | Timeline, DataTable | workflowRuns, workers | `/api/v1/ranges/{id}/operations` | cross-cutting runs | partial |
| `/platform/integrations` | IntegrationsPage | DataTable | integrations | `GET /api/v1/plugins` | — | partial |
| `/platform/audit` | AuditPage | DataTable, FilterBar | auditEvents, evidence | **`GET /api/v1/audit`** | evidence list | **wireable now** |
| `/platform/settings` | PlatformSettingsPage | form controls | *(none)* | — | — | not wired |
| `/platform/retention` | RetentionPage | Accordion | *(none — static)* | — | retention policy | **missing** |
| `*` | → redirect to entry | — | — | — | — | n/a |

The `deployments` sub-app router re-declares 8 of the deployment routes above
plus two cross-application stubs (`/events/:eventId`, `/scenarios/:scenarioId`
render a "belongs to another application" card). See §4.2.

---

## 2. Routes — states, authorization, testing

State columns record what the **migrated code actually implements**, which is
`loading`, `empty` and `error` and nothing else.

`unavailable`, `stale`, `refused`, `partial-observation` and
`recovery-required` are SECP backend concepts. They are **not modeled anywhere
in the migrated UI**. The words do occur in the tree, and it would be easy to
mistake that for coverage, so precisely:

- `unavailable` — occurs only inside the literal fallback string
  `'Mock data unavailable.'` passed to `ErrorState`. It is a message, not a state.
- `stale` — occurs **nowhere** in `prototype-suite/core`.
- `refused` — occurs only as hardcoded copy and a hardcoded union in
  `ProvidersPage` (§4.1).
- `recovery_required` — occurs once, in explanatory prose in `WorkflowsPage`.
- `partial-observation` — occurs nowhere.

Marking these "present" because the strings exist is exactly the mistake this
document is meant to prevent.

| Route group | loading | empty | error | unavailable / stale / refused / partial-obs / recovery-req | Authorization | Fixture labeling | Production wiring | Tests | Visual equivalence |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `/` command center | yes | no | yes | **none modeled** | **none** — no permission gate anywhere in the migrated tree | badge via `ProvenanceBoundary` | not wired | provenance only | not yet verified |
| `/events/*` (9 routes) | yes | 5 of 9 | 8 of 9 | **none modeled** | **none** | badge | not wired | provenance only | not yet verified |
| `/scenarios/*` (6) | 3 of 6 | 3 of 6 | 3 of 6 | **none modeled** | **none** | badge | not wired | provenance only | not yet verified |
| `/deployments/*` (8) | 6 of 8 | 2 of 8 | 2 of 8 | **none modeled** | **none** | badge | not wired | provenance only | not yet verified |
| `/infrastructure/*` (5) | yes | no | yes | **none modeled** | **none** | badge | not wired | provenance only | not yet verified |
| `/reports` | yes | no | yes | **none modeled** | **none** | badge | not wired | provenance only | not yet verified |
| `/platform/*` (9) | 7 of 9 | no | 7 of 9 | **none modeled** | **none** | badge | not wired | provenance only | not yet verified |

### Authorization is the largest single gap

The destination enforces permissions: `Sidebar` gates entries on the
principal's `permissions`, and the API declares a vocabulary including
`provisioning:manage`, `target:manage`, `topology:decide`,
`worker_identity:approve`, `readiness:approve` and others.

**The migrated prototype contains no authorization logic of any kind.** No
permission check, no capability gate, no principal-aware rendering. Every screen
renders every control for everyone — including `DangerousOperationDialog` on
`/deployments/:id/advanced`.

This is safe today only because nothing is wired to a mutating endpoint. It
stops being safe the moment any page is connected to a real one. Wiring a page
to production must therefore include its permission gate in the same change,
not as a follow-up.

---

## 3. Shell surfaces (not routed)

The shell switches applications via `useState<SecpAppId>`, not the router, so
these have no URL. Recorded for completeness of the "every donor surface
exists" check.

| Surface | Component | Data | Status |
| --- | --- | --- | --- |
| Home | `SecpHome`, `HomeAppGrid`, `HomeAppIcon` | `shellData.ts` (static) | migrated |
| Dock | `SystemDock` | `appRegistry.ts` | migrated |
| Notch / status | `DynamicIsland` | `shellData.ts` activities | migrated |
| Global search | `global-search/SpatialGlobalSearch` | `shellData.ts` | migrated |
| Widgets ×4 | AiSummary, Deployments, Discovery, EnvironmentHealth | static | migrated |
| Command menu | `ai-core/CommandMenuOverlay` | static | migrated |
| AI orb / prompt | `ai-core/AiCoreOrb`, `AiCoreButton`, `AiPromptBox`, `GradientOrb` | none | migrated |
| Enrollment scene | `scene/EnrollmentScene` + `CameraRig`, `DatacenterEnvironment`, `ServerLane`, `ServerRack` | GLB models | migrated |
| Container scene | `scene/containers/LocalContainerScene` | static | migrated |
| OS settings | `apps/settings/SettingsApp` | `localStorage` | migrated |
| Activity | `apps/activity/ActivityApp` | `shellData.ts` | migrated |
| Placeholder apps | `SecpAppHost` fallback | `appRegistry.ts` | migrated — renders "ready for implementation" for unmapped ids |

`appRegistry.ts` registers 7 apps; `SecpAppId` declares 15 ids. The 8 ids with
no registry entry (`environments`, `discovery`, `network-map`, `ai-operations`,
`evidence`, `integrations`, plus `home`/`activity`) either alias onto a
registered app in `SecpAppHost` or fall through to the placeholder card. That is
donor behaviour, migrated unchanged.

---

## 4. Findings that need a decision

### 4.1 `ProvidersPage` hardcodes security claims about Proxmox

`ProvidersPage.tsx` contains a static, hand-written capability table asserting
that for Proxmox every mutating operation — plan, apply, reset, destroy — is
`'refused'`, that discovery is GET-only, and that refusals are audited.

Nothing verifies any of that. It is frontend copy, not an observation, and it is
a claim about a security control. It is the same failure shape as the
"Simulated execution only — no real infrastructure" banner that stayed green in
tests for months after it became false.

It is also **actively becoming false**: other streams are building real Proxmox
plan, apply and destroy paths (`/api/v1/ranges/{id}/proxmox/apply-authorization`,
`…/destroy-plan`, `…/verification` are registered today). This table should be
driven from `GET /api/v1/providers/capabilities` — which exists — or removed.
It should not be migrated forward as prose. Flagged, not changed: rewriting it
is a product decision, and it is fixture-labelled in the meantime.

### 4.2 The deployments sub-app is a fork, not a duplicate

`apps/deployments/prototype/` and `apps/prototype-suite/core/` are two copies of
the same code: of 47 comparable files, **43 are byte-identical**, and 4 differ —
`components/index.ts`, `components/PopButton.tsx`,
`layouts/DeploymentWorkspaceLayout.tsx`, plus `components/pop-button.css` which
exists only in the deployments copy.

Both were migrated verbatim, because collapsing them is a behavioural change and
P7-C is a migration. The provenance work in P7-C.2 was applied to **both** and
shares one module, so the two cannot diverge on data honesty. Consolidation
should be a deliberate follow-up.

### 4.3 `server-rack-new.glb` is 22.6 MB that nothing loads

The donor ships two glTF binaries. The scene loads exactly one of them:
`scene/config/scene.ts` sets `url: '/models/server-rack.glb'` — the **6.1 MB**
model. `server-rack-new.glb` (**22,615,248 bytes**) is referenced by nothing:
not by any `.ts`/`.tsx`/`.css` in the donor source, not by `index.html`, and not
by any of the donor's ~37 backup directories either, so it was not a
recently-superseded reference. It appears to be an intended replacement that was
never wired up.

It has been migrated, because the migration brief named it explicitly and
dropping a named asset unilaterally is not this slice's call. But it is worth an
explicit decision, because git blobs are forever: **22.6 MB is added to every
future clone of this repository for an asset no code path reaches.** Removing it
is cheap now — the branch is unmerged and the history rewrite touches only my
commits — and expensive later.

`migration-completeness.test.ts` now resolves the configured model URL to the
file on disk and pins its exact byte count. That is deliberately stronger than
checking a `.glb` string appears somewhere: a missing, renamed, truncated or
LFS-stub model produces an **empty scene at runtime and no other symptom** — no
build error, no type error, nothing a conventional test would observe.

### 4.4 Two model files for one product

`spatial/apps/**/models/types.ts` (hand-written, prototype) and
`src/api/types.ts` (the real transport types) describe overlapping concepts with
no relationship. Every "transport-type status" cell above is *absent* for this
reason. Reconciling them is the natural first step of any real wiring.

---

## 5. What P7-C delivers against this matrix

- Every donor route and page **exists** in the repository — 40 routed + 12 shell
  surfaces, no omissions.
- Every fixture-backed surface is **observably** fixture-backed at runtime.
- **Zero** routes are wired to production, and the matrix says so per row rather
  than implying readiness.
- `/infrastructure/targets` and `/platform/audit` are the two surfaces whose
  production endpoint exists **exactly** today; they are the natural first
  candidates for real wiring, each with its permission gate.
