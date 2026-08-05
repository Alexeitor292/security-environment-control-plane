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
| ~~`/platform` → secrets~~ | ~~SecretsPage~~ | — | — | — | — | **REMOVED — see §4.5** |
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

### Authorization is the largest single gap — now mechanically enforced

The destination enforces permissions: `Sidebar` gates entries on the
principal's `permissions`, and the API declares a vocabulary including
`provisioning:manage`, `target:manage`, `topology:decide`,
`worker_identity:approve`, `readiness:approve` and others.

**The migrated prototype contains no authorization logic of any kind.** No
permission check, no capability gate, no principal-aware rendering. Every screen
renders every control for everyone — including `DangerousOperationDialog` on
`/deployments/:id/advanced`.

This is survivable today only because the adapter is entirely read-only: all 22
methods are `list*`/`get*`. It stops being survivable the moment somebody adds
`approvePlan()` or `destroyRange()` and wires a button to it.

**Standing rule, from P7-D onward.** No page may be wired to a mutating
production endpoint without its permission gate landing in the *same* change. And
**hiding or disabling a control is not an authorization boundary** — the server
refuses; the UI merely reflects. `DangerousOperationDialog` is a confirmation
step, not a permission check, and must never be the only thing between an
operator and a mutation.

`src/spatial/authorization-boundary.test.ts` makes that mechanical rather than
remembered. The classification is **inverted** on purpose: every method on the
live interface must be explicitly acknowledged as read-only, and anything not
acknowledged is treated as mutating and must be gated at every call site. A guard
phrased the other way round — "the mutating methods we know about are gated" —
would pass vacuously forever, since there are currently no mutating methods, and
would go red only when someone removed a gate that does not yet exist.

So **adding a method is what turns it red**, which is the moment the decision
actually gets made. Mutation-verified:

| Simulated change | Result |
| --- | --- |
| Add `destroyRange()` to the interface | fails, naming the method and the rule |
| …and call it from a page with no gate | fails again, naming the file |

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

### 4.1 RESOLVED — unobserved security claims removed from five pages

`ProvidersPage.tsx` carried a hand-written table asserting that for Proxmox every
mutating operation — plan, apply, reset, destroy — was `'refused'`, that
discovery was GET-only, and that refusals were audited. Nothing verified any of
it, and it had already been falsified: the Proxmox apply, destroy, verification
and residue-proof paths shipped in SECP-PROXMOX #105–#110, so the page told
operators operations were refused while the endpoints to perform them existed.

**Sourcing the table from `GET /api/v1/providers/capabilities` was considered and
rejected.** That endpoint returns a hardcoded constant — `PROVISIONING_ENABLED =
False`, *"Proxmox provisioning is deferred to SECP-002B"* — and is stale in
exactly the same way. Wiring the page to it would have **relocated the false
claim from the frontend to the backend and made it look observed**, because a
claim sourced from an API reads as verified. That is a harder lie to catch than a
visibly hand-written one. Wiring waits for P7-D, once the endpoint reports
observed capability rather than a constant.

Every capability cell now renders **not determined** in the `unknown` tone —
never `ok` (which reads as permitted) and never `error` (which reads as refused).

**A guard found the same defect on four more pages**, which is why it was written
to scan every page rather than the one named:

| Page | Claim removed |
| --- | --- |
| `ProvidersPage` | "every mutating operation … is refused, and the refusal is audited"; "GET-only"; the `sealed` tag |
| `DeploymentAdvancedPage` (both forks) | "the apply subprocess is hard-sealed … **no real host has ever been contacted**" |
| `InventoryPage` | "GET-only reads … read-only by construction"; "today only fake-mode collection runs" |
| `TargetsPage` | a confirmation dialog promising "new plans and applies for this target **are refused**" |

The `DeploymentAdvancedPage` line was the worst of them: an absolute safety
assertion, already false, on a page with a destructive-operation dialog. The
`InventoryPage` line is the "Simulated execution only" claim in another costume.

Enforced by `src/spatial/security-claims.test.ts`. Mutation-verified: restoring
the refusal tone fails it, and restoring the "hard-sealed" prose fails it.

### 4.1a Security-property claims are a distinct class

The general rule, recorded because it is the thing most likely to be forgotten:

> **A fixture label does not make a false security claim safe.**

"This data is illustrative" is an adequate hedge for a deployment count. It is
**not** adequate for "every mutating operation is refused", because an operator
may act on that, and the error runs in the direction where someone gets hurt.
Under-claiming is recoverable; over-claiming safety is not.

So the matrix treats these as a separate column class from ordinary fixture data:

| Claim class | Fixture label sufficient? | Permitted rendering when unobserved |
| --- | --- | --- |
| Counts, names, timestamps, status text | yes | fixture badge + the value |
| **Enforcement / refusal / isolation / "cannot happen"** | **no** | **`unknown` only — never a comforting default** |

An unobserved security property may render as *unknown*. It may never render as
*safe*.

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

### 4.3 One model migrated, one excluded — and how the survivor is guarded

The donor ships two glTF binaries. The scene loads exactly one:
`scene/config/scene.ts` sets `url: '/models/server-rack.glb'` — the **6.1 MB**
model — and `ServerRack.tsx` holds the only `useGLTF` call site.
`server-rack-new.glb` (**22,615,248 bytes**) is referenced by nothing: no
`.ts`/`.tsx`/`.css` in the donor source, not `index.html`, and none of the
donor's ~37 backup directories, so it was not a recently-superseded reference —
an intended replacement that was never wired up.

**It is excluded.** A git blob is permanent, so carrying it would add 22.6 MB to
every future clone of this repository forever for an asset no code path reaches.
This is not a simplification of the scene: the model the donor actually renders
is here byte-identical, so what a user sees is exactly what the donor showed. The
donor is untouched and read-only, so the file is one copy away if anyone wires it
up. Git LFS was considered and rejected — at 6.1 MB it is unwarranted, and a
misconfigured LFS checkout substitutes a **~130-byte pointer file** for the
binary, which fails silently at runtime as an empty scene.

**The survivor is guarded by `src/spatial/scene/model-integrity.test.ts`**, which
asserts the glTF magic number (`67 6C 54 46`), container version 2, a JSON first
chunk, and the exact byte count. Its strongest assertion is none of those: the
glTF header **declares its own total length** at bytes 8–12, so the file is
checked against itself and any truncation fails without anyone needing to know
the right size.

That distinction is not theoretical. Mutation-verified against the three
realistic corruptions:

| Simulated failure | Result |
| --- | --- |
| Git LFS pointer stub in place of the binary | all 4 assertions fail |
| Truncated copy (first 1 MB) | header-length + byte-count fail |
| Text-mode corruption (LF → CRLF) | header-length + byte-count fail |

The CRLF case is the instructive one: **the magic bytes survive it**, so a test
that checked only the magic number would have passed on a corrupt model. The
self-consistency check is what catches it.

A hash table in a pull request cannot do this job — whoever writes the migration
produces both sides of it, so it can only restate itself, and nothing re-runs it.
This test lives in the repository and fails for anybody.

### 4.5 One route and one page were REMOVED — secrets management

**This is the only donor surface that does not exist in the repository, and it is
recorded here because a missing page must never be silently missing.**

The donor ships a secrets-management page under Platform: a table of secret
references, rotation posture, and a card describing the OpenBao adapter. Two
**backend** guards — `apps/api/tests/test_openbao_resolver.py` and
`apps/api/tests/test_resolver_activation_security.py` — scan every frontend
`.ts`/`.tsx` for thirteen forbidden strings and fail the build on any hit. The
route and the page tripped them.

**The guard is right and the donor is wrong.** Secret resolution in this product
is sealed and worker-side, and deliberately has no browser surface at all. The
donor was drawn as a mock without that constraint, so the page is a *technically
false mock assumption* with no truthful production meaning — not a real surface
whose data happens to be mocked. Removed, with everything that pointed at it:

| Removed | Why |
| --- | --- |
| `SecretsPage.tsx` | the surface itself |
| its route in `PrototypeSuiteApp.tsx` | a reachable route is the thing forbidden |
| the nav entry in `SectionLayout.tsx` | a link to nothing |
| the card in `PlatformOverviewPage.tsx` | same |
| the `SpatialGlobalSearch` index entry | a search result leading nowhere is worse than an absent one |

**Renaming the route to evade the substring was available and was not done.**
`/secret-store` or `/vault` would have gone green while shipping the surface the
guard forbids. That is the cheapest repair and the worst one.

`SecretRef` and `listSecretRefs` remain, because they are still used by
`DeploymentAdvancedPage` and because the model carries no secret value — only
name, purpose, provider, rotation schedule and health. The guards permit opaque
references by design; what they forbid is a credential-entry field or a
secret-reading route. **That embedded table is flagged for a decision, not
removed unilaterally** — it is a different surface from the one that was ruled on.

There is **no credential-entry field anywhere** in the migrated tree: a scan
wider than the guards' own (covering `type={...}`, `autocomplete="…-password"`,
`passphrase`, `private_key`) found nothing.

### 4.6 Nine backend tests read the frontend tree

**Standing number: nine.** These Python tests scan `apps/web/src/**/*.{ts,tsx}`
and can fail a frontend change for a reason no frontend test can express:

| Test | Enforces |
| --- | --- |
| `test_openbao_resolver.py` | no secret-reading/resolution route or credential field |
| `test_resolver_activation_security.py` | no secret backend or activation toggle |
| `test_resolution_lease_boundary.py` | no lease/activation **control indicator** (own matcher, not the token list) |
| `test_readonly_preflight_security.py` | no credential entry or secret-resolution route |
| `test_worker_identity_security.py` | no identity verifier or attestation surface |
| `test_live_preflight_evidence_security.py` | no live-evidence interface |
| `test_web_api_contract_guard.py` | frontend/API contract agreement |
| `tests/test_ci_workflow.py` | CI wiring |
| `tests/test_openapi_artifact.py` | committed artifact matches a fresh export |

Two properties that cost real time to learn:

1. **They `assert` inside their loop**, so pytest reports only the *first*
   violating file. The reported filename is never the complete set. Replicate the
   scan yourself before changing anything.
2. **They do not share a token list.** `test_resolution_lease_boundary.py` uses
   its own `_forbidden_frontend_hits` matcher, which is why a sweep of the other
   guards' 13 tokens missed it entirely.

The general form, learned twice here at a cost: **two independent enumerations,
both thorough, both scoped to the guards their author already knew about.** An
include list of *guards* fails the same way an include list of *files* does. The
tree tells you what it forbids only when you ask the tree.

### 4.7 For P7-D: claims enter scope when you wire a module — by design

**If you wire `domain/proxmox/proxmox-view.ts` (or `adapter-endpoint-map.ts`) into
a component and `security-claims.test.ts` goes red, that is the guard working, not
a broken test.**

The claims guard scopes itself by **reachability**: a module is in scope if any
`.tsx` can reach it by following imports, recomputed from the tree every run.
A string no component can reach is not user-facing copy, so it is not checked.

`domain/proxmox/proxmox-view.ts` carries deliberate safety copy — `UNPROVEN_IS_NOT_CLEAN_NOTE`,
`AUTHORIZATION_IS_SERVER_SIDE_NOTE`, and 8 absolute claims. Nothing imports it
today, so it sits outside scope. **The moment a component imports it, those 8
claims become user-facing and must each be removed or acknowledged with a written
reason.**

That is the correct moment for the decision: the copy becomes a claim to an
operator exactly when it can reach a screen, and not before. What it is *not* is
a reason to add the module to an exemption list — the claims are the point of
review, and the review is owed at the moment of wiring.

The same applies to `api/adapter-endpoint-map.ts`, which additionally pins its
importer set (currently empty): importing it from anywhere at all, component or
not, fails that pin and forces the exemption to be re-decided rather than
silently becoming false.

### 4.8 What the frontend suite structurally could not catch

The backend guards found a real boundary violation that **1058 passing frontend
tests did not**. That is not a gap in those tests; it is the shape of the
problem. A frontend suite can only confirm that the frontend renders what the
frontend says. The constraint being violated — *secret resolution has no browser
surface* — is a property of the product, and it is held where the product
defines it.

A frontend mirror of the scan was considered and **deliberately not written**.
It would have to obfuscate the forbidden tokens to avoid tripping the backend
scan on its own source, and it would replace an independent check with a copy
that can drift. The independence is the value.

The general form for this matrix: **when a donor surface encodes an assumption
the product contradicts, the product's guard wins and the surface goes.** The
matrix records the removal; it does not quietly reduce a count.

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
