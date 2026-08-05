# P7-D presentation plan — wiring order for the spatial pages

The order in which the migrated spatial pages get wired onto the transport layer
#118 landed, what each one can and cannot show, and the permission gate each
carries.

**This is a plan. No page is wired by it.** P7-D proper starts once #115 is on
`main`.

## How this was built

| Input | Source |
| --- | --- |
| Page → adapter method | the pages' own `useQuery((a) => a.method())` call sites, read from the migration branch |
| Method → endpoint, status, unsourced fields | `apps/web/src/api/adapter-endpoint-map.ts` (#118), which re-resolves itself against the committed OpenAPI document |
| Permission per read | the **service layer** — `actor.require(Permission.X)` in `apps/api/secp_api/services/*.py` |
| Gate mechanism | `resolveNavItem` / `requiresAnyPermission` in `components/shell/nav.ts` |

**Permissions are not enforced in routers.** `grep "require(" apps/api/secp_api/routers/*.py`
returns **zero**. Every check lives in a service function, so "which permission
does this page need" cannot be answered from the route table and has to be
resolved per call. That is why the column below is per method rather than per
page family.

## The headline: nothing is `exact`

Of 22 adapter methods: **0 exact, 15 shaped, 6 absent, 1 withheld.**

There is no page that can simply be pointed at an endpoint. Every wiring is a
projection with named gaps, and **the gaps are the work** — not the fetching.

## Two things that come first

### 1. Wiring `proxmox-view.ts` will turn the claims guard red. That is correct.

`domain/proxmox/proxmox-view.ts` carries deliberate safety copy and **8 absolute
claims**. It is outside the claims guard's scope today only because no component
imports it. **The moment a page imports it, those 8 claims become user-facing and
the guard fails.**

Meet it as designed: each claim is removed, or acknowledged with a written
reason, in the same change that does the wiring. It is **not** grounds for adding
the module to an exemption list — the claims are the review, and the review is
owed at the moment the copy can reach an operator. See §4.7 of the migration
matrix.

### 2. `placement-view.ts` has tests and no consumer

It was preserved from #111, is now tested (27 tests, mutation-verified in #117),
and **nothing imports it**. An unimported module rots quietly, and this is the
only one in the tree carrying tests that exercise nothing.

**Recommendation: `WorkersPage` should consume it.** It already needs the
enrollment/discovery-node join that `workerRows` implements, and #118's
`listWorkers` reader is *already built on it*. Wiring `WorkersPage` therefore
consumes the module and the reader together. If that is rejected, the module
should be dropped rather than left unwired — but not silently, because its tests
encode real invariants (a worker present in only one source still gets a row).

## Wiring order — cheapest first

Ordered so each merge is small enough to review. "Cost" is the number of
unsourced fields needing a presentation decision, not the fetching.

| # | Page | Methods | Unsourced fields to decide | Permission | Notes |
| ---: | --- | --- | ---: | --- | --- |
| 1 | **AuditPage** | `listAuditEvents`, `listEvidence` | 1 + 4 | **`audit:read`** | Smallest real gap. `origin` unsourced |
| 2 | **TargetsPage** | `listTargets`, `listWorkers` | 10 + 5 | org-scope; workers need **`target_discovery:manage`** | See the permission trap below |
| 3 | **WorkersPage** | `listTargets`, `listWorkers` | 10 + 5 | as above | **Consumes `placement-view.ts`** |
| 4 | **PlacementPage** | `listTargets` | 10 | org-scope only | Same reader as #2 |
| 5 | **InventoryPage** | `listTargets`, `listEvidence` | 10 + 4 | org-scope + evidence | |
| 6 | **IntegrationsPage** | `listIntegrations` | 2 | org-scope | `category`, `detail` unsourced |
| 7 | **EventScoringPage** | `listScores`, `listTeams` | 6 + 11 | org-scope | Scores are entirely unsourced — see below |
| 8 | **TeamsAccessPage** | `listTeams`, `listParticipants`, `listAccessProfiles` | 11 + 3 + **absent** | org-scope | Partially blocked |
| 9 | **ScenarioLibraryPage** | `listScenarios` | 10 | org-scope | |
| 10 | **DeploymentPortfolioPage** | `listDeployments`, `listEvents`, `listScenarios` | 11 + **absent** + 10 | **`exercise:operate`** | Blocked on `listEvents` |
| 11 | **WorkflowsPage** | `listWorkers`, `listWorkflowRuns` | 5 + 3 | mixed | |
| 12 | Topology pages ×3 | `getTopology`, `listTeams` | see trap | varies | **Hardest, not easiest** |

### Blocked entirely — these stay fixture-backed with the badge

| Page | Blocking method | Status |
| --- | --- | --- |
| `ReportsPage`, `EventReportsPage` | `listReports` | **absent** |
| `IdentityPage`, `OrganizationsPage` | `listUsers` | **absent** — `/api/v1/me` is the current principal only |
| `CommandCenterPage`, `ControlRoomPage` | `listAlerts`, `listApprovals` | **absent** ×2 |
| `EventsListPage`, `ScenarioOverviewPage` | `listEvents` | **absent** |
| `PlatformOverviewPage` | `listUsers`, `listApprovals` | **absent** ×2 |
| `DeploymentAdvancedPage` | `listSecretRefs` | **withheld — must stay that way** |

These are an **input to P7-A**, not a frontend problem to work around. A page
that cannot be wired keeps its fixture badge and its `not determined` states; it
does not get a plausible-looking placeholder.

## Three traps, named so nobody walks into them

### `listEvents` is not `/ranges/{id}/events`

`EventItem` is a scheduled competition — phases, teams, announcements, scoring.
`RangeEventOut` is a **log line** (kind, level, message, sequence). One word, two
concepts, and the wiring is one character from looking right. #118's reader calls
its method `listRangeLog` specifically so the name cannot mislead, and its test
asserts the map never connects the two.

### `getTopology` looks like the cleanest mapping and is the hardest

It is the only `shaped` method with **zero** unsourced fields, which reads as
"nothing missing". The opposite is true: the two generic topology routes return
**untyped** objects — the contract publishes no shape at all — so a client gets
`unknown`. The fields are not missing; the whole payload is opaque. It is an
explicit carve-out in `adapter-endpoint-map.test.ts` for that reason. **Wire the
topology pages last, not first.**

`subjectId` is ambiguous too: three id spaces reach three different routes and
the method takes one string.

### Reads can require write-shaped permissions

Intuition says a read page needs a read permission. Measured, that is false:

| Read | Requires |
| --- | --- |
| `list_audit_events` | `audit:read` |
| `list_worker_nodes` | **`target_discovery:manage`** |
| `list_ranges` | **`exercise:operate`** |
| `list_targets`, `list_teams`, `scoreboard` | organization scope only, no permission |

So a page gated on a guessed `*:read` permission would be **wrong in both
directions** — refusing users who should see the page, and admitting users the
service will refuse anyway. **Resolve the permission from the service function
that backs the call, every time.**

## Unsourced fields: the presentation rule

`unsourcedFields` names, per method, every domain field no endpoint supplies.
The rule, before any wiring:

> **A field with no wire source renders as *not supplied*. Never as `0`, `—`,
> `unknown`, empty string, or a plausible default.**

`Deployment.costToDate` with no source rendered as `0` and a real cost of zero
**look identical on screen and mean opposite things**. Same for
`InfraTarget.capacity`, `Deployment.drift`, and every `ScoreEntry` numeric —
`listScores` has **6 unsourced fields including `total`**, so a scoreboard wired
naively would display invented totals with the authority of a reading.

This is the `provenance.tsx` distinction at field granularity, and the existing
`Sourced<T>` discipline in `domain/proxmox/provenance.ts` is the shape to reuse —
it already makes offline absorbing, so a panel mixing one live reading with one
unsourced field degrades to the cautious claim rather than the confident one.

## The permission gate lands in the same change

Not after. Restating the standing rule because it is the one most easily lost in
a wiring PR:

- the gate ships **in the same commit** as the call it guards
- **hiding or disabling a control is not an authorization boundary** — the server
  refuses; the UI reflects
- `resolveNavItem` already implements the right shape: a gated item renders with
  an `unavailableReason` and **no href**, rather than vanishing

## What this plan does not do

- It does not wire anything.
- It does not decide the per-field presentation for all 15 shaped methods — it
  states the rule and names the fields; the decision belongs to the change that
  wires each page.
- It assumes #118's map is accurate. That map re-resolves itself against the
  committed OpenAPI document on every test run, so the assumption is checked
  rather than trusted — but it is still an assumption inherited from another
  slice.
- Ordering by unsourced-field count is a proxy for review cost. It is not a
  measurement of implementation difficulty, and the topology pages are the case
  where the proxy is most wrong — which is why they are listed last on other
  grounds.
