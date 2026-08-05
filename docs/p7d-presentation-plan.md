# P7-D presentation plan — wiring order for the spatial pages

The order in which the migrated spatial pages get wired onto the transport layer
#118 landed, what each one can and cannot show, and the permission gate each
carries.

**This is a plan. No page is wired by it.** #115 merged as `640bbb3`; wiring
begins from this order.

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
| 2 | **TargetsPage** | `listTargets`, `listWorkers` | 10 + 5 | targets: **none** (org-scope, verified a decision); workers: **`target_discovery:manage`** | Two different answers on one page |
| 3 | **WorkersPage** | `listTargets`, `listWorkers` | 10 + 5 | as above | **Consumes `placement-view.ts`** |
| 4 | **PlacementPage** | `listTargets` | 10 | **none** — org-scope, verified a decision | Same reader as #2 |
| 5 | **InventoryPage** | `listTargets`, `listEvidence` | 10 + 4 | targets: none; evidence: resolve per route | |
| 6 | **IntegrationsPage** | `listIntegrations` | 2 | resolve at wiring | `category`, `detail` unsourced |
| 7 | **EventScoringPage** | `listScores`, `listTeams` | 6 + 11 | **`exercise:operate`** | Scores entirely unsourced — see the ruling below |
| 8 | **TeamsAccessPage** | `listTeams`, `listParticipants`, `listAccessProfiles` | 11 + 3 + **absent** | **`exercise:operate`** | Partially blocked |
| 9 | **ScenarioLibraryPage** | `listScenarios` | 10 | resolve at wiring | |
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

| Read | Requires | Where the check lives |
| --- | --- | --- |
| `list_audit_events` | `audit:read` | in the function |
| `list_worker_nodes` | **`target_discovery:manage`** | in the function |
| `list_ranges` | **`exercise:operate`** | in the function |
| `list_teams` | **`exercise:operate`** | **one call upstream** |
| `scoreboard` | **`exercise:operate`** | **one call upstream** |
| `list_team_members`, `list_challenges` | **`exercise:operate`** | **one call upstream** |
| `list_targets` | organization scope only | query filter |

So a page gated on a guessed `*:read` permission would be **wrong in both
directions** — refusing users who should see the page, and admitting users the
service will refuse anyway. **Resolve the permission from the service function
that backs the call, every time.**

#### A gate can be one call upstream, and grep will not see it

**The first version of this table was wrong**, and the error is worth keeping
because it is the exact mistake this section warns against. It listed
`list_teams` and `scoreboard` as "organization scope only", derived by grepping
for `require(Permission.` **inside each function body**.

Both are gated. Their first statement is
`competition = get_competition(session, principal, competition_id)`, and
`get_competition` requires `exercise:operate` and then `require_org`. The same
holds for `list_team_members` and `list_challenges`.

**Grepping a function body finds gates that are written there and misses gates
that are delegated.** A wiring decision made from that table would have gated a
scoreboard on nothing while the server demanded `exercise:operate` — failing at
the boundary rather than at the gate, which reads as a server bug.

**Method that actually works:** follow the call graph from the service function
the route invokes, through every helper it delegates to, until a permission
check or an explicit organization scope is reached. Cheapest reliable form is to
read the first few lines of the function rather than to grep it.

### `list_targets` has no permission, and that is a decision rather than a gap

Flagged for verification because "no permission" and "nobody added one" are
indistinguishable from a call site. Verified: it is a **decision**.

- **Reads are organization-scoped structurally.** `list_targets` filters on
  `actor.organization_id` in the query itself; `get_target` calls
  `actor.require_org(...)`.
- **Writes on the same resource all require a permission** — `register_target`
  and `disable_target` require `target:manage`, and both credential rotations
  require `credential_binding:manage`.
- The module docstring states the model outright: *"Targets are
  organization-scoped, secret-free, and have immutable configuration."*

A clean read/write asymmetry plus a stated model is a design, not an omission.
So **`TargetsPage` and `PlacementPage` carry no permission gate for their read**,
and adding one would be inventing a boundary the server does not enforce — which
hides the question instead of answering it.

If that reading is ever revisited, it belongs to `owner-operator-api`; the
frontend must not compensate for it either way.

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

**Never synthesise a score total in the browser** — not as a fallback, not "just
for display". `listScores` leaves `total` unsourced, and a total computed by
summing components client-side carries the authority of a reading on the one
surface where people act on the number without checking where it came from. The
server already refuses this on its own side: `scoreboard()` in
`services/competitions.py` documents that it computes from the award ledger and
*"nothing here trusts a client-supplied total"*. The browser must hold the same
line in the other direction.

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
