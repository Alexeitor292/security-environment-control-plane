# Surfaces the frontend needs and the control plane does not serve

<!-- GENERATED FILE - DO NOT EDIT. Source: apps/web/src/api/adapter-endpoint-map.ts
     Regenerate: cd apps/web && npm run generate:api-docs -->

Seven gaps, resolved against the routes the live application registers rather than against anyone's recollection. Each is verified continuously: `adapter-endpoint-map.test.ts` carries a probe per gap and fails if a route appears that looks like it closes one, so this document cannot quietly describe an API that has moved on.

**Scoping is the recurring problem, not a detail.** Six of these are not "the concept does not exist" — they are "the concept exists, but only under a parent the operator has to name first". An audit page cannot ask for evidence across an organization, and an approvals inbox cannot ask what is waiting, because every route demands an id the screen is trying to discover.

| method | sketch | unblocks |
| --- | --- | --- |
| `listArtifactIndex` | `no new route — GET /api/v1/ranges then /ranges/{range_id}/teardown-evidence` | The evidence half of the audit surface, behind a range picker |
| `listApprovals` | `GET /api/v1/approvals?status=pending` | An approvals inbox |
| `listEvents` | `GET /api/v1/competitions` | Any competition index |
| `listUsers` | `GET /api/v1/users` | Any surface naming a person other than the viewer |
| `listAlerts` | `GET /api/v1/alerts` | An alerting surface |
| `listReports` | `GET /api/v1/reports` | Reporting, entirely |
| `auditOutcomeFacet` | `GET /api/v1/audit/outcomes  (or a `facets` block on the audit response)` | A truthful outcome filter on the audit surface |
| `workerLiveness` | `a heartbeat, then GET /api/v1/workers with a last-seen and a reachability state` | WorkersPage, which is currently unbuildable rather than degraded |
| `listAccessProfiles` | `GET /api/v1/access-profiles?team_id=` | Participant access surfaces |

## `listArtifactIndex`

**Sketch** — `no new route — GET /api/v1/ranges then /ranges/{range_id}/teardown-evidence`

**Scoping** — PARENT-NOT-SELECTED, and therefore NOT a backend ask. The eight evidence routes are all scoped to a parent id, but `GET /api/v1/ranges` exists, so the range-scoped one is reachable behind a picker. This was on the backend list until the parent was checked. The org-wide question — evidence across an organization — is a genuinely different surface, and worth raising only if a screen needs it. What blocks the audit page today is a selection step. Original note: all eight evidence routes are scoped to a parent — range, onboarding, enrollment, dossier, authorization, registration — so a surface can only show evidence for a subject somebody already named. The audit page's job is the opposite: find the subject FROM the evidence.

**Unblocks** — The evidence half of the audit surface, behind a range picker. `GET /api/v1/audit` serves the action log org-wide with no picker, so the two halves of that page ask for their scope differently — which is a design problem, not a missing route.

**What exists today** — nothing

SPLIT FROM `listEvidence` on 2026-08-05, which named TWO concepts. This one is the org-wide content-addressed artifact index the spatial adapter wants — `kind`, `sha256`, `store` — and it has no backend at all. `secp_api.models.Artifact` has the right columns and NO writer, NO reader and NO route; it has never held a row, and there is no artifact store for its `uri` to point at. The other concept — per-range residue verdicts — is served, and is recorded separately as `listTeardownEvidence`. One entry where there were two concepts was the inventory's own version of the collision.

## `listApprovals`

**Sketch** — `GET /api/v1/approvals?status=pending`

**Scoping** — NOT manifest-scoped. Change-sets are already enumerable per manifest; the missing question is 'what is waiting on me', which cannot name a manifest in advance.

**Unblocks** — An approvals inbox. Keep the six families DISTINCT in whatever is returned — they authorize different acts, and one flattened queue is how an approval for one operation gets read as authorizing another.

**What exists today** — `/api/v1/manifests/{manifest_id}/change-sets`

CORRECTED THREE TIMES, and it moved BACK. It said `absent`, which had stopped being true; then `shaped`, which overstated it; then `parent-unreachable`, which was right until GET /api/v1/manifests landed. It is `shaped` again now, for the reason `shaped` originally overstated: the serving route works and the parent IS enumerable, so what remains is a shape problem rather than a reachability one. GET /api/v1/manifests/{manifest_id}/change-sets enumerates change-set approvals PER MANIFEST, so 'what is waiting on me' means walking every manifest and merging client-side. The other five approval families (plan-secret, plan-generation, activation-dossier, readonly-preflight, resolver-activation) remain GET-by-id only; the manifest-scoped routes that mention them are POSTs that CREATE an authorization, not lists. So the inbox still cannot be built — but nothing is unreachable any more. Recorded because the churn is the lesson: this entry was wrong four times and every correction came from a COMPUTATION (analyseReachability, the generated route map) refusing to agree with it, never from re-reading the prose.

## `listEvents`

**Sketch** — `GET /api/v1/competitions`

**Scoping** — Organization-wide. `/ranges/{id}/competition` serves one, given a range.

**Unblocks** — Any competition index. Note separately that CompetitionOut carries no phases, schedule, announcements or participant counts, so the product's 'event' is only partly modelled even once a list exists — that is a modelling question, not a routing one.

**What exists today** — nothing

NOT /api/v1/ranges/{range_id}/events — that returns RangeEventOut, a log line. A domain EventItem is a scheduled competition. A competition can be read one at a time via /api/v1/competitions/{competition_id} or /api/v1/ranges/{range_id}/competition, but nothing enumerates them, so there is no list to return.

## `listUsers`

**Sketch** — `GET /api/v1/users`

**Scoping** — Organization-wide. `/me` is the current principal only.

**Unblocks** — Any surface naming a person other than the viewer. Carry `is_dev_fallback` through: a development-fallback identity must never render as a real account.

**What exists today** — nothing

/api/v1/me returns the CURRENT principal only (user_id, email, organization_id, permissions, is_dev_fallback). There is no user directory.

## `listAlerts`

**Sketch** — `GET /api/v1/alerts`

**Scoping** — Organization-wide, and it needs write state — `acknowledged` is a fact the control plane would have to hold, which nothing does today.

**Unblocks** — An alerting surface. `RangeEventOut.level` is the nearest real signal but it is a per-range append-only log; treating a log line as acknowledge-able invents the acknowledgement.

**What exists today** — nothing

No alerting surface exists. The nearest real signal is RangeEventOut.level on /api/v1/ranges/{range_id}/events, but that is a per-range append-only log, not an alert stream, and treating a log line as an acknowledged-able alert invents the acknowledgement.

## `listReports`

**Sketch** — `GET /api/v1/reports`

**Scoping** — Organization-wide, and it is the one gap where scoping is not the hard part. Nothing generates, lists or stores a report, so there is no existing route with the wrong scope to widen — the concept is absent rather than misplaced.

**Unblocks** — Reporting, entirely. Nothing generates, lists or stores a report — this is a product concept that does not exist rather than a routing gap.

**What exists today** — nothing

No reporting surface is registered. Nothing generates, lists or stores a report.

## `auditOutcomeFacet`

**Sketch** — `GET /api/v1/audit/outcomes  (or a `facets` block on the audit response)`

**Scoping** — NO-ENDPOINT. Not a scoping problem at all — no route publishes the DISTINCT SET of audit outcomes, so a filter can only offer the outcomes that appear in the rows currently loaded. The set shrinks as you page, and an outcome with no rows on this page looks like an outcome that never happens.

**Unblocks** — A truthful outcome filter on the audit surface. Without it the control is a summary of the current page wearing the clothes of a filter over the whole log.

## `workerLiveness`

**Sketch** — `a heartbeat, then GET /api/v1/workers with a last-seen and a reachability state`

**Scoping** — NOT a field gap, which is how it was first measured. WorkersPage splits the whole page into online and offline, drives its unserved-targets panel from that split, and renders four columns from `status`, `taskQueues`, `lastHeartbeat` and `version`. None of those exists on the wire, and the reason is deeper than five missing fields: NOTHING IN THIS SYSTEM OBSERVES WORKER LIVENESS. `WorkerNodeOut` and `EnrollmentStatusOut` carry timestamps, revisions and fingerprints — no heartbeat, no last-seen, nothing meaning 'reachable now'.

**Unblocks** — WorkersPage, which is currently unbuildable rather than degraded. And a warning for whoever builds it: `enrollmentState: healthy` is NOT `status: online`. Enrollment is a lifecycle record; liveness is a heartbeat. Mapping one to the other asserts the single fact an operator most needs during an incident, from a record that cannot know it.

## `listAccessProfiles`

**Sketch** — `GET /api/v1/access-profiles?team_id=`

**Scoping** — Team-scoped is fine here; the team id is on screen when the question is asked.

**Unblocks** — Participant access surfaces. If it is added: public metadata ONLY. The domain type carries `publicKeyFingerprint` and no private material, which is the right line — a profile a browser can render must never be a profile a browser could use.

**What exists today** — nothing

No gateway, VPN, or participant-access surface is registered. Nothing in the 230 operations returns a WireGuard/OpenVPN/Guacamole profile or an endpoint fingerprint.

