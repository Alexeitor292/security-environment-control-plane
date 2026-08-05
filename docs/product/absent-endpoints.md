# Surfaces the frontend needs and the control plane does not serve

<!-- GENERATED FILE - DO NOT EDIT. Source: apps/web/src/api/adapter-endpoint-map.ts
     Regenerate: cd apps/web && npm run generate:api-docs -->

Seven gaps, resolved against the routes the live application registers rather than against anyone's recollection. Each is verified continuously: `adapter-endpoint-map.test.ts` carries a probe per gap and fails if a route appears that looks like it closes one, so this document cannot quietly describe an API that has moved on.

**Scoping is the recurring problem, not a detail.** Six of these are not "the concept does not exist" — they are "the concept exists, but only under a parent the operator has to name first". An audit page cannot ask for evidence across an organization, and an approvals inbox cannot ask what is waiting, because every route demands an id the screen is trying to discover.

| method | sketch | unblocks |
| --- | --- | --- |
| `listEvidence` | `GET /api/v1/evidence?subject_type=&subject_id=&after=` | The evidence half of the audit surface |
| `listApprovals` | `GET /api/v1/approvals?status=pending` | An approvals inbox |
| `listEvents` | `GET /api/v1/competitions` | Any competition index |
| `listUsers` | `GET /api/v1/users` | Any surface naming a person other than the viewer |
| `listAlerts` | `GET /api/v1/alerts` | An alerting surface |
| `listReports` | `GET /api/v1/reports` | Reporting, entirely |
| `listAccessProfiles` | `GET /api/v1/access-profiles?team_id=` | Participant access surfaces |

## `listEvidence`

**Sketch** — `GET /api/v1/evidence?subject_type=&subject_id=&after=`

**Scoping** — ORGANIZATION-WIDE. All eight evidence routes in the contract are scoped to a parent id — range, onboarding, enrollment, dossier, authorization, registration — so a surface can only show evidence for a subject somebody already named. The audit page's job is the opposite: find the subject FROM the evidence.

**Unblocks** — The evidence half of the audit surface. `GET /api/v1/audit` already serves the action log org-wide, so the page is half-served today and the asymmetry is the whole problem.

**What exists today** — `/api/v1/ranges/{range_id}/teardown-evidence` · `/api/v1/onboarding/{onboarding_id}/evidence` · `/api/v1/target-discovery/{enrollment_id}/evidence`

Evidence exists in three unrelated, differently-shaped, separately-scoped places and there is no combined feed. TeardownEvidenceOut is the richest and carries the zero-residue proof — verdict, probe_reachable, expected_count, removed_confirmed, still_present, unproven_count. `unproven_count` has no domain field, and folding it away turns 'nobody could prove these are gone' into 'these are gone'.

## `listApprovals`

**Sketch** — `GET /api/v1/approvals?status=pending`

**Scoping** — NOT manifest-scoped. Change-sets are already enumerable per manifest; the missing question is 'what is waiting on me', which cannot name a manifest in advance.

**Unblocks** — An approvals inbox. Keep the six families DISTINCT in whatever is returned — they authorize different acts, and one flattened queue is how an approval for one operation gets read as authorizing another.

**What exists today** — `/api/v1/manifests/{manifest_id}/change-sets`

CORRECTED 2026-08-05: this said `absent`, and it had stopped being true. GET /api/v1/manifests/{manifest_id}/change-sets enumerates change-set approvals — but PER MANIFEST, so an operator must already know which manifest to ask about. The other five approval families (plan-secret, plan-generation, activation-dossier, readonly-preflight, resolver-activation) remain GET-by-id only; the manifest-scoped routes that mention them are POSTs that CREATE an authorization, not lists. So an approvals inbox — 'what is waiting on me' — still cannot be built.

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

## `listAccessProfiles`

**Sketch** — `GET /api/v1/access-profiles?team_id=`

**Scoping** — Team-scoped is fine here; the team id is on screen when the question is asked.

**Unblocks** — Participant access surfaces. If it is added: public metadata ONLY. The domain type carries `publicKeyFingerprint` and no private material, which is the right line — a profile a browser can render must never be a profile a browser could use.

**What exists today** — nothing

No gateway, VPN, or participant-access surface is registered. Nothing in the 230 operations returns a WireGuard/OpenVPN/Guacamole profile or an endpoint fingerprint.

