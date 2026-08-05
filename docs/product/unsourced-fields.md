# What the designed experience assumes, and the platform does not produce

<!-- GENERATED FILE - DO NOT EDIT. Source: apps/web/src/api/adapter-endpoint-map.ts
     Regenerate: cd apps/web && npm run generate:unsourced-fields -->

The spatial frontend talks to the control plane through one interface of **22 methods**. Resolving each against the routes the live application actually registers gives:

| | methods |
| --- | --- |
| Served, and complete | 0 |
| Served, with fields the platform does not produce | 15 |
| Served, but nothing enumerates the id it needs | 1 |
| No endpoint at all | 5 |
| Deliberately not served | 1 |

Across them, **120 distinct product fields have no source on the wire**. They are not bugs and they are not oversights in the frontend: they are places where the designed experience describes something the platform does not measure.

**Why this matters at the pixel.** A `0` for a cost and a `—` for "not supplied" look identical on a screen and mean opposite things. Every field below has to render as an absence, or be produced by the backend, or be dropped from the design. Rendering it as a plausible default is the one option that is not available.

Three kinds of decision are mixed together here and it is worth separating them: some of these the control plane arguably **should** measure (a deployment's drift, a target's capacity); some are **presentation** choices it should never own (a team's display colour); and some describe a **product concept that does not exist yet** (score components, event phases). Only the first kind is backend work.

## Served, with fields the platform does not produce

### `getEvent`

`/api/v1/competitions/{competition_id}`

CompetitionOut supplies id, name, range_id, state, team_count, challenge_count, total_points, started_at, stopped_at. Everything an operator would call the EVENT — its phases, schedule and announcements — is absent.

Fields with no source:

- `phases`
- `announcements`
- `rules`
- `type`
- `startsAt`
- `endsAt`
- `health`
- `connectedParticipants`
- `totalParticipants`
- `description`
- `scenarioVersion`
- `scoringEnabled`

### `listScenarios`

`/api/v1/range-templates`

RangeTemplateOut is the closest real thing: slug, name, summary, description, difficulty, provider, components, challenge_count, total_points, estimated_deploy_seconds, warning. It is a catalogue entry, not a versioned scenario — there is no version history anywhere.

Fields with no source:

- `teamRange`
- `estimatedResources`
- `estimatedCostPerHour`
- `supportedProviders`
- `requiredPlugins`
- `currentVersion`
- `validation`
- `tags`
- `updatedAt`
- `versions`

### `getScenario`

`/api/v1/range-templates/{slug}`

Same shape as listScenarios, keyed by slug rather than by an opaque id.

Fields with no source:

- `teamRange`
- `estimatedResources`
- `estimatedCostPerHour`
- `supportedProviders`
- `requiredPlugins`
- `currentVersion`
- `validation`
- `tags`
- `updatedAt`
- `versions`

### `listDeployments`

`/api/v1/ranges`

RangeOut is the deployment. Its `state` is a NINE-member RangeState (draft, deploying, ready, active, resetting, recovery_required, failed, destroying, destroyed) against the domain's eight, and the mismatch is not cosmetic: `recovery_required` means the range could not be OBSERVED, which is neither running nor failed. Collapsing it into either is the substitution this programme exists to prevent. Resources come from a second call, /api/v1/ranges/{range_id}/resources.

Fields with no source:

- `scenarioVersion`
- `eventId`
- `targetId`
- `region`
- `health`
- `drift`
- `costToDate`
- `estimatedCostPerHour`
- `expiresAt`
- `owner`
- `workflowRunIds`

### `getDeployment`

`/api/v1/ranges/{range_id}` · `/api/v1/ranges/{range_id}/resources`

RangeOut plus RangeResourceOut for the resource list. RangeResourceOut carries component_key, kind, name, state, provider, image, image_digest, host_port, external_id and removed_at — richer than DeploymentResource, and `removed_at` in particular has no domain field, so a removed resource looks identical to a live one after mapping.

Fields with no source:

- `scenarioVersion`
- `eventId`
- `targetId`
- `region`
- `health`
- `drift`
- `costToDate`
- `estimatedCostPerHour`
- `expiresAt`
- `owner`
- `workflowRunIds`
- `resources[].ip`
- `resources[].health`
- `resources[].teamId`

### `listTeams`

`/api/v1/ranges/{range_id}/teams`

SCOPING MISMATCH, and it is the load-bearing part. The method signature is `listTeams(eventId?)` with the argument OPTIONAL; the route is range-scoped and the id is REQUIRED. There is no route that returns teams across ranges, so the optional form cannot be served at all. TeamOut supplies id, name, slug, score, solved_count, join_code, competition_id — the scoreboard half. The network half is entirely absent.

Fields with no source:

- `color`
- `memberIds`
- `subnet`
- `systems`
- `connection`
- `connectedDevices`
- `gatewayHealth`
- `vpnEndpoint`
- `allowedRoutes`
- `restrictions`
- `objectives`

### `listParticipants`

`/api/v1/ranges/{range_id}/teams/{team_id}/members`

Reachable only as (range, team). The signature takes `teamId?` alone, which is not enough to build the URL, and the optional form has no route at all.

Fields with no source:

- `email`
- `role`
- `lastSeen`

### `listTargets`

`/api/v1/targets`

The cleanest mapping of the 22 at ENTITY level — TargetOut is the target — but not at field level. Operational state (health, capacity, cost, deployment count) is not on the target record. `secret_ref` is an opaque reference and MUST stay one: it is the presence of a credential, never the credential.

Fields with no source:

- `location`
- `health`
- `capacity`
- `costStatus`
- `workerId`
- `credentialStatus`
- `capabilities`
- `deploymentCount`
- `lastDiscovery`
- `onboardingState`

### `listWorkers`

`/api/v1/target-discovery/read-only-bootstrap/worker-nodes` · `/api/v1/enrollment`

TWO endpoints describe one worker between them and neither is sufficient alone. The discovery node carries published key material; the enrollment record carries the lifecycle state and release fingerprint. `placement-view.workerRows` already performs exactly this join and emits a row for a worker present in only ONE of them — an enrolled worker that never published keys, and published keys with no enrollment, are both real states and neither may be dropped.

Fields with no source:

- `status`
- `taskQueues`
- `lastHeartbeat`
- `version`
- `targetIds`

### `listIntegrations`

`/api/v1/plugins` · `/api/v1/providers/capabilities`

PluginOut gives name, version, capabilities, contract_version, and two booleans — `healthy` and `simulated`. The domain wants a nine-member CapabilityStatus. `simulated: true` is NOT 'implemented', and mapping it to anything but `simulated` claims a capability the platform does not have. /providers/capabilities returns an untyped object, so nothing can be read from it without a contract.

Fields with no source:

- `category`
- `detail`

### `listWorkflowRuns`

`/api/v1/ranges/{range_id}/operations`

RangeOperationOut is the real thing: kind, status, phase, percent, steps, completed_steps, total_steps, failure_code, lease_expires_at, and `stale`/`stale_reason` — a run whose lease expired without a terminal status, which is neither running nor failed and has NO domain WorkflowStatus member. The declared filter is {eventId, deploymentId}; the route is range-scoped and cannot be filtered by event.

Fields with no source:

- `taskQueue`
- `eventId`
- `name`
- `steps[].detail`

### `listAuditEvents`

`/api/v1/audit`

The closest to exact of the 22. AuditEventOut supplies id, actor, action, outcome, created_at, resource_type, resource_id and an untyped `data` blob. The domain's single `resource` string is two fields on the wire, which is the better shape.

Fields with no source:

- `origin`

### `listEvidence`

`/api/v1/ranges/{range_id}/teardown-evidence` · `/api/v1/onboarding/{onboarding_id}/evidence` · `/api/v1/target-discovery/{enrollment_id}/evidence`

Evidence exists in three unrelated, differently-shaped, separately-scoped places and there is no combined feed. TeardownEvidenceOut is the richest and carries the zero-residue proof — verdict, probe_reachable, expected_count, removed_confirmed, still_present, unproven_count. `unproven_count` has no domain field, and folding it away turns 'nobody could prove these are gone' into 'these are gone'.

Fields with no source:

- `kind`
- `sha256`
- `store`
- `subject`

### `listScores`

`/api/v1/ranges/{range_id}/scoreboard` · `/api/v1/competitions/{competition_id}/scoreboard`

SIGNATURE MISMATCH: `listScores(eventId)` takes an event id; both routes are keyed by range or competition. ScoreboardEntryOut gives team_id, team_name, rank, score, solved_count, solved_challenge_ids, last_solve_at. The domain's four score COMPONENTS (defense/availability/attack/penalties) do not exist — the server holds one total, and deriving components in the browser would be inventing the scoring model.

Fields with no source:

- `total`
- `defense`
- `availability`
- `attack`
- `penalties`
- `trend`

### `getTopology`

`/api/v1/instances/{instance_id}/topology` · `/api/v1/exercises/{exercise_id}/topology` · `/api/v1/ranges/{range_id}/proxmox/topology`

The two generic topology routes return UNTYPED objects — the contract publishes no shape, so a client receives `unknown` and must narrow at runtime or not read them at all. The Proxmox route is the typed one (ProxmoxTopologyOut), but it is provider-specific and its `topology` member is itself an opaque document. `subjectId` is also ambiguous: three different id spaces reach three different routes, and the method takes one string.

## Served, but nothing enumerates the id it needs

### `listApprovals`

`/api/v1/manifests/{manifest_id}/change-sets`

CORRECTED TWICE. It said `absent`, which had stopped being true; then `shaped`, which overstated it. The route exists AND cannot be reached. GET /api/v1/manifests/{manifest_id}/change-sets enumerates change-set approvals — but PER MANIFEST, so an operator must already know which manifest to ask about. The other five approval families (plan-secret, plan-generation, activation-dossier, readonly-preflight, resolver-activation) remain GET-by-id only; the manifest-scoped routes that mention them are POSTs that CREATE an authorization, not lists. So an approvals inbox — 'what is waiting on me' — still cannot be built. AND THE PARENT IS UNREACHABLE. Nothing enumerates manifests: every GET yielding a manifest id needs a manifest, a change-set or a provisioning-operation id, and those three form a closed cycle. The only way in is POST /api/v1/plans/{plan_id}/manifest, which CREATES one — so an operator reaches approvals only for a manifest made in the same session. Plans themselves ARE reachable, via GET /api/v1/exercises/{exercise_id}/plan, so the chain breaks at exactly ONE level and the fix is ONE collection route.

**What it would take:** GET /api/v1/manifests — a collection route so the parent can be listed. ONE route, not two: plans are already reachable through exercises. Do not rebuild /manifests/{manifest_id}/change-sets; it works, nothing can get to it. Whatever is added must keep the six families DISTINCT rather than flattening them into one queue: they authorize different acts, and a single 'approval' list is how an approval for one operation gets read as authorizing another — the same property `operation_kind` protects on the Proxmox side.

Fields with no source:

- `title`
- `requestedBy`
- `riskLevel`
- `scope`
- `operation`

## No endpoint at all

### `listEvents`

_No registered endpoint._

NOT /api/v1/ranges/{range_id}/events — that returns RangeEventOut, a log line. A domain EventItem is a scheduled competition. A competition can be read one at a time via /api/v1/competitions/{competition_id} or /api/v1/ranges/{range_id}/competition, but nothing enumerates them, so there is no list to return.

**What it would take:** GET /api/v1/competitions (a list route). CompetitionOut carries no phases, announcements, rules, schedule or participant counts; those need modelling first.

Fields with no source:

- `phases`
- `announcements`
- `rules`
- `type`
- `startsAt`
- `endsAt`
- `health`
- `connectedParticipants`
- `totalParticipants`
- `description`
- `scenarioVersion`
- `deploymentIds`

### `listAccessProfiles`

_No registered endpoint._

No gateway, VPN, or participant-access surface is registered. Nothing in the 230 operations returns a WireGuard/OpenVPN/Guacamole profile or an endpoint fingerprint.

**What it would take:** An access-profile read surface. NOTE the shape carefully if it is ever added: the domain type carries `publicKeyFingerprint` and no private material, which is the right line — a profile a browser can render must never be a profile a browser could use.

### `listAlerts`

_No registered endpoint._

No alerting surface exists. The nearest real signal is RangeEventOut.level on /api/v1/ranges/{range_id}/events, but that is a per-range append-only log, not an alert stream, and treating a log line as an acknowledged-able alert invents the acknowledgement.

**What it would take:** An alert surface, if alerts are a product concept. `acknowledged` implies write state the control plane does not currently hold anywhere.

### `listReports`

_No registered endpoint._

No reporting surface is registered. Nothing generates, lists or stores a report.

**What it would take:** A report catalogue and generation surface, if reports are in scope.

### `listUsers`

_No registered endpoint._

/api/v1/me returns the CURRENT principal only (user_id, email, organization_id, permissions, is_dev_fallback). There is no user directory.

**What it would take:** A user-directory read route. `is_dev_fallback` on the principal is worth carrying through whatever is added: a development-fallback identity must never render as a real account.

## Deliberately not served

### `listSecretRefs`

_No registered endpoint._

No secret-reference surface is registered, and none should be. #115 removed the donor's secrets-management screens for this reason.

**What it would take:** NOTHING. This must stay unimplemented. Even a metadata-only listing puts credential inventory — purpose, bound target, rotation schedule, lease expiry — in a browser, and the frontend has no need for it that a per-target `secret_ref` presence flag does not already meet. If a future brief asks for this, it should be pushed back on rather than served.

