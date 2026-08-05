# SECP Range API contract

**Owner:** `owner-range-backend` (branch `feature/secp-range-backend`, base `055e8dc9`).
**Consumer:** `owner-range-ui`.
**Status:** shapes below are FROZEN. Any change is announced to the lead and to `owner-range-ui`
before it lands.

All routes are under `/api/v1`, authenticated exactly like the rest of the API
(`Authorization: Bearer <token>`; the dev fallback applies only when no header is sent). Every
resource is organization-scoped by the principal — no `organization_id` is ever accepted from the
caller.

Errors use the existing envelope:

```json
{ "error": { "code": "not_found", "message": "range not found" } }
```

Range-specific codes: `range_not_found` (404), `range_invalid_transition` (409),
`range_provider_unavailable` (503), `competition_not_open` (409), `submission_rejected` (422),
`forbidden` (403).

---

## 1. Enumerations

| Enum | Values |
| --- | --- |
| `RangeState` | `draft`, `deploying`, `ready`, `active`, `resetting`, `recovery_required`, `failed`, `destroying`, `destroyed` |
| `RangeOperationKind` | `deploy`, `reset`, `destroy` |
| `RangeOperationStatus` | `pending`, `running`, `succeeded`, `failed`, `unproven` |
| `RangeResourceKind` | `network`, `container` |
| `RangeResourceState` | `pending`, `creating`, `created`, `verified`, `removing`, `removed`, `unproven`, `failed` |
| `ResidueVerdict` | `clean`, `residue`, `unproven` |
| `CompetitionState` | `draft`, `running`, `stopped` |
| `SubmissionVerdict` | `accepted`, `incorrect`, `duplicate`, `already_solved`, `not_open`, `attempts_exhausted` |

### `unproven` is a real third state — please render it

`unproven` is NOT a synonym for failure and NOT a synonym for success. It means the provider could
not be observed, so the answer is unknown. It appears on `RangeOperationStatus`,
`RangeResourceState` and `ResidueVerdict`. The canonical case: Docker is unreachable during
teardown, so both the removal AND the "is it gone?" check fail for the same reason. The range then
lands in `recovery_required`, not `destroyed`. Please give it its own visual treatment (amber /
"needs a human"), distinct from both green and red.

---

## 2. Range catalog

### `GET /api/v1/range-templates` → `200 RangeTemplateOut[]`
### `GET /api/v1/range-templates/{slug}` → `200 RangeTemplateOut`

```json
{
  "slug": "web-breach-lab",
  "name": "Web Breach Lab",
  "summary": "Two intentionally vulnerable web applications on an isolated Docker network.",
  "description": "Longer markdown-free prose for the detail pane.",
  "provider": "local_docker",
  "difficulty": "beginner",
  "estimated_deploy_seconds": 180,
  "warning": "Contains intentionally vulnerable software. Ephemeral local Docker only — never expose to an untrusted network.",
  "components": [
    {
      "key": "juice-shop",
      "name": "OWASP Juice Shop",
      "role": "target",
      "image": "bkimminich/juice-shop:v17.1.0",
      "container_port": 3000,
      "protocol": "http",
      "path": "/"
    },
    {
      "key": "dvwa",
      "name": "DVWA",
      "role": "target",
      "image": "vulnerables/web-dvwa:1.9",
      "container_port": 80,
      "protocol": "http",
      "path": "/"
    }
  ],
  "challenge_count": 6,
  "total_points": 600
}
```

`role` is one of `target` | `scoring` | `support`. `container_port` is `null` for components with no
HTTP surface.

---

## 3. Range lifecycle

### `POST /api/v1/ranges` → `201 RangeOut`

```json
{ "template_slug": "web-breach-lab", "name": "Tuesday cohort" }
```

`name` is optional; it defaults to the template name. Creates a range in `draft`. Deploys nothing.

### `GET /api/v1/ranges` → `200 RangeOut[]`

Newest first. Optional `?state=ready` (repeatable) and `?include_destroyed=false` (default `false`).

### `GET /api/v1/ranges/{range_id}` → `200 RangeOut`

This is the polling endpoint. While an operation is in flight, poll it every 2s; `progress` and
`state` are the only fields that move.

```json
{
  "id": "0f2c…",
  "name": "Tuesday cohort",
  "template_slug": "web-breach-lab",
  "template_name": "Web Breach Lab",
  "provider": "local_docker",
  "state": "ready",
  "state_reason": null,
  "created_at": "2026-08-04T10:00:00Z",
  "updated_at": "2026-08-04T10:03:12Z",
  "deployed_at": "2026-08-04T10:03:12Z",
  "destroyed_at": null,
  "competition_id": "9ab1…",
  "current_operation": {
    "id": "77aa…",
    "kind": "deploy",
    "status": "succeeded",
    "phase": "verify",
    "completed_steps": 6,
    "total_steps": 6,
    "percent": 100
  },
  "residue_verdict": null,
  "access": [
    {
      "component_key": "juice-shop",
      "name": "OWASP Juice Shop",
      "url": "http://127.0.0.1:34011/",
      "host": "127.0.0.1",
      "port": 34011,
      "protocol": "http",
      "reachable": true,
      "observed_at": "2026-08-04T10:03:12Z"
    }
  ]
}
```

`current_operation` is `null` before the first operation. `access` is `[]` unless the range is
`ready` or `active`, and every entry's `reachable` came from an actual observed response — it is
never assumed from "the container was created".

### `POST /api/v1/ranges/{range_id}/deploy` → `202 RangeOperationOut`

Allowed from `draft` and `failed`. `409 range_invalid_transition` otherwise. Returns immediately;
the operation runs in the background. Poll `GET /ranges/{id}` or `GET /range-operations/{op_id}`.

### `POST /api/v1/ranges/{range_id}/reset` → `202 RangeOperationOut`

Allowed from `ready`, `active`, `failed`. Recreates the target containers on the same network and
clears competition scores + submissions (the competition itself, its teams and its challenges
survive). Deterministic: the same template yields the same post-reset state.

### `POST /api/v1/ranges/{range_id}/destroy` → `202 RangeOperationOut`

Allowed from every state except `destroying` and `destroyed`. Removes every resource this range
owns and nothing else. Terminal state is `destroyed` (proved gone) or `recovery_required`
(`unproven` — could not observe).

### `GET /api/v1/range-operations/{operation_id}` → `200 RangeOperationOut`

```json
{
  "id": "77aa…",
  "range_id": "0f2c…",
  "kind": "deploy",
  "status": "running",
  "phase": "verify",
  "completed_steps": 4,
  "total_steps": 6,
  "percent": 66,
  "failure_code": null,
  "failure_message": null,
  "started_at": "2026-08-04T10:00:04Z",
  "finished_at": null,
  "steps": [
    { "key": "network", "label": "Create isolated network", "status": "succeeded", "detail": "secp-range-0f2c9b", "at": "2026-08-04T10:00:06Z" },
    { "key": "pull:juice-shop", "label": "Pull OWASP Juice Shop", "status": "succeeded", "detail": null, "at": "2026-08-04T10:01:40Z" },
    { "key": "verify:juice-shop", "label": "Verify OWASP Juice Shop responds", "status": "running", "detail": null, "at": null }
  ]
}
```

`steps[].status` is `pending` | `running` | `succeeded` | `failed` | `unproven`.

### `GET /api/v1/ranges/{range_id}/operations` → `200 RangeOperationOut[]`

Newest first.

### `GET /api/v1/ranges/{range_id}/resources` → `200 RangeResourceOut[]`

```json
{
  "id": "3c1d…",
  "kind": "container",
  "provider": "local_docker",
  "component_key": "juice-shop",
  "name": "secp-range-0f2c9b-juice-shop",
  "external_id": "9f4c2a1b7e35…",
  "image": "bkimminich/juice-shop:v17.1.0",
  "state": "verified",
  "host_port": 34011,
  "created_at": "2026-08-04T10:01:52Z",
  "removed_at": null,
  "detail": { "network": "secp-range-0f2c9b" }
}
```

### `GET /api/v1/ranges/{range_id}/events` → `200 RangeEventOut[]`

Append-only timeline, oldest first. Optional `?after_sequence=42` for incremental fetch.

```json
{
  "id": "aa11…",
  "range_id": "0f2c…",
  "sequence": 7,
  "kind": "resource_verified",
  "level": "info",
  "message": "OWASP Juice Shop responded on 127.0.0.1:34011",
  "data": { "component_key": "juice-shop" },
  "occurred_at": "2026-08-04T10:03:12Z"
}
```

`level` is `info` | `warning` | `error`. `kind` is a stable machine string; render `message`.

### `GET /api/v1/ranges/{range_id}/teardown-evidence` → `200 TeardownEvidenceOut[]`

Newest first; `[]` if the range was never destroyed.

```json
{
  "id": "b2c3…",
  "range_id": "0f2c…",
  "operation_id": "88bb…",
  "verdict": "clean",
  "probe_reachable": true,
  "expected_count": 4,
  "removed_confirmed": 4,
  "still_present": 0,
  "unproven_count": 0,
  "reason": null,
  "observed_at": "2026-08-04T11:00:00Z",
  "resources": [
    { "kind": "network", "name": "secp-range-0f2c9b", "external_id": "b71f…", "verdict": "removed" }
  ]
}
```

`resources[].verdict` is `removed` | `present` | `unproven`. When `probe_reachable` is `false`,
`verdict` is `unproven` and `reason` explains that the removal and the existence check share a
failure mode, so absence was not proved.

---

## 4. Competition

### `POST /api/v1/ranges/{range_id}/competition` → `201 CompetitionOut`

```json
{ "name": "Tuesday CTF" }
```

One competition per range. Seeds the template's challenges and flags. `409` if one already exists.

### `GET /api/v1/ranges/{range_id}/competition` → `200 CompetitionOut` (`404` if none)
### `GET /api/v1/competitions/{competition_id}` → `200 CompetitionOut`

```json
{
  "id": "9ab1…",
  "range_id": "0f2c…",
  "name": "Tuesday CTF",
  "state": "running",
  "started_at": "2026-08-04T10:10:00Z",
  "stopped_at": null,
  "team_count": 3,
  "challenge_count": 6,
  "total_points": 600,
  "created_at": "2026-08-04T10:05:00Z"
}
```

### `POST /api/v1/competitions/{competition_id}/start` → `200 CompetitionOut`

`409 range_invalid_transition` unless the range is `ready` and at least one team exists. Moves the
range to `active`.

### `POST /api/v1/competitions/{competition_id}/stop` → `200 CompetitionOut`

Moves the range back to `ready`. Submissions are refused while stopped.

### `POST /api/v1/competitions/{competition_id}/teams` → `201 TeamOut`

```json
{ "name": "Red Team" }
```

### `GET /api/v1/competitions/{competition_id}/teams` → `200 TeamOut[]`

```json
{
  "id": "d4e5…",
  "competition_id": "9ab1…",
  "name": "Red Team",
  "slug": "red-team",
  "join_code": "R7K2QX",
  "score": 300,
  "solved_count": 3,
  "created_at": "2026-08-04T10:06:00Z"
}
```

### `DELETE /api/v1/competitions/{competition_id}/teams/{team_id}` → `204`

Refused with `409` once the competition has started.

### `GET /api/v1/competitions/{competition_id}/challenges` → `200 ChallengeOut[]`

```json
{
  "id": "e5f6…",
  "competition_id": "9ab1…",
  "key": "js-admin-login",
  "title": "Log in as the administrator",
  "description": "Reach the Juice Shop admin account.",
  "category": "web",
  "points": 100,
  "component_key": "juice-shop",
  "hint": "The login form is not as strict as it looks.",
  "max_attempts": 25,
  "solve_count": 2,
  "solved_by_team_ids": ["d4e5…"]
}
```

**The flag value is never present in any response.** Flags are stored salted-hashed and compared
server-side only.

### `POST /api/v1/competitions/{competition_id}/submissions` → `200 SubmissionOut`

```json
{ "team_id": "d4e5…", "challenge_id": "e5f6…", "value": "SECP{…}" }
```

Always `200` with a verdict (a wrong flag is a normal outcome, not an HTTP error). `422
submission_rejected` only for a malformed body or a team/challenge that does not belong to this
competition.

```json
{
  "id": "f6a7…",
  "competition_id": "9ab1…",
  "team_id": "d4e5…",
  "team_name": "Red Team",
  "challenge_id": "e5f6…",
  "challenge_title": "Log in as the administrator",
  "verdict": "accepted",
  "points_awarded": 100,
  "attempts_remaining": 24,
  "submitted_at": "2026-08-04T10:22:31Z"
}
```

Verdicts: `accepted` (first correct solve for this team), `already_solved` (this team already
solved it — 0 points, no duplicate credit), `duplicate` (this team already submitted this exact
value), `incorrect`, `not_open` (competition not `running`), `attempts_exhausted`.

**Scores are computed and stored server-side only.** `points_awarded` in the response is a report of
what the server recorded, never an instruction to the client. The browser is never authoritative.

### `GET /api/v1/competitions/{competition_id}/submissions` → `200 SubmissionOut[]`

Newest first. Optional `?team_id=`, `?challenge_id=`, `?limit=` (default 100, max 500).

### `GET /api/v1/competitions/{competition_id}/scoreboard` → `200 ScoreboardOut`

Poll every 3s while `active`.

```json
{
  "competition_id": "9ab1…",
  "state": "running",
  "generated_at": "2026-08-04T10:25:00Z",
  "total_points": 600,
  "entries": [
    {
      "rank": 1,
      "team_id": "d4e5…",
      "team_name": "Red Team",
      "score": 300,
      "solved_count": 3,
      "last_solve_at": "2026-08-04T10:22:31Z",
      "solved_challenge_ids": ["e5f6…"]
    }
  ]
}
```

Ties share a rank and are ordered by earliest `last_solve_at`.

### `POST /api/v1/competitions/{competition_id}/reset-scores` → `200 CompetitionOut`

Clears submissions and scores; keeps teams and challenges. Does not touch the containers — use
`POST /ranges/{id}/reset` for the environment (which also clears scores).

---

## 5. Suggested UI flow

1. `GET /range-templates` — catalog page.
2. `POST /ranges` then `POST /ranges/{id}/deploy` — deploy page; poll `GET /ranges/{id}` every 2s
   and render `current_operation.percent` + `GET /ranges/{id}/events`.
3. On `state: "ready"` — show `access[]` as launch links.
4. `POST /ranges/{id}/competition`, then teams, then `POST /competitions/{cid}/start`.
5. Submissions page + `GET /competitions/{cid}/scoreboard` poll.
6. `POST /ranges/{id}/reset` or `POST /ranges/{id}/destroy`; on `recovery_required` show
   `GET /ranges/{id}/teardown-evidence` and say plainly that residue could not be disproved.
