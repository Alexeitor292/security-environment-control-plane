# SECP Safety Invariants

**Status:** append-only record. A committed hook (`.claude/hooks/guard_writes.py`) denies any
edit that removes an existing line. Corrections are new entries carrying `supersedes: <id>`.

**Observed at:** `e72f28f` (`main`, SECP-PR5H-B2A).
**Method:** 25-agent read-only audit — 12 non-overlapping domain specialists, a contradiction
detector, adjudicators, and three independent skeptics. Every row is anchored to code.

`enforcementKind` vocabulary: `code-seal` · `settings-validator` · `db-constraint` ·
`db-trigger` · `alembic-fence` · `boundary-test` · `ci-gate` · `import-guard` · `repo-ruleset` ·
`convention-only`.

---

## 0. Read this before trusting any seal list

**SI-000 — The seal census is not the infrastructure-contact surface.**
Do not reason "not named as sealed, therefore it cannot reach a provider."

Verified counter-example: the legacy SECP-002A `discover_activity` is registered on the
**shipped** ordinary Temporal queue (`apps/worker/secp_worker/temporal_app.py:111-140`) and
reaches a real `ProxmoxPlugin` over a real httpx transport, ungated at every hop:
`apps/api/secp_api/routers/providers.py:154-160` →
`apps/api/secp_api/services/inventory.py:51,100` →
`apps/worker/secp_worker/discovery.py:32-39` (`return ProxmoxPlugin()`; the mock transport
applies only under a test environment variable).

The read-only GET allowlist still constrains what that path may do, so this is not an escape —
but it *is* a live provider-contact path that no seal governs. Trace call chains; do not read
lists.

**SI-001 — In production, no authenticated API call is possible through any supported path.**
There is no first-class identity-lifecycle API/UI/CLI: `sub` bindings must be created by a direct
DBA write, which is outside the SECP mutation path and produces **no** `AuditEvent`. Therefore
every "a customer can do X through /api/v1" claim fails at the identity layer before any feature
gate is reached. `enforcementKind: code-seal` (`apps/api/secp_api/auth.py:132-136`).

---

## 1. Repository and delivery

| id | Invariant | enforcedAt | kind | breakableBy |
| --- | --- | --- | --- | --- |
| SI-100 | `main` is linear; no merge commits | GitHub ruleset 18301624 `required_linear_history` | repo-ruleset | Ruleset edit (bypass actors: none) |
| SI-101 | `main` cannot be force-pushed or deleted | ruleset `non_fast_forward`, `deletion` | repo-ruleset | Ruleset edit |
| SI-102 | Every change reaches `main` via a PR | ruleset `pull_request` | repo-ruleset | Ruleset edit |
| SI-103 | Two named CI contexts must be green to merge | ruleset `required_status_checks` | repo-ruleset + ci-gate | Renaming a job silently drops its gate — `tests/test_ci_workflow.py:208-213` pins the names |
| SI-104 | The Backend aggregate fails unless every backend job succeeded | `.github/workflows/ci.yml:1303-1360`; `tests/test_ci_workflow.py:200-205` | ci-gate | Adding a job without adding it to the aggregate's needs |
| SI-105 | No path filtering, no duplicate runs, no suppression primitives in CI | `tests/test_ci_workflow.py:57-84,:73-77,:176-195` | boundary-test | Adding `continue-on-error` or a path filter |
| SI-106 | Root-privileged CI jobs fail closed on an untrusted runner | `infra/ci/attest_trusted_ancestry.py:60` (`EXIT_INFRASTRUCTURE_INVALID = 78`) | ci-gate | Weakening the root-owned ancestor rule. **Currently firing on `main`**: `/etc` on `ubuntu-24.04` is uid 1001. This is the control working — do not repair it in an agent PR |
| SI-107 | Secrets cannot be pushed | repo secret scanning + push protection | repo-ruleset | Disabling the setting |

## 2. Corpus completeness

| id | Invariant | enforcedAt | kind | breakableBy |
| --- | --- | --- | --- | --- |
| SI-200 | Sharded corpus == canonical corpus at pytest node level | `scripts/ci/pytest_shards.py:288-325`; `ci.yml:111` | ci-gate | — |
| SI-201 | No unmanaged pytest file outside declared roots | `scripts/ci/pytest_shards.py:130-144`; `.ci/pytest-suite.json:17-25` | ci-gate | Adding a test root without updating the manifest |
| SI-202 | Every authoritative shard runs against real PostgreSQL | `tests/test_ci_workflow.py:102-114` | boundary-test | — |
| SI-203 | Root fences fail closed on skip/under-collection (pytest exit code untrusted) | `ci.yml:214-246, 306-369, 454-488, 668-700, 814-848, 948-980` | ci-gate | `backend-pytest`, the authoritative corpus job, has **no** equivalent JUnit floor — a silent under-collection there is not caught |
| SI-204 | 26 modules skip **silently** without `SECP_TEST_POSTGRES_URL` | pytest skipif markers | convention-only | Treating a local green run as coverage |

## 3. Control-plane API

| id | Invariant | enforcedAt | kind | breakableBy |
| --- | --- | --- | --- | --- |
| SI-300 | API imports no subprocess, provider SDK, IaC tool or worker internals; `httpx` only in `oidc.py`/`oidc_preflight.py` | `tests/test_architecture_boundary.py:27-121` | import-guard | — |
| SI-301 | API may never call plugin `apply`/`reset`/`destroy` | `tests/test_architecture_boundary.py:124,194-209` | boundary-test | — |
| SI-302 | Inline execution only for the exact bootstrapped Simulator instance | `apps/api/secp_api/safety.py:52-104`; `registry.py:116-124` | code-seal | — |
| SI-303 | Inline dispatcher impossible in production | `apps/api/secp_api/dispatch.py:620-628`; `config.py:365-369` | settings-validator | — |
| SI-304 | `EnvironmentVersion` immutable (portable ORM + PG trigger) | `immutability.py:116-132,971-976`; migration `b2c9e5a1f4d7:63-140` | code-seal + db-trigger | Adding a lifecycle table with only one of the two layers |
| SI-305 | `AuditEvent` is append-only; one construction site | `immutability.py:1380-1381,1486-1487`; `audit.py:25` | db-trigger | A second recorder bypassing `audit.py:record()` |
| SI-306 | Plans bind exactly one `EnvironmentVersion`, fail closed | `services/planning.py:74-96`, called at `:386,:416,:448` | code-seal | — |
| SI-307 | `v1alpha2` versions only via the publication service | `services/catalog.py:137-142` | code-seal | — |
| SI-308 | Target-pinned deployment refuses before any workflow work | `services/planning.py:467-501` | code-seal | — |
| SI-309 | Authorization is service-layer; routers never call `require()` | convention across 25 service modules | convention-only | A new router that checks permissions itself looks correct and is wrong |
| SI-310 | A route without `Depends(current_principal)` is silently public | — | convention-only | Nothing enumerates allowed public routes |
| SI-311 | Production config hard-refusal (9 unsafe settings) | `config.py:348-429` | settings-validator | `enable_real_provisioning` is **absent** from the refusal list — only `enable_fake_provisioning` and `enable_opentofu_subprocess` are covered |

## 4. Authentication

| id | Invariant | enforcedAt | kind | breakableBy |
| --- | --- | --- | --- | --- |
| SI-400 | Bearer verified first, never falls back to dev | `deps.py:104-118` | boundary-test | — |
| SI-401 | Fixed RS256 allowlist | `oidc.py:45,239-240,252` | code-seal | — |
| SI-402 | No just-in-time user provisioning | `auth.py:132-136` | boundary-test | — |
| SI-403 | Token claims grant nothing; org/roles/permissions come only from DB | `auth.py:104-139` | boundary-test | — |
| SI-404 | Dev fallback structurally impossible in production | `config.py:343-346,360-364` | settings-validator | — |
| SI-405 | Production CORS empty; no wildcard in any environment | `config.py:420-424,109-130,431-439` | settings-validator | — |
| SI-406 | Every auth failure is closed and redacted | `errors.py:268-294`; `main.py:94-100` | code-seal | — |

## 5. Worker, provisioning and providers

| id | Invariant | enforcedAt | kind | breakableBy |
| --- | --- | --- | --- | --- |
| SI-500 | OpenTofu real subprocess unconstructible | `provisioning/process_executor.py:123` `_B1A_SUBPROCESS_SEALED = True`, raising `:193` | code-seal | Flipping the literal |
| SI-501 | Activation factory always returns the fake executor | `provisioning/activation.py:31,58-60` | code-seal | Flipping the literal |
| SI-502 | Shipped plan-execution composition disabled and empty | `plan_gen/composition.py:80,137-145`; asserted `apps/api/tests/test_plan_execution_components.py:78-86` | code-seal + boundary-test | — |
| SI-503 | `apply`/`destroy` absent from the plan-only grammar | `plan_gen/process_boundary.py:96-118,143-217` | code-seal | Adding a subcommand to the grammar |
| SI-504 | Operator worker cannot start | `apps/deployment/secp_operator_deployment/runner.py:29,55-60` | code-seal | — |
| SI-505 | Queue separation: ordinary `secp-orchestration` vs operator `secp-controlled-live-v1` | `apps/worker/secp_worker/main.py:201-206` (only queue binding) | settings-validator | Constructing a second `Worker(...)` |
| SI-506 | Only `ssh_channel.py` may spawn a subprocess for host contact | `ssh_channel.py:23,29-30` | boundary-test | — |
| SI-507 | Discovery package is architecturally mutation-incapable | `tests/test_discovery_boundary.py:26-103` | import-guard | — |
| SI-508 | Proxmox transport GET-only, path-allowlisted before any request | `readonly_policy.py:221-235,93-98` | code-seal | Widening the allowlist = provider mutation |
| SI-509 | Mutating Proxmox capabilities refuse before any request | `plugins/proxmox/.../plugin.py:149-159` | boundary-test | — |
| SI-510 | Plugins never import control-plane internals | — | convention-only | **No test exists.** Only `secp_management` imports are covered |

## 6. Management plane

| id | Invariant | enforcedAt | kind | breakableBy |
| --- | --- | --- | --- | --- |
| SI-600 | `apps/api` must not import `secp_management` | `tests/test_pr5h_architecture_guards.py:258-264` | boundary-test | — |
| SI-601 | `apps/management` must not import `secp_api` or `secp_discovery_activation` | `tests/test_pr5f_discovery_activation_boundary.py:244-262` | boundary-test | — |
| SI-602 | Management installer stays local-first (no provider/IaC/SSH/subprocess) | `tests/test_management_plane_boundary.py:100-104` | boundary-test | — |
| SI-603 | Management plane is provider-neutral | textual scan `tests/test_pr5h_architecture_guards.py:23-74` **plus** structural `apps/management/tests/test_provider_neutrality.py:30-190` | boundary-test | — |
| SI-604 | Every mutation requires `--write` AND `--confirm` | `transaction.py:25-41` `WriteGate` | code-seal | — |
| SI-605 | Shipped adapter composition is sealed (5 `Sealed*` classes) | `adapters.py:335-428`; `finalization.py:264-300` | code-seal | Widening `EngineDeps` defaults |
| SI-606 | Only three exact systemd unit paths are writable | `layout.py:274-283` | code-seal | — |
| SI-607 | Managed writes confined to owned roots; 14 forbidden system roots | `layout.py:24-39,285-304` | code-seal | — |
| SI-608 | Four safety seals must be intact before any bootstrap write | `topology.py:80-111` `SealState`/`read_seals`; enforced `engine.py:514-515,:57x` | code-seal | — |
| SI-609 | Real leaves constructed only by `production.py` from root-owned files | `production.py:181-200` | code-seal | Unconditional hard-deny to edit |

## 7. Schema and migrations

| id | Invariant | enforcedAt | kind | breakableBy |
| --- | --- | --- | --- | --- |
| SI-700 | Exactly one Alembic head | `apps/api/tests/test_pr5h_schema_parity.py:203-206` | boundary-test | **Not detectable across branches** — see SI-701 |
| SI-701 | Branching heads are invisible to CI | — | convention-only | Two branches with the same `down_revision` both pass; the break appears only after the second merge. Mitigation: one live migration contract repo-wide |
| SI-702 | Live database head required before any enrollment operation | `worker_enrollment_schema.py:42-67` | code-seal | Forgetting to advance `RUNTIME_REQUIRED_MIGRATION_HEAD` is a silent production-only failure |
| SI-703 | PR5F Ed25519 rollback write fence (named CHECK), installed on upgrade AND downgrade | migration `d8f1a2b3c4e5:52,197-203,210-222` | db-constraint + alembic-fence | The same DDL exists in two places (`discovery_activation_rollback_fence.py:27` and the migration) and can diverge |
| SI-704 | Single-use enrollment invitation nonce | migration `b6e2f4a9c1d7:99,115-124` | db-constraint | — |
| SI-705 | Append-only enrollment revision history | migration `b6e2f4a9c1d7:208-212` | db-constraint | — |
| SI-706 | Exactly one ACTIVE controller identity | migration `c2f8e1a4b6d9:57,61-65` | db-constraint | Uses a *second* single-active idiom (`active_marker` + plain UNIQUE) rather than the established partial unique index — do not propagate |
| SI-707 | CHECK parity is compared **by name only** | `test_pr5h_schema_parity.py` | boundary-test | A silently divergent predicate passes in both directions |

## 8. Frontend

| id | Invariant | enforcedAt | kind | breakableBy |
| --- | --- | --- | --- | --- |
| SI-800 | Session-scoped tokens only; no localStorage/IndexedDB/cookies | `apps/web/src/auth/boundary.test.ts:40-47` | boundary-test | A direct `fetch()` bypassing the client seam |
| SI-801 | `sessionStorage` only through the reviewed seam | `boundary.test.ts:49-54` | boundary-test | — |
| SI-802 | No refresh token, no silent renewal | `boundary.test.ts` | boundary-test | — |
| SI-803 | Production API base is same-origin | `api/client.ts` `resolveApiBase` | boundary-test | — |

## 9. Cross-cutting content and documentation

| id | Invariant | enforcedAt | kind | breakableBy |
| --- | --- | --- | --- | --- |
| SI-900 | No real endpoint, host or public IP in any authored file (incl. `docs/`) | `tests/test_no_real_endpoints.py:22-92` | ci-gate | — |
| SI-901 | `.env` gitignored; `.env.example` placeholders only | `tests/test_compose_config.py:78-93`; `.gitignore` | boundary-test | — |
| SI-902 | Dev Compose may contain only development-safe services | `tests/test_compose_config.py:19-75` | boundary-test | The forbidden-token scan inspects only resolved `image` and `command` |
| SI-903 | STATUS/README truthfulness markers | `tests/test_project_status_truthfulness.py:33-170` | boundary-test | **Checks marker presence, not freshness.** STATUS.md is two shipped milestones behind HEAD and this guard did not notice. Mitigated by `.claude/hooks/session_start_orient.py` |
| SI-904 | Charter §6 invariants amendable only via approved ADR | `docs/PROJECT_CHARTER.md:355` | convention-only | Prose only; no test |
| SI-905 | Environment workloads must not reach management, corporate or public networks by default | Charter Invariant 17 | convention-only | The containment boundary for a platform whose payload is deliberately vulnerable systems and offensive tooling. Any change that could breach it is an architecture escalation |
