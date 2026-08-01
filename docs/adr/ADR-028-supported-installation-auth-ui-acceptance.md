# ADR-028 — Supported installation, operator authentication, enrollment UI, and two-host acceptance (SECP-PR5H-B2)

- **Status:** Accepted (SECP-PR5H-B2)
- **Supersedes/extends:** [ADR-025 management-plane bootstrap](ADR-025-management-plane-bootstrap.md), [ADR-026 automated management bootstrap and enrollment](ADR-026-automated-management-bootstrap-and-enrollment.md), [ADR-027 durable worker-enrollment foundation](ADR-027-durable-worker-enrollment-foundation.md), [ADR-017 OIDC bearer](ADR-017-oidc-bearer-authentication.md), [ADR-018 browser PKCE](ADR-018-oidc-browser-pkce-authentication.md), [ADR-019 production OIDC](ADR-019-production-oidc-deployment-operations.md).
- **Predecessor merged:** PR #64 (SECP-PR5H-B1) squash-merged to `main` at `5e6fd8b9e715e339cf3cbd198faa61d8ffdb4d83`; sole Alembic head `c2f8e1a4b6d9`.

## 1. Context

PR5H-B1 delivered the *mechanisms* of supported worker enrollment but left them **sealed or unwired**: the evidence-driven exchange API, the authenticated worker exchange, the root-gated UDS signer broker, and the `secpctl` enrollment commands are all present, but no supported install composition turns them on, and operator authentication consumes only a protected token *file*. This ADR records the decisions for the customer-facing installation, authentication, UI, and acceptance path that makes automatic controller→worker enrollment operable end to end.

### 1.1 Inherited seams (verified by Phase-1 discovery — reuse, do not reinvent)

| Concern | Existing seam (path :: symbol) | State today |
|---|---|---|
| Management CLI | `apps/management/secp_management/cli.py` :: `build_parser`/`_dispatch`/`run`/`main` | verbs `release/host/bootstrap/adopt/status/evidence/rollback/enrollment/worker`; `WriteGate` (`--write --confirm`, dry-run default) |
| Install engine | `engine.py` :: `bootstrap`/`adopt`/`_write_transaction`/`EngineDeps`/`_build_controller_plan`/`_run_controller_ops` | one transactional engine with receipt + compensation + `recovery_required`; `EngineDeps` shipped **sealed** |
| Real deps composer | `production.py` :: `production_engine_deps()` | the **only** real-deps composer; **never wired into `cli.run`** (called by tests only) — the central gap |
| Fixed paths / unit allowlist | `layout.py` :: `ManagementLocations`/`assert_unit_writable` | exactly 2 unit paths permitted (controller-stack, operator-worker) |
| Hardened units | `systemd.py` :: `render_service_unit`/`render_enrollment_signer_broker_service`/`render_operator_unit_disabled` | broker unit renders **disabled** and is never installed |
| Real host adapters | `real_adapters.py` :: `RealControllerBootstrapAdapter`/`RealWorkerBootstrapAdapter`/`RealManagementHostObserver`/`RealManagementRollbackAdapter` | present; sealed defaults in `adapters.py` |
| Hardened filesystem | `secp_commissioning/runtime.py` :: `RealFilesystem` (`exclusive_install`/`atomic_install`/`remove_created_file`/`created_file_matches`/`safe_read`) | dir-fd/`O_NOFOLLOW`, trusted-ancestor, `O_EXCL`, `renameat2 RENAME_NOREPLACE` |
| Enrollment key | `controller_enrollment_signer.py` :: `prepare_controller_enrollment_key`/`rotate_controller_enrollment_key`/`CONTROLLER_ENROLLMENT_KEY_PATH` | crash-safe; **no production caller** |
| Identity activation | `services/controller_identity.py` :: `activate_controller_identity(VerifiedControllerIdentity)` | reachable only via dev factory `controller_identity_dev.build_test_verified_controller_identity` — **no production producer** |
| Signer DB role | `enrollment_signer_identity.py` :: `ENROLLMENT_SIGNER_DB_ROLE`/`ENROLLMENT_SIGNER_DB_GRANTS` | constants only; **no provisioning caller** |
| UDS broker | `enrollment_signer_broker.py` :: `build_production_broker`/`bind_broker_socket`/`PeerCredentialPolicy(allowed_peers=…)` | composable; **no `__main__` serve entrypoint, no fixed `BROKER_ENTRYPOINT`** |
| API signer enablement | `api/config.py` :: `enrollment_signer_enabled` → `build_enrollment_offer_signer` | env flag; off by default |
| Controller-API locator | `controller_api_locator.py` :: `record_controller_api_locator`/`ControllerApiLocator` | sealed until the file is recorded |
| Worker key seam | `secp_worker/enrollment_driver.py` :: `WorkerEnrollmentKeySeam`/`SealedWorkerEnrollmentKeySeam` | only sealed |
| Worker health | `enrollment_driver.py` :: `WorkerHealthProbes`/`LocalWorkerHealthObserver`/`SealedWorkerEnrollmentHealthObserver` | orchestrator + Protocol exist; **no concrete 11-probe set** |
| Worker restart store | `enrollment_driver.py` :: `SealedWorkerEnrollmentStateStore`(default)/`InMemory…`(tests) | **no fixed-path hardened store**; `build_worker_enroller` wires the in-memory one |
| Worker transport | `enrollment_http_transport.py` :: `HttpxWorkerEnrollmentTransport`/`SealedEnrollmentTransport`/`EnrollmentInvitationInputs` | pinned client; sealed factory default |
| Worker enroller | `worker_enroller.py` :: `build_worker_enroller`; `enrollment_cli.py` :: `WorkerEnroller`/`SealedWorkerEnroller` | all-sealed composition |
| Operator auth | `operator_auth.py` :: `OperatorAccessTokenProvider`/`ProtectedTokenFileProvider`/`OperatorAccessToken`/`OPERATOR_TOKEN_FILE_ENV` | token **file** only; POSIX-only |
| OIDC verify | `api/oidc.py` :: `OidcVerifier`/`get_oidc_verifier` | **verify-only** (no token acquisition anywhere) |
| Frontend | `apps/web` :: `main.tsx` router, `components/shell/nav.ts`, `api/client.ts`, `api/types.ts`, `AuthBoundary`, permission helpers | **no enrollment view/route/nav/client** |
| Acceptance | `test_management_controller_real_adapters_root.py`, `test_management_real_adapters_root.py`; `tests/oidc_helpers.build_verifier`; `*_postgres.py` fences | single-host E2Es; **no two-host harness**; deterministic FakeIdp available |

### 1.2 Gaps B2 must ADD (no existing seam)

1. Wire `production_engine_deps()` into `cli.run`/`main` for `bootstrap/adopt/status/evidence/rollback` (mirroring `_production_enrollment_deps`), sealed-fallback on any `ManagementError`.
2. Root-gated **producer of `VerifiedControllerIdentity`** that builds the proof from the prepared enrollment key + reviewed bootstrap evidence, then calls `activate_controller_identity`.
3. Controller-install wiring of `prepare_controller_enrollment_key`, `record_controller_api_locator`, the signer DB role/grants, and the **broker unit** (renderer → `ReviewedUnit` → `install_broker_unit` op → `layout` fixed path + `assert_unit_writable` + `BROKER_ENTRYPOINT` constant + `wanted_by="multi-user.target"`).
4. Real worker seams: fixed-path crash-safe `WorkerEnrollmentKeySeam`, concrete 11-method `WorkerHealthProbes`, fixed-path hardened `WorkerEnrollmentStateStore` (the `secp_worker.health` idiom), production `transport_factory` with a deployment-local CA-bundle path — wired inside `build_worker_enroller`.
5. `secpctl auth login|status|logout` — OAuth 2.0 **Device Authorization Grant** acquisition + a **typed OS credential store** (`OperatorCredentialStore` implementing `OperatorAccessTokenProvider`), both sealed-by-default; a device-capable public CLI client enabled in the dev Keycloak realm.
6. Minimal **Enrollment/Workers** UI (route, nav, typed API client, RBAC gates) consuming the three supported endpoints.
7. A **two-host** root-gated acceptance harness + its no-skip CI job (and any needed PG fence), registered in the `backend` aggregate gate.

## 2. Decision

**Extend the existing management engine and command family; add every new production behaviour behind a sealed-by-default seam composed only in `production.py`; never select behaviour by an arbitrary CLI/env argument.** The nine customer capabilities map onto supported verbs; no capability requires manual JSON, digests, keys, systemd files, SQL, CA placement, UDS config, Compose edits, offer/result copying, raw DB, or remote root SSH.

### 2.1 Command surface (final)

Repository convention uses `secpctl <verb> <role>`. B2 delivers:

| Customer intent | Supported command | Basis |
|---|---|---|
| Install controller | `secpctl bootstrap controller --write --confirm` | EXTEND `engine.bootstrap` (wire real deps + enrollment seams) |
| Upgrade controller | `secpctl upgrade controller --to <release> --write --confirm` | NEW verb → release-bound re-run of the controller transaction |
| Verify controller | `secpctl status controller` / `secpctl verify controller` | EXTEND `engine.status` + a read-only composition proof |
| Uninstall controller | `secpctl rollback controller --write --confirm` (+ `uninstall` alias) | EXTEND `engine.rollback` to compose FS + service + identity/locator/broker teardown |
| Operator login | `secpctl auth login` | NEW — device grant → credential store |
| Auth status / logout | `secpctl auth status` / `secpctl auth logout` | NEW |
| Install worker | `secpctl install worker --invitation <file> --write --confirm` | EXTEND worker bootstrap + `build_worker_enroller` real seams |
| Upgrade / verify / uninstall worker | `secpctl upgrade worker` / `verify worker` / `uninstall worker` | NEW/EXTEND, symmetric to controller |

Every mutating verb keeps the `WriteGate` (`--write --confirm`, dry-run default). Root entrypoint is required only for install/upgrade/uninstall; the browser/API never performs a root install.

### 2.1a Phase 2b clean-host installation blocker (authorized STOP — 2026-07-27)

Implementability discovery over the merged code established that a **clean-host** root controller
install cannot prepare all required production inputs from **authenticated / code-owned** sources
with the merged release contract. Per the Phase-2b stop protocol (missing signed artifact / no
code-owned API-TLS source / no reviewed DB-credential channel → **stop and report; never manufacture
an unsigned value, env fallback, or manual operator step**), Phase 2b's *clean-host installation
composition* is **paused pending the reviewed release-governance changes below**. The engine
transaction extension and the enrollment-finalization *scaffolding* are implementable and unblocked,
but they cannot yield a functioning clean-host install until the foundational inputs exist.

Corrected classification (2026-07-27): only **c** is a genuine hard governance blocker; **a**, **e**, **db** are implementable via the release-governance + deployment-policy + installer foundations below (see §2.1b). Phase 2b as a whole is **not** architecturally blocked once those implementable portions land.

| # | Required input | Exact existing source | Classification & smallest safe path |
|---|---|---|---|
| **c** | the release-signing **public** anchor that verifies the signed bundle | `signing.py :: SHIPPED_TRUST_ROOT = ReleaseTrustRoot(anchors=(), test_only=False)` — **EMPTY**; manifest carries only `signing_anchor_id` (key_id) | **GENUINE HARD GOVERNANCE STOP.** Requires an **explicitly reviewed public anchor** (fingerprint approval); **no production private key may enter the repo**. Installer code + tests use an **injected reviewed test trust root**; only committing the real candidate public anchor to `SHIPPED_TRUST_ROOT` requires approval. |
| **a** | host container/compose/service-manager executable pins | `production.py :: _load_executables/PinnedExecutables` | **IMPLEMENTABLE** — a signed, versioned **host-runtime profile** in the v1alpha2 manifest (logical capability + closed invocation shape + absolute path + SHA-256 + closed subcommand surface). Not an undefined artifact kind. |
| **e** | controller API TLS + canonical origin | `config.py :: public_origin ← SECP_PUBLIC_ORIGIN` (env); API terminates no TLS (external edge) | **IMPLEMENTABLE** — deployment-specific values are **never** in a generic release. The release signs a **closed TLS policy** (allowed modes `generated_local_ca`/`imported_enterprise_tls`, algorithms, validity/SAN/EKU/CA-constraints/min-TLS, fixed paths). The **root installer** creates or imports the actual deployment-local TLS identity (via a narrow `--public-origin` + `--tls-mode`) and binds it into authenticated management evidence. |
| **db** | `secp_enrollment_signer` DB authentication for the root broker | containerized Postgres/TCP + DSN password; broker runs as root on host | **IMPLEMENTABLE** — a dedicated **LOGIN** role (`NOSUPERUSER/NOCREATEDB/NOCREATEROLE`, owns nothing, `CONNECT`+`USAGE`+`SELECT`-only on the identity table, advisory-lock op) with a high-entropy SCRAM password minted at install and stored **only** as a fixed root-owned **systemd credential** (0600) for the broker, which connects **directly** as that role. **Rejected: NOLOGIN + `SET ROLE` over an administrator connection** — the underlying connection retains administrator capability, so `RESET ROLE` would restore it; it is not a real least-privilege boundary. |

### 2.1b Phase 2b unblock sequence (release-governance + deployment-policy + installer foundations)

- **2b-1 — versioned release contract + offline release authority.** Introduce `secp.management-bootstrap/v1alpha2` (legacy `v1alpha1` stays readable for upgrade/rollback; a bounded, closed compatibility window; clean-host B2 installs require v1alpha2; a v1alpha1 bundle lacking the B2 profile refuses B2 with a bounded reason). The v1alpha2 manifest adds a signed **platform profile**, a signed **host-runtime executable-pin profile**, and a signed **controller TLS policy** (all provider-neutral, no deployment-specific value). A distinct **offline** `secp-release-authority init|build|sign|verify` tool (no network; private key never in Git; protected out-of-repo 0600 key; separate public anchor; deterministic canonical manifest). `SHIPPED_TRUST_ROOT` is **not** populated in this commit; a candidate keypair may be generated by the tool and its **public** key/fingerprint reported for approval.
- **2b-2 — deployment-local TLS/runtime inputs + dedicated broker DB credential.** A narrow root-only `--public-origin` (canonical HTTPS origin; never a runtime override); `generated_local_ca` and `imported_enterprise_tls` producers at fixed code-owned paths (CA/server keys 0600, public material 0644; verify chain/validity/EKU/SAN/policy before activation); an upgraded locator binding installation ID/identity/origin/release/mgmt+evidence digests/CA digest/timestamp with the CA at a fixed `ManagementLocations` path; and the dedicated **LOGIN** signer role + systemd credential, proven by a real-PostgreSQL fence (dedicated-role login, lease/advisory-lock serialization, unrelated reads/writes refuse, `RESET ROLE` cannot yield admin, rotation, uninstall drops role+credential, zero skips).
- **2b-3 — controller enrollment finalization.** The closed typed `ControllerEnrollmentFinalizationPlan` + sealed-by-default `ControllerEnrollmentFinalizationAdapter` (typed receipts + compensation; no dict/callback) driven by the existing controller bootstrap transaction; activation is the final identity switch after all candidate dependencies verify; a failure after activation transactionally restores the prior identity or yields `recovery_required` with exact residual classification.

Tests throughout use **ephemeral test trust roots**; the only required stop is before committing the real candidate public anchor into `SHIPPED_TRUST_ROOT`.

### 2.2 Controller installation state machine

```
absent
  └─(bootstrap --write --confirm, root)→ PREPARING
PREPARING: release-verify → migrate(to a1d4f7c2e9b6) → provision signer DB role/grants
  → prepare_controller_enrollment_key (0600 root) → build VerifiedControllerIdentity → activate_controller_identity
  → record_controller_api_locator(origin,ca) → render+install broker unit (disabled→enabled) → render+install API/stack units
  → daemon-reload → enable API signer client → start (ordering: db → broker → api → stack) → REOBSERVE
REOBSERVE: coherent? ──no──→ COMPENSATE → (prior valid install | recovery_required)
           └─yes→ COMMIT → INSTALLED  (idempotent rerun = adopt; upgrade = release-bound re-run)
any-op failure → COMPENSATE(only-this-transaction's-artifacts) → prior-valid | recovery_required
```

Identity is written **first**, evidence/attestation **last** (matches `_write_transaction`); a partial transaction can never leave an active controller identity without a usable signer key, nor a broker unit without its 0600 key.

### 2.3 Worker installation state machine

```
absent
  └─(install worker --invitation <file> --write --confirm, root)→ PREPARING
PREPARING: release-verify → prepare worker enrollment key (0600) → compose fixed-path restart store
  → compose real WorkerHealthProbes + LocalWorkerHealthObserver → compose pinned transport (deployment CA)
  → render+install ordinary worker unit → ensure operator-worker unit present-but-DISABLED+STOPPED
  → import invitation (strict, non-secret) → ENROLL (bind → offer verify → observe health → result) → RECONCILE
RECONCILE: controller-authoritative state==healthy? ──no──→ report bounded state (never fabricate)
           └─yes→ COMMIT marker → HEALTHY
any-op failure → COMPENSATE(only-this-transaction's-artifacts) → prior-valid | recovery_required
```

The worker performs **outbound HTTPS only**; all controller identity/trust comes from the invitation; the operator never copies an offer/result/digest/key.

### 2.4 Upgrade & rollback contracts

- **Upgrade** is **release-bound**: `--to <release>` verifies the new reviewed release, re-runs the transaction, and is idempotent (adopts an already-current install). It never rotates the enrollment identity/key unless a rotation is explicitly requested and reviewed. A failed upgrade rolls back to the prior valid release (`atomic_install` guarantees either the old or the new artifact, never a partial).
- **Rollback/uninstall** owns and removes **only artifacts this install transaction created** (tracked by `RealFilesystem` receipts + the engine's created-artifact ledger): units, config, the locator, the signer socket, the enrollment key(s), the signer DB role, and the recorded identity/evidence documents. It never deletes pre-existing host state, and a failed compensation surfaces a *distinct* bounded code (never a silent partial teardown).

### 2.5 Secret ownership matrix

| Secret / material | Created by | Stored at | Owner:mode | Read by | Deleted by | Never on |
|---|---|---|---|---|---|---|
| Controller enrollment private key | `prepare_controller_enrollment_key` (root) | `/var/lib/secp/bootstrap/controller-enrollment-signing.key` | `root:root 0600` | broker (root) only | controller uninstall | PostgreSQL, HTTP, logs, audit, evidence, API image |
| Signer DB role password | controller install (root) | out-of-band DB grant / bootstrap secret | DBA-scoped | broker DB engine | controller uninstall | HTTP, logs, repo |
| Worker enrollment private key | worker key seam (root) | fixed worker key path | `root:<worker> 0600` | worker signer only | worker uninstall | controller, HTTP, logs |
| Operator OIDC access/refresh token | `secpctl auth login` (device grant) | OS credential store (sealed default) | OS-keyring, operator account | `HttpsEnrollmentControllerClient` bearer | `auth logout` | argv, env, logs, telemetry, shell history, JSON/human output |
| Invitation (non-secret) | controller (`enrollment invite create`) | operator-chosen file, then worker import | operator-readable | worker driver | — | (public material; no secret) |

### 2.6 Process / user / group / mode matrix

| Component | User:group | Privilege | Transport |
|---|---|---|---|
| `secpctl bootstrap/upgrade/uninstall` | root | install-time only | local FS + Compose |
| Controller API / stack | `secp` non-root (uid/gid 10001) | none root | inbound HTTPS; UDS client → broker |
| Signer broker | root | reads 0600 key; SO_PEERCRED gate | AF_UNIX only (no TCP) |
| Signer DB role | `secp_enrollment_signer` | CONNECT+USAGE+SELECT only | PG |
| Worker service | non-root worker | none root | outbound HTTPS only |
| Operator-worker unit | (present) | **disabled + stopped** | none (sealed) |

### 2.7 Installed-artifact inventory (controller)

`secp-controller-stack.service`; `secp-enrollment-signer-broker.service` (enabled); Compose config; `/run/secp/enrollment-signer.sock` (root:`secp` 0660, code-owned); `/var/lib/secp/bootstrap/controller-enrollment-signing.key` (0600); the controller-API locator file (`/etc/secp/controller/api-locator.json`); the `secp_enrollment_signer` PG role + grants; the persisted ACTIVE `controller_enrollment_identity` row; the reviewed bootstrap identity/evidence/release/attestation documents. **Worker:** ordinary worker service unit; worker enrollment key (0600); fixed-path restart-state marker; imported invitation; the operator-worker unit present-but-disabled.

### 2.8 Failure-compensation matrix (per op)

| Op | On failure | Compensation | Distinct code on compensation failure |
|---|---|---|---|
| migrate | abort before any identity write | none needed (transactional) | — |
| provision DB role | drop only if this tx created it | `DROP OWNED BY` + `DROP ROLE` | `signer_role_compensation_failed` |
| prepare key | remove only the created 0600 file | `remove_created_file(receipt)` | `enrollment_key_compensation_failed` |
| activate identity | not committed until reobserve | savepoint rollback | `identity_activation_failed` |
| record locator | remove only the created file | `remove_created_file` | `locator_compensation_failed` |
| install unit(s) | remove only created units + daemon-reload | `remove_created_file` + reload | `unit_compensation_failed` |
| start | stop only what this tx started | service stop | `service_stop_failed` |

## 3. Interactive OIDC device-authorization contract (Phase 4)

`secpctl auth login` uses the **OAuth 2.0 Device Authorization Grant** (RFC 8628) against the controller's *reviewed* OIDC authority (discovered from the recorded controller/OIDC config — **no arbitrary issuer override in production**). It displays bounded verification URI + user code; polls with the server-provided interval honouring `authorization_pending`/`slow_down`, with a bounded timeout + cancellation; verifies issuer/audience/signature/expiry/required claims and the org+role/permission mapping; and persists the resulting `OperatorAccessToken` into the credential store. No password is ever collected; no token appears in argv/env/logs/telemetry/output. `auth status` shows the resolved operator principal (no token); `auth logout` deletes only owned credential material; expired/revoked credentials fail closed. If the configured provider does not advertise device grant, `auth login` reports the exact provider limitation and does **not** fall back to a password grant.

### 3.1 MVP production host and controller-trust posture

Production authenticated enrollment commands are supported only from the **trusted POSIX,
controller-local management posture**. The controller bootstrap records the canonical HTTPS origin
and reviewed CA-bundle path in the fixed root-owned locator, and `secpctl` reads that locator through
the POSIX hardened filesystem seam. The invocation-pinned locator guarantees that the HTTPS
destination, CA source and credential account observe one immutable controller identity during a
command. That consistency property does not provision or authenticate a trust root by itself.

PR5H-B2 deliberately does **not** invent a Windows locator or CA-provisioning workflow. The Windows
Credential Manager binding remains implemented, fail-closed and genuinely exercised end to end on
the Windows developer host, but that is assurance of the **credential backend only**. Windows
end-to-end authenticated controller access is not production-supported until a separate reviewed
workflow provisions and protects both the controller locator and CA bundle on Windows. No operator
may supply a replacement URL, CA path, issuer or trust override.

| Host / backend | Credential-backend assurance in this repository | MVP production authenticated controller access |
|---|---|---|
| Windows / Credential Manager | `live` on the Windows developer host: the real ctypes binding round-trips against the real Credential Manager | **Not production-supported.** No reviewed Windows locator + CA provisioning workflow exists. |
| macOS / Keychain | `stand_in`: binding logic runs against a documented substitute; this is not verification of the real frameworks. A read-only status can still prompt on a locked Keychain. | Only the trusted POSIX/controller-local posture is in scope; no macOS live-keystore or end-to-end host claim is made. |
| Linux / Secret Service | `stand_in`: binding logic runs against a documented substitute; this is not verification of the real library. Headless Ubuntu CI has no session D-Bus and exercises no live OS keystore. | Supported only on the trusted POSIX/controller-local management host when the bootstrap locator/CA and a reachable OS keystore are present; otherwise it refuses closed. |

## 4. OS credential storage contract (Phase 5)

A typed `OperatorCredentialStore` implements `OperatorAccessTokenProvider` with: a **sealed default**; Windows Credential Manager, macOS Keychain and Linux Secret Service bindings; bounded account/service identifiers; access+refresh lifecycle; non-serializable + constant redacted repr (the `OperatorAccessToken`/`ProtectedTokenFileProvider` posture); atomic replacement; explicit logout deletion; expiry validation; concurrency safety. A backend's availability or live backend test is not an end-to-end controller-trust claim; the production host posture remains §3.1. The protected token **file** remains only as a sealed/test/recovery seam. **No silent plaintext fallback**: if no supported backend is present, return a bounded setup error with the installation requirement. Tests use a fake store; never real tokens.

## 5. Minimal enrollment UI contract (Phase 6)

One **Enrollment / Workers** view (route under `AuthBoundary`, nav item, typed client in `api/client.ts` + types in `api/types.ts`) that lists enrollments by org; shows site/state/revision/creation/expiry/bounded status; creates an invitation; presents the **non-secret** invitation for supported transfer/download; copies only public material; revokes; shows recovery-required/refused; refreshes/reconciles; and gives a clear next action. It never exposes private keys, bearer tokens, raw attestations, internal state digests, transaction internals, or DB identifiers. RBAC: `enrollment:read` gates viewing, `enrollment:manage` gates create/revoke; the API remains authoritative (no frontend-only enforcement). Uses the existing design system; adds accessibility/loading/empty/error/expired states. No app-wide redesign.

## 6. Two-host acceptance contract (Phase 7)

One root-gated, explicitly-enabled harness with a controller host + worker host + real PostgreSQL + real migration + real service units (or the closest existing isolated production adapter) + real root FS posture + non-root API + real UDS broker + real signer role + real HTTPS cert/CA + a deterministic device-auth provider (`tests/oidc_helpers.build_verifier`/dev Keycloak) + a credential-store test adapter + real worker outbound exchange + restart + rollback. It proves the 19 numbered steps (clean controller install → verify → operator device login → invite → clean worker install → auto-enroll to healthy → controller/worker restart mid-exchange → exact lost-response recovery → status via secpctl + UI/API → revoke → re-enroll → controller/worker upgrade → failed-upgrade rollback → worker uninstall → controller uninstall → **zero residual** keys/credentials/sockets/services/roles/locator/DB state) **and** zero provider calls / OpenTofu ops / operator activation / controlled-live workflows / operator-queue polling / remote root SSH. No proof may pass because a required action was skipped (fail-closed JUnit no-skip gate).

## 7. Non-goals / prohibitions (preserved)

B2 introduces **no** Proxmox/cloud/Kubernetes mutation, OpenTofu apply/destroy, Ansible workload config, provider credentials, operator-worker activation, controlled-live workflow submission, provider-discovery expansion, PR6 behaviour, remote root SSH from HTTP/UI, arbitrary shell execution, or arbitrary root filesystem operations. All current seals + queue separation are preserved. Sole Alembic head is now `a1d4f7c2e9b6` — the C3 controller-identity activation-receipt migration, the one genuinely required new head, a linear successor of `c2f8e1a4b6d9` (no branch).

## 8. Completion & acceptance gates

Ready only when **all** hold: controller + worker installs are automated and idempotent; production enrollment seams compose without manual wiring; interactive OIDC login works; OS credential storage works with no plaintext fallback; the minimal UI works with correct RBAC; the two-host install/enroll/restart/revoke/re-enroll passes; upgrade + rollback pass; uninstall proves zero residual owned state; exact-head CI is green; root + PostgreSQL fences run with zero skips; no unresolved HIGH/MEDIUM findings; all review threads resolved; the PR body is truthful; the worktree is clean; `stash@{0}` unchanged; and the provider/operator/OpenTofu/controlled-live prohibitions remain intact. **Green CI alone is never sufficient** — the review threads are the completion authority.
