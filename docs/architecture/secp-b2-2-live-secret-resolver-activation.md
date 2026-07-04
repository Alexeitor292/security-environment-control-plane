# SECP-B2-2 — Live Secret Resolver Activation Design and Evidence Contract

**Status:** Design and static-contract only. **Nothing here is enabled, wired, or implemented.**
This document defines the non-negotiable approval, evidence, runtime-binding, replay, and rollback
contract that a **future** production, worker-only secret resolver must satisfy before it may be
implemented, reviewed, or activated. It adds no secret backend, no secret-manager client, no
environment/file/Docker/database secret resolution, no HTTP/socket/subprocess/provider activity,
no live enablement switch, and no infrastructure or deployment configuration.

It does not add, and forbids adding, any real value: hostname, IP, URL, port, cluster/node/storage/
bridge/VLAN name, credential, token, password, secret, `secret_ref`, or checksum. Live
configuration lives **outside source control** (an approved secret manager and an operator runbook).

The shipped default remains the SECP-B2-1 `SealedUnavailableResolver`: every read-only preflight
still ends `credential_unavailable`, no transport is constructed, and no collector executes.

## 1. Purpose and scope

SECP-B2-1 shipped the sealed worker-only secret-resolution contract
(`secp_worker.preflight.secret_resolution`): a closed `ResolutionPurpose`, a redacted
`TrustedResolutionRequest`/`ResolutionContract`, opaque non-serializable `SecretMaterial`, a
per-field `assert_resolution_authorized` gate, and a `WorkerSecretResolver` seam whose only
implementation fails closed. This document (SECP-B2-2) is the **activation contract** for a later
implementation PR. It converts the two B2-1 adversarial-review findings into binding obligations,
specifies the authoritative trust anchors, and defines the replay-lease, worker-identity, evidence,
gate, and rollback model. It is design/static-test only; no runtime behavior changes.

## 2. Trust model: a TrustedResolutionRequest is not a capability

**Finding (B2-1 review, high-risk 2).** The B2-1 constructor seal (`_CONSTRUCTION_TOKEN`) is
best-effort: `TrustedResolutionRequest.__new__` plus name-mangled slot assignment can attach an
arbitrary contract without the token, and `dataclasses.replace` can forge a modified frozen
`ResolutionContract`. Static AST guardrails plus worker-only execution are the defense, not object
identity.

**Obligation.** Possession of a `TrustedResolutionRequest` (or a `ResolutionContract`) is never
proof of authorization. The future resolver must treat every request object as untrusted input and
independently re-verify authorization against authoritative records and backend-side policy at
resolution time. No code path may grant resolution because an object is of the right type, carries
the construction token, or passed an earlier gate. The request is a **carrier of claims to be
re-checked**, not a bearer credential.

## 3. Authoritative trust anchors and source of truth

**Finding (B2-1 review, high-risk 1).** In B2-1 the orchestration builds the `request` and the
`expectation` back-to-back from the **same** `VerifiedLiveReadAuthorization`, so
`assert_resolution_authorized(request.contract, expectation)` is self-referential — both sides are
caller-supplied and always match. Its real value is only the pinned-label/expiry/blank-reference
re-check. It is **not** an independent authorization check.

**Obligation.** The future resolver must derive its authoritative expectation from a **source of
truth independent of the request**, at resolution time:

| Authoritative fact | Source of truth (independent of the request) |
|---|---|
| Organization, execution target, onboarding identity | The worker's authoritative database records (`ExecutionTarget`, `TargetOnboarding`), re-loaded at resolution time |
| Live-read authorization identity, version, status, expiry | The `LiveReadAuthorization` record, re-loaded and re-verified via `load_and_verify_live_read_authorization` (SECP-002B-1B-6) |
| Connection-identity hash / boundary hash | Recomputed from the authoritative records (`connection_identity_hash`, onboarding boundary), never taken from the request |
| Collector-contract version, endpoint-allowlist (policy) version | The app-side pinned constants (`LIVE_READ_COLLECTOR_CONTRACT_VERSION`, `PROXMOX_READONLY_POLICY_VERSION`) |
| Credential reference | The authoritative `ExecutionTarget.secret_ref` record (see §4) |
| Backend access decision | The external secret backend's own policy, scoped to the exact target/reference/purpose (see §6) |

The resolver re-runs the SECP-002B-1B-6 verifier itself; it does not accept a caller-built
"expected contract" as the anchor. The request's claimed fields are compared **against** the
independently derived authoritative values, and any divergence fails closed before backend access.

## 4. Credential-reference three-way binding

Before any backend access, the resolver must require exact equality across three independently
sourced references and fail closed on any mismatch:

1. **Authoritative target reference** — `ExecutionTarget.secret_ref` from the re-loaded record.
2. **Verified live-read binding reference** — the credential reference carried by the freshly
   re-verified `VerifiedLiveReadAuthorization` binding.
3. **Resolver request reference** — the opaque `TrustedCredentialReference` in the request's
   contract.

All three must be byte-for-byte identical (constant-time comparison; the reference is an opaque
locator, never hashed, logged, audited, serialized, or exposed via `repr`). Any mismatch, or a
blank reference on any side, yields a fail-closed refusal **before** the backend is contacted. This
prevents a request from redirecting resolution to a different target's reference even if it were
forged past the object seal (§2).

## 5. Replay, retry, and resolution-lease model

The future resolver must acquire a durable, single-purpose **resolution lease** before contacting
the backend, and must never resolve twice for the same operation without a fresh authorization.

### 5.1 Durable uniqueness key vs recorded fields

The **durable uniqueness key** — the boundary that decides single-use, replay refusal, and the
retry budget — is exactly:

```
(authorization_id, authorization_version, operation_fingerprint)
```

This key is **global**: it does not include `worker_identity_id`. Two different worker
identities resolving the same queued operation share the same key and therefore the same single-use
state and the same retry budget; they can never each hold a separate valid pre-success lease for
that operation (see §5.2).

Beyond the uniqueness key, each lease **record** also carries, for binding and audit only (never as
part of the uniqueness boundary): `execution_target_id` + `onboarding_id`; resolution `purpose`
(`readonly_staging_preflight` only); `authorization_expiry` (canonical UTC); and the authenticated
`worker_identity_id` that requested issuance (§6). The `operation_fingerprint` is the secret-free
`sha256:` digest of the preflight work item (per B2-1). The lease record stores **no** `secret_ref`,
credential reference, secret material, endpoint, or provider response — only identities, versions,
the opaque fingerprint, and status.

### 5.2 Global single-use and transactional issuance

- **Single-use is global per uniqueness key.** Once a resolution **succeeds** for
  `(authorization_id, authorization_version, operation_fingerprint)`, that key is marked
  **consumed**; any later resolution attempt for the same key — from **any** worker identity — is
  **refused (`replay_refused`)** and fails closed. Worker identity is required for authenticated
  issuance, backend authorization, and secret-free audit evidence, but it is not part of the
  uniqueness boundary and never permits a separate concurrent lease for the same operation.
- **Transactional issuance (durable CAS).** Lease issuance must use a durable compare-and-swap (a
  conditional insert/update on the uniqueness key, e.g. a unique constraint on
  `(authorization_id, authorization_version, operation_fingerprint)` with an `IntegrityError`
  fail-closed, or an equivalent `FOR UPDATE`-style guard) so that under concurrency **at most one**
  worker obtains a valid pre-success lease for a given key. A worker that loses the CAS is refused
  and fails closed; it never resolves in parallel.

### 5.3 Durable retry budget (fixed N=3)

- The bounded retry limit is **fixed at N = 3** and is counted **durably per
  `(authorization_id, authorization_version, operation_fingerprint)`**, across **every** lease and
  **every** worker identity for that key.
- A fresh lease **must not reset or expand** the retry budget. Acquiring, losing, or re-issuing a
  lease for the same key draws from the same durable, already-consumed attempt count.
- A retry may occur **only** while (a) the authorization has **not** expired and (b) the durable
  per-operation attempt budget remains. Any attempt at/after `authorization_expiry`, or once the
  budget is exhausted, fails closed.
- Once the budget is exhausted, resolution is **refused with a closed, secret-free reason code**
  (`retry_bound_exceeded`) and stays refused **until a new `authorization_version` exists** — a new
  version is a distinct uniqueness key with its own fresh budget. Expiry alone does not grant new
  attempts.
- A lease never outlives the authorization: `lease.expires_at = min(issued_at + short_ttl,
  authorization_expiry)`. An expired lease is not renewable.
- Resolved material (§6) is short-lived, never cached, and never reused across leases, operations,
  or targets.

### 5.4 Durable replay/refusal evidence (secret-free)

Every lease transition is durably recorded as **audit-safe metadata only**: lease id, the uniqueness
key fields, `worker_identity_id`, status (`issued` → `consumed` | `refused` | `expired`),
timestamps, the durable per-operation attempt count, and a closed **reason code** (e.g.
`replay_refused`, `retry_bound_exceeded`, `authorization_expired`, `reference_mismatch`,
`worker_identity_untrusted`, `backend_policy_denied`). The evidence records **no** secret reference
and **no** secret material. This provides a durable, reviewable trail of what was attempted and
refused without ever persisting a resolvable value.

## 6. Worker identity and backend access policy

- **Independently authenticated worker identity.** The worker authenticates to the secret backend
  as its own hardened identity (e.g. workload identity / mTLS), issued and rotated out of band. The
  identity is **not** derived from, shared with, or reachable by the API or UI.
- **Backend policy scoped to exact target/reference/purpose.** The backend's own policy authorizes
  a resolution only for the exact `(worker_identity, reference, target, purpose)` tuple. The backend
  is the final authority; a worker-side pass never overrides a backend denial.
- **No API/UI identity or path.** The API and UI have no credential to the backend and no network
  route to it. Static boundary tests continue to prove the API cannot import resolver code and the
  UI has no credential-entry field or secret-resolution route.
- **Short-lived resolution only; no caching or reusable credentials.** Resolution yields a
  short-TTL credential handed directly to the (future) transport as opaque `SecretMaterial`; it is
  never stored, cached, logged, or reused. Distinct operations resolve distinctly.
- **Rotation and revocation.** A rotated reference resolves the new value only within a valid,
  unexpired authorization; a revoked reference or authorization resolves **closed**. Rotation never
  resurrects an expired authorization or a consumed lease.
- **Fail-closed response mapping.** Every backend outcome maps to a closed, secret-free result:
  backend-unreachable, policy-denied, reference-unknown, revoked, expired, mismatch, and
  retry/replay refusals all map to `credential_unavailable` (or the appropriate closed
  authorization outcome) with a redacted reason code. There is no partial, cached, or
  best-effort success, and no code path returns material outside a valid, single-use lease.

## 7. Fail-closed ordering (unchanged, extended)

The B2-0/B2-1 ordering is preserved and extended; each step must pass before the next:

1. authoritative authorization + binding verification (re-run at resolution time, §3);
2. credential-reference three-way binding (§4);
3. pinned policy/contract-label check;
4. worker-identity authentication + backend policy decision (§6);
5. single-use resolution-lease acquisition (§5);
6. secret-resolution boundary → opaque `SecretMaterial` (future);
7. GET-only, canonicalized transport factory (future);
8. read-only collector (future).

A failure at any step fails closed with a redacted reason code, records secret-free lease/refusal
evidence, and constructs no transport and no collector.

## 8. Activation evidence package (closed checklist)

Before a later implementation PR may be **approved**, the closed evidence package in
`docs/proxmox/live-secret-resolver-activation-checklist.md` must be complete and independently
human-reviewed. It requires, at minimum:

- isolated staging-control-plane identity proof;
- worker-only network-path proof (no API/UI route to the backend);
- backend access-policy review (scoped to exact target/reference/purpose);
- reference-grammar review;
- redaction / log / audit verification (no reference or material leaks);
- transport remains GET-only and canonicalized;
- no production or shared target;
- rollback / kill-switch drill executed and verified;
- independent adversarial review of threat model, code, and tests;
- explicit, time-bound human approval recorded.

The checklist items are a **closed set**: no item may be waived, and no evidence outside the list
substitutes for a listed item.

This resolver-activation checklist and the collector-activation checklist
(`docs/proxmox/live-readonly-collector-activation-checklist.md`) are **cumulative**: both must be
satisfied in full and neither ever substitutes for the other. Enabling a secret resolver does not
authorize collector execution, and enabling a collector does not authorize secret resolution.

## 9. Formal activation gates (defense in depth)

**No single layer may enable live resolution.** Activation requires **all** of the following,
independently:

1. **Code review** — the implementation PR is reviewed and approved.
2. **Separate approval record** — a distinct, durable human authorization record (not the code
   review) binds the activation to one approved target and time window.
3. **Activation-specific configuration outside Git** — backend endpoint, worker identity, and
   policy live only in the out-of-band secret manager / runbook, never in source control.
4. **Staging-only target eligibility** — only a disposable/staging `ExecutionTarget` with an
   approved onboarding boundary is eligible; production/shared targets are refused.
5. **Time-bound authorization** — a short-lived, versioned `LiveReadAuthorization`; expiry fails
   closed.
6. **Resolver health / self-test that reveals no secret** — a liveness/self-test path that proves
   the resolver is wired without resolving, returning, logging, or exposing any secret or reference.
7. **Revocation / rollback path** — a tested kill-switch (§10) that immediately inerts resolution.

Removing or failing any one gate fails closed. The presence of code alone, configuration alone, or
an authorization alone is insufficient.

## 10. Rollback and kill-switch sequence

The activation is reversible at any time. The tested rollback/kill-switch sequence is:

1. **Revoke the out-of-band activation configuration** — remove the worker's backend identity /
   policy binding in the secret manager; the resolver can no longer authenticate → fail closed.
2. **Revoke the authorization** — set the `LiveReadAuthorization` to revoked; the re-verification
   step (§3) fails closed and no lease is issued.
3. **Disable the default-disabled activation gate** — the resolver seam reverts to the sealed
   `SealedUnavailableResolver`; every preflight returns `credential_unavailable`.
4. **Confirm inert** — a self-test (§9.6) confirms no resolution occurs and no material is
   returned; lease evidence shows only refusals.
5. **Rotate/quarantine** — rotate the affected reference out of band and, if required, quarantine
   the secret-free lease/refusal evidence per the runbook.

Each step is independently sufficient to stop resolution; together they fully inert the path. The
drill must be executed and verified (checklist §8) before activation is approved.

## 11. Future implementation plan and explicit non-goals

A later implementation PR (not this one) may, only after §8 and §9 are satisfied:

- implement a worker-only `WorkerSecretResolver` that performs §3 re-verification, §4 three-way
  binding, §5 lease acquisition, and §6 backend policy resolution, returning opaque short-lived
  `SecretMaterial`;
- add the durable, secret-free resolution-lease/refusal evidence store;
- wire the injected collection runner behind the resolver (GET-only, canonicalized).

**This PR (B2-2) explicitly does NOT and MUST NOT add:** a real secret backend or client
(secret-manager, environment, file, Docker-secret, or database resolution); any HTTP/socket/
subprocess/provider activity; real Proxmox collector wiring; a resolver settings object, endpoint
configuration, secret-source registration, secret-entry API, or credential-upload UI; a
secret-bearing database column; a live feature switch or runtime/environment flag that could enable
resolution; or any infrastructure, container, service, or deployment configuration. All B2-0 closed
error behavior, the separate `LiveReadAuthorization` lifecycle, the app-owned queue-only API,
worker-only execution, endpoint-policy pinning, staging-lab isolation, and fake-only no-contact
guarantees remain unchanged.
