# SECP-002B-1B-2 — Live Read-Only Proxmox Collector: Threat Model and Activation Design

**Status:** Design / threat model only (no code, no client, no live access)
**Related:** ADR-015 (this design lock), ADR-006/007/008/013/014; Charter §5/§6/§13;
[Proxmox safety model](../proxmox/safety-model.md),
[read-only discovery](../proxmox/read-only-discovery.md),
[activation checklist](../proxmox/live-readonly-collector-activation-checklist.md)

This document is the implementation-ready design and threat model for the **first real,
read-only** Proxmox target-evidence collector. It is **documentation only**. Nothing here
contacts, inspects, authenticates to, configures, or mutates any real target; no Proxmox SDK /
API client / HTTP client / socket / subprocess / shell / Docker / IaC / Ansible is added; no
credential, endpoint, secret, or environment variable is created; the B1-B-1 live-evidence
seal is **not** lifted; and the existing simulated collector behaviour is unchanged.

Concrete infrastructure values are intentionally omitted. Placeholders use angle-bracket tokens
(`<proxmox-host>`, `<node>`, `<segment>`, `<storage>`). Proxmox API **path templates** (e.g.
`/api2/json/nodes`) are public API surface, not target values.

## 0. Context and current state

After SECP-002B-1B-1 the platform has: immutable, simulated-only target evidence
(`TargetEvidenceRecord`), worker-owned simulated collection (the only collector call site is
`secp_worker.onboarding.orchestration.run_simulated_preflight`), provider-neutral
boundary↔evidence comparison, a full-record evidence hash, a `target_preflight →
target_evidence_record` binding, audit records, and onboarding approval gates. Live-verified
evidence and the `provider_worker` collector remain **sealed**
(`SealedProviderTargetEvidenceCollector.collect` raises `LiveEvidenceSealedError`).

The first live collector will replace *how the payload is produced* — a worker-only,
read-only observation of an approved disposable/staging Proxmox target — while reusing the
existing validate → compare → hash → persist → audit → bind pipeline unchanged. It will remain
gated behind a **default-disabled** feature flag and a human authorization record until a
future, separately reviewed activation PR.

## 1. Threat model

### 1.1 Assets to protect

| Asset | Why it matters |
| --- | --- |
| Management-plane credentials | A Proxmox API token/password can read (and, if over-scoped, mutate) the whole cluster. |
| Target inventory | Node/VM/container/storage lists reveal the estate and its blast radius. |
| Network topology | Bridges/VNets/VLANs/CIDRs reveal segmentation and reachable networks. |
| Workload metadata | Guest names/notes/config can leak tenant or business information. |
| Control-plane integrity | The API/DB decide what is "approved" and "passing"; corruption defeats every gate. |
| Audit trail | Tamper-evident history of who authorized/collected what. |

### 1.2 Trust boundaries

```
[Browser] ──1── [API] ──2── [Dispatcher] ──3── [Durable Worker] ──4── [Secret Resolver]
                 │                                     │
                 └── [Database / Audit store] ◄─5──────┘         6
                                                        [Worker] ──6── [Proxmox management API]
```

1. **Browser ↔ API** — authenticated operators; the API never receives or returns secrets.
2. **API ↔ Dispatcher** — the API only *requests* work; it never collects or contacts a target.
3. **Dispatcher ↔ Durable Worker** — durable (Temporal) hand-off; inline is refused for live.
4. **Worker ↔ Secret Resolver** — just-in-time, worker-only credential resolution.
5. **API/Worker ↔ Database/Audit** — the only place evidence/records/audit persist.
6. **Worker ↔ Proxmox management API** — the *only* boundary that ever touches a real target;
   read-only, method/endpoint-allowlisted, pinned to an approved target identity.

### 1.3 Threats and mitigations

| # | Threat | Mitigation (design) |
| --- | --- | --- |
| T1 | **Credential exposure** (log/DB/audit/API/UI leak) | Opaque `secret_ref` only in control-plane records; worker-only JIT resolution into a transient `ProviderCredential` (no dict/JSON/pickle, `reveal_secret()` only); redaction of all errors; secrets never hashed, persisted, or placed in audit payloads or API responses. |
| T2 | **Confused deputy** (API tricked into privileged provider action) | The API cannot import a provider client (architecture test); it only dispatches. Collection runs solely in the worker seam. |
| T3 | **Target substitution** (collect from the wrong/attacker target) | Every collection job binds to an approved `execution_target_id` + pinned `config_hash` + an explicit human authorization record; the worker re-verifies the target identity/hash before connecting; endpoint host is taken only from the approved immutable target config, never from request input. |
| T4 | **SSRF-like endpoint abuse** (redirect / cross-target / metadata) | Absolute endpoint host comes only from approved target config; **redirects are not followed**; an egress allowlist restricts the destination; only path templates from the endpoint allowlist are issued; no user/request-supplied URL. |
| T5 | **API mutation** (accidental or malicious write) | Strict **GET-only** method allowlist enforced in the transport *before send*; endpoint allowlist excludes all task/action/config/console/agent/backup endpoints; unknown endpoints denied. |
| T6 | **Unsafe retries** (a retried request causes side effects) | Only idempotent GETs are retried, with capped attempts and backoff; retries never change method/endpoint; a task-triggering endpoint can never be reached (not on the allowlist), so retries cannot start work. |
| T7 | **Inventory-data leakage** (topology/workload metadata over-collected) | Minimal evidence categories only; provider-neutral normalization; redaction rules drop notes/descriptions/tokens/keys; out-of-scope resources filtered before persistence. |
| T8 | **Post-collection tampering / binding drift** (persisted record altered, or its bindings changed, after collection) | Full-record immutable evidence hash + immutable record detect **post-collection** alteration and binding drift; approval and the gate re-verify the hash. This does **not** prove the response was truthful at collection time (see T10 and §1.5). |
| T9 | **Worker compromise** | Least-privilege read-only identity; default-disabled live gate; durable audit of every job; egress allowlist; short-lived credentials with rotation/revocation; no write capability even if abused. Does not prevent a compromised worker from producing false read data (T10). |
| T10 | **False-but-plausible evidence** (a compromised target or worker returns well-formed but untrue read data) | **Not fully mitigated — no remote attestation exists.** Plausible false evidence can compare as `passed`; the evidence hash does not detect forgery committed at collection time. TLS identity verification, strict target/config/boundary binding, worker hardening, minimal read-only collection, least-privilege identity, audit, and mandatory human review **reduce** but do not eliminate this residual (§1.5). |

### 1.4 Residual risks and human review gates

- **Over-scoped credential** — mitigated but not eliminated by process; a human must review the
  Proxmox identity's effective permissions out of band (checklist §2).
- **Read-side information disclosure** — a legitimate read still returns real metadata; the
  redaction rules and minimal categories reduce, not remove, this. Human review of the
  normalized shape is required before activation.
- **TLS trust** — a mis-issued/mis-pinned certificate could enable interception; certificate
  identity must be verified out of band (checklist §3). `verify_tls=false` remains refused.
- **Compromised target or worker (false evidence)** — the collected payload is **not**
  independently attested. A compromised target or worker can return well-formed, plausible but
  untrue read data that **passes** comparison; a hostile target does **not** necessarily produce
  an `unverifiable`/`fail` result. The evidence hash does not detect forgery committed at
  collection time (it detects only post-collection alteration and binding drift). This residual
  is **reduced, not removed**, by TLS identity verification, strict target/config/boundary
  binding, worker hardening, minimal read-only collection, least-privilege identity, audit, and
  mandatory human review.

These residuals are accepted **only** behind the activation checklist and an explicit,
recorded human authorization; none is unlocked by this design PR.

### 1.5 Evidence integrity vs. evidence truthfulness

These are distinct properties and must not be conflated:

- **Integrity (what the hash gives us).** The immutable, full-record evidence hash detects
  **post-collection alteration** of the persisted record and **binding drift** (a record that
  no longer matches its onboarding / target / boundary / authorization bindings). Approval and
  the worker gate re-verify the hash.
- **Truthfulness (what the hash does NOT give us).** The hash does **not** prove the provider
  response was truthful, complete, or independently attested, and it cannot detect evidence that
  was **false at the moment of collection** (a compromised target or worker returning plausible
  but untrue data). SECP has **no remote attestation** of the target in this design.

Consequently, well-formed false data can compare as `passed`; a hostile target is **not**
guaranteed to fail closed. The controls in this document reduce the likelihood and blast radius
of false evidence but are **not** a substitute for attestation — which is why activation
additionally mandates out-of-band verification (endpoint/certificate identity, effective
permissions) and human review before any real collector is enabled.

## 2. Read-only collector contract

### 2.1 In-scope evidence categories (first collector)

The first collector may observe **only** what the boundary comparison already consumes:

- **Nodes** — node names/status (for `allowed_nodes`).
- **Storage** — storage ids/types/availability (for `allowed_storage`).
- **Network segments** — bridge/VNet/VLAN identifiers (for `network_segments`).
- **VM-ID availability / ranges** — in-use VM-IDs / free ranges (for `vmid_range`
  non-overlap).
- **Capacity / quotas** — node/cluster capacity signals (for quota headroom).
- **Isolation-relevant posture signals** — specifically approved, allowlisted read-only
  observations relevant to `fully_segregated` (see §2.5), observed, never changed. Generic
  inventory alone is **not** sufficient to pass isolation.

### 2.2 Out of scope for the first connector

Guest configuration bodies, guest-agent data, console/VNC, tasks/jobs, backups, firewall
rule contents, user/token/ACL enumeration, SDN mutation, per-guest secrets/notes, and
**anything write-shaped**. Provisioning and any mutation remain a later, separate milestone.

### 2.3 Normalized, provider-neutral evidence shape

The collector emits the **existing** `secp-002b-1b-1/target-evidence/v1` payload shape
(`schema_version`, `evidence_source`, `verification_level`, `observed{…}`) so the API-side
`compare_boundary_to_evidence`, hashing, and persistence are reused verbatim. Only two new
provider-neutral constants are anticipated for the live path (added in a future code PR, not
here): a `live_readonly_proxmox` evidence source and the `live_verified` verification level —
both remaining behind the seal until activation.

Redaction rules (design): keep only ids/status/counts/ranges needed for comparison; strip
descriptions/notes/comments/tags; never include tokens, keys, passwords, cookies, CSRF
tickets, or endpoint auth material; reject any payload containing secret-like tokens (reuse
the existing `_contains_secret_token` guard).

### 2.4 Unverifiable, never inferred as passing

Missing, malformed, ambiguous, partial, or errored observations map to **`unverifiable`** per
comparison dimension (existing `missing_evidence_findings` / fail-closed semantics). A category
is `passed` only on an explicit, well-formed, matching observation. `unverifiable` and `fail`
both block approval; silence is never success. (Passing comparison proves the observation
*matched the declared boundary* — not that the observation was *true*; see §1.5.)

### 2.5 Verifying `fully_segregated` isolation (necessary rigor)

Generic inventory data — the mere **presence** of a bridge/VNet, a segment **name**, or a
node/storage list — is **insufficient** to pass `fully_segregated` isolation. Names and
presence do not prove isolation.

A future collector may return `passed` for `fully_segregated` **only** when **every** required
isolation assertion is verified using specifically approved, allowlisted, read-only
observations and deterministic rules. At minimum the applicable required facts include:

- **Dedicated lab segment identity** — the segment is the approved dedicated lab segment by
  verified identity, not merely a matching name.
- **No protected-network uplink/routing** — no uplink or route from the lab segment to any
  management / home / corporate / storage / public network class.
- **No default route / no external connectivity where policy is `deny`** — no default gateway
  and no external egress on the segment when the declared boundary denies external
  connectivity.
- **Host-side isolation controls** — any host/hypervisor-side isolation controls required by
  the declared boundary are observed to be in place.

When any required fact is **unavailable, ambiguous, not safely observable with read-only
allowlisted calls, or out of scope** for the first connector, the isolation result is
**`unverifiable`** and **blocks approval**. It must **never** be inferred from incomplete
inventory, from segment names, or from segment presence. Which of these facts are safely
observable read-only is itself part of the reviewed activation decision; any fact that is not
so observable remains `unverifiable`.

## 3. Non-mutation enforcement design

The future transport is **read-only by construction**, enforced in code before any request:

- **Method allowlist:** `GET` only. Any other method raises before send (mirrors the existing
  `MutatingRequestRefused` pattern in the discovery transport).
- **Endpoint allowlist:** an explicit, closed set of GET path templates (e.g. `/api2/json/nodes`,
  `/api2/json/nodes/{node}/storage`, `/api2/json/cluster/resources`,
  `/api2/json/cluster/sdn/vnets`). Requests to any path not on the allowlist are **denied**.
- **Explicitly forbidden** (never on the allowlist): write methods; task/action endpoints
  (`…/status/start|stop|shutdown|reboot`, `…/tasks/…`); console/VNC/SPICE/term/shell;
  file upload/download; guest-agent (`…/agent/…`); backup/restore (`vzdump`, `…/backup`,
  restore); any VM/container create/config/delete; firewall or network create/modify/delete;
  storage allocation; user/token/ACL mutation.
- **No redirects, no cross-target:** redirects are not followed; the destination host must
  equal the approved target's configured host; a response redirecting elsewhere is a failure.
- **Unknown-endpoint deny + unknown-response fail-closed.**

### 3.1 Test-first plan (fake transport, before any live access)

A `FakeProxmoxReadOnlyTransport` returns canned JSON for allowlisted GET paths and **fails the
test** on: any non-GET method, any non-allowlisted path, any redirect, and any cross-host
destination. Unit tests (no network) must prove: GET-only; endpoint allowlist accept/deny;
mutation refused before send; redirect refused; normalization correctness; redaction; and that
ambiguous/missing data becomes `unverifiable`. These tests land **before** any live-capable
adapter code and run with the live gate disabled.

## 4. Credential and target-binding design

- **Opaque reference only:** control-plane records store an opaque `secret_ref`
  (`<scheme>:<locator>`), never a secret. `ExecutionTarget.config` stays non-secret.
- **Worker-only JIT resolution:** the worker resolves `secret_ref` via the `SecretResolver`
  immediately before the read, into a transient `ProviderCredential` (`reveal_secret()` only).
  The API never resolves it.
- **No secret exposure:** secrets are never logged, persisted, hashed, returned in API
  responses, or written to audit payloads; resolution errors are redacted.
- **Complete job binding:** every live collection job binds to, at minimum, **all** of:
  `execution_target_id`; the target `config_hash`; the `onboarding_id`; the onboarding
  `boundary_hash`; the `authorization_id` **and** the authorization's **expiry/version**; the
  `evidence_source` / `verification_level`; and the **collector-contract / endpoint-allowlist
  version**. The worker re-verifies every bound value before connecting. **Any** mismatch,
  expired or superseded authorization, target/config/boundary drift, or collector-contract /
  allowlist version mismatch **fails closed** and produces **no reusable passing result**
  (a prior job's `passed` outcome is never reused under a changed binding).
- **Rotation / revocation / expiration / failure (conceptual):** credentials are short-lived
  and rot=able at the secret store without code change; a revoked/expired credential yields a
  redacted resolution failure and an `unverifiable` result — never a partial write, never a
  cached secret; an authorization record carries an expiry after which jobs are refused.

## 5. Execution model

- **Durable worker only:** live collection runs exclusively on the durable (Temporal) worker
  path. The inline dispatcher **refuses** live collection (as it already refuses discovery and
  the simulated-preflight Temporal path is fail-closed today).
- **Default-disabled feature gate:** a dedicated setting (e.g. `SECP_ENABLE_LIVE_READONLY_COLLECTOR`,
  default `false`, refused in production without explicit review) gates the entire live path.
  With it disabled, the collector is inert and the seal stands.
- **Idempotency:** each job has a deterministic idempotency key derived from the **full
  binding** — `sha256(execution_target_id + config_hash + onboarding_id + boundary_hash +
  authorization_id + authorization_version + evidence_source + verification_level +
  endpoint_allowlist_version)`. A duplicate request with an identical binding maps to the same
  job; if **any** bound value differs — including the authorization version/expiry or the
  collector-contract / endpoint-allowlist version — the key differs and **no** prior passing
  result is reused.
- **Timeout / retry / cancellation:** bounded per-request timeout; capped, backed-off retries
  of idempotent GETs only; a job is cancellable; a cancelled/timed-out job records
  `unverifiable` and audits, never a partial pass.
- **Evidence retention / failure semantics:** produced evidence remains immutable and
  hash-bound (unchanged); failures persist a redacted failure + `unverifiable` findings and
  audit; nothing is silently retried into a passing state.

## 6. Human activation checklist

The gate-list that must be satisfied and human-reviewed **in a future PR** before any real
collector is enabled lives in
[live-readonly-collector-activation-checklist.md](../proxmox/live-readonly-collector-activation-checklist.md)
(disposable/staging target approval; restricted read-only identity reviewed; endpoint +
certificate identity verified out of band; egress allowlist approved; secret storage approved;
alerting/audit review complete; rollback/revocation tested; manual test plan approved; explicit
user authorization recorded).

## 7. Future implementation plan (separate PRs)

1. **Fake transport + allowlist tests** — `FakeProxmoxReadOnlyTransport`, GET-only + endpoint
   allowlist + redirect/cross-host refusal, normalization + redaction + `unverifiable`
   semantics. Live gate absent/disabled. No network.
2. **Provider adapter implementation, live gate still disabled** — worker-only read-only
   adapter behind the default-disabled feature gate; reuses the existing validate/compare/hash/
   persist/audit pipeline; seal remains until activation.
3. **Staging-only manual validation** — against a disposable/staging target, behind the gate,
   with the activation checklist partially exercised; results human-reviewed.
4. **Independent security review** — threat model + code + tests reviewed by someone other than
   the author.
5. **Separate authorization to enable real collection** — an explicit, recorded human
   authorization flips the gate for a specific approved target only.
6. **Provisioning remains a later, separate milestone** — this track is read-only evidence
   only; no mutation/provisioning is designed or enabled here.

## 8. What this PR deliberately does NOT do

No Proxmox SDK/API/HTTP client, socket, subprocess, shell, Docker, Terraform/OpenTofu, or
Ansible is added. No real target is contacted, inspected, authenticated to, configured, or
mutated. No Proxmox user/role/token/permission/endpoint/secret/env var is created. No real
hostname/IP/URL/bridge/VLAN/storage/credential/secret-ref/infrastructure value is added. The
live-evidence seal is **not** lifted, and the simulated collector behaviour is unchanged. This
PR is design/threat-model/checklist documentation only.
