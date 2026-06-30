# SECP-002A — Provider Safety, Inventory Foundation, and Read-Only Proxmox Discovery

**Status:** Accepted for implementation
**Milestone:** SECP-002A (first sub-phase of SECP-002: Proxmox Foundation)
**Governing document:** [`docs/PROJECT_CHARTER.md`](../PROJECT_CHARTER.md)
**Builds on:** [`docs/architecture/secp-001-design.md`](./secp-001-design.md)
**Related ADRs:** ADR-006 … ADR-010 (plus ADR-001 … ADR-005)

---

## 1. Purpose and hard boundary

SECP-002A prepares the platform to *eventually* trust a real infrastructure
provider. It does **not** provision, modify, reset, destroy, reconfigure, or scan
any real Proxmox resource. The only provider action introduced is **read-only
discovery**, and even that is not exercised against any real endpoint during
development, tests, CI, or runtime verification — it runs only against fakes /
mock HTTP transports.

This milestone closes six architectural gaps that must exist before any real
provider action is ever permitted (SECP-002B+):

1. Real execution destinations become explicit, scoped, auditable, secret-free
   database records (`ExecutionTarget`).
2. Provider discovery runs only through the worker and the durable workflow path.
3. Inventory/topology persistence becomes **provider-neutral** (no `simulated_*`
   names, no Proxmox-specific columns).
4. Address space is **reserved transactionally** so concurrent environments cannot
   collide before any real network is ever created.
5. `requiredPlugins` is a capability *declaration*, never "the first plugin to run."
6. The **Temporal** durable path becomes operational (not just scaffolding).

No existing charter invariant is removed or weakened.

---

## 2. Execution targets (ADR-006)

An `ExecutionTarget` is a generic, organization-scoped record describing an
**approved destination** for an environment deployment. It is *not* a
provider-specific table.

Fields (minimum): `organization_id`, `display_name`, `plugin_name`,
`config` (immutable non-secret JSON), `config_hash`, `secret_ref` (opaque
reference, never a secret), `status` (`active` | `disabled` | `discovery_failed`),
`created_by`, timestamps, optional `scope_policy` JSON (generic).

Rules:

- **No plaintext secrets, ever** — no tokens, passwords, private keys, or
  certificates in `config`, `secret_ref`, snapshots, audit events, errors, logs,
  or API responses. `secret_ref` only says *where* the worker can resolve a secret
  (e.g. `env:SECP_PROVIDER_SECRET__<id>` in local dev), never *what* it is.
- **Immutable configuration** — changing target configuration requires a **new**
  target record. A target is never silently edited once plans may reference it.
  (`config` + `config_hash` are treated as immutable after creation, enforced like
  `EnvironmentVersion`.)
- An `Exercise` may *optionally* reference one execution target. Existing simulator
  exercises keep working with **no** execution target (the safe Simulator path).
- A `DeploymentPlan` pins `execution_target_id` and `target_config_hash` when a
  target is selected, so "approve exactly this destination" is verifiable.
- `requiredPlugins` declares required capabilities/integrations only. Provider
  selection is driven by the bound `ExecutionTarget.plugin_name`, never by list
  order. With no target, the inline Simulator path is used as today.

In SECP-002A an exercise may **not** deploy to a Proxmox target — provisioning is
deferred to SECP-002B. Targets exist for registration + read-only discovery only.

---

## 3. Generic observed inventory and topology (ADR-008)

The `simulated_*` tables are renamed to provider-neutral equivalents, preserving
all existing data and behavior:

| Old | New |
| --- | --- |
| `simulated_network` | `environment_network` |
| `simulated_node` | `environment_node` |
| `simulated_topology_edge` | `environment_topology_edge` |

The generic observed models carry: instance ownership, `provider` name, optional
`provider_resource_id` (external id), `provider_resource_type`, observed `status`,
`observed_at`, provenance (`source`, `simulated` bool), and generic `attributes`
JSON. **No Proxmox-specific columns.** For the Simulator, rows are written with
`provider="simulator"`, `simulated=true`, `source="simulator"` — identical
behavior and topology as SECP-001. The ResourcePort, Simulator plugin, API
responses, topology UI, and tests are updated to the neutral names; the UI shows
simulated exercises exactly as before.

A backfilling Alembic migration renames the tables (data-preserving) and adds the
new generic columns with safe defaults.

---

## 4. Provider inventory snapshots (ADR-008)

Two generic models capture discovery output:

- `ProviderInventorySnapshot` — belongs to an org-scoped `ExecutionTarget`. Records
  `plugin_name`, `plugin_version`, `target_config_hash`, `requested_at`,
  `completed_at`, `workflow_run_id`, `status` (`queued`|`running`|`completed`|
  `failed`), and an immutable `summary`. **Immutable after completion.**
- `ProviderInventoryResource` — normalized rows: generic `resource_type`,
  `provider_external_id`, `display_name`, `parent_ref` (scope/parent), `status`,
  generic `attributes`. No secrets, no Proxmox-only columns.

Inventory is organization-scoped and access-controlled (`inventory:read`). Every
target registration, discovery request/start/complete/failure emits an audit
event. Secrets never appear in snapshots, resources, audit events, errors, or UI.

---

## 5. Network reservations and address-space policy (ADR-009)

A provider-neutral reservation service reserves CIDRs **before** any future real
provisioning. Two generic models:

- `AddressSpacePolicy` — approved address spaces for an `ExecutionTarget`
  (CIDR blocks + allowed subnet prefix length). Declared as target config policy.
- `NetworkReservation` — a reserved CIDR for an `(execution_target, exercise,
  team_ref)`, with status (`reserved` | `released`).

Rules:

- Reservations are **transactional** per execution target; a unique constraint plus
  an overlap check prevents two concurrent exercises from reserving overlapping
  CIDRs on the same target.
- For a real execution target, a requested per-team network must fall inside an
  **approved** address space.
- The Simulator path is unchanged: it does not require an execution target and
  keeps its deterministic per-team `/24` allocation. (Reservations are exercised by
  the new service + tests, and are wired for real targets in SECP-002B.)
- Reservations are released only through explicit lifecycle rules (release on
  destroy / explicit release), audited.
- **No real network is created** in this milestone.

Tests cover deterministic allocation, collision prevention, concurrent reservation
handling, release behavior, and cross-organization denial.

---

## 6. Plugin contract: discovery and partial capability support (ADR-003 addendum)

The contract is extended **without** a breaking `apiVersion` change (still `v1`):

- New typed models: `DiscoveryRequest`, `DiscoveryResult`, `DiscoveredResource`,
  `TargetValidationResult`.
- A new **optional** `DiscoveryProtocol` (capability-specific). Existing plugins do
  not implement discovery and are unaffected.
- `UnsupportedCapabilityError` — a typed error a plugin raises for capabilities it
  structurally exposes (for Protocol conformance) but does not support. It must be
  raised **before** any provider request.

The Simulator continues to implement the core protocol; it does not implement
discovery. The control plane checks capability support before dispatch.

---

## 7. Read-only Proxmox plugin (ADR-007)

Lives under `plugins/proxmox/` (worker/plugin code only — never imported by
`apps/api`). Advertised capabilities: **`validate`, `health`, `discover`,
`status`** (status reads only from persisted discovery data). It does **not**
advertise `apply`, `reset`, or `destroy`; if those methods must exist structurally,
they hard-fail with `UnsupportedCapabilityError` before any provider request.

The Proxmox HTTP client:

- exists only in plugin/worker code;
- uses an **injectable transport abstraction** (fake/mock in tests);
- allows **HTTP `GET` only** — POST/PUT/PATCH/DELETE/any mutation method is rejected
  **before** a request is sent (a `MutatingRequestRefused` guard);
- normalizes discovered data into provider-neutral records;
- filters results through the configured **scope policy** before persistence;
- performs **no** guest-agent calls, console actions, start/stop, task actions,
  config mutation, or any write.

Architecture tests prove `apps/api` imports none of: provider SDKs, the provider
HTTP client, Proxmox client code, OpenTofu, Terraform, Ansible, `subprocess`, or
shell execution.

---

## 8. Worker-only secret resolution (ADR-007)

- The API may validate a `secret_ref`'s **syntax** but must never resolve it.
- The worker resolves a `secret_ref` only **immediately before** a provider
  operation, via a `SecretResolver` abstraction.
- Local dev uses a safe `EnvSecretResolver` (resolves from a namespaced env var)
  documented as a placeholder for a real secret manager. Tests use a `FakeResolver`
  and never read real environment secrets.
- Errors are **redacted** (never echo the secret or its value). Resolved secrets are
  never persisted and never exposed to logs, audit events, API responses, workflow
  details, or frontend state.

The interface is shaped to be compatible with a future production secret manager.

---

## 9. Temporal activation (ADR-010)

The durable path becomes operational before any real-provider work is allowed:

- Add a `queued` workflow state and durable workflow identifiers.
- `TemporalDispatcher` actually **enqueues** supported workflows (deploy, reset,
  destroy, **discover**) instead of raising unavailable.
- The API **creates/queues** work; the **worker** performs state-changing plugin
  actions. The inline Simulator-only dev mode is preserved.
- `InlineDispatcher` refuses any non-Simulator plugin (identity-based allowlist,
  unchanged from the SECP-001 hardening) — real providers require Temporal.
- New **provider discovery workflow**; discovery uses the Temporal worker path in
  normal operation. The API never calls the Proxmox plugin and never resolves its
  secret reference.

Runtime verification proves the Temporal path works against the local Temporal
service using **only** the Simulator and a fake/mock provider.

---

## 10. API and UI

A minimal administrator **Provider Targets** area: list targets; register a target
(non-secret config + opaque `secret_ref`; **no secret-entry form**); inspect status
+ discovery history; request **read-only** discovery (with a clear warning); view a
**sanitized** inventory snapshot; show scope + address-space policy; and clearly
state that **Proxmox provisioning is NOT enabled in SECP-002A** (discovery is
read-only; provisioning deferred to SECP-002B). An exercise may not deploy to a
Proxmox target.

---

## 11. Permissions and audit

New narrowly-scoped permissions: `target:manage`, `inventory:discover`,
`inventory:read`. Organization checks everywhere. New audit actions: target
created/disabled, discovery requested/started/completed/failed, secret-resolution
failure (no sensitive detail), provider operation refused, and address-space
reservation lifecycle events.

---

## 12. Explicit exclusions (unchanged scope discipline)

No real Proxmox provisioning; no VM/container/pool/storage/bridge/VLAN/firewall/
DNS/DHCP/network creation; no OpenTofu/Terraform/Ansible execution; no Wazuh/CTFd;
no real Kali/Ubuntu/vulnerable targets; no real reset/destroy against Proxmox; no
real endpoint discovery anywhere; no AI features. Provisioning, the OpenTofu runner,
isolated networks, and VM lifecycle are SECP-002B; reconciliation and reset/destroy
against real infra are SECP-002C.

---

## 13. Intentional placeholders (recorded honestly)

- Real Proxmox endpoint discovery is never run; only fakes/mocks.
- `EnvSecretResolver` is a local-dev placeholder for a production secret manager.
- Network reservations are wired and tested but not consumed by real provisioning
  (SECP-002B).
- Temporal end-to-end is verified with the Simulator and a mock provider; no real
  provider call occurs.
