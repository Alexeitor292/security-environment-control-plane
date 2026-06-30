# ADR-003 — Plugin contract

- **Status:** Accepted
- **Date:** 2026-06-29
- **Milestone:** SECP-001
- **Deciders:** Implementation engineering
- **Related:** Charter §11, Invariants 8, 9, 16; ADR-005

## Context

Every external integration must be a versioned, replaceable plugin (Charter §11). The
core must not contain provider-specific logic or columns (Invariant 9). The control
plane must talk to **capabilities**, not vendors, and must be able to discover what a
plugin supports and its health/version (Invariant 16). SECP-001 ships only the
Simulator, but the contract it defines must be the *same* one real plugins (Proxmox,
OpenTofu runner, Ansible runner, Wazuh, CTFd) will implement.

## Decision

Define a versioned plugin contract in `contracts/plugin-api/v1` as a Python
`Protocol` (structural typing) plus typed Pydantic result models. Capability surface:

| Method | Purpose | Side effects |
| --- | --- | --- |
| `validate(spec)` | check a spec is deployable by this plugin | none |
| `plan(version, instances)` | deterministic plan of actions | none |
| `apply(plan)` | create/update resources | yes (per instance) |
| `status(instance)` | read observed state | none |
| `reset(instance)` | restore known-good baseline | yes, idempotent |
| `destroy(instance)` | tear down | yes, idempotent |
| `health()` | liveness + capabilities + version | none |

Rules:

- **Capability discovery**: `health()` returns the set of supported capabilities and a
  semantic version. The control plane checks capability support before dispatching an
  operation, so a partial plugin degrades gracefully rather than erroring opaquely.
- **Determinism**: `plan()` is a pure function of the immutable version + target
  instance ids. The same inputs yield the same plan; this is what makes approval
  meaningful (ADR-004).
- **Idempotency**: `apply`, `reset`, `destroy` are idempotent state-machine steps.
- **No secrets in the contract**: configuration is passed by secure reference; the
  Simulator needs none.
- **Versioning**: the package is `secp_plugin_api` under a `v1` namespace. A breaking
  change to the contract creates `v2`; plugins declare which contract version they
  implement. The control plane can support multiple contract versions side by side.
- **Execution location**: plugins are invoked **only** from the worker
  (Charter Invariants 6, 7), never from the API. The contract types are importable by
  the API for typing/plan-shaping, but the API never calls `apply/reset/destroy`.
- **`health().simulated` is observability, not authorization**: the `simulated` field
  in `HealthReport` is a descriptive/observability field only. It is NOT the
  authorization control for inline execution routing. The `PluginRegistry` uses an
  **identity-based** check: `is_inline_safe(plugin)` returns `True` only for the
  exact `SimulatorPlugin` instance created during registry bootstrap. A plugin named
  'simulator', a new `SimulatorPlugin()` instance, or any plugin reporting
  `simulated=True` are all refused unless they ARE that specific bootstrapped object.
  The public `register()` API has no `inline_safe` argument — no external caller can
  grant inline permission. See ADR-005.

The Simulator (`plugins/simulator`) is the reference implementation and the target of
a **conformance test suite** that every future plugin must also pass.

## Consequences

**Positive**

- One contract, many backends; the core stays provider-neutral.
- A conformance suite turns "implements the contract" into something machine-checked.
- Structural `Protocol` typing avoids forcing a base-class hierarchy on plugin authors
  while still giving mypy-level checking.

**Negative / risks**

- A `Protocol` is checked at type-check time, not enforced at import time. Mitigation:
  a runtime registry validates that a registered plugin exposes all capability methods
  it advertises, and the conformance suite is mandatory in CI.
- The capability surface may need additions (`reconcile`, `discover`,
  `collect-artifacts` per Charter §11). These are reserved as optional capabilities;
  `v1` ships the SECP-001-required subset and advertises only what is implemented.

**Placeholder**

- `reconcile`, `discover`, `collect-artifacts` are declared as optional/future
  capabilities, not implemented by the Simulator in SECP-001.
