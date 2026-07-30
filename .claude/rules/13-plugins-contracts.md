---
paths:
  - "plugins/**"
  - "contracts/**"
---

# Plugins and contracts

## The provider seam

`contracts/plugin-api/secp_plugin_api/v1` declares `PluginProtocol` (7 lifecycle methods:
health/validate/plan/apply/status/reset/destroy) plus an optional `DiscoveryProtocol`
(validate_target/discover). A new provider (VMware, AWS, Azure, GCP, Kubernetes) implements
exactly this seam — no provider-specific logic may enter the core.

The `Capability` enum declares 10 names, but **`reconcile` and `collect-artifacts` have no
method, no implementation and no dispatch** anywhere. They are vocabulary only. Do not assume a
capability exists because it is named.

## Read-only Proxmox

`ProxmoxPlugin` advertises exactly `{validate, health, discover, status}` and raises
`UnsupportedCapabilityError` from `plan`/`apply`/`reset`/`destroy`
(`plugins/proxmox/secp_plugin_proxmox/plugin.py:149-159`). Its `status` is a passthrough of the
control plane's own topology store, not a provider read.

Transport is **GET-only and path-allowlisted before any request**
(`readonly_policy.py:221-235`, called from `transport.py:106-107`). Adding a non-GET method or
widening the allowlist is provider mutation — an unconditional hard-deny.

## Simulator is a reference implementation, not a mock

`SimulatorPlugin` is the full reference implementation with DB-only effects and deterministic
CIDR/IP allocation. Only the exact bootstrapped instance may execute inline
(`apps/api/secp_api/safety.py:52-104`). Keep it contract-faithful — it is the harness every real
plugin is measured against.

## Enforced boundaries

- The API may not import a provider plugin, provider SDK, HTTP client, IaC tool or subprocess
  (`tests/test_architecture_boundary.py:27-73`).
- The API may never call `apply`/`reset`/`destroy` (`:124`, `:194-209`).
- No real endpoint, public IP or non-placeholder provider host in any authored file
  (`tests/test_no_real_endpoints.py` — `SCAN_DIRS` includes `contracts` and `plugins`).
- Every plugin package must be declared in **every** packaging surface
  (`tests/test_python_image_package_closure.py`) — `pyproject.toml` has five parallel lists that
  must stay in sync.

**Gap worth knowing:** no test asserts that plugins never import control-plane internals. Only
`test_management_plane_boundary.py:32-34` covers `plugins/`, and only for `secp_management`.
Treat that as convention you must uphold manually.
