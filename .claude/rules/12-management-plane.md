---
paths:
  - "apps/management/**"
  - "apps/commissioning/**"
  - "apps/deployment/**"
---

# Management / commissioning / deployment planes

## Plane boundary — machine-enforced

- `apps/management` must **not** import `secp_api`
  (`tests/test_pr5h_architecture_guards.py:258-264`).
- `apps/management` must **not** import `secp_discovery_activation`
  (`tests/test_pr5f_discovery_activation_boundary.py:244-262`).
- The installer stays **local-first**: no provider SDK, IaC tool, SSH or bare subprocess
  (`tests/test_management_plane_boundary.py:100-104`).
- Strictly **provider-neutral**: no Proxmox/K8s/AWS/Azure/GCP/VMware concept in any management
  identity, release, evidence, enrollment or config surface. Two guards enforce this — a textual
  provider-token scan and a structural one (`apps/management/tests/test_provider_neutrality.py`).

Note the deliberate non-import: `worker_enrollment_schema.py` (control plane) and
`migration_heads.py` (deployment plane) hold the same head literal and must agree, but must
**not** import each other. Agreement is asserted by test only.

## Never touch

`production.py` (the production trust-root loader — reads five fixed root-owned files) and
`signing.py` (`SHIPPED_TRUST_ROOT`). Both are unconditional hard-denies.

## Sealed composition

The shipped `EngineDeps` defaults are five `Sealed*` classes (`adapters.py:335-428`,
`finalization.py:264-300`) that raise `ManagementError`. Real leaves exist but are constructed
**only** by `production.py`. Do not widen the default composition.

Every mutation requires **both** `--write` and `--confirm` (`transaction.py:25-41` `WriteGate`).
Invoking that combination is a hard-deny for agents.

## Canonical systems

- One host-mutation adapter family per concern. Two Compose-driving adapters already exist
  (management bootstrap, PR5F discovery activation) — do not add a third.
- Three console scripts already have overlapping install/verify/status/rollback verbs
  (`secpctl`, `secp-discovery-activation`, `secp-admission-proxy`). Extend, do not add.
- `layout.py` owns the production filesystem layout: three exact writable systemd unit paths,
  fourteen forbidden roots. It is a contended file.
