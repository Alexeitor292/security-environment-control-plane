# SECP-002B-1B-0 — Target Onboarding Verification

**Date:** 2026-07-01 (amended — enforceable-binding + execution-boundary correction passes)
**Branch:** `feature/secp-002b1b-target-onboarding-contract`

This records an **actual** in-process run of the target onboarding + automated deployment
contract using **only fakes**. **No real Proxmox host/cluster/node/bridge/VLAN/storage/
network/credential/endpoint/OpenTofu binary/Docker socket was contacted, inspected,
configured, authenticated to, or mutated.** Preflight is fake-only.

## Why in-process (not Docker)

This is a design/model/API/fake-only slice. The onboarding lifecycle, preflight recording,
approval, activation, drift invalidation, automated-deployment semantics, and the
real-provisioning onboarding gate are all exercised in-process with the fake preflight
collector and fake process executor. The full backend suite (incl. PostgreSQL immutability +
migration) runs in CI on the authoritative Ubuntu / Python 3.11 environment. Docker is not
run, per the safety boundaries.

## Verified run (actual output)

```
== both onboarding modes / isolation models are valid ==
  clean_server           / physical -> status draft
  existing_environment   / logical  -> status draft

== logical isolation requires no-route evidence ==
  preflight without no_route -> passed: False
  submit refused: onboarding requires a passing preflight result befor

== full onboarding to active (fake preflight; nothing real inspected) ==
  onboarding status  : active
  preflight collector: fake

== deployment is automated + declarative ==
  plan: manual_pre_creation_required = False | scenario_resources_created_by_secp = True
  manifest.deployment.mode           = automated

== real provisioning requires an active onboarding ==
  after retire -> refused: target has no approved & active onboarding record; real prov

== preflight evidence is redacted (no real values/secrets) ==
  evidence leaks     : NONE
```

## What this demonstrates

- **Both modes** (`clean_server`, `existing_environment`) and **both isolation models**
  (`physical`, `logical`) are valid.
- **Logical isolation requires `no_route_to_protected`** evidence: a preflight lacking it does
  not pass, and review submission is refused.
- The onboarding reaches **`active`** only through create → preflight → submit → **human
  approve** → activate; the preflight collector is `fake` (inspects nothing real).
- **Deployment is automated + declarative**: the plan states
  `manual_pre_creation_required=false` and `scenario_resources_created_by_secp=true`; the
  manifest deployment mode is `automated`.
- **Real provisioning requires an active onboarding**: after retiring the onboarding, the
  real-provisioning gate refuses.
- **Preflight evidence is redacted**: no token/password/secret and no real (fake fixture)
  node/storage/bridge/CIDR/VM-ID values survive into the stored evidence.

## Enforceable-binding correction pass (actual output)

```
== plan + manifest carry exact onboarding bindings ==
  plan.onboarding_id == active ob : True
  manifest evidence hash bound    : True
  manifest.content.onboarding     : True

== simulated evidence: fine for review, never for live ==
  approved level                  : simulated
  require_live=False              : accepted
  require_live=True               : refused -> live real provisioning requires live_verified

== API/worker preflight cannot forge live eligibility ==
  API-recorded preflight level    : simulated (always simulated)
  worker live_verified attempt    : refused -> live_verified onboarding evidence cannot be

== boundary broader than target scope is refused ==
  refused                         : declared boundary is broader than the target p

== binding drift refuses manifest + real provisioning ==
  manifest gen after retire       : refused -> target has no active onboarding; onboard
  real dry-run after retire       : refused -> target has no approved & active onboardi
```

This demonstrates: plan + manifest carry the exact onboarding/preflight bindings (echoed
into immutable manifest content); simulated evidence is accepted for the fake/review path
but **refused for live** provisioning; the API preflight route always yields `simulated`
evidence (no live forgery); the B1-B-0 worker seam also refuses `live_verified` /
`provider_worker` evidence until a separately reviewed B1-B collector exists; a boundary
broader than the target scope is refused; and any onboarding binding drift fails closed at
both manifest generation and the real-provisioning gate.

Focused correction-pass tests: `test_onboarding_bindings.py` (plan/manifest bindings,
retire/verification-level/evidence-tamper drift refusals at manifest + gate,
simulated-vs-live eligibility, boundary/scope intersection), `test_target_onboarding.py`
(boundary⊆scope, single-active DB index + service fail-closed on multiples),
`test_onboarding_preflight.py` (request/result contract, collector/level contract,
complete evidence-package hash, immutability).

## Execution-boundary correction pass (actual output)

```
== B1-B-0 live-evidence seal (code-level, not config) ==
  API preflight level             : simulated (always simulated)
  worker live_verified attempt    : refused -> live_verified onboarding evidence cannot be
  provider_worker collector        : inert (collect refuses)

== simulated evidence: contract path OK, never live ==
  require_live=True               : refused -> live real provisioning requires live_verifie

== effective boundary (declared ∩ scope) is bound + enforced ==
  plan.effective_boundary_hash    : sha256:b97e1b79763ae7dde
  boundary object plan/manifest/content: True
  boundary hash plan/manifest/content  : True
  in-bound manifest dry-run        : allowed by the effective-boundary gate
  out-of-bound node action         : refused -> team1: node 'pve-node-99' is outside the
  boundary object tamper           : refused -> effective boundary drift
  boundary hash tamper             : refused -> effective boundary drift

== exact approved-preflight identity everywhere ==
  plan preflight-id tamper         : refused -> onboarding binding drift: plan approved

== toolchain provenance binding ==
  disabled toolchain after manifest: refused -> pinned toolchain profile is missing or n

== robust redaction of preflight detail ==
  secret-bearing 'password=hunter2trustm'  : refused
  secret-bearing 'https://proxmox.exampl'  : refused
  secret-bearing 'vmbr0 local-lvm'         : refused
  generic simulated detail leaks   : NONE
```

This demonstrates: (1) **live evidence is sealed** in B1-B-0 by an unconditional code-level
seal — the API preflight is always `simulated`, the worker recorder refuses `live_verified` /
`provider_worker`, and the `provider_worker` collector is inert; (2) simulated evidence is
accepted for the fake/contract path but **never** for live; (3) the **effective execution
boundary** (declared onboarding boundary ∩ target scope) object and hash are persisted and
hash-bound across plan, manifest column, and immutable manifest content; manifest generation
and the worker gate recompute and require exact object+hash agreement, an in-bound manifest
passes the gate, and every out-of-bound node/storage/network/CIDR/VM-ID/quota/external action
is refused by the worker enforcement seam; (4) the **exact approved-preflight identity** must
agree across plan/manifest/content (a direct-SQL id tamper is refused before rendering/secret/executor/
runner); (5) **toolchain provenance** is bound through preflight approval → manifest → gate
(a disabled/replaced profile is refused); and (6) preflight detail redaction robustly rejects
secret/endpoint/inventory values while the generic simulated details leak nothing.

Focused execution-boundary tests: `test_effective_boundary.py` (computation, emptiness,
enforcement seam in-bound pass + every out-of-bound dimension refused, plan/manifest/content
object+hash binding, direct-SQL boundary object/hash tampers at manifest gen + gate),
`test_onboarding_bindings.py`
(seal refusal, exact preflight-id corruption tests for plan/manifest/content),
`test_onboarding_toolchain_binding.py` (toolchain drift refused at approval/manifest/gate),
`test_onboarding_preflight.py` (seal + inert collector, robust redaction of token/password/
credential/endpoint/inventory detail values).

## Final local verification (actual commands)

All commands below ran on 2026-07-01 from
`feature/secp-002b1b-target-onboarding-contract` using the repository Python 3.11.15 virtual
environment. No Docker, OpenTofu, provider endpoint, credential, or real infrastructure command
was run.

```
uv run ruff format --check apps contracts plugins tests
141 files already formatted

uv run ruff check apps contracts plugins tests
All checks passed!

uv run python -m mypy apps/api/secp_api apps/worker/secp_worker contracts plugins
Success: no issues found in 89 source files

uv run pytest apps/api/tests/test_migrations.py apps/api/tests/test_generic_topology_migration.py -q
4 passed in 6.84s

uv run pytest apps/api/tests/test_effective_boundary.py apps/api/tests/test_onboarding_bindings.py apps/api/tests/test_onboarding_toolchain_binding.py apps/api/tests/test_onboarding_preflight.py -q
61 passed in 21.00s

uv run pytest apps/api/tests tests -q
565 passed, 8 skipped, 1 warning in 137.14s (0:02:17)
```

## Automated proof coverage

| Requirement | Test |
| ----------- | ---- |
| clean_server and existing_environment are both valid | `test_target_onboarding.py` |
| physical and logical isolation are both valid | `test_target_onboarding.py` |
| existing environment cannot activate without complete boundaries | `test_target_onboarding.py` |
| logical isolation cannot activate without no-route evidence | `test_target_onboarding.py`, `test_onboarding_preflight.py` |
| a target cannot activate with external connectivity allowed by default | `test_target_onboarding.py` |
| plan/manifest state SECP creates scenario resources automatically | `test_automated_deployment_semantics.py` |
| no standard plan requires manually created VMs/containers | `test_automated_deployment_semantics.py` |
| onboarding approval is immutable/auditable | `test_target_onboarding.py` |
| scope/config drift invalidates onboarding approval | `test_target_onboarding.py` |
| real provisioning requires an approved active onboarding | `test_automated_deployment_semantics.py` |
| preflight evidence is redacted + immutable | `test_onboarding_preflight.py` |
| API boundary remains clean | `tests/test_architecture_boundary.py`, `tests/test_provisioning_boundary.py` |
| fixtures use clearly fake non-routable values only | `tests/test_no_real_endpoints.py` |

## Honesty notes / limits

- Preflight is the **`FakePreflightCollector`** only; it derives evidence from the declared
  boundary and inspects **no** real target. B1-B will add a real collector behind the same
  seam.
- Targets used placeholder configuration (`proxmox.example.test`) and opaque secret
  references; no real secret was read. Declared boundaries used clearly fake, non-routable
  values (`pve-node-1`, `local-lvm`, `vmbr0`, `10.60.0.0/16`, VM-IDs 9000–9100).
- Real evidence collection, real provider-specific boundary verification, and the
  pre-existing-asset import/adoption workflow are future work (B1-B and beyond).
