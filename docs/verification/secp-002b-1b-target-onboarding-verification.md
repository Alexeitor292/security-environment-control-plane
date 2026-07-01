# SECP-002B-1B-0 — Target Onboarding Verification

**Date:** 2026-07-01 (amended — enforceable-binding correction pass)
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

== API preflight cannot forge live eligibility ==
  API-recorded preflight level    : simulated (always simulated)

== trusted worker collector CAN produce live_verified ==
  worker-recorded preflight level : live_verified

== boundary broader than target scope is refused ==
  refused                         : declared boundary is broader than the target p

== binding drift refuses manifest + real provisioning ==
  manifest gen after retire       : refused -> target has no active onboarding; onboard
  real dry-run after retire       : refused -> target has no approved & active onboardi
```

This demonstrates: plan + manifest carry the exact onboarding/preflight bindings (echoed
into immutable manifest content); simulated evidence is accepted for the fake/review path
but **refused for live** provisioning; the API preflight route always yields `simulated`
evidence (no live forgery); only the trusted worker collector produces `live_verified`; a
boundary broader than the target scope is refused; and any onboarding binding drift fails
closed at both manifest generation and the real-provisioning gate.

Focused correction-pass tests: `test_onboarding_bindings.py` (plan/manifest bindings,
retire/verification-level/evidence-tamper drift refusals at manifest + gate,
simulated-vs-live eligibility, boundary/scope intersection), `test_target_onboarding.py`
(boundary⊆scope, single-active DB index + service fail-closed on multiples),
`test_onboarding_preflight.py` (request/result contract, collector/level contract,
complete evidence-package hash, immutability).

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
