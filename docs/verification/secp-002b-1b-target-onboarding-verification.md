# SECP-002B-1B-0 — Target Onboarding Verification

**Date:** 2026-07-01
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
