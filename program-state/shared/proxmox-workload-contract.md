# Proxmox workload, reset and reconciliation contract

Owner: `owner-proxmox-workload` (P5). Branch `feature/secp-proxmox-workload-bootstrap`.
Built on the exact merged `#107` main (`7f42afb`).

This file records the contracts other streams may depend on. It is descriptive: the modules are
authoritative, and every claim below is pinned by a test in
`apps/api/tests/test_proxmox_workload.py` or `apps/api/tests/test_proxmox_reset_reconcile.py`.

## Files owned by this stream

| File | Plane |
| --- | --- |
| `apps/api/secp_api/range_providers/proxmox_workload.py` | API — workload compiler, competition readiness, secret guard |
| `apps/worker/secp_worker/provisioning/proxmox_bootstrap.py` | Worker — guest bootstrap accounting |
| `apps/worker/secp_worker/provisioning/proxmox_reset.py` | Worker — reset planning and re-verification |
| `apps/worker/secp_worker/provisioning/proxmox_reconcile.py` | Worker — reconciliation over an interrupted apply |

No existing file is modified. No installer file, no durable-identity file, no Alembic migration,
no sealed workflow or activity change.

## Consumed, not redefined

| From | What is consumed |
| --- | --- |
| `#107` `proxmox_verification` | `VerificationOutcome`, `VerificationCheck`, `CheckFinding`, `VerificationReport`, `decide_outcome`, `ObservedInfrastructure`/`ObservedGuest`, `_first_host` (scoring-address derivation) |
| `#105` `proxmox_model` | `Ownership`, `is_owned_by_secp`, `ObjectProvenance`, `GuestSpec`/`CloudInitSpec`/`GuestAddress`, `BlockedPlan`/`MissingPrerequisite` |
| `#105` `proxmox_ipam` | `AllocationLedger` (sealing semantics), `AllocationKind`, `IpamPools`, `AllocationRequestLog` |
| `#105` `proxmox_network` | `SegregatedNetworkPlan`, `SegmentRole`, `evaluate_flow` |
| `#106` `proxmox_manifest` | `to_manifest_payload` — the workload serializes into the existing payload unchanged |
| range core | `range_catalog.WEB_BREACH_LAB` is the product definition; the native competition core stays the authoritative scoreboard |

No new outcome vocabulary was introduced. `ReconcileAction` is an *action* alongside the #107
outcome, not a replacement for it.

## Workload contract

`compile_workload(request, network, observation, ledger) -> WorkloadPlan | BlockedPlan`

Per team: one attacker guest on the team's `attacker` segment, one guest per catalog `target`
component on the team's `vulnerable` segment. Two teams minimum. Six guests for `web-breach-lab`.

Blocking reason ids (all returned together, never one at a time):

- `proxmox.workload.image_not_reviewed`
- `proxmox.workload.template_not_observed`
- `proxmox.workload.profile_missing`
- `proxmox.workload.no_eligible_node`
- `proxmox.workload.storage_not_observed`
- `proxmox.workload.placement_not_eligible`
- `proxmox.workload.team_set_mismatch`
- `proxmox.workload.no_scoring_segment`
- `proxmox.workload.segment_missing`
- `proxmox.workload.no_target_component`
- `proxmox.workload.support_component_unmapped`

Constructor-level refusals: a floating workload version, a missing base-image digest, a missing
approval reference, more than `MAX_BOOTSTRAP_OPERATIONS` (10) bootstrap steps, a single-team
request.

**Scoring endpoint.** Pinned to the first host of the scoring subnet — the same derivation
`proxmox_verification._check_reachability` uses. One derivation, not two.

**Probe address.** `GuestAddress.probe_address` is populated only where `evaluate_flow` says the
compiled rules permit the vantage to reach the guest. On the isolated segments of a Web Breach Lab
that is nobody, so it is `None` and readiness travels the guest's own outbound report instead.
There is no fallback to `published_address`.

## Bootstrap reporting

`BootstrapState` is closed and has exactly four members, with no `in_progress`:

| state | meaning |
| --- | --- |
| `ready` | reported, attributed, running the pinned version at the pinned digest |
| `failed` | reported, and the answer is no |
| `timed_out` | the bound elapsed with no attributable report — a closed failure |
| `unobserved` | the report channel could not be consulted |

`bootstrap_finding(verdicts) -> CheckFinding(check=guest_readiness, ...)`. Any `unobserved` guest
sets `observed=False`, so `decide_outcome` cannot return `verified`. An empty verdict set is
`observed=False`, never vacuously ok.

A report is accepted only when its `attestation_ref` and `vmid` both match. An unattributable
report is evidence in neither direction; duplicate reports for one guest mean neither is trusted.

## Secrets

`MaterialRef` has no `value` field. Flags, team credentials and per-guest attestation values are
references delivered over `material_channel` (`secp.post-provisioning.v1`), never through
cloud-init and therefore never into OpenTofu state.

`assert_no_durable_secrets(payload, forbidden_values=...)` keys on **content**, not field names,
and names the path without quoting the value. `unsearchable_values(values)` reports declared values
a substring guard cannot protect — DVWA's shipped flag is literally `password`, which occurs inside
the public challenge key `dvwa-sqli-password-hash`. Being on that list is the finding.

## Reset semantics

| Subject | Disposition |
| --- | --- |
| range identity, SDN zone, VNets, subnets and VLANs, firewall objects, allocation ledger | `preserved` |
| team membership | `preserved` — always, not an option |
| scores | `preserved` unless `ResetRequest.clear_scores` is explicitly true |
| guests | `recreated` from the reviewed base image at their existing vmid/MAC/address |
| challenge state | `restored` — material refs replanted after the guests report ready |

Refusal codes: `no_approved_desired_state`, `topology_change_without_approval`,
`allocation_ledger_drift`, `ledger_not_sealed`, `operation_generation_not_advanced`.

`topology_fingerprint(desired_state)` hashes the desired state with `operation_generation` stripped
at every depth. Equal fingerprints mean the same topology across operations. It notices a moved
guest, a renumbered guest, a resized disk and a reordered firewall rule.

**A reset still requires an approval.** Advancing `operation_generation` restamps every ownership
tag, so `desired_state_hash` changes and the apply gate refuses until the new plan is approved.
What this module guarantees is that the plan being approved is the *same topology*.

`REQUIRED_RESET_CHECKS = {guest_readiness, required_reachability, cross_team_denial,
management_denial}`. `evaluate_reset_verification` downgrades a report that says `verified` over a
finding set missing any of them.

## Reconciliation

`decide_reconciliation(...) -> ReconcileDecision`, actions `no_action | resume_apply | halt`.

Halts, in severity order, all with a #107 outcome:

| reason | outcome |
| --- | --- |
| `provider_outcome_unknown` | `recovery_required` |
| `provider_unobservable` | `recovery_required` |
| `observation_incomplete` | `recovery_required` |
| `ledger_not_sealed` | `recovery_required` |
| `isolation_violation_observed` | `isolation_failed` |
| `foreign_object_at_allocated_id` | `state_disagreement` |
| `state_claims_absent_resource` | `state_disagreement` |
| `resource_not_in_sealed_ledger` | `state_disagreement` |

An observation is *incomplete* when OpenTofu state was not read, no provider-derived address list
was collected, ownership tags were not read for every observed guest, or the desired state lacks a
usable ownership stamp. Incomplete halts — it is never reasoned over.

`resume_apply` may only name vmids that (a) a complete observation proved absent and (b) the sealed
ledger already records. It never mints an identity and never names something already present, so a
retry cannot duplicate infrastructure.

## Known divergence to raise with the range-lifecycle owner

`apps/worker/secp_worker/range/execution.py:422` clears scores on **every** range reset
(`reset_scores_for_range`), unconditionally, on the provider-neutral Docker path. The Proxmox reset
contract above makes score clearing opt-in. That file belongs to another writer and was not
touched. Reconciling the two is a lifecycle decision, not a Proxmox one.
