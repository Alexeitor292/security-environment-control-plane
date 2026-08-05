# Proxmox destroy and zero-residue contract

Owner: `owner-proxmox-workload` (P6). Branch `feature/secp-proxmox-destroy-residue`, from `ce9cde6`.

Descriptive, not authoritative — the modules are. Every claim below is pinned by a test in
`apps/api/tests/test_proxmox_destroy_residue.py`.

## Files owned by this stream

| File | Purpose |
| --- | --- |
| `apps/worker/secp_worker/provisioning/proxmox_destroy_gate.py` | Destroy authorization, separate from apply |
| `apps/worker/secp_worker/provisioning/proxmox_residue.py` | Ownership-bounded deletion, absence proof, reservation release |

No existing file is modified. No migration, no sealed-set change.

## Consumed, not redefined

| From | What |
| --- | --- |
| `#107` `proxmox_verification` | `ObservedInfrastructure`, `ObservedGuest` |
| `#105` `proxmox_model` | `is_owned_by_secp`, `ObjectProvenance`, `Ownership` |
| `#105` `proxmox_ipam` | `AllocationLedger.release(absence_proved=...)`, `AllocationKind` |
| range core | `TeardownResourceOutcome` (removed/present/unproven), `ResidueVerdict` (clean/residue/unproven) |
| `proxmox_apply_gate` | `WorkerIdentity`, `INFRASTRUCTURE_OPERATOR_ROLE` |

`SupplementalObservation` is **additive** — the #107 observation contract is not widened. It carries
only the provider inventory `ObservedInfrastructure` does not (disk volumes, NIC MACs, bridges,
subnet CIDRs, VLAN tags, firewall rules and aliases, cloud-init snippets, bootstrap objects), with
the same `| None` = "not observed" convention.

## An apply approval never authorizes a destroy

Enforced twice, independently:

1. `DestroyApproval.__post_init__` raises `DestroyApprovalError` for any `operation_kind` other than
   `destroy`. There is no constructor that accepts an apply approval.
2. `evaluate_destroy_gate` separately requires the regenerated change set's own `kind` to be
   `destroy`. This is not redundant: the first binds the **approval**, the second binds the
   **plan**. An operator approving "destroy this range" against a change set that in fact creates
   twelve VMs is caught only by the pair.

Destroy approvals are one-shot: `approval_already_consumed` refuses a replay rather than succeeding
as a no-op, because "already destroyed" and "someone is replaying an approval" look identical from
outside.

### Refusal codes (16, all parametrized against the enum so an untested code fails collection)

`approval_is_not_for_destroy` · `no_destroy_approval` · `approval_already_consumed` ·
`destroy_change_set_hash_mismatch` · `prepared_plan_is_not_a_destroy_plan` ·
`stale_binary_destroy_plan` · `deletion_set_mismatch` · `ownership_not_verified` ·
`discovery_stale` · `ownership_scope_mismatch` · `worker_identity_mismatch` ·
`worker_release_mismatch` · `target_mismatch` · `remote_state_lock_unavailable` ·
`credential_unresolvable` · `ordinary_worker_on_controlled_live_path`

`ownership_verified` and `discovery_fresh` are tri-state: `None` refuses exactly as `False` does.

### The deletion-set hash

`deletion_set_hash(addresses)` hashes the sorted, de-duplicated **set** of resource addresses. The
change-set hash binds the ACTIONS; this binds WHAT they act on. A plan whose canonical change set
matches the approval but which would delete a different resource is refused with
`deletion_set_mismatch`.

## Residue coverage — 25 classes

Provider: `qemu_vm` `lxc_container` `disk_volume` `nic` `sdn_zone` `vnet` `bridge` `subnet`
`vlan_assignment` `firewall_group` `firewall_rule` `ip_set` `firewall_alias` `cloud_init_snippet`
`bootstrap_object`

Ledger: `vmid_reservation` `mac_reservation` `ip_reservation` `subnet_reservation`
`vlan_reservation` `remote_state_key_reservation`

Local/remote artifacts: `transient_workspace` `binary_plan_file` `temporary_credential_file`
`remote_state_object`

`CLASS_PROBE_DOMAIN` maps every class to the probe domain that can answer for it; a test asserts the
mapping is exhaustive over both enums, so a class with no probe cannot exist.

## How a foreign resource is proven safe from deletion

`bound_deletion_set` classifies each owned resource into exactly one of four buckets:

| bucket | meaning |
| --- | --- |
| `deletable` | a working observation found it AND `is_owned_by_secp(tags, expected)` returned `secp_owned` |
| `protected` | something is there and its tags say `untagged`, `unreadable` or `secp_foreign_scope` |
| `already_absent` | a working observation did not find it |
| `undetermined` | the provider was unobservable, or the object's tags were never read |

Tested with an impostor carrying a **byte-identical name** at one of our own allocated vmids: it
lands in `protected`, is absent from `deletion_addresses`, keeps its reservation held, and makes the
verdict `unproven`. A partial `secp.*` tag set reads as `unreadable` and is likewise protected.

`DeletionSet.may_proceed` is False whenever anything is `undetermined`, so a destroy cannot run at
all against an unobservable provider. Protected objects do **not** block the destroy — the range's
own resources are still removed — they only make `clean` unreachable.

## Unknown is never clean

Each probe domain carries its own health flag measured **after** the deletion attempts:
`ObservedInfrastructure.reachable`, `ArtifactProbe.readable`, `RemoteStateProbe.readable`. When a
domain's probe could not run, every class in that domain reports `unproven`, never `removed`. An
uncollected supplemental inventory is likewise `unproven`, not "empty".

`AbsenceFinding.absence_proved` is `probe_healthy AND outcome is removed`. A forged `removed` from
an unhealthy probe still yields `absence_proved == False` — the health flag overrides the outcome,
not the reverse.

`residue_verdict` grades against the **expected** list, not the findings it was handed. A resource
with no finding at all is `unproven`; an empty finding set is `unproven`; an empty expected list is
`unproven`. `uncovered_classes` names which class went unexamined.

## How reservations are gated on proved absence

`releasable_allocations(findings, protected=...)` sets `release` **from `finding.absence_proved`**,
never a literal. A protected identifier is retained unconditionally: handing on an id something else
occupies is how the next range collides with a live VM.

`release_proved_allocations` passes `absence_proved=decision.release` through to
`AllocationLedger.release`, so the ledger's own refusal remains a real backstop — a test proves
`ledger.release(absence_proved=False)` raises and frees nothing. It returns
`(released, retained, already_released)`; an allocation the ledger does not hold is `already_released`
rather than an error, so a destroy interrupted partway through its release phase is safe to re-run.

`zero_residue_proof` composes the reservation findings itself from `decisions`/`released`, so a
caller cannot grade the two halves inconsistently. It computes the verdict — it is never passed one.
