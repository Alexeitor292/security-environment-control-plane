# SECP live Proxmox deployment dossier

**Status: none of the seven packets below has been executed.** No Proxmox identity, role, token or
ACL exists. No credential has been resolved. The target has not been contacted. No OpenTofu command
has run. No SDN object has been prepared or activated. No guest has been created or configured.

Observed at commit `348b097` on
`feature/secp-https-discovery-integration`. Every capability claim here is anchored to
[`pre-live-readiness-inventory.json`](pre-live-readiness-inventory.json), which records 443
capabilities with file:line evidence and an adversarial verification pass.

Read this alongside [`authorization-packets.md`](authorization-packets.md), which holds the detailed
Packet 1 and Packet 2 contracts. This document is the **sequence**, and it states for each packet
whether the code behind it is ready.

---

## The honest position, first

Packets 1 and 2 are ready to be decided on. **Packets 3 through 7 are not**, and not because they
are unwritten: three of them depend on capabilities that are *absent* or *sealed behind boundaries
no agent may cross*. The measured state is:

| | count |
| --- | --- |
| production-reachable | 149 |
| test-only (correct code, only tests call it) | 110 |
| sealed (deliberate fail-closed default) | 79 |
| absent | 66 |
| declared-unimplemented | 24 |
| simulated / fake-only | 15 |
| **total** | **443** |

Approving a packet whose code is not production-reachable would authorise an operation SECP cannot
perform. Each packet below therefore carries a **readiness** line, and the sequence stops where the
readiness stops.

---

## Packet 1 — the read-only Proxmox identity

**Readiness: ready to decide.** The proposal is rendered by code, derived from the required-fact
table, and executed by nothing.

**What it does.** Creates a dedicated realm user, a read-only role, an ACL entry at `/`, and a
privilege-separated API token with its own ACL entry. It is a Proxmox access-control mutation.

**Exact commands, privileges and rollback.** Rendered by
`secp_api.proxmox_discovery_credential_proposal`. Print them with:

```
uv run python -c "from secp_api.proxmox_discovery_credential_proposal import *; \
print(unauthorized_notice()); print(*provisioning_commands(), sep=chr(10))"
```

The privilege list is computed by `privileges_required()` from the required-fact table, so the grant
is exactly what the facts need. A hand-written list in prose drifts, and it always drifts toward
asking for more.

**Expected effective permissions.** `GET /access/permissions`, called by the token about itself,
should return the four audit privileges at `/` with propagate `1`. **Verified by the preflight, not
assumed** — the SDN authority preflight and the effective-permissions read must agree before any
empty index is read as absence.

**Evidence to capture.** The rendered command set, the operator who ran it, the timestamp, and the
effective-permissions response.

**Refusal conditions.** Any privilege outside the derived set; any ACL entry below `/`; a token
backed by the PAM-realm superuser (Proxmox skips the privilege-separation intersection entirely for
that account, which silently defeats the whole separation).

**Approving this does not authorise Packet 2.**

---

## Packet 2 — live read-only discovery

**Readiness: ready to decide, with one operator prerequisite.** The engine is complete and now has
a production caller. The prerequisite is that no credential backend is configured: the shipped
`SealedDiscoveryCredentialResolver` always fails closed, so an authorized run today reaches the
credential step and refuses **before a socket is opened**.

**What it does.** One privileged worker resolves the Packet 1 token, opens a CA-pinned HTTPS client,
executes up to twenty-four reviewed read operations, and returns a signed snapshot.

**Target identity.** `<enrolled-target-host>:<api-port>` plus the `/api2/json` base path, taken from
the enrolled `ExecutionTarget` — never from a caller.

**Pinned CA.** The deployment-local CA bundle path, an installation fact. There is no default and no
fallback to ambient system trust; a transport without a pinned CA is not constructible.

**Credential reference.** The dedicated `provider_plan_secret_ref` on the target — an opaque
pointer, never the generic fallback, resolved only inside the worker.

**Typed operation inventory.** Twenty-four operations; the transport's allowlist is *derived* from
their declarations, so a reviewed operation and an authorised request are the same fact. Print it:

```
uv run python -c "from secp_worker.proxmox_discovery_operations import discovery_request_grammar; \
[print(k, v[0], v[1]) for k, v in sorted(discovery_request_grammar().items())]"
```

**Expected observation sequence.** Phase 1 needs no identifier (version, cluster status, node index,
the SDN authority preflight, effective permissions, the cluster-wide indexes). Phase 2 needs a node
name. Phase 3 needs a storage id, a vnet id or a zone id. Every dynamic segment carries a
`sourced_from` provenance label naming the response it came from.

**Evidence to capture.** The signed snapshot binding, the fact commitment digest, the operation
manifest, the per-node accounting, and every refusal with its reason code.

**Stop conditions.** Any binding mismatch; a signer that is not the registered worker; an expired or
consumed admission; a superseded authorization version; a snapshot outside the freshness bound; any
required fact that is not `observed`.

**Rollback / revocation.** Revoke the live-read authorization, revoke the worker identity
registration, then run the Packet 1 rollback commands. The token is removed before the user that
owns it.

---

## Packet 3 — target-specific OpenTofu plan

**Readiness: BLOCKED. Do not schedule this packet.**

Two independent reasons, both measured:

1. **This packet cannot contain a plan until Packet 2 has run.** By design — the plan is a function
   of the discovered cluster fingerprint.
2. **No shipped code path executes the OpenTofu binary.** The plan-execution composition gate is
   sealed (`SealedPlanExecutionCompositionProvider` can never return an enabled composition), the
   generic subprocess executor is sealed in two independent places
   (`_B1A_SUBPROCESS_SEALED = True`), the operator worker that would host the alternative is sealed
   *and* contains no Temporal worker construction even if unsealed, and the entire apply/destroy
   family has zero production callers.

The plan/apply separation the packet would enforce — generate, `init`, `plan`, persist the exact
plan hash, human review, authorize that exact hash, apply that exact plan — is durably modelled
(`ProvisioningChangeSetApproval` binds `change_set_hash`, `authorizes_kind`, and four binding
hashes; apply and destroy use separate authorization kinds). The model is sound. Nothing runs it.

**When it becomes decidable:** after Packet 2 has produced a fingerprint AND the seals in §"What is
blocked" below have been resolved by their owner.

---

## Packet 4 — SDN preparation (Stage 1)

**Readiness: BLOCKED.**

The five-stage model is fully specified and thoroughly tested, and **not one of the five stages has
a production driver**. `build_pending_sdn_document` requires a `VerifiedDiscoverySnapshot`, whose
sole issuer had no production caller until this branch; the pending-SDN facts it consumes come from
the discovery run; no code computes `pre_stage1_absence_evidence_digest` or
`durable_ownership_provenance_digest`; and there is no `PUT /cluster/sdn` on any executable line.

**What the packet will contain when it is decidable:** the exact SDN object families to prepare
(zones, vnets, subnets, controllers, and fabrics where the target supports them), the expected
identifiers, the expected pending-state evidence, and the Stage 1 stop point — objects prepared,
nothing activated.

---

## Packet 5 — SDN activation (Stages 3–5)

**Readiness: BLOCKED**, on the same absence as Packet 4.

**This is the packet with cluster-wide blast radius**, and the contract is worth stating now even
though it cannot yet be executed: activation is a **cluster-wide commit**. It applies every pending
SDN object on the cluster, not only ours. That is why authorization requires all six ownership
counts to hold simultaneously — `total_pending > 0`, `current_operation == total_pending`,
`other_secp_operation == 0`, `foreign == 0`, `unknown == 0`, `unclassified == 0` — and why both
digests are recomputed immediately before the commit, with any drift refusing.

Stage 5 must then observe zones, vnets, subnets, VLAN materialization, node bridges, firewall
objects, permitted paths and prohibited paths. **Correct configuration objects are not proof of
isolation** — and today nothing in the repository tests traffic.

---

## Packet 6 — guest deployment and configuration

**Readiness: BLOCKED, and this is the deepest gap in the programme.**

Guest *deployment* has no production path: the Proxmox plugin raises `UnsupportedCapabilityError`
for plan, apply, reset and destroy; the worker's range-provider registry knows only `local_docker`;
and no `apply` verb exists in the plan-only command grammar.

Guest *configuration* is worse than sealed — it is **absent**. There is no code path anywhere that
can place a package list, a file, or a command inside a guest:

- no cloud-init user-data that installs, writes or runs anything;
- no inbound bootstrap report channel — the plan publishes an address a guest should report to, and
  nothing listens there;
- no post-provisioning material channel, so every dynamic value (attestation ref, challenge flag,
  per-team credential) is a reference whose delivery mechanism does not exist;
- no Ansible runner, playbooks or inventory;
- no WinRM, PowerShell remoting, Sysprep or unattend.xml — **a Windows guest cannot be configured by
  SECP at all**;
- no guest agent, no image baking, no config-drive or seed-ISO generation;
- **no plugin-contract verb** through which any future provider could supply the capability.

The scenario schema's only levers over the inside of a guest are an opaque `image` string and a list
of `vulnerabilityPacks` references that nothing resolves.

Consequence for the competition premise: SECP can, once unsealed, create guests from images it did
not build and cannot modify. It cannot install a vulnerable package version, set a password, write a
flag, or place attacker tooling.

---

## Packet 7 — reset and destroy

**Readiness: BLOCKED** on the same execution seals as Packet 3.

The *contracts* are unusually complete — reset, reconcile, destroy gates, residue verification and
foreign-resource protection all exist with real tests — and the reset/destroy authorization hashes
occupy separate domains, so a destroy authorization can never satisfy an apply. What is missing is
execution: the gate family is imported only by tests.

**Zero-residue** is therefore currently a claim no run can make. When it becomes decidable the packet
will enumerate every SECP-owned class to verify absent — VM, LXC, disk, snapshot, SDN object, VNet,
subnet, VLAN, firewall object, state object, credential artifact, work directory, access profile,
bootstrap artifact — and assert foreign infrastructure untouched.

---

## What is blocked, and who owns it

| # | Blocker | Owner |
| --- | --- | --- |
| 1 | The guest configuration plane does not exist, and no plugin-contract verb could carry it | architecture (Charter §6/§15) |
| 2 | OpenTofu execution seals — two `_B1A_SUBPROCESS_SEALED` constants, `PlanExecutionGate`, `_OPERATOR_ACTIVATION_SEALED` | seal owner; agents are unconditionally barred |
| 3 | Proxmox mutating capabilities are unimplemented, and enabling them requires widening the GET-only read transport | provider authority |
| 4 | No packaged worker runtime artifact, and no creation of the dedicated service account | engineering (multi-PR) |
| 5 | No first-class identity lifecycle, so no authenticated API call is possible in production | architecture |

Nothing in this dossier authorises any of the above. Packets 1 and 2 are decisions; packets 3
through 7 are not yet decisions, because the operations they would authorise cannot be performed.
