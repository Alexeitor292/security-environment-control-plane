# Isolated SECP Staging Control-Plane — Topology Correction (SECP-002B-1B-8)

**Status:** Documentation-only correction of the SECP-002B-1B-7 disposable staging design.
**Nothing here is performed, provisioned, registered, configured, or connected now.** This
document corrects a topology error **before any infrastructure change** and introduces no code,
configuration, wiring, endpoint, credential, or activation. It supersedes, within the
SECP-002B-1B-7 operating design, the standalone-worker reference topology and the earlier claim
that destroying staging is without consequence.

Do not add any real value (hostname, IP, URL, port number, bridge/VNet name, VMID, storage
name, certificate data or fingerprint, credential reference, secret backend name, token, user
account, or checksum) to this document or anywhere else in the repository. Live operating values
exist only outside source control (secret manager + operator runbook). Placeholders in angle
brackets (for example `<staging-target-host>:<api-port>`) are deliberate and must never be
replaced in Git.

This correction adds no target registration, no API/UI/dispatcher/workflow/Compose/runtime
wiring, no environment variable, no secret backend, no transport, no collector, no network call,
and no live evidence persistence. The default-disabled gate (SECP-002B-1B-4), the trusted-record
binding (SECP-002B-1B-5), and the authorization contract (SECP-002B-1B-6) are unchanged.

## 1. What is being corrected

The SECP-002B-1B-7 reference topology described a lone "SECP worker" reaching the target across a
single isolated segment. Read literally as a worker with only one target-facing interface, that
would **strand the worker from the authoritative API and database** the SECP-002B-1B-6
loader/verifier contract requires: the worker must load `ExecutionTarget`, `TargetOnboarding`,
and `LiveReadAuthorization` records from an authoritative store, and a worker holding only a
target-facing interface has no authoritative store to read. This document replaces that concept
with a self-contained isolated staging control plane.

## 2. Isolated SECP staging control-plane VM

The "SECP worker VM" concept is replaced by a single **isolated SECP staging control-plane VM**.
It is self-contained and contains a **staging-only API**, a **staging database**, and a
**staging worker**, all inside that one isolated VM.

- The staging API, staging database, and staging worker are provisioned only for this isolated
  staging environment and are destroyed with it.
- The VM **must never use the production SECP database** or any production control-plane
  service — not the production API, dispatcher, queue, secret backend, or audit store.
- Nothing in production depends on the staging control plane, and the staging control plane
  depends on nothing in production.

## 3. Authority path

- Target, onboarding, and authorization records are **loaded from the isolated staging
  database** only.
- The **staging worker accesses them locally**, over the in-VM control-plane path (section 4),
  never over the target-facing segment and never from production.
- The **future staging authorization is authoritative only for this isolated staging
  environment**. It confers no authority in production and is meaningless outside the staging
  control plane that issued it.
- Consistent with SECP-002B-1B-6, **no caller-supplied records can substitute for the staging
  database**: the loader/verifier reads authoritative records through the repository seam backed
  by the staging database, never caller-built ORM objects presented as a trust source.

## 4. Two-plane topology

The staging control plane has two separate planes — a local control-plane plane and a
target-facing plane:

```text
Isolated SECP staging control-plane VM
  [ staging API ] <-- loopback / internal container network --> [ staging database ]
         ^
         |  local only (loopback / internal container network)
         v
  [ staging worker ] -- one approved API flow --> <staging-target-host>:<api-port>
                                                  (disposable nested Proxmox target API,
                                                   TLS-verified, read-only)
```

- **Local control-plane communications** — staging API to staging database, and staging worker
  to staging API/database — stay on **loopback or an internal container network** inside the VM.
  They never traverse a routable or target-facing interface.
- **Target-facing segment** — **one isolated NIC** carrying the single approved flow to the
  disposable nested Proxmox target, and nothing else.
- **No default gateway, no DNS, no LAN, no WAN, and no production-control-plane route** exist on
  the staging VM.
- **Future target-facing traffic is limited to the one approved API flow** from the staging
  worker to the single disposable nested Proxmox target API; every other destination is
  default-denied.

## 5. Offline bootstrap requirement

- The installation ISO/template and all required packages and container artifacts are prepared
  through an **operator-controlled offline process** before the VM is isolated.
- Staging VMs **never download dependencies after isolation** — no package index, registry,
  mirror, module source, or provider download occurs once the target-facing plane exists.
- Artifact **provenance and integrity are verified outside Git** (secret manager + operator
  runbook), before isolation.
- **No real artifact locations or checksums enter the repository** — only this placeholder-level
  design.

## 6. Corrected scope language

- Nested Proxmox on a **shared production hypervisor** is acceptable **only for controlled
  functional validation** of the read-only control plane.
- It is **not equivalent to dedicated-hardware or hypervisor-level isolation**: it shares a
  kernel and hypervisor with production and must be treated as a functional test substrate, not
  as an isolation boundary or a security control.
- The staging environment **must not execute untrusted workloads**; it exists to exercise the
  read-only control-plane path against inventory, not to run adversary or participant code.
- The earlier claim that destruction is without consequence is **withdrawn**. Destroying the
  staging environment affects only **bounded, reversible staging resources** and is permissible
  only against **verified production headroom** (CPU, RAM, and storage confirmed spare out of
  band). Consequence to the shared host is acknowledged, bounded, and reversible — never assumed
  absent.

## 7. Updated readiness checklist (completed outside Git)

These items **extend** the SECP-002B-1B-7 readiness checklist and must be completed, evidenced,
and independently reviewed **outside Git** before any activation PR may be proposed. None of them
is satisfied by anything in this repository.

- [ ] The staging API, staging database, and staging worker are **self-contained** within the
      isolated staging control-plane VM.
- [ ] **Production control-plane access is absent and tested** — the staging VM cannot reach the
      production API, the production database, or any production control-plane service (verified
      negative test, not assumption).
- [ ] **Offline bootstrap artifacts are verified** — provenance and integrity confirmed out of
      band; no post-isolation download path exists.
- [ ] **Resource caps and production headroom are verified** — staging CPU, RAM, and storage are
      capped and confirmed to fit within spare host headroom.
- [ ] **Staging scope is restricted to functional read-only validation** — no untrusted workload
      runs, and the environment is not treated as a hardware or hypervisor isolation boundary.

## 8. Guardrails in this repository

Static tests (`apps/api/tests/test_isolated_staging_control_plane_design.py`) assert that this
correction requires a self-contained staging API, database, and worker; forbids any production
control-plane or production-database dependency; requires offline bootstrap; does not overclaim
isolation (it is not a hardware or hypervisor boundary) or claim that destroying the nested
design is without consequence; and adds no real infrastructure value or activation code/config.
The SECP-002B-1B-7 guardrails remain in force.

## 9. Application-owned desired-state workflow (SECP-002B-1B-9)

SECP-002B-1B-9 makes SECP the owner of this design's desired state instead of a manual command
runbook. It adds an application-owned, **fake-only** workflow — a durable `StagingLab`
desired-state record, a deterministic immutable topology compiler, an explicit approval boundary,
a worker-owned fake execution seam, and a controlled teardown — surfaced in the web UI
(create, plan, approve, simulate, observe, teardown). The compiler emits the logical resources
described above (self-contained staging control plane, one host-only no-uplink network, one
disposable nested target, exactly one target-facing read-only connection, checkpoint/rollback,
teardown), each carrying an immutable ownership label, and fails closed on production reuse,
shared/production networks, more than one target-facing network or nested target, missing
self-containment, standing authorizations, missing ownership, or an unapproved substrate.

B1-B9 creates no bridge, VM, VNet, target, token, or connection; contacts no infrastructure; and
adds no activation switch. A staging-lab plan approval permits fake simulation only and is not a
live-read authorization. This self-contained staging control-plane constraint remains mandatory
for any future adapter, which must arrive in a later, separately reviewed PR before real
provisioning can occur.
