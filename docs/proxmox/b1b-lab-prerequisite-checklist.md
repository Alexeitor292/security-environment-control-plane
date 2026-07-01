# SECP-002B-1B — Disposable Isolated Lab Prerequisite Checklist

**Status:** Prerequisite gate for the FUTURE B1-B milestone. **Nothing here is performed in
B1-A.** Do not add any real lab value (hostname, IP, cluster/node/storage/bridge/VLAN name,
provider URL, credential, or checksum) to the repository — B1-B configuration lives outside
source control (secret manager + operator runbook).

This checklist must be **fully satisfied and human-reviewed** before the first real
worker-only OpenTofu dry run against a disposable Proxmox lab. It is intentionally
conservative: the first real run is narrowly scoped, reviewed, applied, verified, and
destroyed.

## 1. Dedicated, disposable target

- [ ] A **dedicated** Proxmox host/cluster reserved for disposable labs only — never a
      production, home, or shared cluster.
- [ ] The environment is **rebuildable from scratch** and contains no data of value.
- [ ] Registered as a distinct `ExecutionTarget` classified via an `isolated_lab`
      toolchain profile; not reused from any other purpose.

## 2. Scoped, non-overlapping resource allocation

- [ ] A dedicated node allowlist (`allowed_nodes`) covering only disposable nodes.
- [ ] A dedicated storage allowlist (`allowed_storage`) on disposable storage only.
- [ ] A dedicated bridge/VLAN allocation (`allowed_bridges`) isolated from all other
      networks.
- [ ] A dedicated, non-overlapping CIDR range (`allowed_cidr_reservations`) reserved for
      the lab and not routable to any other network.
- [ ] A dedicated VM-ID range (`vmid_range`) that cannot collide with any existing guest.
- [ ] Explicit resource caps (teams / VMs / containers / vCPU / RAM / disk) sized for the
      lab.

## 3. Isolation and no-route validation

- [ ] External connectivity policy is `deny` (enforced by the scope policy + gate).
- [ ] **Verified no route** from lab networks to management, home, corporate, or public
      networks (tested, not assumed).
- [ ] Firewall/VLAN isolation confirmed at the hypervisor and network layers.

## 4. Trusted TLS and least-privileged credentials

- [ ] Provider `base_url` uses `https://` with a **trusted CA** (or an approved
      certificate-pinning approach). `verify_tls=false` is refused.
- [ ] A **least-privileged** API token scoped to only the lab node/storage/bridge/VM-ID
      allocation — never a root/full-admin token.
- [ ] The credential is stored **only** in a secret manager and referenced by an opaque
      `secret_ref`; it is resolved **just-in-time in the worker** and never persisted,
      logged, or committed.
- [ ] Credential rotation and revocation procedure documented.

## 5. Verified offline toolchain and provider mirror

- [ ] Pinned OpenTofu version + verified binary integrity digest.
- [ ] Provider plugins and modules served from an **offline, pinned, verified** worker-side
      mirror; runtime internet download disabled.
- [ ] Provider lockfile hash and module-bundle hash recorded in the toolchain profile and
      verified against the mirror.

## 6. Remote state protection

- [ ] A **remote** state backend (never local) with access control, encryption at rest,
      and state locking.
- [ ] State backend credentials handled like all other secrets (worker-only, redacted).
- [ ] Backup/restore of state tested.

## 7. Approval, recovery, and destroy

- [ ] The dry-run change set is **human-reviewed and explicitly approved** (exact hash)
      before any apply.
- [ ] A separate **destroy change set** is generated, reviewed, and approved before any
      destroy.
- [ ] Documented **recovery procedure** if apply fails midway (including manual cleanup).
- [ ] A **tested destroy path** that fully removes all lab resources, verified on a
      throwaway run first.

## 8. Runtime arming (last)

- [ ] `SECP_ENABLE_OPENTOFU_SUBPROCESS` armed **only** in the reviewed lab worker, never in
      production.
- [ ] `SECP_ENABLE_REAL_PROVISIONING=true` and
      `SECP_PROVISIONING_APPLICATION_MODE=isolated_lab` set only for the lab run.
- [ ] Temporal/durable worker path only; inline execution remains refused.
- [ ] A rollback/kill plan is ready before the first apply.

Only when **every** box is checked and independently reviewed may B1-B proceed to a
narrowly scoped first real dry run → approval → apply → verify → destroy.
