# SECP-002B-1B — Disposable Isolated Lab Prerequisite Checklist

**Status:** Prerequisite gate for the FUTURE B1-B milestone. **Nothing here is performed in
B1-A.** Do not add any real lab value (hostname, IP, cluster/node/storage/bridge/VLAN name,
provider URL, credential, or checksum) to the repository — B1-B configuration lives outside
source control (secret manager + operator runbook).

This checklist must be **fully satisfied and human-reviewed** before the first real
worker-only OpenTofu dry run against a disposable Proxmox lab. It is intentionally
conservative: the first real run is narrowly scoped, reviewed, applied, verified, and
destroyed.

> **No box in this checklist is checked by the ADR-020 architecture-lock PR (B1B-PR1).**
> That PR is documentation + tests only; it activates nothing and satisfies no prerequisite.
> Every box remains **unchecked** and is satisfied only by the future reviewed implementation
> slices (B1B-PR2…PR8) plus deployment-local operator review. See
> [ADR-020](../adr/ADR-020-first-real-disposable-lab-lifecycle.md),
> [architecture](../architecture/secp-002b-1b-real-lab-lifecycle.md), and
> [implementation plan](../implementation/secp-002b-1b-plan.md).

## 0. Approved target onboarding (SECP-002B-1B-0, ADR-014)

- [ ] The target has an **approved & active `TargetOnboarding`** record with no config/scope
      drift since approval (the real-provisioning gate enforces this).
- [ ] The **onboarding mode** is declared (`clean_server` or `existing_environment`) and the
      **isolation model** is explicit (`physical` preferred; `logical` only behind a
      complete, declared, enforceable boundary).
- [ ] The **declared boundary** is complete and matches the target scope policy (nodes /
      storage / network segments / CIDRs / VM-ID range / quotas / deny-external /
      least-privilege credential scope).
- [ ] Preflight evidence is present, redacted, and **passing** — for `logical` isolation the
      `no_route_to_protected` check must pass. (B1-B replaces the fake collector with a real,
      still-redacted collector.)

> **B1B-PR3 note:** the controlled worker-owned read-only eligibility preflight seam
> (`run_real_eligibility_preflight`) now exists — sealed by default. It reuses the dormant read-only
> Proxmox transport and the existing `TargetPreflight`/`TargetEvidenceRecord` tables to produce
> redacted, expiry-bound, hash-bound `live_verified` eligibility evidence via a versioned deterministic
> policy. That does **not** check any box here: no operator has run it against a real target, the
> shipped composition is disabled (no transport/resolver/collector injected), it runs no OpenTofu and
> mutates nothing, and a passing unit fixture is not deployment evidence. These boxes are satisfied only
> by a reviewed activation against an actual disposable lab. Both B1-A subprocess seals remain `True`.

## 1. Dedicated, disposable target

- [ ] A **dedicated** Proxmox host/cluster reserved for disposable labs only — never a
      production, home, or shared cluster. *(Physical isolation is preferred but not
      mandatory; a shared environment is acceptable only with an approved `logical`
      onboarding boundary per §0.)*
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
- [ ] A **real `ToolchainVerifier`** (replacing the B1-A `FakeToolchainVerifier`) attests
      the executable identity, exact version, binary-integrity digest, module-bundle
      identity/hash, provider lockfile hash, offline mirror identity, and renderer version
      against the actual on-disk toolchain **before** any init/plan/apply/destroy. The
      runner refuses to execute unless every facet is attested.

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

## 9. Activation dossier (deployment-local, reviewed — ADR-020 §D)

- [ ] A **deployment-local activation dossier** (outside source control) binds organization,
      execution target, onboarding record, exact node/storage/bridge-VLAN/CIDR/VM-ID allowlists,
      quotas, deny-external policy, trusted TLS identity, least-privileged **credential reference**
      (no raw credential), OpenTofu executable identity/version/digest, module-bundle identity/hash,
      provider-lockfile hash, offline-mirror identity, renderer version, remote-state backend
      reference, state-locking proof, state backup/restore proof, recovery owner, emergency-stop
      owner, approval actors, review timestamp, and dossier revision/hash.
- [ ] The dossier is **human-reviewed**; only its **redacted hash + bound ids** become durable SECP
      evidence; raw values and the credential remain external operator evidence.

## 10. Operation-specific unseal phases (ADR-020 §C, plan B1B-PR2…PR7)

- [ ] Each capability (plan / apply / destroy) has its **own** code seal constant, **own** runtime
      enablement, and **own** human approval; unsealing one leaves the others sealed as `True`.
- [ ] Advancing a capability is a **reviewed code-and-review change plus the full runtime gate** —
      never a configuration flag.

## 11. Real toolchain attestation (ADR-020 §F; §5 above)

> **B1B-PR2 note:** the `RealToolchainVerifier` code now exists (worker-local, filesystem-only
> attestation). That does **not** check any box below — no operator has attested a real installed
> toolchain, the verifier is not wired into any execution path, and a passing unit fixture is not
> deployment evidence. These boxes are satisfied only by a reviewed deployment-local attestation of
> the actual on-disk toolchain.

- [ ] The **real** `ToolchainVerifier` (not `FakeToolchainVerifier`) attests the on-disk toolchain
      before any init/plan/apply/destroy; no fake verifier and **no fake-runner fallback** may satisfy
      a real-lab gate.

## 12. Exact minimum first-lab resource budget (ADR-020 §P)

- [ ] The first run uses the **smallest** already-representable shape: one target, one allowed node,
      one dedicated disposable storage target, one isolated network boundary, one bounded CIDR, one
      minimal disposable guest (or smallest existing fixture), strict CPU/RAM/disk caps, and no
      external connectivity. If the renderer cannot yet emit a genuinely minimal *real* resource, that
      is an explicit implementation prerequisite (B1B-PR5), not something fabricated.

## 13. Plan-only stage before apply enablement (ADR-020 §C, plan B1B-PR5)

- [ ] A reviewed **plan-only** run (real `init`/`plan`/`show`) has completed with an **exact
      change-set-hash approval** **before** apply is ever enabled. Apply and destroy remain
      technically **incapable** (their seal constants `True`) during the plan-only stage.

## 14. Verification criteria (post-apply — ADR-020 §K)

- [ ] Post-apply verification compares approved change-set resources, remote state, Proxmox observed
      inventory, expected VM/container/network/disk identities, target boundary, reservations, quotas,
      network-isolation + no-route checks, and health/readiness. **A successful exit code alone is not
      sufficient.** Outcomes are closed: `verified` / `verification_failed` / `state_disagreement` /
      `isolation_failed` / `recovery_required`.

## 15. Destroy readiness + separate approval before first apply (ADR-020 §L)

- [ ] The **destroy** implementation and a tested destroy path are ready **before** the first apply.
- [ ] Destroy uses its **own** newly generated change set, its **own** redacted canonical hash, and a
      **separate** human approval — never a reuse of the apply approval.

## 16. Zero-residue closeout (ADR-020 §L)

- [ ] Zero-residue verification independently re-inspects the provider **and** state to prove absence
      of guests, disks/volumes, network attachments, generated firewall entries, unreleased
      reservations/leases, workspace artifacts, transient binary plans, and removable state objects
      inside the declared boundary. **Destroying resources does not by itself prove cleanup.**

## 17. Emergency stop and manual containment (ADR-020 §N)

- [ ] A **deployment-local kill mechanism** can stop new privileged work without mutating approvals
      into success, erasing evidence, enabling a fake fallback, or bypassing state locking.
- [ ] The distinction between preventing new work, terminating a local process, stopping a Temporal
      workflow, provider-side in-progress operations, and manual containment is documented.

## 18. Partial-apply recovery owner + manual cleanup (ADR-020 §M)

- [ ] A named **recovery owner** and a documented **manual-cleanup procedure** exist **before** the
      first apply; no automatic blind re-apply or blind destroy; destructive recovery requires a fresh
      exact approval.

## 19. Evidence retention (ADR-020 §O)

- [ ] Immutable, redacted, hash-bound evidence is retained for preflight, toolchain attestation, plan,
      approval, apply, verification, destroy, zero-residue, recovery, and kill-switch events. Evidence
      contains ids/hashes/categories/counts/timestamps only — never credentials, raw plan/state, or
      provider bodies.

Only when **every** box is checked and independently reviewed may B1-B proceed to a
narrowly scoped first real dry run → approval → apply → verify → destroy.
