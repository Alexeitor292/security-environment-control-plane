# Live Read-Only Proxmox Collector — Human Activation Checklist

**Status:** Activation gate for the FUTURE first real read-only Proxmox collector
(SECP-002B-1B-2 design; enablement is a later PR). **Nothing here is performed now.** Do not
add any real value (hostname, IP, URL, cluster/node/storage/bridge/VLAN name, credential,
token, secret, or checksum) to the repository — live configuration lives outside source control
(secret manager + operator runbook).

SECP-002B-1B-6 adds only a durable authorization model and worker-owned loader/verifier
contracts. It does not authorize, enable, configure, or connect to any staging target, and it
adds no real endpoint, secret backend, API action, UI action, dispatcher wiring, worker workflow,
feature switch, or live evidence persistence.

SECP-002B-1B-7 adds only the disposable staging target operating design and readiness contract
(`disposable-staging-target-operating-design.md`). It performs no registration, wiring, access,
or activation. Its out-of-band eligibility requirements and readiness evidence checklist must be
complete and independently reviewed before any box in this activation checklist may be checked.

SECP-002B-1B-8 corrects that design (`isolated-staging-control-plane-design.md`): the future
staging worker lives inside a self-contained **isolated SECP staging control-plane VM** with its
own staging-only API and database (kept local to the VM), reaching only one disposable nested
Proxmox target API. It performs no registration, wiring, access, or activation, and its added
readiness items (self-contained staging control plane, tested absence of production
control-plane access, verified offline bootstrap, verified caps/headroom, functional read-only
scope) must also be complete and independently reviewed out of band.

SECP-002B-1B-9 adds the application-owned, **fake-only** desired-state / plan / approval /
simulation / teardown workflow (SECP owns the desired state, not a shell runbook). It creates no
bridge, VM, VNet, target, token, or connection, contacts no infrastructure, and adds no
activation switch. A staging-lab plan approval permits fake simulation only and is separate from
the live-read authorization required below. The self-contained staging control-plane constraint
remains mandatory, and a later separately reviewed adapter PR is required before any real
provisioning.

Every box must be **checked and independently human-reviewed**, and an explicit user
authorization recorded, before the default-disabled live-collection feature gate is enabled for
a specific approved target. The collector is **read-only**; it never mutates a target.

## 1. Disposable/staging target approval
- [ ] The disposable staging target operating design (SECP-002B-1B-7,
      `disposable-staging-target-operating-design.md`) eligibility requirements and readiness
      evidence checklist are complete and independently reviewed **out of band**.
- [ ] A **disposable or staging** Proxmox target reserved for read-only evidence trials — never
      a production, home, or shared production cluster.
- [ ] The environment is rebuildable and contains no data of value.
- [ ] Registered as a distinct `ExecutionTarget`; not reused from any other purpose.
- [ ] The target has an approved onboarding boundary (ADR-014) matching its scope policy.

## 2. Restricted read-only identity reviewed
- [ ] A dedicated Proxmox identity scoped to **read-only** on only the approved nodes/storage/
      segments — never root/full-admin, never a write/task/console/agent capability.
- [ ] The identity's **effective permissions verified out of band** (a human confirmed it
      cannot mutate, trigger tasks, open consoles, or read guest secrets).
- [ ] Rotation and revocation procedure documented and owned.

## 3. Endpoint and certificate identity verified out of band
- [ ] The endpoint host is the approved target's immutable configured host (no request input).
- [ ] `https://` only; `verify_tls=false` refused; a **trusted CA** or an approved
      certificate-pinning approach is in place.
- [ ] Certificate identity/fingerprint **verified out of band** against the expected target.

## 4. Egress allowlist approved
- [ ] Worker egress restricted to the single approved target host:port; no other destination
      reachable; redirects not followed; cross-target destinations refused.

## 5. Secret storage approved
- [ ] The read-only credential is stored **only** in an approved secret manager and referenced
      by an opaque `secret_ref`; never committed, logged, hashed, persisted, or returned.
- [ ] Just-in-time worker-only resolution confirmed; API never resolves the reference.
- [ ] Credential expiry set; expired/revoked credential yields a redacted `unverifiable`
      result, never a partial read.

## 6. Alerting / audit review complete
- [ ] Every authorization, job start/complete/fail, and refusal is audited (secret-free).
- [ ] Alerting on unexpected methods/endpoints/redirects/egress is configured and tested.
- [ ] A human reviewed the normalized evidence shape + redaction rules for information leakage.
- [ ] Reviewer explicitly accepts that collected evidence is **not remotely attested**: the
      full-record hash proves post-collection **integrity and binding**, not **truthfulness**;
      a compromised target or worker could return plausible false data that passes comparison.
      Human review and out-of-band checks (not the hash) are what compensate.

## 6a. Fully-segregated isolation verification
- [ ] `fully_segregated` is **not** inferred from inventory, bridge/VNet presence, or segment
      names. Each required fact is verified by an approved, allowlisted, read-only observation:
      dedicated lab segment **identity**; **no** protected-network uplink/route; **no** default
      route / external egress where policy is `deny`; required host-side isolation controls.
- [ ] Any required isolation fact that is unavailable, ambiguous, not safely observable, or out
      of scope yields **`unverifiable`** and **blocks approval** — never a pass.

## 7. Rollback / revocation procedure tested
- [ ] Disabling the feature gate immediately inerts the collector (verified).
- [ ] Credential revocation verified to stop all further collection.
- [ ] A tested procedure exists to purge/quarantine collected evidence if required.

## 8. Manual test plan approved
- [ ] A read-only manual test plan (allowlisted GETs only) reviewed and approved.
- [ ] Fake-transport unit tests (GET-only, endpoint allowlist, redirect/cross-host refusal,
      normalization, redaction, `unverifiable` semantics) are green **before** live access.

## 9. Explicit user authorization recorded
- [ ] A future PR wires exactly one approved target through the authoritative worker-owned
      loader/verifier; no caller-built target/onboarding/auth records are accepted as the trust
      anchor.
- [ ] An explicit, time-bounded human authorization record binds this activation to the exact
      approved `execution_target_id`, `onboarding_id`, connection hash, boundary hash,
      authorization version/expiry, evidence source, verification level, collector-contract
      version, and endpoint-allowlist version; any drift fails closed.
- [ ] The direct-instantiation guard remains in force: production live-read modules do not
      directly instantiate the collector, construct the live transport, or invoke the dormant
      runner outside the reviewed activation seam.
- [ ] Credential references remain exact in-memory bindings only: never hashed, logged, audited,
      serialized, or exposed through `repr()`.
- [ ] Independent security review of the threat model, code, and tests is complete.

Only when **every** box is checked, independently reviewed, and the authorization is recorded
may a future PR enable the live read-only collector for that one approved target. Provisioning
and any mutation remain a separate, later milestone.
