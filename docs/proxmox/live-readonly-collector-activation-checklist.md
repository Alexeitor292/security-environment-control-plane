# Live Read-Only Proxmox Collector — Human Activation Checklist

**Status:** Activation gate for the FUTURE first real read-only Proxmox collector
(SECP-002B-1B-2 design; enablement is a later PR). **Nothing here is performed now.** Do not
add any real value (hostname, IP, URL, cluster/node/storage/bridge/VLAN name, credential,
token, secret, or checksum) to the repository — live configuration lives outside source control
(secret manager + operator runbook).

Every box must be **checked and independently human-reviewed**, and an explicit user
authorization recorded, before the default-disabled live-collection feature gate is enabled for
a specific approved target. The collector is **read-only**; it never mutates a target.

## 1. Disposable/staging target approval
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

## 7. Rollback / revocation procedure tested
- [ ] Disabling the feature gate immediately inerts the collector (verified).
- [ ] Credential revocation verified to stop all further collection.
- [ ] A tested procedure exists to purge/quarantine collected evidence if required.

## 8. Manual test plan approved
- [ ] A read-only manual test plan (allowlisted GETs only) reviewed and approved.
- [ ] Fake-transport unit tests (GET-only, endpoint allowlist, redirect/cross-host refusal,
      normalization, redaction, `unverifiable` semantics) are green **before** live access.

## 9. Explicit user authorization recorded
- [ ] An explicit, time-bounded human authorization record binds this activation to the exact
      approved `(execution_target_id, config_hash)`; hash drift fails closed.
- [ ] Independent security review of the threat model, code, and tests is complete.

Only when **every** box is checked, independently reviewed, and the authorization is recorded
may a future PR enable the live read-only collector for that one approved target. Provisioning
and any mutation remain a separate, later milestone.
