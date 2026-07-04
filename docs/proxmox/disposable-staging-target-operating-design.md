# Disposable Staging Target — Operating Design and Readiness Contract (SECP-002B-1B-7)

**Status:** Design-only safety contract for the FUTURE first disposable Proxmox staging target
that may eventually support **one controlled read-only SECP validation**. **Nothing here is
performed, provisioned, registered, configured, or connected now.** This document defines the
out-of-band operating design and the readiness evidence that must exist before any activation
PR may even be proposed.

Do not add any real value (hostname, IP, URL, port number, cluster/node/storage/bridge name,
VLAN id, certificate data or fingerprint, credential reference, secret backend name, token,
user account, or checksum) to this document or anywhere else in the repository. Live operating
values exist only outside source control (secret manager + operator runbook). Placeholders in
angle brackets (for example `<staging-target-host>`) are deliberate and must never be replaced
in Git.

SECP-002B-1B-7 adds no target registration, no API/UI/dispatcher/workflow wiring, no
environment variable or Compose change, no Proxmox access, no network/subprocess/provider
activity, no live evidence persistence, no collector/transport/resolver execution, and no
creation, approval, or activation of any `LiveReadAuthorization` record. The default-disabled
gate (SECP-002B-1B-4), the trusted-record binding (SECP-002B-1B-5), and the authorization
contract (SECP-002B-1B-6, PR #13) are unchanged by this document.

> **Correction notice (SECP-002B-1B-8).** The single-node "SECP worker" shown in the reference
> topology below is **superseded** by the *isolated SECP staging control-plane VM* defined in
> `isolated-staging-control-plane-design.md`. A worker with only a target-facing interface would
> be stranded from the authoritative API and database the SECP-002B-1B-6 loader/verifier
> requires. The earlier claim in section 1 that destruction is without consequence is likewise
> **withdrawn** and replaced with the bounded/reversible, verified-headroom language in
> SECP-002B-1B-8. The
> readiness evidence in section 5 is **extended** by the SECP-002B-1B-8 readiness checklist.

## 1. Staging target eligibility

A candidate staging target qualifies **only if every requirement below holds**. Any single
failure disqualifies the target; there is no compensating-control substitution.

- **Disposable or recoverable from a known-clean state.** The entire target can be destroyed
  and rebuilt from documented automation, or reverted to a verified known-clean snapshot,
  at any time; it holds only bounded, reversible staging resources and its destruction is
  validated against verified production headroom (SECP-002B-1B-8), never assumed to be without
  consequence.
- **Isolated by default.** The target is segregated from home, corporate, management, and
  public networks by default-deny controls in both directions. Any reachability that exists
  is an explicit, documented, removable exception — never an inherited flat network.
- **No production workload dependency.** Nothing outside the staging environment depends on
  the target being up, reachable, or intact. Destroying it affects only bounded, reversible
  staging resources and requires verified production headroom on any shared host — it is never
  asserted to be without consequence (corrected by SECP-002B-1B-8).
- **No shared credentials.** No credential, token, key, or account on the target is shared
  with any other system, environment, person, or purpose. Every identity used is created for
  this target alone and dies with it.
- **Independently documented rollback path.** A rollback/rebuild procedure exists outside Git,
  is owned by a named operator, and has been exercised — not merely written down.
- **No participant access during validation.** No exercise participant, student, or other
  non-operator identity can reach the target or its management plane while a validation
  window is open.
- **Exactly one approved target.** One `ExecutionTarget` record, approved for this purpose
  only, never reused from any other purpose.
- **Exactly one approved onboarding.** One `TargetOnboarding` record with an approved,
  immutable declared boundary matching the staging segment.
- **Exactly one time-bound authorization.** One approved, unexpired `LiveReadAuthorization`
  (SECP-002B-1B-6) bound to that target and onboarding; never a standing or renewable-by-default
  authorization.

## 2. Reference topology (placeholders only)

Provider-neutral reference flow — every concrete value is a placeholder and is configured
out of band only:

```text
SECP worker (runtime)
  --> explicit egress firewall allow rule (exactly one destination)
    --> one approved staging target  <staging-target-host>:<api-port>
      --> Proxmox API (TLS-verified, read-only, allowlisted paths only)
```

Required topology controls:

- **Default-deny worker egress.** The worker runtime has no outbound reachability except the
  single explicit allow rule to `<staging-target-host>:<api-port>`. Everything else — including
  other hosts on the staging segment — is denied by default.
- **No DNS-based widening.** The allow rule is pinned to the approved destination, not to a
  resolvable name whose answer can drift. If name resolution is ever proposed, it requires its
  own explicit justification and review in a later PR — it is not permitted by this design.
- **No proxy inheritance.** The worker must not inherit HTTP(S) proxy, system trust, or
  environment-supplied routing. Trust-environment lookups stay disabled; a proxy is not an
  approved path to the target.
- **TLS verification required.** Certificate verification is mandatory; an unverifiable or
  plaintext connection is refused, never downgraded.
- **Redirects disabled.** HTTP redirects are never followed; a redirect response terminates the
  attempt and is treated as a policy violation to investigate.
- **Management plane segmentation.** The target's own management interfaces live on a segment
  the worker cannot reach except through the single allowed rule; operator access to the
  management plane uses a separate, independently controlled path.
- **Break-glass rule removal.** The egress allow rule has a documented, tested, single-step
  removal procedure executable by the infrastructure operator at any time without coordination,
  immediately severing the only path from worker to target.

No real network values (addresses, names, ports, segments, or rules) appear in this repository.

## 3. Least-privilege Proxmox identity design

The future staging identity is designed before it exists. Its role must be:

- **read-only** — observation of approved inventory paths only;
- **no VM/container lifecycle permissions** — cannot create, start, stop, migrate, clone,
  modify, or delete guests;
- **no console access** — cannot open any guest or host console;
- **no shell access** — no host shell, no guest agent execution;
- **no task execution** — cannot trigger, resume, or cancel tasks;
- **no upload/download** — cannot move images, ISOs, templates, or files in either direction;
- **no backup/restore** — cannot create, read, or restore backups or snapshots;
- **no token management** — cannot create, list, modify, or revoke tokens or API keys;
- **no user/role/admin permissions** — cannot read or modify users, groups, roles, ACLs, or
  realm/datacenter configuration;
- **scoped only to required inventory paths** — permissions attach to the minimum resource
  scope the read-only evidence contract needs, never a root or datacenter-wide grant.

The exact role, user, and token are created **manually, out of band, by the target
administrator**, are recorded only in the operator runbook and approved secret backend, and are
**never committed to source control** in any form (including hashes or partial values). The
control plane stores at most an opaque credential reference, as already contracted in
ADR-007 and SECP-002B-1B-1.

## 4. Certificate trust and target identity

Before any authorization is approved, the future activation operator must verify the target's
identity **out of band**:

- **Subject/SAN expectations.** The expected certificate subject and subject-alternative-name
  set for `<staging-target-host>` are documented in the operator runbook (never in Git) and
  must match exactly at verification time.
- **Pinned certificate or trusted private CA.** Trust is anchored either by pinning the exact
  expected certificate or by a dedicated private CA created for the staging environment. Public
  or system-default trust stores are not, by themselves, sufficient for this target.
- **Independent verification channel.** The certificate presented over the network is compared
  against identity material obtained through a second, independent channel (for example,
  reading it directly from the target's management plane via the operator path) — never solely
  through the same connection being verified.
- **Rotation/revocation procedure.** Certificate rotation and trust revocation are documented,
  owned, and tested: replacing or revoking the certificate must immediately cause verification
  failure until an operator re-verifies identity out of band.
- **Explicit refusal.** If identity cannot be verified — mismatch, expiry, revocation,
  ambiguity, or unavailable verification channel — the operator must refuse to approve
  activation. There is no "verify later" state.

No actual certificate data (subjects, SANs, fingerprints, serials, or PEM blocks) is recorded
in this repository.

## 5. Readiness evidence checklist (completed outside Git)

Every item below must be completed, evidenced, and independently reviewed **outside Git**
before any future activation PR may be opened. This checklist is evidence of operation, not of
code; none of it is satisfied by anything in this repository.

- [ ] Target is disposable/recoverable: rebuild-from-clean demonstrated end to end.
- [ ] Backup/snapshot rollback tested: revert to known-clean state exercised and timed.
- [ ] Egress restriction tested: worker can reach only `<staging-target-host>:<api-port>`;
      probes to any other destination fail.
- [ ] Least-privilege identity tested: the staging identity can read the approved inventory
      paths and demonstrably cannot do anything else.
- [ ] No write operations possible: mutation attempts with the staging identity are refused by
      the target (verified negative test, not assumption).
- [ ] Certificate identity verified out of band via the independent channel (section 4).
- [ ] Authorization state approved and unexpired: exactly one `LiveReadAuthorization` is
      `approved`, time-bound, and not revoked.
- [ ] Target/onboarding hashes verified: connection hash and boundary hash match the
      authoritative records; any drift fails closed.
- [ ] Credential reference exists in the approved secret backend and resolves only from the
      worker path; the API cannot resolve it.
- [ ] Secret revocation tested: revoking the credential stops all further access immediately.
- [ ] Audit sink available: authorization, refusal, and lifecycle events are being recorded
      secret-free and are reviewable.
- [ ] Emergency disable and egress removal tested: the kill-switch plan (section 6) has been
      walked through end to end at least once.

## 6. Rollback and kill-switch plan

Conceptual operator actions only — each action is independently sufficient to stop collection,
and any one operator layer can execute its own step without waiting for the others:

1. **Revoke the authorization.** Move the single `LiveReadAuthorization` to `revoked`
   (SECP-002B-1B-6); the verifier then refuses fail-closed on the next attempt.
2. **Remove the worker egress rule.** Execute the break-glass removal (section 2); the only
   network path from worker to target ceases to exist.
3. **Revoke the target credential.** Delete/disable the staging identity's token in the target
   and remove the secret from the backend; resolution and authentication both fail.
4. **Disable the target.** Mark the `ExecutionTarget` inactive; the verifier refuses
   `target_not_active`.
5. **Invalidate certificate trust.** Remove the pinned certificate / private CA anchor so TLS
   verification fails until identity is re-verified out of band.
6. **Destroy or revert the disposable staging environment.** Tear down or roll back to the
   known-clean snapshot; the target ceases to exist as configured.
7. **Preserve the audit trail.** Audit events, authorization history (including revocation
   metadata), and operator runbook entries are retained — rollback never deletes evidence of
   what happened.

## 7. Separation of responsibilities

No single layer can activate collection alone; each holds a distinct key:

| Layer | Owns | Cannot do |
| --- | --- | --- |
| SECP control plane (API) | Authorization records, approval/revocation lifecycle, audit trail, org scoping | Resolve secrets, reach the target, execute collection |
| Worker runtime | Fail-closed verification, secret resolution at use, transport construction within contract | Approve authorizations, widen egress, mint credentials |
| Infrastructure/network operator | Default-deny egress, the single allow rule, break-glass removal, segmentation | Approve authorizations, create target identities, alter code paths |
| Target administrator | Staging target lifecycle, least-privilege identity, certificate identity, snapshots/rollback | Approve authorizations, change worker egress, alter control-plane records |
| Human approver | Time-bound authorization approval after independent review; final refusal authority | Operate infrastructure, hold or resolve credentials, execute collection |

Activation therefore requires, at minimum: an approved authorization (control plane + human
approver), a verifying worker (runtime), an explicit egress rule (network operator), a live
least-privilege identity (target administrator), and verified certificate trust (target
administrator + operator). Withholding any one of these keeps collection impossible.

## 8. Explicit future activation entry criteria

A future activation PR may **begin** (not merge) only when all of the following are true:

- the operating and readiness checklists in this document are complete out of band and
  independently reviewed;
- the SECP-002B-1B-6 (PR #13) authorization contract is present and unmodified in `main`;
- exactly one disposable staging target has been approved under section 1;
- independent review of the threat model, operating evidence, and this design is complete;
- a human authorization exists, is time-bound, and is not expired or revoked;
- no unresolved blocker exists in any prior live-read review.

Meeting these criteria permits only the *proposal* of an activation PR. That PR still requires
its own independent review, the full activation checklist
(`live-readonly-collector-activation-checklist.md`), and its own explicit human authorization
before any live read-only path can be enabled.

## 9. Guardrails in this repository

Static tests (`apps/api/tests/test_staging_target_operating_design.py`) assert that this
document exists with the required sections, that the live-read documents contain no real
endpoint-like, credential-like, or certificate-like values, and that no code path, environment
switch, or infrastructure wiring references a staging live-read activation. The existing
dormant-path, authorization, redaction, sealed-evidence, and no-direct-instantiation tests
continue to guard the code.
