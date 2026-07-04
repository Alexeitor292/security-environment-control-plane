# Live Secret Resolver — Human Activation Checklist (SECP-B2-2)

**Status:** Activation gate for the FUTURE first real worker-only secret resolver. **Nothing here
is performed now.** This is design/static-contract only. Do not add any real value (hostname, IP,
URL, port, cluster/node/storage/bridge/VLAN name, credential, token, password, secret, `secret_ref`,
or checksum) to the repository — live configuration lives **outside source control** (an approved
secret manager + operator runbook).

The shipped default remains the SECP-B2-1 `SealedUnavailableResolver`: every read-only preflight
ends `credential_unavailable`, no transport is constructed, and no collector executes. This
checklist governs a later implementation PR that would replace that sealed default with a real
worker-only resolver for exactly one approved staging target. See the design contract in
`docs/architecture/secp-b2-2-live-secret-resolver-activation.md`.

**This checklist and the collector-activation checklist are cumulative.** This resolver-activation
checklist (`live-secret-resolver-activation-checklist.md`) and the collector-activation checklist
(`live-readonly-collector-activation-checklist.md`) must **both** be satisfied in full; satisfying
one **never substitutes** for the other. Enabling a secret resolver does not authorize collector
execution, and enabling a collector does not authorize secret resolution — each remains a separate,
independently reviewed activation.

Every box must be **checked and independently human-reviewed**, and an explicit, time-bound user
authorization recorded, before the default-disabled resolver may be enabled for one approved target.

## 1. Trusted request is not a capability
- [ ] The implementation treats every `TrustedResolutionRequest`/`ResolutionContract` as untrusted
      input; possession, type, construction token, or a prior gate is **never** proof of
      authorization.
- [ ] The resolver independently re-runs the authoritative binding verifier
      (`load_and_verify_live_read_authorization`) against re-loaded database records at resolution
      time; it does not trust the request's claimed fields.

## 2. Authoritative trust anchors (no self-referential trust)
- [ ] The authoritative expectation is derived from the worker's database records and the app-side
      pinned constants — **not** from a caller-built "expected contract."
- [ ] Organization, execution target, onboarding, authorization id/version/status/expiry, and the
      connection/boundary hashes are all re-derived from authoritative records and compared against
      the request; any drift fails closed.

## 3. Credential-reference three-way binding
- [ ] Exact, constant-time equality is enforced between the authoritative `ExecutionTarget.secret_ref`,
      the re-verified live-read binding reference, and the resolver request reference.
- [ ] Any mismatch or blank reference fails closed **before** any backend access; the reference is
      never hashed, logged, audited, serialized, or exposed via `repr`.

## 4. Replay and resolution-lease review
- [ ] A durable, single-use resolution lease is required before backend access, keyed by
      authorization id+version, target/onboarding, purpose, operation fingerprint, expiry, and
      authenticated worker identity.
- [ ] Replay of a consumed lease is refused; retries are bounded and only before expiry; a lease
      never outlives the authorization.
- [ ] Lease/refusal evidence is durable and **secret-free** (records no reference and no material),
      with closed reason codes.

## 5. Worker identity and backend policy
- [ ] The worker authenticates to the backend as an independently issued, out-of-band-rotated
      identity; the API/UI have no credential and no network path to the backend.
- [ ] The backend's own policy authorizes only the exact `(worker identity, reference, target,
      purpose)` tuple; a worker-side pass never overrides a backend denial.
- [ ] Resolution is short-lived with no caching or reusable credentials; rotation/revocation
      behavior and fail-closed response mapping are verified.

## 6. Activation evidence package (closed set)
- [ ] Isolated staging-control-plane identity proof.
- [ ] Worker-only network-path proof (no API/UI route to the backend).
- [ ] Backend access-policy review (scoped to exact target/reference/purpose).
- [ ] Reference-grammar review.
- [ ] Redaction / log / audit verification (no reference or material leaks anywhere).
- [ ] Transport remains GET-only and canonicalized.
- [ ] No production or shared target — disposable/staging only.
- [ ] Rollback / kill-switch drill executed and verified.
- [ ] Independent adversarial review of threat model, code, and tests.
- [ ] Explicit, time-bound human approval recorded.

No item in this package may be waived, and no evidence outside this list substitutes for a listed
item.

## 7. Formal activation gates (all required; none alone suffices)
- [ ] Code review of the implementation PR.
- [ ] Separate, durable human approval record (distinct from the code review).
- [ ] Activation-specific configuration lives outside Git (secret manager / runbook only).
- [ ] Staging-only target eligibility (production/shared targets refused).
- [ ] Time-bound, versioned authorization; expiry fails closed.
- [ ] Resolver health / self-test that reveals no secret or reference.
- [ ] Tested revocation / rollback / kill-switch path.

## 8. Rollback / kill-switch sequence tested
- [ ] Revoking the out-of-band activation configuration inerts the resolver (verified).
- [ ] Revoking the authorization stops lease issuance and resolution (verified).
- [ ] Disabling the default-disabled activation gate reverts to `SealedUnavailableResolver`
      (`credential_unavailable`) (verified).
- [ ] A self-test confirms the path is inert and returns no material.
- [ ] Reference rotation/quarantine and secret-free evidence handling are tested.

Only when **every** box is checked, independently reviewed, and the time-bound authorization is
recorded may a future PR enable the live worker-only secret resolver for that one approved target.
Any real target contact, transport construction, or collector execution remains a separate, later,
independently reviewed step.
