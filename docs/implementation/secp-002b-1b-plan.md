# SECP-002B-1B — Implementation plan (PR decomposition)

**Status:** implementation plan for the future B1-B milestone, locked by
[ADR-020](../adr/ADR-020-first-real-disposable-lab-lifecycle.md) and detailed in
[`docs/architecture/secp-002b-1b-real-lab-lifecycle.md`](../architecture/secp-002b-1b-real-lab-lifecycle.md).
This document is **design-only**. It **activates nothing** and unseals nothing. B1B-PR1 (this
architecture lock) is docs/tests only; every later PR is a separate, independently reviewed change.

**Global invariants for every PR below:** the API never runs a process or resolves a secret; no
`shell=True`; no floating/`latest`/wildcard toolchain; no local state; no runtime provider download;
no external connectivity; no automatic plan→apply or apply→destroy; no fake fallback in a real-lab
request; no raw plan/state/secret persisted; no real value committed to source control; both B1-A
subprocess seals stay `True` until the specific PR that unseals a specific capability by a reviewed
code change. **No configuration flag alone advances a capability.**

## Phase / activation map

| PR | Capability unsealed | Live contact | Mutation | Both B1-A seals after |
| --- | --- | --- | --- | --- |
| B1B-PR1 | none (architecture lock) | none | none | `True` / `True` |
| B1B-PR2 | real on-disk toolchain attestation | worker filesystem only | none | `True` / `True` |
| B1B-PR3 | real read-only eligibility preflight | read-only Proxmox | none | `True` / `True` |
| B1B-PR4 | remote-state + JIT secret readiness | state backend + secret manager (read/validate) | none | `True` / `True` |
| B1B-PR5 | real `init`/`plan`/`show` (plan-only) | Proxmox read + plan | none (plan only) | plan unsealed; **apply/destroy seals stay `True`** |
| B1B-PR6 | first apply + verification | Proxmox apply + read | one disposable lab | apply unsealed; **destroy seal stays `True`** |
| B1B-PR7 | destroy + zero-residue | Proxmox destroy + read | destroy of that lab | destroy unsealed |
| B1B-PR8 | closeout | none | none | reviewed defaults |

---

## B1B-PR1 — Architecture lock (this PR)

- **Allowed code surfaces:** `docs/adr/`, `docs/architecture/`, `docs/implementation/`,
  `docs/runbooks/` (non-runnable skeleton only), `docs/proxmox/b1b-lab-prerequisite-checklist.md`,
  `docs/STATUS.md`, and cross-cutting architecture/status truth tests under `tests/`.
- **Forbidden code surfaces:** all `apps/api`, `apps/worker`, frontend, models, migrations, Settings,
  environment examples, Docker Compose, Kubernetes, CI workflows, shard config, timing weights,
  OpenTofu modules, provider lockfiles, process executors, activation factories, secret resolvers,
  transports, provider clients. **Neither B1-A seal may change.**
- **Activation before → after:** sealed → sealed (unchanged).
- **Live-contact level:** none. **Mutation level:** none.
- **Required tests:** `tests/test_b1b_architecture_lock.py` (design-only assertions + both seals
  `True`); existing `tests/test_architecture_boundary.py`, `tests/test_provisioning_boundary.py`,
  `apps/api/tests/test_no_real_process.py`, `apps/api/tests/test_lab_activation_gate.py`, and the
  STATUS truth tests must stay green **unchanged**.
- **Human-review gate:** architecture + threat-model review; confirm no live value committed.
- **Rollback:** revert the docs/tests commit (no runtime impact).
- **Evidence required:** approved ADR-020; approved architecture + plan; enforcing test green.
- **Completion:** merged docs/tests; seals still `True`; STATUS still `partially-implemented`,
  `production-blocked`.

## B1B-PR2 — Real toolchain attestation

**Status: implemented by this slice** (worker-local, filesystem-only `RealToolchainVerifier` +
`ToolchainFilesystemLayout`; expanded facet set; comprehensive tests over inert fixtures). No
execution capability was unsealed; both B1-A subprocess seals remain `True`; the verifier is not
wired into the runner/`run_real_provisioning` default (still fake). B1B-PR3 remains next.

- **Allowed:** the worker `ToolchainVerifier` real implementation (`RealToolchainVerifier`) —
  **filesystem verification only** of the on-disk executable/version/binary-digest/module-bundle/
  lockfile/offline-mirror/renderer/CLI-config/remote-state-backend-class/no-runtime-download.
- **Forbidden:** any endpoint contact; any OpenTofu execution; any subprocess execution; any secret
  resolution; API changes beyond recording an attestation evidence category. **Both subprocess seals
  stay `True`.**
- **Activation before → after:** sealed → attestation-only (no execution capability).
- **Live-contact:** worker local filesystem only. **Mutation:** none.
- **Required tests:** real-verifier unit tests over fixture toolchains (attest + refuse on any facet
  mismatch); a test that attestation performs no subprocess/network; seals still `True`.
- **Human-review gate:** verifier review; confirm no execution path added.
- **Rollback:** revert; verifier falls back to inert/refusing.
- **Evidence:** attestation pass/refuse events (redacted).
- **Completion:** real attestation works on-disk; no execution unsealed.

## B1B-PR3 — Real eligibility preflight

**Status: implemented by this slice** (sealed by default). A worker-owned `run_real_eligibility_preflight`
seam reuses the **existing** dormant read-only Proxmox transport (Path B, `run_live_readonly_collection`)
and the **existing** immutable `TargetPreflight`/`TargetEvidenceRecord` tables (no parallel evidence
table) to produce redacted, org/target/onboarding/authorization/worker-identity/policy-bound, hash-bound,
expiry-bound `live_verified` eligibility evidence via a versioned, deterministic, provider-neutral
eligibility policy. **Transport choice (documented truthfully):** the authoritative transport is the
HTTP read-only Proxmox collector (Path B), because it is the only shipped transport whose normalized
observations feed the mandated `compare_boundary_to_evidence` pipeline and the network/CIDR/isolation
dimensions the SSH discovery path (Path A, `target_discovery`) structurally cannot observe; the two paths
are independent (neither delegates to the other) and are never both activated. **Durable execution is
part of PR3 (not deferred to PR4):** the API is enqueue-only (durable `WorkflowRun` + outbox; inline
execution refused with no fallback); a worker-only `EligibilityPreflightWorkflow`/activity loads the
authoritative records and runs the seam; live-evidence persistence is worker-only (the API cannot import
it) and takes a typed evaluator result (the source/level label alone can never create live evidence). The
seam is **durably wired but default-disabled**: the shipped `build_eligibility_composition` is fully sealed
(no transport/resolver/collector; the seal is an out-of-band reviewed composition, never an env flag), so
the durable path runs to completion but refuses at the seal before any contact. The actual production
collector, through the reviewed GET allowlist, yields `unverifiable`/`ineligible` — **never `eligible`**
(isolation/VM-ID/quota/disposability are not inferred; reaching `eligible` is a documented deployment
prerequisite), proven by an integration test over the exact real chain. No OpenTofu runs, nothing is
mutated, both B1-A subprocess seals remain `True`, and no real Proxmox host has been contacted. B1B-PR4
(remote-state + JIT secret readiness) remains next.

- **Allowed:** a worker-only, **read-only** Proxmox eligibility/boundary preflight producing
  immutable, redacted, org-scoped, target-bound, timestamped, hash-bound, expiry-bound evidence
  (target identity, TLS verified, nodes/storage/bridge/VLAN exist, VM-ID no collision, CIDR no
  overlap, quotas enforceable, **no-route**, deny-external, least-privileged credential, no target
  drift, onboarding still matches).
- **Forbidden:** any OpenTofu execution; any mutation; API-side secret resolution or process
  execution; accepting caller-asserted eligibility. **Both subprocess seals stay `True`.**
- **Activation before → after:** attestation-only → attestation + read-only eligibility.
- **Live-contact:** **read-only** Proxmox. **Mutation:** none.
- **Required tests:** preflight over injected read-only transport fixtures (pass + each refusal);
  evidence immutability/redaction/expiry/drift-invalidation; no mutation import; seals still `True`.
- **Human-review gate:** read-only transport + evidence review.
- **Rollback:** revert; preflight seam returns to unavailable.
- **Evidence:** preflight requested/completed/refused (redacted).
- **Completion:** real read-only eligibility evidence; still no OpenTofu, no mutation.

## B1B-PR4 — Remote-state and secret-resolution readiness

- **Allowed:** remote-state backend validation (remote only, encryption at rest, state locking,
  least-privileged access, tested backup/restore, exact workspace/state identity binding); worker-only
  JIT secret injection readiness (`WorkerSecretResolver` real path replacing `SealedSecretResolver`,
  allowlisted child env via `build_process_env`/`build_lab_secret_env`, redaction).
- **Forbidden:** any plan/apply/destroy; local state or local fallback; API-side secret resolution;
  state contents in logs/audits/responses. **Both subprocess seals stay `True`.**
- **Activation before → after:** read-only eligibility → + state/secret readiness (still no execution).
- **Live-contact:** state backend + secret manager (validate/resolve readiness). **Mutation:** none.
- **Required tests:** backend validation refuses local/unlocked/unencrypted; backup/restore proof;
  JIT resolution injects only allowlisted redacted env; no secret persisted; seals still `True`.
- **Human-review gate:** state + secret-handling review.
- **Rollback:** revert; resolver returns to sealed `credential_unavailable`.
- **Evidence:** state readiness + resolution readiness (redacted).
- **Completion:** state + secret readiness proven; still no plan/apply/destroy.

## B1B-PR5 — Live plan-only execution

- **Allowed:** unseal **only** real `init`/`plan`/`show -json` for **one** disposable target (a
  reviewed change to the **plan** seal constant only), producing the canonical redacted change set +
  `change_set_hash`; human review + exact-hash approval flow end-to-end against the real target.
- **Forbidden:** apply and destroy (their seal constants **stay `True`** — technically incapable);
  automatic plan→apply; fake fallback; runtime provider download; external connectivity; raw plan/
  state persistence. **Apply/destroy subprocess capability remains sealed.**
- **Activation before → after:** readiness → plan-only (apply/destroy still sealed).
- **Live-contact:** Proxmox read + real plan. **Mutation:** **none** (plan only).
- **Required tests:** real plan generates a redacted canonical change set; apply/destroy still refuse
  (seals `True`); TOCTOU re-prepare/hash-match logic; no raw plan/state persisted; exact-hash approval
  required.
- **Human-review gate:** first real plan review; confirm apply/destroy remain impossible.
- **Rollback:** re-seal the plan constant; revert.
- **Evidence:** real plan generated/refused; change set approved/rejected (redacted).
- **Completion:** one reviewed real plan + exact approval; **no apply**.

## B1B-PR6 — First apply and verification

- **Allowed:** unseal **only** apply for **one exact approved prepared plan** (a reviewed change to
  the **apply** seal constant); apply via `apply_prepared` under the full gate (ADR-020 §J); post-apply
  observed-state + isolation verification (§K).
- **Forbidden:** destroy (its seal **stays `True`**); automatic apply→destroy; apply of any plan other
  than the exact approved prepared plan; recording success before verification completes; API-direct
  apply.
- **Activation before → after:** plan-only → apply-enabled for the one approved plan (destroy sealed).
- **Live-contact:** Proxmox apply + read. **Mutation:** **one disposable lab**.
- **Required tests:** apply requires the exact prepared plan + fresh hash match + full gate; drift
  refuses; verification produces `verified`/`verification_failed`/`state_disagreement`/
  `isolation_failed`/`recovery_required`; exit-code-alone is insufficient; destroy still refuses.
- **Human-review gate:** first real apply review + go/no-go; recovery owner on standby.
- **Rollback:** re-seal apply; manual cleanup procedure (must exist before this PR).
- **Evidence:** apply requested/started/completed/failed; verification completed/failed (redacted).
- **Completion:** one verified real apply; **no automatic destroy**.

## B1B-PR7 — Destroy and zero-residue

- **Allowed:** unseal **only** destroy through its **own** newly generated destroy change set, its own
  redacted canonical hash, and its own **separate** human approval (a reviewed change to the
  **destroy** seal constant); destroy via `destroy_prepared` under the full gate; zero-residue proof
  (§L); state closeout.
- **Forbidden:** reusing the apply approval for destroy; assuming destroy proves cleanup; leaving
  state/workspace/transient-plan residue.
- **Activation before → after:** apply-enabled → destroy-enabled (its own approval).
- **Live-contact:** Proxmox destroy + read. **Mutation:** destroy of that lab.
- **Required tests:** destroy requires its own approval + gate; idempotent/retry-safe; zero-residue is
  an independent provider+state re-scan producing `zero_residue_confirmed`/`zero_residue_failed`.
- **Human-review gate:** first real destroy review; zero-residue sign-off.
- **Rollback:** re-seal destroy; manual containment + cleanup.
- **Evidence:** destroy planned/approved/started/completed/failed; zero-residue confirmed/failed.
- **Completion:** one successful destroy + confirmed zero residue + state closeout.

## B1B-PR8 — Closeout

- **Allowed:** evidence review; STATUS correction to reflect one completed reviewed run; lessons
  learned; a **review** of seals/defaults (not an automatic expansion).
- **Forbidden:** automatic expansion to other targets; leaving any capability unsealed by default;
  overclaiming production readiness.
- **Activation before → after:** run-complete → reviewed defaults (capabilities **re-sealed by
  default**; each future run re-unseals under review).
- **Live-contact:** none. **Mutation:** none.
- **Required tests:** STATUS truth tests updated to the real, evidenced state; seals reflect the
  reviewed default.
- **Human-review gate:** closeout review.
- **Rollback:** n/a (documentation).
- **Evidence:** the full immutable audit chain from one run; documented recovery observations.
- **Completion:** B1-B success definition (ADR-020 §Q) met by evidence from **one** real run — not a
  test or fake.
