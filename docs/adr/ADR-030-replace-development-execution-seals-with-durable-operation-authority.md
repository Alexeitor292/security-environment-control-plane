# ADR-030 — Replace the development execution seals with durable operation authority

- **Status:** Accepted
- **Date:** 2026-08-07
- **Accepted:** 2026-08-07 by Juan; the three governance changes it names landed with it
- **Milestone:** SECP pre-live Proxmox readiness
- **Deciders:** Juan (authorizing); implementation engineering (specifying)
- **Related:** Charter §6 (invariants), §15; ADR-013 (isolated-lab activation), ADR-022
  (plan-only activation and the process boundary); `docs/program/SAFETY_INVARIANTS.md`
  SI-500…SI-505, SI-605, SI-608; `docs/proxmox/pre-live-readiness-inventory.json`

## Context

Five development-phase seals currently make real infrastructure execution *unconstructible*
rather than *unauthorized*:

| Seal | Site | Effect |
| --- | --- | --- |
| `_B1A_SUBPROCESS_SEALED` | `provisioning/process_executor.py:123` | the real subprocess executor raises rather than running |
| `_B1A_SUBPROCESS_SEALED` | `provisioning/activation.py:31` | a **second** copy; the factory always returns the fake executor |
| `PlanExecutionGate` | `plan_gen/composition.py:77` | the shipped composition can never be enabled |
| `_OPERATOR_ACTIVATION_SEALED` | `secp_operator_deployment/runner.py:29` | the operator worker cannot start |
| `REAL_PROVISIONING_SEALED` | `secp_api/routers/providers.py:51` | the provisioning route refuses |

They were correct for the phase that produced them: the surrounding authorization model did not
exist yet, so an unconditional refusal was the only honest control. That premise has now changed —
the durable authority model exists (`ProvisioningChangeSetApproval`, `ToolchainProfile`,
`WorkerDiscoveryAdmission`, `WorkerIdentityRegistration`, `LiveReadAuthorization`), and the signed
discovery chain that feeds it reached production reachability at `0b9b82e`.

A measured readiness audit (443 capabilities, adversarially verified — see the inventory) found
that **no shipped code path executes the OpenTofu binary**, and that the apply/destroy family is
reachable from no registered activity, mounted route, console script or unit.

### The decision this ADR records

Juan has authorized the transition from *sealed and fake-only* to *production-capable and
authorization-gated*. This ADR specifies what replaces each seal, so that the change is reviewable
as a design rather than as a diff that flips constants.

**A boolean is not the replacement for a boolean.** Setting `_B1A_SUBPROCESS_SEALED = False` would
convert an unconditional refusal into an unconditional permission, which is strictly worse than
either the old state or the intended one.

## Decision

### 1. One authority answer, derived from durable state

Delete the five constants. Do not leave compatibility aliases: an alias is a name future code can
come to depend on, and its presence would let a later edit re-acquire a global "may execute" switch.

Replace them with a single derivation answering one question —

> may **this exact operation**, for **this exact target**, on **this exact worker**, against
> **this exact approved change set**, execute **now**?

— computed from durable rows at the moment of execution, never cached, never passed in, and never
influenced by process configuration. Sixteen conditions must all hold:

1. the selected privileged worker is enrolled;
2. the worker identity matches the durable operation;
3. the worker release matches the registered release;
4. the target identity matches the operation;
5. the target is active and eligible;
6. discovery evidence is verified and fresh;
7. the required facts are complete;
8. the `ToolchainProfile` is active;
9. the OpenTofu binary identity matches the pinned profile;
10. the provider lockfile / mirror identity matches;
11. the generated configuration digest matches;
12. the operation generation matches exactly;
13. the exact plan / change-set hash is authorized;
14. the operation kind matches the authorization domain;
15. no conflicting writer exists;
16. the operation has not been consumed, except under the existing exact-retry semantics.

Every failure is a distinct closed reason code naming the row an operator must fix. "Unauthorized"
tells an operator to retry; these tell them what to do.

### 2. No ambient bypass, at any layer

The following must not exist in any form: `armed=True`, `real=True`, `unsealed=True`,
`SECP_ENABLE_REAL`, or any environment variable, settings field, constructor flag or request field
whose value widens what may execute. Permission originates in the durable operation. A test that
enumerates the constructor surface of the executor and its factory enforces this.

### 3. The executable surface stays closed

`SubprocessProcessExecutor` becomes production-constructible **through the reviewed worker factory
only**, and accepts only `ProcessSpec` values produced by the OpenTofu execution engine. The
permitted command set is exactly the reviewed lifecycle verbs (`version`, `init`, `validate`,
`plan`, `show`, `apply`, and the approved destroy form) — expressed, as the discovery transport
already is, as a **derived grammar** rather than a hand-maintained list, so a reviewed operation and
an executable command are the same fact.

Prohibited, structurally rather than by check: `shell=True`, `/bin/sh -c`, PowerShell command
strings, argv from an API request, caller-supplied environment, caller-supplied working directory,
and caller-selected executables. Pinned executable identity, bounded output, timeout, cancellation,
controlled environment, private working directories and redaction all remain.

### 4. Plan and apply remain separate facts

An apply must apply **the exact reviewed change set**, never a freshly regenerated one. Destroy uses
a separate authorization domain; reset is modelled explicitly; and no operation kind falls through
to deploy — the dispatch is exhaustive with a refusing default.

### 5. Consequences for the seal census

`docs/program/SAFETY_INVARIANTS.md` is append-only. SI-500, SI-501, SI-502, SI-503 and SI-504 are
**not** deleted; each gains a superseding entry recording that the invariant it described has been
replaced by the derivation above, with this ADR as the authority. The new invariant is:

```text
production capability exists
AND unauthorized production execution is impossible
```

not

```text
production capability does not exist
```

## The control that had to change first, and how it changed

`CLAUDE.md` §2 lists these seals as an **unconditional hard-deny with no unlock path**, and
`.claude/hooks/guard_writes.py:40-48,119-134` enforces that mechanically: any edit under
`apps/**`, `plugins/**` or `contracts/**` that changes one of the seal literals is denied by a
committed hook. The rule exists specifically so that the seals cannot be opened by a conversation,
and CLAUDE.md instructs agents never to wait for a human to approve past a hook denial.

That control did its job: it refused to be opened by a conversation, and it was retired the same
way it was created — by a commit to the repository, authorized by the owner, with this ADR as the
review artifact. **All three changes landed together with this ADR's acceptance:**

1. `.claude/hooks/guard_writes.py` — remove the retired literals from `SEAL_LITERALS`, keeping
   `SHIPPED_TRUST_ROOT`, `SealState` and `read_seals`, which this ADR does **not** propose to
   retire (release-signing anchors and the management bootstrap seals are a different boundary);
2. `CLAUDE.md` §2 — move the retired seals out of the unconditional list, replacing them with the
   durable-authority requirement above, so the governing document describes the new invariant;
3. this ADR — `Proposed` → `Accepted`.

``assert_inline_execution_allowed`` was NOT retired, and the distinction is worth recording: it
gates inline in-process dispatch to the exact bootstrapped Simulator instance, which is a dev/test
affordance rather than part of the real execution path this ADR opens.

## Implementation status

This section records what exists in the tree, with file references, and is the part of this ADR
that must be re-checked rather than believed. A condition listed as *derived* means the check runs;
it does **not** mean an execution path calls the derivation yet.

`apps/api/secp_api/provisioning_execution_authority.py` holds the derivation.
`authorize_provisioning_execution` takes six parameters — session, operation id, organization id,
worker installation id, the worker's observed toolchain, and a clock — and returns an
`AuthorizedExecution` or raises `ExecutionAuthorityRefused` with one of thirty closed reasons. It
reads the target, manifest, change-set hash, approval, generation and release rather than accepting
them, because an execution whose expected values a caller may choose is one that authorizes itself.

**Condition 2 needed a schema change and got one.** Nothing in `provisioning_operation` recorded
which worker an operation had selected, so condition 2 — the worker identity matches the durable
operation — had no durable side to match against and the derivation refused every execution.
Migration `e3b7a9c25f41` adds one nullable column, `provisioning_operation.worker_installation_id`.
The properties that make it a binding rather than a field:

- **selection is the control plane's.** `services/provisioning_worker_selection.py` exposes
  `select_provisioning_worker(session, *, organization_id)`. There is no worker parameter anywhere
  on that surface, so a request body, a Temporal payload, a worker's own claim, an environment
  variable and the executor have nowhere to express a preference — which is stronger than a
  preference being ignored. It is not derived from `WorkerDiscoveryAdmission` (that binds a worker
  selected for a *read*, under its own nonce and expiry) and does not reuse `runner` (a
  deterministic runner operation id, in which a worker identity would be indistinguishable from the
  value already written);
- **"any healthy enrolled worker" is explicitly not sufficient.** That authorizes every healthy
  worker in the organization to execute every operation in it, which is the property condition 2
  exists to remove. Selection happens once, is recorded, and is then compared;
- **write-once, enforced at the ORM layer.** `bind_provisioning_worker` is the only writer and
  refuses a different value; independently, `secp_api/immutability.py` refuses the transition
  worker-A → worker-B and worker-A → NULL for any session, including one bypassing the service.
  This required `active_history=True` on the column (`models.py`): without it a post-commit
  assignment reports no previous value and the guard compares against `None`;
- **NULL is honest and fails closed.** Rows predating the column were not backfilled — inventing a
  selection would be fabricating an authorization record. `assert_dispatchable` refuses to let a
  NULL-bound operation reach `queued` or `destroy_queued`, and the derivation refuses a NULL binding
  outright, so a historical row is unexecutable rather than open to anyone;
- **the gate is in the transition, not the caller.** `services/provisioning.advance` — the single
  audited transition function, and the only importer of `provisioning_lifecycle.transition` in
  non-test source — calls `assert_dispatchable` before applying a transition into a dispatchable
  status. A future enqueue path therefore cannot reach `queued` unbound by forgetting a call;
- **an exact retry keeps its binding, a new worker needs a new operation.** There is no path that
  changes a written binding, so "the worker that was authorized" and "the worker that executes"
  remain the same fact across a retry; re-selection is a new operation, which the existing
  per-(manifest, kind) idempotency key already provides.

Conditions 6 and 7 are derived from the latest `TargetEvidenceRecord` for the target — the latest
rather than one a caller names, since a caller able to point at an older passing record could keep
an expired observation alive indefinitely. `unverifiable` refuses distinctly from `fail`: they are
different operator actions, and reporting the second as the first sends someone to fix a target that
may be fine. The freshness bound is a property of the contract, not a caller's argument.

**What is not yet true.** No production path calls `authorize_provisioning_execution`; there is no
provisioning enqueue endpoint, and `advance` has no callers. The derivation and its gate exist and
are tested; the executor that would consult them does not. Nothing in this section should be read
as evidence that a real operation can run.

## Consequences

**Positive.** Real execution becomes possible under a gate that is auditable per operation rather
than per build. The five constants stop being a thing anyone can flip. The authority answer becomes
uniform with the discovery chain's, which already derives its transport allowlist from typed
operations rather than a maintained list.

**Negative, and worth stating.** The blast radius of a bug moves from "nothing can run" to "the
wrong thing could run if sixteen conditions are wrongly evaluated". That is the intended trade, and
it is why this ADR requires the adversarial review of the transition itself, refuting by default,
before any live authorization — and why the first real rehearsal remains gated behind Packet 1 and
Packet 2 regardless of what the code can do.

**Not decided here.** This ADR covers the execution seals only. The guest configuration plane, the
worker runtime package, the production identity lifecycle, and the Proxmox mutation capability are
absent rather than sealed; they are ordinary engineering and need no seal decision.
