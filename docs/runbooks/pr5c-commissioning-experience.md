# SECP commissioning — the intended finished experience (SECP-PR5C)

> **THIS DESCRIBES A TARGET EXPERIENCE, NOT AN ACTIVATION GUIDE.** It contains no runnable
> deployment commands and no real values. Real endpoints, images, and descriptors live only in the
> deployment-local activation dossier (ADR-020 §D), outside source control. Nothing in this document
> starts an operator worker, submits a workflow, runs OpenTofu, or contacts any infrastructure. See
> [ADR-023](../adr/ADR-023-commissioning-automation-foundation.md).

> **Current roadmap correction (PR5F):** the diagram below is the historical PR5C target experience,
> not the current B8 enrollment sequence. B7/B8 subsequently delivered the existing browser
> **Read-Only Bootstrap** wizard and its idempotent Proxmox script. That wizard does **not** become a
> generic front end for this commissioning CLI. PR5F reuses it only after the ordinary worker has
> generated/published its persistent public key; on the already-strapped Proxmox host, rerunning the
> script is key rotation/binding. No second enrollment or bootstrap engine is required.

## The finished flow

```
   environment inspection                 [inspect]   read-only host facts
              |
              v
   immutable commissioning plan           [plan]      deterministic, canonically hashable
              |
              v
   explicit administrator confirmation    [--write --confirm]  noninteractive-automation friendly
              |
              v
   automated installation + validation    [install-prepared] + [status]  PREPARED, DISABLED
              |
              v
   first supervised plan-only operation    (separate, reviewed operator step — HAS NOT OCCURRED)
              |
              v
   separate human approval                 (PENDING, human-only, exact-hash — never auto-approved)
```

The commissioning stages from `inspect` through `evidence` are one engine and the CLI
(`python -m secp_commissioning`) consumes its deterministic `--json`. The existing B8 Read-Only
Bootstrap wizard is a separate, already-implemented control-plane workflow and does not call this
commissioning engine.

## What exists in THIS PR (software, tested against inert fixtures)

| Stage | Command | Status in PR5C |
|---|---|---|
| Environment inspection | `inspect` | **Implemented** — read-only host facts via injected seams. |
| Immutable commissioning plan | `plan` | **Implemented** — deterministic, canonically hashable, enforces reviewed pins. |
| Render staging bundle | `render` | **Implemented** — directory manifest, ordinary-worker config (descriptive), operator PREPARATION bundle, DISABLED operator entrypoint template + service unit. |
| Precondition verification | `verify` | **Implemented** — descriptor + plan preconditions (source/queue pins, operator disabled + distinct queue). |
| Prepared installation | `install-prepared` | **Implemented** — dry-run default; `--write --confirm` installs root-owned, disabled material; idempotent; refuses silent overwrite; atomic partial rollback. |
| Independent status | `status` | **Implemented** — re-verifies file digests + ownership/mode + image presence + operator-disabled; `absent \| invalid \| drifted \| prepared \| activation_not_supported`. |
| Rollback | `rollback-prepared` | **Implemented** — removes only files the matching plan created; refuses foreign/modified. |
| Evidence | `evidence` | **Implemented** — secret-free, immutable, topology-safe prepared-state record. |

## Subsequent delivery and remaining work

- **The Read-Only Bootstrap wizard and idempotent Proxmox script were delivered by B7/B8.** PR5F
  does not replace them. The real target's read-only strap already exists; its SECP-managed key must
  be rotated to the newly persistent worker key through that script after worker activation.
- **The narrow PR5F B8 activation package now exists in the repository** but was not installed or
  exercised by this change. It activates only ordinary-worker read-only discovery and does not call
  this commissioning engine as a browser-enrollment backend.
- **The reviewed operator deployment package exists in the repository but is not installed in the
  current deployment.** Its installation is the next separate step. Until a later reviewed operator
  deployment/activation, the controlled-live composition remains absent and the operator stays
  absent.
- **Operator activation** — starting the operator worker. There is deliberately **no `activate`
  command** in this milestone (`status` answers `activation_not_supported`).
- **No real OpenTofu plan has run.** Apply and destroy remain unavailable, and PR6 remains frozen.

## Human roles (separation of duties, for the future activation flow)

- **Operator** — runs the PR5C commissioning CLI and supplies its descriptor; separately, for B8
  key rotation, uses the existing Read-Only Bootstrap wizard/script.
- **Approver** — approves the prepared plan digest before any write; later approves the first real
  plan.
- **Reviewer** — reviews the deployment-local controlled-live plan composition and later activation.
- **Security owner** — holds the emergency stop.

No one person holds Operator + Approver + Reviewer. Commissioning is `prepared`-only; activation
requires an installed operator package, a separately reviewed controlled-live composition, and a
separate human approval. None is supplied or activated by this PR5C sequence.

## Invariants this experience preserves

- Within this PR5C sequence, the exact reviewed PR5B ordinary worker keeps running untouched on
  `secp-orchestration`; PR5F's later receipt-bound recreation is a separate activation operation.
- No operator worker is started; the current deployment has no operator package or service.
- No Proxmox / OpenBao / remote state / Temporal / PostgreSQL contact; no OpenTofu; no credential
  resolution; no workflow submission; no plan execution.
- `_PLAN_ONLY_PROCESS_SEALED` stays `False`; both `_B1A_SUBPROCESS_SEALED` stay `True`; PR6 frozen.
