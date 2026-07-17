# SECP commissioning — the intended finished experience (SECP-PR5C)

> **THIS DESCRIBES A TARGET EXPERIENCE, NOT AN ACTIVATION GUIDE.** It contains no runnable
> deployment commands and no real values. Real endpoints, images, and descriptors live only in the
> deployment-local activation dossier (ADR-020 §D), outside source control. Nothing in this document
> starts an operator worker, submits a workflow, runs OpenTofu, or contacts any infrastructure. See
> [ADR-023](../adr/ADR-023-commissioning-automation-foundation.md).

## The finished flow

```
   Proxmox initialization script          (ONE manual infrastructure action)
              |
              v
   browser onboarding wizard              (calls the SAME engine as the CLI)
              |
              v
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

Every arrow above the dashed line is one engine; the CLI (`python -m secp_commissioning`) and the
future web wizard call it identically and consume the same deterministic `--json`.

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

## What remains FUTURE work (not in this PR)

- **The Proxmox initialization script** — the one manual bootstrap action. Specified, not shipped
  here.
- **The browser onboarding wizard front end** — will call this engine + `--json`. Not shipped here.
- **The reviewed deployment package** that supplies the typed controlled-live compositions + the
  operator run hook. Until it is installed OUT OF BAND, the rendered operator entrypoint fails closed
  with `controlled_live_composition_not_installed`.
- **Operator activation** — starting the operator worker. There is deliberately **no `activate`
  command** in this milestone (`status` answers `activation_not_supported`).
- **The first supervised plan-only operation** and its **separate, human-only, exact-hash approval**
  (ADR-022) — a later, reviewed, human-supervised step that **HAS NOT OCCURRED**.

## Human roles (separation of duties, for the future activation flow)

- **Operator** — runs the bootstrap script + the commissioning CLI/wizard; supplies the descriptor.
- **Approver** — approves the prepared plan digest before any write; later approves the first real
  plan.
- **Reviewer** — reviews the deployment package of controlled-live compositions (a separate PR).
- **Security owner** — holds the emergency stop.

No one person holds Operator + Approver + Reviewer. Commissioning is `prepared`-only; activation
requires the reviewed deployment package AND a separate human approval, neither of which this PR
provides.

## Invariants this experience preserves

- The exact reviewed PR5B ordinary worker keeps running, untouched, polling only `secp-orchestration`.
- No operator worker is started; the operator service is installed **disabled** and fails closed.
- No Proxmox / OpenBao / remote state / Temporal / PostgreSQL contact; no OpenTofu; no credential
  resolution; no workflow submission; no plan execution.
- `_PLAN_ONLY_PROCESS_SEALED` stays `False`; both `_B1A_SUBPROCESS_SEALED` stay `True`; PR6 frozen.
