# SECP operator deployment package — intended operational gate (SECP-PR5D)

> **THIS DESCRIBES A TARGET OPERATIONAL SEQUENCE, NOT AN ACTIVATION GUIDE.** It contains no runnable
> deployment commands and no real values. Real endpoints, images, image digests, profiles, state
> references, and secret locations live ONLY in the deployment-local activation dossier (ADR-020 §D),
> outside source control. Nothing in this document starts an operator worker, submits a workflow, runs
> OpenTofu, or contacts any infrastructure. Package installation is **not** activation. See
> [ADR-024](../adr/ADR-024-operator-deployment-package.md).

## What PR5D adds

The separately-reviewed, root-controlled package `secp_operator_deployment` that the PR5C operator
entrypoint imports, plus production-capable **read-only** real-host commissioning adapters. Operator
activation is **hard-sealed**: `runner.run_operator_worker` refuses (`operator_activation_sealed`)
before any Temporal `Worker` construction. The controlled-live compositions can be BUILT (typed,
provenance-bound, verified) only when a secret-free deployment profile AND a reviewed out-of-band
runtime provisioning are both present; the shipped state has neither and fails closed.

A read-only administrator command is available and OPERATIONAL by default (it resolves its inputs from
the fixed root-controlled production context — the profile, the independent expected-identities file,
the trusted installed-package verification, a bound runtime attestation, and a coherent host
observation — with no Python injection and no `--profile` flag):

```
python -m secp_operator_deployment verify --json
```

It reports SIX distinct dimensions and never conflates them: (A) installed-package **trust** (the
trusted directory-fd walk over the installed modules, compared to the independent expected aggregate),
(B) profile ↔ expected-identity **agreement**, (C) prepared **host** state (a coherent,
generation-checked observation), (D) runtime **provisioning** (a bound attestation), (E) controlled-live
**composition** readiness, and (F) the operator-activation **seal**. Its honest prepared-deployment
SUCCESS is **`sealed_prepared`** (exit 0): it requires A/B/C/F but NOT the future runtime (D) or
composition (E), which stay truthfully unprovisioned until the separate activation milestone. It fails
closed on a missing/invalid profile, missing/disagreeing expected pins, an untrusted install, a failed
or incoherent host inspection, an enabled/running operator, an absent/unhealthy ordinary worker, or
unsafe seals. Its JSON is deterministic, bounded, and secret-free; it constructs no `Worker`, calls
`run_plan_generation` never, resolves no credential, and contacts nothing.

**The exact successful post-merge PREPARED result** (`sealed_prepared`, exit 0): the package is
installed and TRUSTED (root-owned dir-fd walk); the profile and the independent expected pins agree;
the operator systemd unit is present, **disabled**, and **stopped**; the ordinary Docker worker is
running and its exact pinned health contract passes; the operator-activation seal stays `True`; no
workflow is submitted; no OpenTofu runs; no Proxmox mutation occurs; and the controlled-live runtime +
compositions are either separately ready or **truthfully unprovisioned** (the PR5D case — no reviewed
runtime provider is installed).

## The next operational gate (after PR5D merges)

Each step is a separate, explicit, human-supervised action. No step auto-triggers the next; the
operator remains **disabled and not running** at the end.

1. **Build and attest the exact artifacts** — the reviewed operator/ordinary/control-plane images and
   the deployment package, each pinned to an exact content digest and independently attested.
2. **Transfer and load the exact images** onto the site worker by content digest (never a tag, never a
   pull of a floating reference).
3. **Install the deployment package** (`secp_operator_deployment`) root-controlled on the site worker.
   Installing it activates nothing; the operator entrypoint stays disabled.
4. **Create the deployment-local profile OUTSIDE Git** at the fixed root-controlled path, owned by
   root and non-world-writable, carrying only the nonsecret identities the strict schema requires
   (never a credential, endpoint, state key, or secret location).
5. **Run commissioning `inspect`** with the real read-only host adapters injected — observing image
   presence (exact `sha256:` digest, never a pull) and the real topology through the hardened,
   read-only seams: the operator as a prepared/disabled **systemd** unit, the ordinary worker as an
   existing **Docker container**, and ordinary health as the **exact pinned health contract**
   (`<container-runtime> exec <container> <health-argv>`) — never systemd running-state alone. The
   Docker id/running observation obeys a strict closed grammar (one full 64-hex id + `true`/`false`)
   with before/after revalidation, failing closed on any change/malformation.
6. **Generate and review the immutable commissioning plan** (`plan`) — deterministic, canonically
   hashable, gated on every PR5C identity/service/queue invariant.
7. **Render and verify** (`render`, `verify`) the staging bundle + the deployment package
   (`python -m secp_operator_deployment verify --json`), confirming the sealed posture and the exact
   reviewed identities. On the root-controlled install, the package's implementation manifest is
   recomputed through a TRUSTED directory-fd walk (every ancestor from `/` opened
   `O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`, required root-owned and non-world-writable; each module read
   relative to the package-dir fd), and the built wheel's aggregate is proven equal to the source
   aggregate — so a tampered/symlinked/hardlinked install is refused.
8. **`install-prepared` with explicit `--write --confirm`** — installing the DISABLED operator
   material and writing the evidence record, refusing on any drift.
9. **Independently verify `status` and `evidence`** — re-deriving the prepared state from the
   root-controlled evidence, confirming the operator is present-but-disabled-and-not-running and the
   ordinary worker is running/healthy.
10. **Stop with the operator DISABLED and NOT running.** Activation — flipping
    `_OPERATOR_ACTIVATION_SEALED` and constructing the operator `Worker` — is a separate, reviewed
    milestone that **HAS NOT OCCURRED**. PR6 (first apply) does not begin until a supervised,
    exact-hash real plan has been reviewed on an activated composition.

## What remains sealed after this sequence

`_OPERATOR_ACTIVATION_SEALED` stays `True`; `_PLAN_ONLY_PROCESS_SEALED` stays `False` (construction
still token-gated, shipped composition disabled); both `_B1A_SUBPROCESS_SEALED` constants stay `True`;
apply/destroy remain impossible; the ordinary worker is never modified or restarted; no workflow is
submitted; no OpenTofu runs; PR6 remains frozen.
