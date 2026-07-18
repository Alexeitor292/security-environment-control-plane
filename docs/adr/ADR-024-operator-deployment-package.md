# ADR-024 — controlled-live operator deployment package (sealed, not activated)

- **Status:** Accepted for SECP-PR5D. Adds the separately-reviewed, root-controlled, deployment-local
  package `secp_operator_deployment` that the PR5C operator entrypoint imports, plus production-capable
  read-only real-host commissioning adapters. Operator activation is **HARD-SEALED**
  (`secp_operator_deployment.runner._OPERATOR_ACTIVATION_SEALED = True`); nothing here starts an
  operator worker, constructs a Temporal `Worker`, submits a workflow, runs OpenTofu, resolves a
  credential, or contacts Proxmox / OpenBao / remote state / Temporal / PostgreSQL. `_PLAN_ONLY_PROCESS_SEALED`
  stays exactly `False`; both `_B1A_SUBPROCESS_SEALED` constants stay exactly `True`; apply/destroy
  remain impossible. There is deliberately **no `activate` command**.
- **Date:** 2026-07-18
- **Milestone:** SECP-002B-1B — First Real Disposable-Lab Lifecycle, **PR5D** (operator deployment
  package; follows ADR-023 PR5C). PR6 (first apply) remains frozen.
- **Related:** [ADR-023](ADR-023-commissioning-automation-foundation.md) (commissioning engine +
  fixed operator entrypoint); [ADR-022](ADR-022-plan-only-activation-and-process-boundary.md)
  (plan-only activation + operator bootstrap + task-queue routing §12); [ADR-021](ADR-021-remote-state-and-jit-secret-readiness.md)
  (readiness disciplines); [ADR-020](ADR-020-first-real-disposable-lab-lifecycle.md) (activation
  dossier §D); [ADR-001](ADR-001-monorepo.md) (package layout); runbook
  `docs/runbooks/pr5d-operator-deployment.md`; STATUS `docs/STATUS.md`.

> **Package installation is NOT activation.** Adding this package makes the PR5C operator entrypoint's
> `from secp_operator_deployment import compositions, runner` resolve (its ABSENCE was the fail-closed
> state), but the entrypoint remains installed **disabled** and unstarted, and `runner.run_operator_worker`
> **refuses** (`operator_activation_sealed`) before constructing a Temporal `Worker`. No config field,
> environment variable, CLI option, database row, endpoint, installed package, or caller boolean can
> flip the seal — only a separately-reviewed code change to `_OPERATOR_ACTIVATION_SEALED` could, and
> this PR makes none.

> **Round-2 hardening addendum (current truth).** An independent review of the first PR5D head found
> and closed nine merge-blocking defects; the design above is amended accordingly:
> 1. **Coherent host observation.** The service-state adapter models the real topology — operator =
>    prepared/disabled **systemd** unit, ordinary worker = existing **Docker container**, ordinary
>    readiness = the **exact pinned health contract** (`docker exec <container> <health-argv>`), never
>    systemd `SubState`/running-state alone. It returns ONE `ServiceStateSnapshot` from a bounded
>    sequence with before/after revalidation of the operator unit + container id/running state,
>    failing closed if either changes mid-collection, the window is exceeded, or any reading is
>    missing/partial/malformed/timed-out. No mutation verb exists.
> 2. **Bounded streaming subprocess.** The command seam reads stdout INCREMENTALLY (never full-capture-
>    then-check), bounds it to `max + a small detection buffer`, validates positive-bounded
>    timeout/output, runs in a fresh session/process group, and on timeout OR overflow terminates the
>    whole group (SIGTERM → grace → SIGKILL → reap), failing closed (`command_reap_failed`) if reap
>    is unprovable.
> 3. **Executable object pinning.** Every host-invoked executable (container runtime, service
>    inspector) is opened `O_NOFOLLOW`, fstat-verified regular/single-hardlink/root-owned/non-writable,
>    stream-hashed, compared to its reviewed digest, and executed via `/proc/self/fd/<fd>` (descriptor
>    kept open through spawn) — a replacement race or digest mismatch refuses. No PATH lookup.
> 4. **Independent `ExpectedDeploymentIdentities`.** The profile is never the sole authority: an
>    immutable, independently-injected trusted-pins object pins every security-sensitive value (package
>    identity + manifest digest, source SHAs, image digests, UID/GIDs, queues, exact health argv,
>    operator unit, ordinary container, executable path+digests, composition identities); the profile
>    must MATCH it and the pins are themselves cross-checked against the code. Shipped default absent →
>    fail closed.
> 5. **Real implementation manifest.** `package_implementation_digest()` is a deterministic aggregate
>    over the FIXED inventory of covered package modules (per-file SHA-256 with symlink/hardlink/type/
>    trust refusal), not a hash of the label — content change with an unchanged label is detected.
> 6. **Truthful verification.** `verify --json` reports distinct sections (never conflated), honest
>    status classes (`seals_unsafe` | `sealed_but_unprovisioned` | `profile_invalid` |
>    `identity_mismatch` | `host_unavailable` | `host_not_ready` | `sealed_and_host_ready`) with stable
>    exit codes; a missing profile / unbuildable composition is never "success"; the only no-effect
>    claims are SCOPED to the invocation (`effects_of_this_verification`).
> 7. **Exact registration type check.** The runner validates `type(reg) is OperatorWorkerRegistration`
>    (authoritative type imported lazily, no module-level `temporalio`), refusing forged
>    `__module__`/`__qualname__` look-alikes; the real object reaches the `operator_activation_sealed`
>    seal.
> 8. **Duplicate-key rejection.** The profile reader rejects any duplicate JSON key at any depth
>    (`profile_duplicate_key`, never echoing the key) before validation, preserving all prior hardening.
> 9. **Composition identity coverage.** All three controlled-live branches are provider-identity bound,
>    so a foreign implementation copying a classification string or gate value refuses — not just the
>    plan renderer/process pins. (Round-3 replaced the `module.qualname` string compare with an EXACT
>    authoritative TYPE-OBJECT check — see the round-3 addendum below.)

> **Round-3 hardening addendum (current truth; supersedes the round-2 notes where they conflict).** A
> second independent review of the PR5D head found and closed nine further merge blockers:
> 1. **Process-group disappearance is PROVEN, not inferred.** On timeout/overflow the runner captures
>    the child's pgid after spawn, SIGTERMs the group, then PROBES the whole group with
>    `killpg(pgid, 0)` (ESRCH == gone, not merely the leader's exit); if any member survives (e.g. a
>    SIGTERM-ignoring grandchild) it SIGKILLs the group and re-probes within a bounded deadline, always
>    reaps the direct child, and refuses (`command_group_not_terminated` / `command_reap_failed`) if
>    complete disappearance cannot be proven. A real POSIX test spawns a stubborn grandchild in the
>    group and asserts both are gone + `killpg` returns ESRCH + no orphan.
> 2. **Trusted directory-fd manifest for the installed package.** Installed-package verification opens
>    every ancestor from `/` with `O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC` relative to its parent fd, requires
>    each is a real directory, root-owned, and non-group/other-writable, keeps the package-dir fd, and
>    enumerates + reads every module RELATIVE to that fd (`O_NOFOLLOW`, regular/nlink==1/root-owned/
>    non-writable/bounded) — never `Path.resolve()` as a trust boundary. A symlinked package dir or
>    ancestor, a replacement race, a hardlinked/extra/missing module all refuse. (The cross-platform
>    content reader still computes the same aggregate for provenance/fixtures without root.)
> 3. **Wheel build/install identity.** A CI test builds the wheel from the exact tree, extracts it into
>    a clean location, recomputes the manifest, and proves the wheel aggregate == the source aggregate,
>    every covered module ships exactly once, no unexpected module ships, and a modified wheel module
>    invalidates the match. No built wheel is committed.
> 4. **Deployment root-security CI job.** A dedicated `backend-deployment-root` job runs the trusted
>    dir-fd/ownership + pinned-exec + real-subprocess tests under passwordless sudo, uploads their JUnit,
>    and FAILS CLOSED by parsing it (>= 20 collected, zero skipped/failed/errored) — the pytest exit
>    code alone is not trusted. It is in the aggregate backend gate; CI-contract tests prove it cannot be
>    removed, skipped, or omitted.
> 5. **Exact provider TYPE identity.** All three provider checks use `type(x) is <ExactProviderType>`
>    (the authoritative type OBJECT), not a forgeable `module.qualname` string; a class spoofing both
>    `__module__` and `__qualname__` and copying `classification="controlled_live"` is refused.
> 6. **Three provider-identity agreement points.** The profile carries strict required
>    `plan/readiness/eligibility_provider_identity`; the independent `ExpectedDeploymentIdentities` pins
>    them; `require_profile_agreement` compares them exactly; and the pins are cross-checked against the
>    code-owned constants — three separate agreement points, plus the actual constructed exact types.
> 7. **Structurally truthful verification.** `verify --json` no longer calls any runtime resolver/factory
>    method, never calls `plan_execution_seams()`, constructs no secret resolver, and contacts nothing.
>    It consumes an ALREADY-CONSTRUCTED reviewed `ControlledLiveCompositions` aggregate + a pure,
>    immutable `RuntimeProvisioningAttestation` (nonsecret booleans only); a foreign duck-typed
>    attestation/aggregate is refused. A hostile runtime double whose `provisioned()`/
>    `plan_execution_seams()` would raise if called proves verify calls neither.
> 8. **Strict Docker observation grammar.** The container inspect must be exactly one full 64-lowercase-
>    hex id + a single space + exactly `true`/`false`; every malformed shape (short/uppercase/non-hex
>    id, extra field/line, empty, bad boolean, identical-malformed before/after) fails closed with a
>    bounded reason, and before/after revalidation compares the validated full id + running state.
> 9. **Stale descriptions corrected.** This ADR (the self-contradictory read-only-`systemctl`/`SubState`
>    text), the runbook, STATUS, docstrings, test comments, and the commit body now describe the systemd
>    operator + Docker ordinary worker + exact pinned health contract, exact-type provider checks, the
>    root-controlled dir-fd manifest + verified wheel identity, and proven (not inferred) process-group
>    disappearance.

> **Round-4 operational-closure addendum (current truth; supersedes earlier notes where they conflict).**
> A third independent review found the prepared deployment could not actually be EXECUTED or verified
> in production, only in tests. Round 4 closes that without weakening any seal:
> 1. **Production binding path.** The fixed PR5C entrypoint's no-argument
>    `build_controlled_live_compositions()` now resolves fixed root-controlled bindings via a code-owned
>    loader (`production_context.load_production_bindings`): the profile, the INDEPENDENT expected pins
>    (a SEPARATE root-controlled file, read through the hardened `RealFilesystem` — never the profile
>    itself), and the installed runtime. The shipped repo has none of these and no reviewed runtime
>    provider, so the no-argument build still fails closed. Test injection is a separate, private seam.
> 2. **Operational administrator CLI.** `python -m secp_operator_deployment verify --json` uses that
>    production context by default (no Python injection, no `--profile` flag). It reports SIX distinct
>    dimensions — (A) installed-package trust, (B) profile/expected agreement, (C) prepared host state,
>    (D) runtime provisioning, (E) composition readiness, (F) activation seal — and has an honest
>    prepared-deployment SUCCESS, **`sealed_prepared`** (exit 0), that requires A/B/C/F but NOT the
>    future runtime (D) or composition (E), which stay truthfully unprovisioned until the separate
>    activation milestone and are reported separately.
> 3. **Bound runtime attestation.** The bool-only attestation is replaced by a bound, versioned,
>    immutable `RuntimeProvisioningAttestation` (contract version, reviewed runtime-provider
>    implementation id+digest, canonical profile + expected digests, release shas, dossier hash, worker
>    registration id, toolchain identity, a self-hash). A bare `provisioned=True` is not constructible; a
>    cross-deployment / stale / fabricated / non-reviewed attestation is refused. `REVIEWED_RUNTIME_PROVIDERS`
>    is EMPTY in PR5D, so no attestation reaches provisioned readiness.
> 4. **Semantic composition verification.** Verify now validates a supplied aggregate SEMANTICALLY — exact
>    `DeploymentProvenance` type + contract/version/id/manifest-digest, provenance bound to the installed
>    trust result and the profile/expected, `verify_plan_execution_composition`, classification, exact
>    executor factory, renderer/process/provider registrations+digests, enabled gates, and exact provider
>    type identities — refusing copied/disabled/stale/foreign/cross-deployment compositions, while
>    constructing no secret resolver and calling no runtime method.
> 5. **Exact types for every verification input.** The profile, expected pins, attestation, aggregate +
>    provenance, and the deployment-owned host observation are all refused unless they are the EXACT
>    authoritative type — without accessing an arbitrary attribute or calling a method.
> 6. **Trusted installed-package gate in the real command.** The CLI's context uses the trusted
>    directory-fd walk (`verify_installed_package_trust`, not `Path.resolve`, not the cross-platform
>    content reader) over the installed modules and compares the aggregate to the independent expected
>    aggregate; prepared success is impossible unless `installed_trust_ok`.
> 7. **Service/container ABA gap closed.** The operator is read with ONE `systemctl show` carrying
>    generation markers (`InvocationID` + `StateChangeTimestampMonotonic`) and the ordinary container
>    with `RestartCount`/`StartedAt`/`FinishedAt`/`Pid`; the before/after revalidation compares the FULL
>    generation tuples, so an ABA restart that returns to the same visible running state fails closed, and
>    a health result from one container generation is never applied to another.

## Why the deployment package is SEPARATE from `secp_commissioning`

`secp_commissioning` is a pure, injected-seam commissioning ENGINE (ADR-023): it imports no
`secp_worker` / `secp_api` / `temporalio` / subprocess / Docker / HTTP / Proxmox / secret resolver,
so a passing in-memory test proves the mechanism without any privileged capability. The controlled-live
deployment material is the OPPOSITE kind of code: it must reference the exact reviewed `secp_worker`
composition types + implementation digests and (for the real-host adapters) touch the local container
runtime and service manager. Mixing the two would drag privileged imports into the engine and dissolve
its purity boundary. So this PR keeps them apart: **`secp_commissioning` never imports
`secp_operator_deployment`** (enforced by the commissioning + deployment boundary tests), while the new
package MAY import `secp_commissioning` (for the injected `ContainerRuntime` / `ServiceStateAdapter` /
`inspect_host` seams) and `secp_worker` (for the authoritative composition types). The engine stays
usable with injected seams + deterministic JSON exactly as before.

## Package trust + provenance

`secp_operator_deployment` pins its own `PACKAGE_CONTRACT_VERSION`, `PACKAGE_VERSION`, and reviewed
`PACKAGE_IMPLEMENTATION_ID` (with a deterministic `package_implementation_digest()`), and binds them
into the composition aggregate's provenance and the verification report. The deployment PROFILE
independently re-pins those identities plus the exact reviewed `secp_worker` renderer/process
registrations + digests; `build_controlled_live_compositions` refuses on any mismatch. Nothing is a
sole source of truth — the profile must MATCH the reviewed package, and the compositions must pass the
authoritative `verify_plan_execution_composition` + `ControlledLive*CompositionProvider` gates.

## Typed controlled-live composition construction

`build_controlled_live_compositions()` returns ONE immutable `ControlledLiveCompositions` aggregate
holding EXACTLY the three authoritative composition types (`PlanExecutionComposition`,
`ReadinessComposition`, `EligibilityPreflightComposition`) — never a raw dict, never a parallel/weaker
type. It constructs the plan-execution composition with the exact reviewed classification
(`controlled_live`), the sealed production issuer bound by identity, and the exact renderer/process
digests (profile-pinned), then VERIFIES it through the authoritative gates. It never selects a task
queue (queue resolution stays inside `build_operator_worker_registration`, called only by the
entrypoint) and refuses a fake/test-only/non-concrete substitute.

**Fail-closed by construction.** The controlled-live plan-execution composition additionally needs
deployment-local RUNTIME pieces that are NOT secret-free identities (concrete OpenBao resolvers, their
activations, the nonsecret provider/state runtime input sources, the on-disk toolchain layout). Those
enter through a separate, sealed-by-default `ControlledLiveRuntime` provisioning seam, NOT the profile.
The shipped default (`SealedControlledLiveRuntime`) is unprovisioned, and the fixed profile path is
absent in Git — so the shipped `build_controlled_live_compositions()` refuses
(`controlled_live_runtime_not_provisioned` / `profile_not_installed`). A real host injects both out of
band; tests inject typed doubles.

## The dedicated operator-activation seal

Activation is gated by a reviewed CODE CONSTANT, `_OPERATOR_ACTIVATION_SEALED = True` — never an
environment flag. `runner.run_operator_worker(registration)` validates the registration is the ONE
reviewed `OperatorWorkerRegistration` type by an un-forgeable EXACT type-object check
(`type(registration) is OperatorWorkerRegistration`, the authoritative type imported lazily so the
module drags in no `temporalio` — a forged `__module__`/`__qualname__` + shaped attributes is refused),
then refuses with the bounded reason `operator_activation_sealed` BEFORE any `Worker` construction. It
imports no `temporalio`, starts no event loop, registers no workflows/activities, inspects no secret,
contacts no Temporal, and mutates no service state.

## Real-host adapter boundaries

The adapters are read-only and injectable into `secp_commissioning` unchanged:

- **Container-runtime adapter** answers ONLY whether an exact `sha256:` digest is present locally
  (`<exe> image inspect --format {{.Id}} <digest>`): never pulls, never resolves a tag/floating
  reference, refuses a non-exact digest, observes each digest once per `snapshot_images` snapshot, and
  runs through a hardened command seam (`shell=False`, absolute pinned executable, exact explicit env
  with no ambient inheritance, `stdin=DEVNULL`, bounded timeout, capped output, closed response parse,
  bounded reason codes).
- **Service-state adapter** returns ONE coherent `ServiceStateSnapshot` modelling the REAL topology:
  the operator is a prepared/disabled **systemd** unit (read-only `systemctl show --property … --value`
  + `is-enabled`), the ordinary worker is an existing **Docker container**, and "ordinary healthy"
  means the container is present AND running AND its **exact pinned health contract** passes
  (`<container-runtime> exec <container> <health-argv>`) — never systemd `SubState`/running-state alone
  and never a host probe that could contact Temporal/PostgreSQL. The Docker inspect observation obeys a
  STRICT closed grammar (exactly one line: a full 64-lowercase-hex container id, a single space, then
  exactly `true`/`false` — a short/uppercase/non-hex id, extra field/line, or bad boolean fails
  closed). It is assembled from a bounded sequence with before/after revalidation of EVERY operator
  property (load/active/enabled) and the validated container id + running state, failing closed if any
  changes mid-collection, the window is exceeded, or any reading is missing/partial/malformed/timed-out.
  It exposes no start/stop/restart/enable/disable/reload verb and never touches the ordinary worker.
- **Host-facts composition** reuses the existing `secp_commissioning.inspect_host` — no plan / install
  / status / evidence logic is duplicated outside the engine, and every PR5C gate is preserved.

## Deployment-local profile handling

The profile is strict (`extra="forbid"` + `strict`), versioned, and secret-free (enforced by schema
AND the reused commissioning forbidden-secret scanner). It carries only nonsecret identities — source
revision, package version/identity, the three image digests, runtime UID/GIDs, the distinct
ordinary/operator queues, the ordinary health command, local service/container identities, toolchain
layout identities, and the exact controlled-live composition implementation identities — and NO
credential, token, private key, secret reference, OpenBao path, state key, Proxmox endpoint, password,
or bearer material. It is read through the HARDENED root-controlled filesystem backend
(`RealFilesystem.safe_read`) at a FIXED path; there is no arbitrary `--profile` flag. Tests inject an
alternate `fs`/`path` through typed DI.

## Why PR6 remains frozen

Building or installing this package activates nothing. Apply/destroy remain impossible (both
`_B1A_SUBPROCESS_SEALED` constants stay `True`); the plan-only seal stays `False` with construction
still token-gated; the operator worker stays disabled and its runner sealed. PR6 (the first real apply)
does not begin until a supervised, exact-hash real plan has been reviewed on an activated
deployment-local composition — future, human-supervised work that **HAS NOT OCCURRED**.

## Consequences

- A new importable package `secp_operator_deployment` (+ `apps/deployment/tests` test root) is wired
  into the hatch wheel packages, pytest `pythonpath`/`testpaths`, mypy `mypy_path` + CI type-check
  target, and the `.ci/pytest-suite.json` sharding roots.
- The commissioning engine stays decoupled: it imports no `secp_operator_deployment` (boundary-tested).
- Future work: the reviewed out-of-band `ControlledLiveRuntime` provisioning + deployment-local
  profile creation on a real site worker; artifact build/attest/transfer; the first supervised real
  commissioning; and — only after that — operator activation (a separate, reviewed milestone).

## Commissioning + deployment: SUPPORTED, NOT EXERCISED / HAS NOT OCCURRED

This package is implemented and tested against in-memory fakes + documentation-only fixtures. It has
**not** been installed on a real host, given a real profile, or provisioned with a real runtime; no
operator worker exists; no operator service has been enabled or started; no real deployment has been
prepared or activated; nothing has been deployed. A passing test proves the MECHANISM only.
`_OPERATOR_ACTIVATION_SEALED` remains `True`, `_PLAN_ONLY_PROCESS_SEALED` remains `False`, and both
`_B1A_SUBPROCESS_SEALED` constants remain `True`.

## Non-goals

This PR does not: activate the operator; construct or start a Temporal `Worker`; enable or start any
service; submit any workflow or call `run_plan_generation`; run OpenTofu or a generic subprocess
(beyond the read-only local image/service inspection seam); resolve any credential; modify or restart
the ordinary worker; alter any process seal; weaken queue separation; contact Proxmox / OpenBao /
remote state / Temporal / PostgreSQL / either VM; build or transfer a live artifact; add real
deployment values (endpoint, hostname, IP, VM-ID, node, storage, bridge, image digest, state key,
credential, or secret location); or begin PR6.
