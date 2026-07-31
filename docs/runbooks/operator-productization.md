# Runbook — controlled-live operator productization (read-only)

This runbook covers the three **read-only** commands the controlled-live operator deployment
package exposes, how to read their output, and — equally important — what they deliberately
cannot do.

**Nothing in this runbook starts an operator worker, submits a workflow, runs OpenTofu, resolves
a credential, or contacts Proxmox, OpenBao, Temporal, remote state, or PostgreSQL.** Every
command below is an observation.

> **"Observation" is not "inert."** On a provisioned POSIX host, `verify` and `queue` resolve their
> inputs by running read-only host commands — `systemctl show`, `docker inspect`, and a
> `docker exec <ordinary-container> <health argv>` health probe. These are read-only and cannot
> submit anything, but they *are* contact, and both reports now say so from a **count taken while
> the commands run**, in `effects_of_this_*.measured_this_invocation`. Note the health probe runs
> the profile-configured health command inside the container; what *that* command does is outside
> this package's control and outside these reports' claims.

> **All three commands are POSIX + root.** The hardened filesystem and command backends refuse to
> construct elsewhere. On a non-POSIX host each command still produces a **bounded report with a
> published exit code** — never a traceback — carrying `filesystem_backend_non_posix` or
> `manifest_trust_non_posix`. Observed on Windows: `verify` → exit 10, `queue` → exit 10,
> `provenance` → exit 15. A refusal that escapes the per-dimension handlers is caught at the top
> level and rendered as `command_unavailable` with exit 20; the exception message is never printed,
> only a bounded reason code, because messages are where absolute paths live.

Companion documents: [ADR-024](../adr/ADR-024-operator-deployment-package.md) (the package
contract) and [pr5d-operator-deployment.md](pr5d-operator-deployment.md) (how the package is
prepared and installed).

---

## 1. The three commands

```
python -m secp_operator_deployment verify --json
python -m secp_operator_deployment provenance --json
python -m secp_operator_deployment queue --json
```

None takes a path argument. `verify` resolves the fixed root-controlled deployment profile and
the **separate** independent expected-identities file; `provenance` inspects the installed
module's own directory, resolved in code; `queue` reuses `verify`'s context loader. This is
deliberate: an operator-supplied path would let a report describe a tree that is not the one that
would actually run. `queue` additionally takes no queue **name**, which is its path-equivalent.

There is no `install`, no `start`, and no command that opens the controlled-live path. That is
not an oversight — see §1.1 for where installation actually happens, and §5 for why the
controlled-live path stays closed.

### 1.1 Where installation happens (it is not here, deliberately)

This package **diagnoses** an installation; it does not **perform** one. The two are split on
purpose: a package that can both install itself and attest to its own installation is its own
witness, and its green tells you much less.

Actuation lives in the commissioning tool, `python -m secp_commissioning`, whose full supervised
sequence is [pr5d-operator-deployment.md](pr5d-operator-deployment.md) (steps 1–10):

| Command | Does |
| --- | --- |
| `inspect` | observe host facts (read-only) |
| `plan` | build the immutable commissioning plan |
| `render` | render the staging bundle |
| `verify` | validate descriptor + plan preconditions |
| `install-prepared` | install the prepared, **disabled** state — **dry-run by default**; writes only with explicit `--write --confirm` |
| `status` | independently re-verify the prepared state |
| `rollback-prepared` | remove only the objects this install created |
| `evidence` | print the prepared-state evidence record |

So the division is: `secp_commissioning install-prepared` puts the host into the prepared state;
`secp_operator_deployment verify` tells you, from the **other side**, whether it is actually there —
and the prerequisite ladder (§2) tells you which rung is missing and whether closing it is yours to
do.

#### The two root-controlled files are different artefacts

`profile_installed` and `expected_identities_installed` are **separate rungs about separate files**,
and their separation is the whole security property: the profile is the deployment's own claim, the
expected-identities file is the independent authority it is checked against. Neither is created by
any command in this package, and they are not created the same way.

| Unmet rung | The artefact | Where it comes from |
| --- | --- | --- |
| `profile_installed` | the deployment profile | **Step 4** of the pr5d sequence — created out of band at the fixed root-controlled path, secret-free, root-owned, non-world-writable |
| `expected_identities_installed` | the independent expected-identities pins | A **separate file at a different path**. **No step in the 1–10 sequence instructs creating it** — pr5d only refers to it descriptively. It is provisioned out of band by whoever holds release authority, and deliberately not by the same hand or the same step as the profile |

That second row is a real gap in the pr5d sequence, recorded here rather than smoothed over: if
your `expected_identities_installed` rung is unmet, there is **no numbered step to follow**, and
you should escalate to release authority rather than improvise the file. Creating it yourself from
the profile would destroy the independence that makes the check meaningful — the profile would
become its own authority, which is exactly what `identities.py` exists to prevent.

Note that `install-prepared` installs the operator unit **disabled**, and that is the terminal
state of the whole sequence. Nothing in either package starts it.

---

## 2. `verify` — where am I, and what is next?

`verify` reports six independent dimensions and never conflates them:

| Dim | Question |
| --- | --- |
| A | Is the installed package trusted? (the directory-fd walk from `/`) |
| B | Do the profile and the independent expected pins agree? |
| C | Is the host in the prepared state? |
| D | Is the controlled-live runtime provisioned? |
| E | Are the controlled-live compositions ready? |
| F | Are the reviewed safety seals intact? |

**Prepared success (`sealed_prepared`, exit 0) requires A, B, C and F — but not D or E.** The
controlled-live runtime and compositions may truthfully remain unprovisioned; they are reported
separately and never gate the prepared result.

### Exit codes

| Status | Exit | Meaning |
| --- | --- | --- |
| `sealed_prepared` | 0 | Prepared. Seals intact, package trusted, identities agree, host ready. |
| `sealed_but_unprovisioned` | 10 | Seals fine; a profile, the expected pins, or a host observation is absent. |
| `profile_invalid` | 11 | The profile file exists but is out of contract. |
| `identity_mismatch` | 12 | The profile disagrees with the independent expected pins. |
| `host_unavailable` | 13 | The host could not be observed coherently. |
| `host_not_ready` | 14 | Observed, but the operator unit or the ordinary worker is not in the prepared state. |
| `install_untrusted` | 15 | The installed package failed the trusted directory-fd verification. |
| `seals_unsafe` | 20 | **A reviewed safety seal has drifted. Stop and escalate.** |

> **POSIX + root.** On a non-POSIX host the profile cannot be read at all, so `verify` reports
> `sealed_but_unprovisioned` (exit 10) with `filesystem_backend_non_posix` on the
> `profile_installed` rung. Like `queue`, that 10 means *not established*, not *fine*.
>
> `verify` also runs the read-only host commands described at the top of this runbook, and reports
> the count in `effects_of_this_verification.measured_this_invocation`.

### The prerequisite ladder

A single status enum answers *"am I prepared?"* but not *"what is left?"*. The `prerequisites`
section answers the second question. It lists every rung in the same priority order the status is
resolved in, and reports each one honestly — including rungs below the first gap — so the whole
remaining path is visible at once:

```json
"prerequisites": {
  "next_blocking": "installed_package_trusted",
  "next_blocking_reason_code": "manifest_ancestor_not_root_owned",
  "next_blocking_remediation": "operator_host_action",
  "blocking_unmet_count": 1,
  "unmet_count": 3,
  "ladder": [ ... ]
}
```

Read `next_blocking` first. If it is `null`, nothing blocks the prepared result.

| Rung | Dim | Blocking |
| --- | --- | --- |
| `seals_correct` | F | yes |
| `profile_installed` | B | yes |
| `profile_schema_valid` | B | yes |
| `expected_identities_installed` | B | yes |
| `identity_agreement` | B | yes |
| `installed_package_trusted` | A | yes |
| `host_observed` | C | yes |
| `host_observation_coherent` | C | yes |
| `operator_prepared_and_disabled` | C | yes |
| `ordinary_worker_running` | C | yes |
| `runtime_provisioned` | D | **no** |
| `compositions_verified` | E | **no** |

The ladder and the status are derived independently, and two test matrices assert they agree: one
breaks a single prerequisite at a time, and one breaks each rung together with every rung below it
— the latter is what pins the ORDER, because relative order can only matter when two rungs are
unmet at once. So the first unmet blocking rung always explains the reported status.

### Remediation classes

Every gap carries one of three classes. **This is the field to read before you start work**:

| Class | Meaning |
| --- | --- |
| `operator_host_action` | You can close this on the host. |
| `reviewed_deployment_material` | Requires out-of-band reviewed material (profile, expected pins, runtime provisioning). Not a host action, not a flag. |
| `reviewed_code_change` | Requires a separately reviewed change to a reviewed **code constant**. **No configuration, environment variable, CLI flag, database row, or file can close it.** |

If you see `reviewed_code_change`, stop looking for a setting. There isn't one, by design.

---

## 3. `queue` — is the controlled-live queue isolated, and is anything consuming it?

The program constraint is that the **controlled-live operator queue must be disabled and isolated
from the ordinary Temporal queue**. `verify` reports queue separation as one section among many;
`queue` is the command for answering that constraint on its own, and it is what you run before a
controlled-live milestone.

```
python -m secp_operator_deployment queue --json
```

It reports **three independent facts and never merges them** into a single "the operator side is
safe" boolean:

| Section | Dim | Question |
| --- | --- | --- |
| `isolation` | B | Are both queues configured, and **distinct**? |
| `operator_consumer` | C | Is anything actually **polling** the operator queue? |
| `submission_stops` | D/E/F | What would **refuse** an attempted controlled-live start? |

### Exit codes

| Status | Exit | Meaning |
| --- | --- | --- |
| `queue_isolated_and_dormant` | 0 | Queues distinct, nothing consuming, every stop closed. |
| `queue_unverified` | 10 | No parsed profile, or the host could not be observed coherently. Isolation or dormancy was **not** established. |
| `queue_not_isolated` | 12 | The queues are missing or shared. The configuration itself is unsafe. |
| `queue_operator_consuming` | 14 | The operator unit is enabled or running — something may be polling the controlled-live queue. |
| `queue_stops_open` | 20 | **A reviewed submission stop is open or unreadable. Stop and escalate.** |

`queue_unverified` is a refusal, not a pass. The dangerous failure mode for this command would be
reporting isolation it never observed, so an absent profile or an incoherent host reads as
*unverified* rather than as *fine*.

> **POSIX + root, like the other two.** On a non-POSIX host `queue` cannot observe isolation or
> dormancy at all and reports `queue_unverified` (exit 10) with `filesystem_backend_non_posix` —
> a bounded refusal, never a traceback. Do not read that 10 as "the queue is fine"; it means
> nothing was established.
>
> **This command is not inert on a real host.** Resolving its inputs runs `systemctl show`,
> `docker inspect` and the `docker exec` health probe. `effects_of_this_queue_check.
> measured_this_invocation.host_commands_executed` reports how many actually ran, counted as they
> ran, and `local_host_contact_performed` is derived from that count — not declared.

### `isolation` (dimension B)

Booleans only — never the queue names, which are profile values:

```json
"isolation": {
  "ok": true, "ordinary_configured": true, "operator_configured": true,
  "distinct": true, "authority": "deployment_profile", "reason_code": null
}
```

A shared queue would let the shipped sealed ordinary worker pick up controlled-live work, so the
profile validator refuses it at parse time (`profile.py::_v_queue_separation`) and this section is
a defence-in-depth report of the same fact. It is built by the **same** builder `verify` uses, so
the two commands can never disagree about it.

#### Which pair this reads — read `authority` before you conclude

The same two key names appear in **three** different artefacts, describing different components.
This section reads one of them:

| Artefact | Names | Read here? |
| --- | --- | --- |
| the **operator deployment profile** (and the commissioning plan) | `ordinary_task_queue` / `operator_task_queue` | **yes** — `authority: "deployment_profile"` |
| the **worker evidence document** — the installed-state proof the management plane enforces | the same two names | no — different component, different package |
| `Settings` — what a **running worker process** polls | `temporal_task_queue` / `temporal_operator_task_queue` | no |

Matching names across three artefacts is exactly why `authority` is in the payload: it says which
one a given green describes.

The profile pair is well-founded rather than self-asserted: the plan validates both against the
independent root-controlled expected pins and separately requires them distinct, so this report is
the third independent enforcement of the same fact.

They also differ **in kind**, which is the part most likely to mislead. This package requires a
non-empty operator queue. The running worker's `temporal_operator_task_queue` is empty by default
and the shipped worker entrypoint **never reads it on any path** — so on the runtime side the
operator queue is disabled by *structural absence*, not by configuration. "Operator queue not
configured" is therefore a fault in this artefact and the correct, safe state in that one.

So a green here says the deployment **material** is isolated. It does not by itself establish that
a running process matches it. The independent check on the running side is **consumer dormancy**
below, observed from the host rather than from any configuration file — which is why the two are
reported separately and never merged into one "the queue is safe" boolean.

### `operator_consumer` (dimension C)

Observed from the host, not from configuration. Note this is deliberately **not** `verify`'s
`operator_prepared_and_disabled` rung. That rung requires the unit to be *present* — a prepared
host has it installed but disabled. This section asks only whether anything **consumes** the
queue, and an absent unit consumes nothing. The two answers differ on exactly one host state, and
they differ correctly; merging them would make one of them wrong.

When the host was not observed coherently, the three unit fields are `null` rather than a guess.

### `submission_stops` and `submission_preview` — the dry run

A controlled-live submission cannot be "tried" — trying it is the thing that must never happen. So
the preview is derived by **reading the reviewed code constants that would refuse**, in the order
they would be encountered along an attempted start:

| Stop | Stops |
| --- | --- |
| `shipped_runtime_sealed` | the no-argument controlled-live composition build |
| `reviewed_runtime_provider_set_empty` | any runtime-provisioning attestation validating |
| `operator_activation_seal` | the operator worker being constructed, so nothing polls the queue |
| `plan_execution_gate_default_disabled` | the shipped plan-execution composition, before any external contact |

```json
"submission_preview": {
  "submission_performed": false,
  "would_be_refused": true,
  "first_refusing_stop": "shipped_runtime_sealed",
  "refusal_reason_code": "controlled_live_runtime_not_provisioned",
  "basis": "observed_reviewed_code_constants"
}
```

Every `closed` boolean carries the value that was **read** next to it in `observed`, so you can
check the verdict rather than take it. `refusal_reason_code` is the bounded code the *real* path
refuses with, so the preview and an actual refusal name the same thing.

Two properties worth knowing:

- **A stop that cannot be read is reported open**, with `submission_stop_unobservable`. An
  unobservable stop is not a stop, and this resolves to exit 20.
- **All four stops are `reviewed_code_change`.** None is operator-closable. See §5.

> This command is the reason there is no `--dry-run` flag anywhere else in the package (§7).

---

## 4. `provenance` — what is actually installed here?

`verify` tells you the installed package is *trusted*. `provenance` tells you *which* package it
is, so you can compare it against the aggregate bound into a signed release **before** trusting
the deployment:

```json
{
  "status": "provenance_ok",
  "source_aggregate":    {"implementation_manifest_digest": "sha256:..."},
  "installed_aggregate": {"implementation_manifest_digest": "sha256:...", "trusted": true},
  "agreement": {"source_equals_installed": true},
  "release_identity": {
    "available": true,
    "release_source_sha": "...", "source_tree_sha": "...",
    "authority": "independent_expected_identities",
    "release_signature_checked": false
  }
}
```

### `release_identity` — *which* release is this?

The aggregate tells you the installed content is internally consistent. It does not tell you which
release you are holding. `release_identity` does, and it takes those values from the **independent
root-controlled expected-identities file** — never from the profile, because a profile must not be
able to name its own release. `build_provenance_report` takes no profile input at all, which is the
structural guarantee rather than a convention.

These two values are release **identifiers**, not configuration and not secrets: they are exactly
what you read off the deployment and compare against the signed release. When the pins are absent
or malformed the section reports `available: false` with a bounded reason, rather than omitting the
question.

Emission is bounded **structurally**, not by convention: the pins object carries thirty fields and
exactly two are read, by name — never by `asdict()` or iteration — so adding a field to it cannot
auto-leak. What stays suppressed is the sensitive class: both queue names, both host executable
paths, service and container names, uid/gids and image digests. The line is that an emitted value
identifies an **immutable artefact that already exists**, while a suppressed one is the **address of
a live resource** — a queue you could publish to, an executable you could target.

`parent_sha` was emitted here and has been **removed**. A signed release names its own commit and
tree, not its parent, so the compare-against-the-release justification never reached it — and it
was the only one carrying commit-graph shape. A field that cannot be justified individually does not
belong in a section whose whole defence is that every value in it is one you must compare.

**Read `release_signature_checked` before you conclude anything.** It is always `false`. This
package verifies no signature — it supplies the values for a comparison you perform. The section is
also reported on the *failure* paths, because the release identity is what you escalate with.

| Status | Exit | Meaning |
| --- | --- | --- |
| `provenance_ok` | 0 | The installed package recomputed to its reviewed aggregate. |
| `provenance_untrusted` | 15 | The dir-fd walk refused, or the aggregates disagree. |
| `provenance_unavailable` | 20 | The aggregate could not be computed at all. |

What `provenance_ok` does **not** mean, stated because the misreading is the risk: it does not mean
a release signature was checked, and it does not mean the deployment-local profile agrees with the
trusted pins. Profile-to-pins agreement is dimension **B**, answered by `verify`, and is
deliberately not re-derived here — half-deriving one fact in two commands is how the two come to
disagree. A missing release identity does not make the aggregate untrusted, and an untrusted
aggregate does not blank the release identity; they are separate facts and stay separate.

The aggregate is a hash over the **content** of every covered module. Any change to any module in
the package changes it — which is the point: a package whose content drifted while keeping its
version label is caught here.

> `provenance` is POSIX + root-installed. On a non-POSIX host it reports
> `manifest_trust_non_posix` and exits 15 rather than guessing.

---

## 5. What these commands cannot do, and why

The controlled-live path is closed by **three independent stops**, each a reviewed code constant,
none reachable from configuration:

1. the plan-execution composition gate — the shipped composition is disabled, so the durable
   orchestration refuses before any filesystem access, secret contact, rendering, executor
   construction, or subprocess;
2. the controlled-live runtime seam — the shipped runtime is sealed and the reviewed
   runtime-provider set is **empty**, so no provisioning attestation can ever validate;
3. the operator-activation seal — the run hook refuses before any Temporal worker is constructed.

`queue` (§3) reports these as **four** rows rather than three: it observes the runtime seam's two
halves separately, because the shipped runtime being sealed and the reviewed provider set being
empty are independent readings and either could change without the other.

Independently, both generic subprocess seals remain closed, and the plan-only command grammar
admits only `init`, a non-destroy `plan`, and `show -json`. **Apply and destroy are not
available, and no command in this package can make them available.**

Opening the controlled-live path is a separately reviewed code-and-review change to those
constants. It is out of scope for these commands, is not something an operator performs, and is
not what a `reviewed_code_change` remediation is inviting you to do — that class is a *stop*
signal, telling you the gap is not yours to close.

### Escalate rather than proceed

- **`seals_unsafe` (exit 20)** — a reviewed safety seal has drifted from its expected value. This
  should never happen on a released build. Do not remediate; escalate.
- **`provenance_untrusted` with an aggregate disagreement** — the installed package content does
  not match the reviewed aggregate. Do not repair in place; escalate.

---

## 6. Known inconsistency (not fixed here)

The prepared operator unit's `ExecStart` and the reviewed topology constant name **two different
paths** for the operator entrypoint, and neither file is present in the repository. This is
latent only because the operator is never started. It is tracked separately; both paths sit
outside this package and are not modified by these commands.

---

## 7. Where each capability lives

The operator-facing capabilities are named one way in the delivery plan and another way in the
code. This map is here so a reviewer can find each one without re-deriving it, and so nobody
implements a second copy of something that already exists under a different name.

| Capability | Where it lives | Proven by |
| --- | --- | --- |
| Supported operator packaging | `manifest.py` (`COVERED_MODULES`, `compute_manifest`, `verify_installed_package_trust`); versions and identity in `__init__.py` | `test_deployment_wheel.py` builds the real wheel and proves wheel aggregate == source aggregate, exact inventory, and tamper detection; `test_deployment_manifest.py`, `test_deployment_root_manifest.py` |
| Install + status diagnostics — *why* not ready, as distinct from the verdict | `PREREQUISITE_LADDER` + `build_prerequisite_ladder` (§2), `REFUSAL_CATALOGUE` + remediation classes (§2). Install **actuation** is `secp_commissioning` (§1.1), deliberately not this package | `test_operator_productization.py`, `test_operator_refusal_catalogue.py` |
| Readiness validation — the verdict | `_resolve_status` + `STATUS_EXIT_CODES` (§2) | `test_operator_productization.py`, `test_deployment_verify.py` |
| Release + provenance verification | `provenance` command, `build_provenance_report` + `_release_identity_section` (§4) — the installed aggregate **and** the release identity from the independent pins | `test_operator_productization.py`, `test_operator_cli_surface.py`, `test_operator_release_provenance.py` |
| Queue configuration validation | the `queue` command, `queue_check.py` (§3); parse time `profile.py::_v_queue_separation`; report time `verify.py::_queue_section` | `test_operator_queue_isolation.py`, `test_deployment_profile.py::test_queue_equality_refused`, `test_operator_productization.py` |
| Evidence observation | `host_adapters.py` → `HostObservationEvidence`, reported by `verify.py::_host_section` and by `queue_check.py` as consumer dormancy (§3) | `test_deployment_adapters.py` — generation/ABA refusal, fail-closed on malformed or ambiguous readings, no mutation subcommand, exact argv; `test_operator_queue_isolation.py` |
| Refusal paths | `REFUSAL_CATALOGUE` + every rung's bounded `reason_code` (§2); the queue ladder + submission stops (§3) | `test_operator_refusal_catalogue.py`, `test_operator_queue_isolation.py` |
| Dry run | `queue`'s `submission_preview` (§3) — what *would* refuse a controlled-live start, derived by reading the reviewed stop constants | `test_operator_queue_isolation.py` — the stops are checked against the constants themselves, and the no-submission claim against a `sys.modules` delta + tripwires |
| Read-only guarantee | **No flag.** All three commands are observations; the `effects_of_this_*` sections declare it and the tests observe it | `test_operator_cli_surface.py` — output byte-identical across runs, installed package byte-identical afterwards; `test_operator_queue_isolation.py`; `test_deployment_boundary.py` |

### Why there is no `--dry-run` flag

No command has a mutating counterpart, so a `--dry-run` **flag** would have nothing to stand in
for — and it would advertise that a non-dry-run mode exists somewhere. On a package whose whole
value is that it cannot activate, that is exactly the flag an operator would go looking for.

What an operator actually wants from a dry run is delivered as a command instead: `queue`'s
`submission_preview` (§3) answers *"if a controlled-live workflow were submitted right now, what
would stop it?"* by reading the stop constants rather than by attempting anything.

The read-only guarantee itself is delivered by making the no-effect claim checkable rather than
declarable. `effects_of_this_*` is a claim; the observations are: reports byte-identical across
runs, the installed package unchanged afterwards, no import of and no call to `temporalio` anywhere
in the package — an AST import scan over every module at any depth, plus an import- and call-shape
scan of the queue check itself — and tripwires on the operator run hook, the composition builder
and the real command runner. A command that submitted, started a consumer or wrote anything fails
those regardless of what its `effects_of_this_*` section says.

Those two `temporalio` scans are STATIC deliberately, and this sentence used to say something
weaker and untrue: that a real `main()` run was observed not to import the module. It never could
be. `temporalio` is an optional extra (`worker`) and every CI job installs `.[dev]` only, so a
runtime check of the imported-module set has nothing to observe and cannot fail. The static scans
hold in any environment, including one that does install the extra, and for any import shape — they
are what the guarantee rests on. The exit code adds a runtime observation of one shape only: a bare
import *deferred into a function on the queue path* raises where the extra is absent, the CLI's
bounded guard turns that into exit 20, and the test asserting a clean exit fails.

Three import shapes, three reporters, and none of them is silent — which is the point, so read the
list as a division of labour rather than as two covered cases and a gap:

| shape | what reports it |
|---|---|
| bare, at module level | collection error — the test file imports `queue_check` at module scope, so pytest exits 2 and the whole run fails before any test executes |
| bare, deferred into a function on the queue path | the exit-code assertion, via the CLI's bounded guard (exit 20) |
| guarded `try: import temporalio / except Exception: pass` | the two static scans; it raises nothing, so the exit-code assertion passes |

The guarded form is how an optional dependency is normally written, so it is the likeliest shape
rather than a contrived one. The static scans remain the load-bearing half — they are the only
reporter blind to none of the three, where the other two each cover exactly one.
