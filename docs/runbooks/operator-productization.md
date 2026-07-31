# Runbook — controlled-live operator productization (read-only)

This runbook covers the two **read-only** commands the controlled-live operator deployment
package exposes, how to read their output, and — equally important — what they deliberately
cannot do.

**Nothing in this runbook starts an operator worker, submits a workflow, runs OpenTofu, resolves
a credential, or contacts Proxmox, OpenBao, Temporal, remote state, or PostgreSQL.** Every
command below is an observation.

Companion documents: [ADR-024](../adr/ADR-024-operator-deployment-package.md) (the package
contract) and [pr5d-operator-deployment.md](pr5d-operator-deployment.md) (how the package is
prepared and installed).

---

## 1. The two commands

```
python -m secp_operator_deployment verify --json
python -m secp_operator_deployment provenance --json
```

Neither takes a path argument. `verify` resolves the fixed root-controlled deployment profile and
the **separate** independent expected-identities file; `provenance` inspects the installed
module's own directory, resolved in code. This is deliberate: an operator-supplied path would let
a report describe a tree that is not the one that would actually run.

There is no `install`, no `start`, and no command that opens the controlled-live path. That is
not an oversight — see §5.

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

## 3. Queue separation

The `queue_separation` section reports booleans only — never the queue names, which are profile
values:

```json
"queue_separation": {
  "ok": true, "ordinary_configured": true,
  "operator_configured": true, "distinct": true, "reason_code": null
}
```

The two queues must be distinct. A shared queue would let the shipped sealed worker pick up
controlled-live work, so the profile validator refuses it at parse time
(`profile.py::_v_queue_separation`) and this section is the defence-in-depth report of the same
fact.

Note which fact this section does **not** carry. Queue *isolation* — both queues configured, and
distinct — is dimension **B**, above. Whether the operator **unit** is installed but disabled and
not running is dimension **C**, reported in `host_observation` and gated by the
`operator_prepared_and_disabled` rung. They are separate facts about separate things and are
deliberately never merged into one "the operator side is safe" boolean.

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
  "agreement": {"source_equals_installed": true}
}
```

| Status | Exit | Meaning |
| --- | --- | --- |
| `provenance_ok` | 0 | The installed package recomputed to its reviewed aggregate. |
| `provenance_untrusted` | 15 | The dir-fd walk refused, or the aggregates disagree. |
| `provenance_unavailable` | 20 | The aggregate could not be computed at all. |

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
| Install + status diagnostics — *why* not ready, as distinct from the verdict | `PREREQUISITE_LADDER` + `build_prerequisite_ladder` (§2), `REFUSAL_CATALOGUE` + remediation classes (§2) | `test_operator_productization.py`, `test_operator_refusal_catalogue.py` |
| Readiness validation — the verdict | `_resolve_status` + `STATUS_EXIT_CODES` (§2) | `test_operator_productization.py`, `test_deployment_verify.py` |
| Release + provenance verification | `provenance` command, `build_provenance_report` (§4) | `test_operator_productization.py`, `test_operator_cli_surface.py` |
| Queue configuration validation | parse time `profile.py::_v_queue_separation`; report time `verify.py::_queue_section` (§3) | `test_deployment_profile.py::test_queue_equality_refused`, `test_operator_productization.py` |
| Evidence observation | `host_adapters.py` → `HostObservationEvidence`, reported by `verify.py::_host_section` | `test_deployment_adapters.py` — generation/ABA refusal, fail-closed on malformed or ambiguous readings, no mutation subcommand, exact argv |
| Refusal paths | `REFUSAL_CATALOGUE` + every rung's bounded `reason_code` (§2) | `test_operator_refusal_catalogue.py` |
| Read-only guarantee (the "dry-run" half) | **No flag.** Both commands are observations; the `effects_of_this_*` sections declare it | `test_operator_cli_surface.py` — output byte-identical across runs, and the installed package byte-identical after both commands; `test_deployment_boundary.py` |

### Why there is no `--dry-run`

Neither command has a mutating counterpart, so a `--dry-run` flag would have nothing to stand in
for — and it would advertise that a non-dry-run mode exists somewhere. On a package whose whole
value is that it cannot activate, that is exactly the flag an operator would go looking for. The
guarantee is delivered instead by making the no-effect claim checkable: the report is byte-identical
across runs and the installed package is unchanged after both commands run, so a command that wrote
anything fails regardless of what its `effects_of_this_*` section claims.
