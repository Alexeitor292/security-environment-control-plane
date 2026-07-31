# Runbook — Production worker installation (SECP Stream B)

How an operator installs, enrolls, observes, upgrades, rolls back and recovers a production SECP
worker.

Every command is **dry-run by default**. A command that changes the host requires both `--write` and
`--confirm`, and refuses without root. Nothing in this runbook contacts a provider, runs
OpenTofu/Terraform, or activates live infrastructure.

---

## 1. What a worker is, and what it is not

A worker is an **outbound-only** node. It serves no browser-reachable API, terminates no TLS for
callers, and holds no controller trust root. It:

- polls the **ordinary** Temporal task queue (`secp-orchestration`) and nothing else;
- ships the operator unit **present, disabled and stopped** — installed so an upgrade path exists,
  never started;
- carries its **own** installation identity and its **own** enrollment key, separate from the
  controller's.

The controlled-live operator queue is a **separate queue served by a separately reviewed operator
worker**. A shipped worker that is observed polling it is refused
(`worker_ordinary_polls_operator_queue`) — on a fresh install and on every upgrade.

---

## 2. Prerequisites

| Requirement | Why |
|---|---|
| Linux, x86_64, root | Host effects are root-gated (`root_required_for_write`) |
| Docker + Compose present | The ordinary worker runs as a container |
| A **signed worker release bundle** | Role, artifacts and images are all signature-bound |
| A **worker-role** bundle specifically | A controller bundle refuses `release_role_mismatch` |

The release trust anchor must already be established. An unsigned, tampered, or wrong-anchor bundle
is refused before any host effect.

---

## 3. Install

Plan first. This writes nothing and touches no host object:

```
secpctl bootstrap worker --bundle /path/to/release
```

Read the report before proceeding:

- `classification` — `fresh` for a first install (see §6 for `managed_upgrade`)
- `plan` — the exact ordered operations
- `operator_enabled: false` — confirm this every time
- `code_seals.safe: true`

Then install:

```
secpctl bootstrap worker --bundle /path/to/release --write --confirm
```

The engine loads the signed images, installs the ordinary config, installs the deployment package,
installs the operator unit **disabled**, reloads the daemon, and starts **only** the ordinary
worker. It then **reobserves the complete end state** and commits evidence only if the observation
matches what the signed release says it should be.

A successful report shows `mode: written` and `reobserved_healthy: true`.

**If it refuses:** nothing is left half-installed. The engine compensates the documents and the host
effects it made. See §8 for the reason codes.

---

## 4. Enroll the worker with its controller

Installation and enrollment are separate steps. Enrollment is driven from the **non-secret
invitation file** the controller operator gives you.

On the controller:

```
secpctl enrollment invitation create --site <site-label> --write --confirm
```

The invitation is displayed **once**. This is deliberate and is not a defect: the invitation is
bearer-grade — whoever presents a valid key first wins the binding — so there is no re-fetch
endpoint. If you lose it, **revoke and create a new one**; that is the supported remedy, and unlike a
silent re-fetch it is audited and visible.

Copy the invitation file to the worker, then on the worker:

```
secpctl worker enroll --invitation /path/to/invitation.json            # plan
secpctl worker enroll --invitation /path/to/invitation.json --write --confirm
```

The worker generates and protects its **own** enrollment key locally — the private half never leaves
the worker and never appears in a log, a report, or the invitation. It proves possession to the
controller, receives the internally-signed controller offer, verifies it against the
invitation-pinned controller key, and drives to `healthy`.

The worker path never uses an operator token and never talks to the controller admin API. There is
deliberately **no** `--url`, `--ca` or `--token` argument on any `secpctl worker` command; everything
it needs is inside the signed invitation.

Check progress at any time (read-only, local):

```
secpctl worker enrollment status --invitation /path/to/invitation.json
```

Retry a stalled enrollment:

```
secpctl worker enrollment retry --invitation /path/to/invitation.json --write --confirm
```

### Enrollment states you may see

| State | Meaning | Action |
|---|---|---|
| `invited` | Invitation created, worker has not bound | Run `worker enroll` on the worker |
| `worker_bound` … `verified` | Exchange in progress | Wait, then re-check status |
| `healthy` | Done | None |
| `refused` | Revoked, or a terminal refusal | Create a new invitation |
| `recovery_required` | Needs an operator decision | See §7 |

From the controller you can list the whole inventory, including revoked and terminal enrollments:

```
GET /api/v1/enrollment?state=invited&state=recovery_required&limit=50
```

---

## 5. Observe status

```
secpctl status worker
```

`ok: true` means the **complete** canonical end state was re-derived from the
**signature-verified** installed-release record and confirmed against a **fresh** observation of the
host. Stored flags and "the install said it worked" never satisfy status on their own.

Confirm on every check:

- `dimensions.ordinary_queue` is the ordinary queue
- `dimensions.operator_queue` is a **different** queue
- the operator unit is present, disabled and stopped

Any drift — config, unit, package, health command, or either image — refuses with a specific reason
rather than reporting a degraded `ok`.

---

## 6. Managed upgrade

An upgrade is **not** "install whatever bundle you were handed over whatever is already there". The
worker accepts a changed release only when it is an **authenticated linear successor** of what is
actually installed (the new release's `parent_sha` equals the installed release's `source_sha`, both
signed), and the prior install is still fully authenticated and undrifted.

This is the property that matters: a validly-signed but **unrelated** release cannot be installed
over a running worker, because it does not descend from what is there. Sideways moves and downgrades
are refused for the same reason.

```
secpctl bootstrap worker --bundle /path/to/release-B                     # plan
```

Confirm `classification: managed_upgrade` before you proceed. If you see
`worker_upgrade_not_linear_successor`, the bundle is not a successor of what is installed — stop and
find out why rather than working around it.

```
secpctl bootstrap worker --bundle /path/to/release-B --write --confirm
```

The upgrade re-runs the reviewed worker operations for the new release, rebinds the identity and
installed-release record, and proves the new end state by reobservation. The operator unit stays
disabled and stopped across the upgrade, and the ordinary worker must still not be on the operator
queue — both are re-checked, not assumed.

**If the upgrade fails:** the prior documents are **restored** (the writer captured them before
overwriting) and the failure is reported with the reason it actually failed. Nothing on disk claims
the new release is installed.

---

## 7. Rollback and recovery

### Rollback

```
secpctl rollback worker                       # lists exactly what would be removed
secpctl rollback worker --write --confirm
```

Rollback removes exactly the documents the install created, after independently authenticating each
one against digests derived from the **signature-verified** release record — never from the
(re-authorable) evidence. A drifted or substituted document refuses **before** anything is removed.

A no-op or sealed rollback adapter can never report `written`.

### `recovery_required`

`recovery_required` means the engine could not **prove** it left the host in a clean state — for
example a compensation it could not verify. It is deliberately not reported as an ordinary refusal,
because an ordinary refusal implies "nothing happened", and here that cannot be claimed honestly.

**Do not retry the command.** Inspect the host, establish the actual state, and remediate
deliberately.

Enrollments also reach `recovery_required`:

- **automatically**, when they expire — a scheduled sweep runs on the **ordinary** Temporal queue
  (every 15 minutes) and drives due, active enrollments to `recovery_required`. It reports aggregate
  counts only and never logs an enrollment or organization id.
- **on demand**, when an operator decides an enrollment is stuck and does not want to wait for the
  TTL:

```
POST /api/v1/enrollment/{enrollment_id}/recover   {"expected_revision": <last observed>}
```

This requires `enrollment:manage`. It is idempotent on an already-terminal enrollment, and a stale
`expected_revision` refuses a conflict rather than clobbering a concurrent change.

The supported remedy for a `recovery_required` enrollment is to **create a new invitation** and
re-enroll. The recovery-required record is kept, not deleted, so the history stays auditable.

---

## 8. Refusal reference

Every refusal is a bounded code. No refusal ever echoes a host path, an endpoint, a token, or key
material.

### Installation

| Code | Meaning |
|---|---|
| `release_role_mismatch` | A controller bundle was pointed at a worker (or vice versa) |
| `release_artifact_digest_mismatch` | A bundle artifact does not match its signed digest |
| `write_requires_confirm` / `confirm_requires_write` | Both flags are required together |
| `root_required_for_write` | A host-changing command was run as non-root |
| `seals_unsafe` | The code seals are not in their safe posture — stop |
| `worker_bootstrap_adapter_not_provisioned` | The production adapter is sealed |
| `preexisting_partial_install` | Some install documents present, some absent |
| `preexisting_foreign_record` | Documents present that this tool did not write |

### End state (the install/upgrade refused and compensated)

| Code | Meaning |
|---|---|
| `worker_ordinary_not_ready` | The ordinary worker did not come up healthy |
| `worker_ordinary_image_mismatch` | The running image is not the signed ordinary image |
| `worker_operator_image_mismatch` | The operator unit is not on the signed operator image |
| `worker_operator_not_disabled_stopped` | **The operator was enabled or running — investigate** |
| `worker_ordinary_polls_operator_queue` | **The worker was on the operator queue — investigate** |
| `worker_operator_package_untrusted` | The deployment package is not trusted |
| `worker_ordinary_config_mismatch` | Installed config is not the reviewed config |
| `worker_operator_unit_mismatch` | Installed unit is not the reviewed unit |
| `worker_deployment_package_mismatch` | Installed package is not the signed package |
| `worker_reobservation_incoherent` | The host changed under the transaction |

The last two in bold are the operator-isolation boundary. Treat either as a security event, not a
flaky install.

### Upgrade

| Code | Meaning |
|---|---|
| `worker_upgrade_not_linear_successor` | The bundle does not descend from the installed release |
| `worker_upgrade_prior_unauthenticated` | The existing install could not be re-authenticated |
| `worker_upgrade_prior_drifted` | Existing install documents have drifted |

### Enrollment

| Code | Meaning |
|---|---|
| `enrollment_invitation_expired` | The TTL elapsed — create a new invitation |
| `enrollment_invitation_revoked` | Revoked — create a new invitation |
| `enrollment_invitation_consumed` | Single-use, already bound |
| `enrollment_already_bound` | A different worker bound first — **investigate** |
| `enrollment_pop_invalid` | The worker's signed evidence failed verification |
| `enrollment_signer_unavailable` | The controller's root-gated offer signer is unavailable |
| `enrollment_revision_conflict` | Concurrent change — re-read status and retry |
| `enrollment_forbidden` | Cross-organization access |

---

## 9. Safety properties this path holds

- Dry-run by default; host changes need `--write --confirm` and root.
- Every artifact is signature-bound; the end state is re-derived from the signed release, never from
  evidence.
- The operator unit is installed disabled and stopped, and never started.
- The ordinary and operator task queues are distinct and re-checked on every install, upgrade and
  status.
- The worker's enrollment private key never leaves the worker.
- The invitation is one-shot; revoke-and-recreate is the supported remedy.
- A failure compensates; an unprovable compensation reports `recovery_required` rather than a false
  success.
- No provider contact, no OpenTofu/Terraform, no apply or destroy, at any point.
