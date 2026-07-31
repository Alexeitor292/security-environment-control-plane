# Follow-up: migrate the root-security fences to a project-controlled environment

**Status:** tier 1 **done** (SECP-WSA). Tier 2 **held** pending an operator decision.

## Why

The trusted-ancestor rule requires every ancestor of a write target to be a real, root-owned,
non-group/other-writable directory. The root fences therefore depend on the machine's `/etc` and
`/` posture — which, on a GitHub-hosted runner, is mutable and outside this repository's control.

It was observed invalid with bounded evidence captured by `infra/ci/attest_trusted_ancestry.py`:

| path | uid | gid | mode | inode | dev | mount |
|---|---|---|---|---|---|---|
| `/` | 0 | 0 | `0o755` | 2 | 2049 | `/` |
| `/etc` | **1001** | **1001** | `0o755` | 42 | 2049 | `/` |

`/etc` alone was owned by the runner user while its children were `root:root`, on the same device
and mount as `/` — a targeted, non-recursive chown of exactly `/etc` by something running as
uid 1001, not a mount or overlay artefact. No step in this repository's workflow chowns `/etc`
(every `chown` targets `/root/...`, `/usr/local/bin/docker-compose`, or a created child with
explicit `0,0`), and no source or test file may chown/chmod a fixed system parent (asserted
structurally in `tests/test_trusted_ancestry_isolation.py`).

### Correction: image pinning cannot fix this

An earlier revision of this document claimed the six root fences being pinned to `ubuntu-24.04`
made a future occurrence "attributable to a specific image rather than to 'some runner'". **That
claim is false and is withdrawn.** Run `30522895412` (main, `e72f28f`) disproves it directly:

* job `90807107915` observed `/etc` uid=1001 gid=1001 and exited **78**, product tests correctly
  never started;
* jobs `90807108008` and `90807107993` — **the same run, the same commit, the same
  `ImageVersion 20260726.254.1`** — observed `/etc` uid=0.

Each job gets its own VM, so this is **per-VM variance within one image version**. Pinning
`runs-on` removes nothing, and a green root fence on a hosted VM is a coin flip rather than
evidence. The cause of the chown remains unidentified (runner image provisioning, or a third-party
action such as `actions/checkout@v4` / `astral-sh/setup-uv@v3`) — and the tier-1 fix below does not
depend on identifying it.

## What is already done

* the posture is **attested before any product test runs**, at every root fence and before both
  PR5F inline preparation steps;
* an invalid machine exits **78 `infrastructure_invalid`** with bounded evidence — never a product
  failure, never a silent pass, never a repair;
* classification is **total**: only `ENOENT` proves absence, and every other `OSError` is
  `not_statable` and therefore `infrastructure_invalid`;
* **tier 1 (SECP-WSA):** the four filesystem-only root fences —
  `backend-realfs-root`, `backend-discovery-activation-root`, `backend-deployment-root`,
  `backend-management-root` — now execute inside a **digest-pinned container** declared by
  `jobs.<job>.container`, whose `/etc` comes from a content-addressed image layer and is root-owned
  by construction. The pin is recorded once in `infra/ci/controlled-root-env.json` and every copy in
  the workflow is machine-checked against it;
* `backend-realfs-root` — previously the one root-elevated fence with **no** attestation gate — now
  attests `/`, its complete ancestry, and is covered by `REQUIRED_GATED_JOBS`;
* each controlled fence records the environment's pristine posture (`stat -c '%u %g %n' / /etc`)
  as its **first** step, before any third-party action runs inside the container;
* the environment is proven to be the pinned image **and nothing else**: no `container.volumes` and
  no host-importing `container.options` (`--privileged`, `-v`, `--volume`, `--mount`, `--userns`).
  A digest pin fixes what the layer contains but says nothing about what is mounted over it, so a
  single `volumes: ["/etc:/etc"]` would have put the hosted VM's `/etc` back inside the namespace
  the gate attests while every other proof stayed green;
* the set of root fences is **derived from the workflow**, not hand-maintained, so a new
  `backend-<x>-root` job cannot appear without being either controlled or explicitly held;
* the manifest's package list is checked against the packages each prelude actually installs, and
  the manifest's `base`/`digest` fields against its own `image`, so it cannot describe an
  environment that is not the one being built.

Every property above has a mutation regression that was **observed failing before the check
existed** — the nine listed in "Proof discipline" below.

### What the first real run of this environment taught us

Run `30609943702` is the first execution of the controlled fences. Three of the four passed
outright. `backend-deployment-root` **failed, correctly**, and the failure was worth more than a
green would have been.

Its attestation gate passed, so the environment's ancestry was trusted; the failure was in the
product tests, exactly the classification this work exists to make possible.
`test_timeout_proves_full_group_disappearance_no_orphan` refused with reason code
`command_group_not_terminated`. A GitHub `container:` job's PID 1 does not reap, so after the
deployment runner's bounded `SIGTERM → grace → SIGKILL` sequence the killed grandchild remained a
**zombie**: `killpg(pgid, 0)` kept succeeding instead of returning `ESRCH`, and the runner could
not prove the process group had disappeared. It refused rather than reporting a termination it had
not proven.

That is the fence working. The defect was in the environment definition, which lacked an orphan
reaper — a property every real machine has. All four fences now declare `options: --init`,
recorded in the manifest and machine-checked against every copy. It grants no capability, mounts no
host path, and leaves the runner's proof obligation and the attested ancestry untouched.

The general lesson, which is the same one this document keeps arriving at: the container is only
*trusted*, not *complete*. Differences from a real machine surface as fences refusing, and a
refusal is the correct outcome — the response is to fix the environment, never to relax the fence.

## Proof discipline

The properties in this document are only worth what their proofs are worth, so each one was broken
first and the proof watched to see whether it noticed. Nine did not, and all nine now do:

| break | was |
|---|---|
| a 7th `-root` job with no gate and no `container:` | undetected |
| host `/etc` bind-mounted via `container.volumes` | undetected |
| `--privileged` / `-v /:/host` via `container.options` | undetected |
| a step inserted above the pristine-posture canary | undetected |
| a canary that observes neither `/` nor `/etc` | undetected |
| the manifest's `digest` contradicting its own `image` | undetected |
| a fence chowning `/etc` in its own prelude | undetected |
| the prerequisite prelude deleted | undetected |
| a namespace escape spelled with tabs, or via `unshare` | undetected |

Moving the gate is sound because it is **namespace-relative by construction**: it observes the
filesystem only through `os.lstat` on plain absolute paths, `ancestors_of` is pure string
splitting, and its single `/proc` read is `/proc/self/mountinfo` (evidence only — it feeds no
verdict). Executed inside the container, it attests that container's ancestry. The script itself is
**byte-for-byte unchanged**, the rule is not relaxed, and an invalid controlled environment still
exits 78 before any product test runs.

## What remains — tier 2, HELD

Two fences still execute directly on the nondeterministic hosted VM:

* `backend-management-real-adapters-root` (real Docker + real systemd)
* `backend-management-controller-real-adapters-root` (real Docker + real migration)

Both install and observe **real systemd units** (`systemctl daemon-reload` / `is-enabled` /
`is-active`) and drive a real container runtime. A GitHub `container:` job has no init system and no
daemon, so it cannot host them. Moving them requires a job-constructed **privileged** environment
(systemd as PID 1 plus a private daemon) or a nested VM — a CI posture decision that belongs to the
operator, and which has been escalated rather than assumed.

A **self-hosted runner is not the answer here**: it requires a real registration credential, and
this repository is public with forking enabled, so a fork PR would obtain code execution on a
machine that has root, Docker and systemd by design.

Two prerequisites are unverified and must be settled before tier 2 is attempted: whether systemd
runs reliably as PID 1 in a privileged container on a cgroup-v2 hosted runner, and whether
`/dev/kvm` is usable there (which decides whether the nested-VM fallback exists at all).

The stale "attributable to a specific image" comment that used to sit on those two jobs has been
**corrected in place** rather than deferred to the tier-2 move: it was false the moment run
`30522895412` was read, and leaving a known-false claim in the workflow because correcting it would
widen a diff is the failure mode this whole document is about. Both jobs now state plainly that
they are tier-2 holdouts whose green is a coin flip. Comment-only; neither job's behaviour changed.

## Re-dispatch rule for the two remaining uncontrolled fences

Applies **only** to `backend-management-real-adapters-root` and
`backend-management-controller-real-adapters-root`. A classified infrastructure-invalid attempt may
be re-dispatched **once**, and only after confirming all three:

1. the attestation step exited **78**;
2. the bounded evidence identifies the invalid posture (which ancestor, and its observed
   uid/gid/mode/kind);
3. the product-test step **did not run** (no JUnit artifact produced).

There is no automatic retry-until-green behaviour, and code must never be changed to satisfy an
invalid machine.

**This rule does not extend to the four controlled fences.** Their environment is constructed from a
pinned digest, so an `infrastructure_invalid` verdict there is a genuine defect in the environment
definition — it must be diagnosed and fixed, never re-dispatched.
