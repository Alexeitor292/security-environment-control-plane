# Follow-up: migrate the host-systemd / host-Docker fences to a project-controlled runner

**Status:** open infrastructure item. **Does not block B2A.**

## Why

The trusted-ancestor rule requires every ancestor of a write target to be a real, root-owned,
non-group/other-writable directory. Two fences write to `/etc/systemd/system/...`, so they depend on
the GitHub-hosted machine's `/etc` posture — which is mutable and outside this repository's control.

It was observed invalid twice, with bounded evidence captured by
`infra/ci/attest_trusted_ancestry.py`:

| path | uid | gid | mode | inode |
|---|---|---|---|---|
| `/` | 0 | 0 | `0o755` | 2 |
| `/etc` | **1001** | **1001** | `0o755` | 42 |
| `/etc/systemd` | 0 | 0 | `0o755` | 369 |
| `/etc/systemd/system` | 0 | 0 | `0o755` | 370 |

`/etc` alone was owned by the runner user while its children were `root:root` — a targeted,
non-recursive chown of exactly `/etc` by something running as uid 1001. No step in this repository's
workflow chowns `/etc` (every `chown` targets `/root/...`, `/usr/local/bin/docker-compose`, or a
created child with explicit `0,0`), no source or test file may chown/chmod a fixed system parent
(asserted structurally in `tests/test_trusted_ancestry_isolation.py`), and it reproduced on a **pinned**
`ubuntu-24.04`. The cause is therefore the runner image or a third-party action
(`actions/checkout@v4`, `astral-sh/setup-uv@v3`).

## What is already done

* the posture is **attested before any product test runs**, at every root fence and before both
  inline preparation steps;
* an invalid machine exits **78 `infrastructure_invalid`** with bounded evidence — never a product
  failure, never a silent pass, never a repair;
* classification is **total**: only `ENOENT` proves absence, and every other `OSError` is
  `not_statable` and therefore `infrastructure_invalid`;
* the six root fences are pinned to `ubuntu-24.04`, so a future occurrence is attributable to a
  specific image rather than to "some runner".

## What remains

Migrate the two host-dependent fences —

* `backend-management-real-adapters-root` (host Docker + host systemd)
* `backend-management-controller-real-adapters-root` (host Docker + real migration)

— to a **project-controlled runner or VM** whose ancestry is **constructed and attested by the job**,
eliminating dependence on the mutable GitHub-hosted posture. Both need a real systemd instance and a
real container runtime, so this is genuine infrastructure work (self-hosted runner image, or a
privileged VM provisioned per run), not a workflow tweak. It was deliberately **not** attempted
half-way inside the B2A reliability commits.

## Re-dispatch rule until then

A classified infrastructure-invalid attempt may be re-dispatched **once**, and only after confirming
all three:

1. the attestation step exited **78**;
2. the bounded evidence identifies the invalid posture (which ancestor, and its observed
   uid/gid/mode/kind);
3. the product-test step **did not run** (no JUnit artifact produced).

There is no automatic retry-until-green behaviour, and code must never be changed to satisfy an
invalid machine.
