# Why SECP-002B-1A must not touch real infrastructure

**Audience:** developers and reviewers working on the provisioning path.

SECP-002B-1A builds the *entire real OpenTofu execution architecture* — toolchain
provenance, the sealed process executor, provider-neutral workspace rendering, dry-run
change-set approval, and the isolated-lab activation gate — **without provisioning
anything**. This is deliberate. Read this before touching the runner, executor, adapter,
or activation code.

## The rule

In B1-A, no code path — in source, tests, CI, or Docker verification — may:

- connect to a Proxmox (or any) endpoint;
- run `tofu`/`opentofu`/`terraform` (`init`/`plan`/`apply`/`destroy`/`show`/`validate`/
  `version`);
- install/download OpenTofu, Terraform, providers, modules, packages, binaries, or images;
- create/modify/reset/destroy any VM, container, bridge, VLAN, storage, firewall, DNS, or
  network;
- add a real hostname, IP, cluster/node/storage/bridge/VLAN name, provider URL, provider
  credential, or provider checksum to source, tests, docs, fixtures, or commits.

Every test uses in-process fakes and a **fake process executor**. Fixture values are
clearly fake and non-routable (`*.example.test`, `example.test/fake/*`, repeated-byte
`sha256:` placeholders, `9.9.9`).

## Why

1. **Blast-radius before capability.** The architecture that *could* create real
   infrastructure must be fully reviewed, tested, and proven safe *before* it is ever
   pointed at hardware. Building the seal first means the first real run (B1-B) is a
   configuration + human-review exercise, not new, unreviewed code.
2. **Charter invariants 6 & 7.** The API must never perform privileged infrastructure
   actions; those happen only in isolated workers. Wiring a real endpoint in this slice
   would blur that boundary while it is still being established.
3. **Irreversibility.** A real `apply`/`destroy` mutates or deletes infrastructure. Until
   the disposable lab, the approval model, and the destroy path are all proven with fakes,
   a real run risks damaging a real environment.
4. **Secret safety.** The just-in-time secret-resolution seam, redaction, and secret-free
   rendering must be demonstrably airtight before any real credential is ever resolved.

## How the seal is enforced

- `SubprocessProcessExecutor` is **disarmed by default**, refused in production, and is
  **never constructed or invoked** in B1-A. `build_process_executor` returns the
  `FakeProcessExecutor`.
- `SECP_ENABLE_REAL_PROVISIONING` and `SECP_PROVISIONING_APPLICATION_MODE=isolated_lab`
  are both off by default; the activation gate additionally requires Temporal, full hash
  agreement, an `isolated_lab` toolchain profile, a remote state backend, `deny` external
  connectivity, and an explicit human-approved change set.
- Architecture-boundary tests prove `apps/api` cannot import the runner/executor/adapter/
  rendering/OpenTofu/`subprocess`/secret-resolver.
- `tests/test_no_real_endpoints.py` fails the build on any public IP or non-placeholder
  provider host in authored files.
- `apps/api/tests/test_no_real_process.py` proves no real binary/network/provider is used
  and the subprocess executor is disarmed.

## What flips the switch (B1-B, not now)

Arming the real path is a separate, human-reviewed milestone (SECP-002B-1B) against a
dedicated disposable lab. Its prerequisites are enumerated in the
[B1-B lab prerequisite checklist](../proxmox/b1b-lab-prerequisite-checklist.md). Do **not**
arm `SECP_ENABLE_OPENTOFU_SUBPROCESS`, register a real target, or add real lab values as
part of B1-A.
