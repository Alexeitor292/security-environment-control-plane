# SECP-B6 — Worker-Mounted Read-Only Discovery Bundle

This document describes the **one** operator action required to enable the already-reviewed SECP-B5
read-only discovery worker to perform its first real, strictly **read-only** SSH discovery run against
an operator's Proxmox host, and the safety properties of the mount.

Discovery **cannot** create, modify, delete, restart, reload, install, upload, download, configure, or
otherwise alter host or Proxmox state — it runs only the closed read-only probe set (see below). The
discovery-derived candidate plan remains **non-executable**; it is the exact input for a later,
separately reviewed controlled deployment-enablement phase.

## The single operator action + its prerequisites

Mount **one** worker-local bootstrap bundle directory into the **worker** container at the fixed path
`SECP_DISCOVERY_BOOTSTRAP_MOUNT` (default `/var/run/secp/discovery-bundle`), **read-only**, and set the
deployment-local profile flag `SECP_DISCOVERY_CONTROLLED_INTEGRATION_ENABLED=true` on the **worker**
container.

The bundle is only *usable* once the control plane already holds, for the exact target, the durable
control-plane records that authorize a live read (created + approved through the normal API):

1. an **approved worker-identity registration** for the organization (exactly one), and
2. an **approved live-read authorization** for the exact execution target + onboarding.

The bundle carries the non-secret IDs of (1)/(2) in its `binding.json` (below); the worker re-verifies
them against the claimed job **before any SSH**. No manual Proxmox bridge, VM, firewall, token, user,
storage, or network setup is needed — discovery is read-only and creates nothing.

- If the flag is unset/false, or the mount is absent/invalid, discovery stays **sealed** (zero host
  contact, no plan).
- The flag and mount path are **deployment-local only** — set in the worker's deploy manifest. They
  are never controlled by the API, UI, or database, and they carry **no** SSH/credential material.

## Bundle mount contract (no live values are shown here)

The mount is a **read-only** directory containing exactly four files:

| File | Purpose | Required mode (POSIX) |
|------|---------|-----------------------|
| `manifest.json` | JSON with exactly `{ssh_host, ssh_port, account, host_key_fingerprint}` — safe tokens, bounded int port, `SHA256:` fingerprint. `account` must be a **scoped, minimally-privileged, read-only** service account — `root` and other privileged accounts are **refused** | owner-only writable (not group/other-writable) |
| `id_key` | the OpenSSH **private key** file (referenced by path; never read into the app, never logged). The server-side key **MUST** be constrained to the minimum read-only access needed for the B6 probes (e.g. a forced-command / restricted PVE role) — client-side command restrictions are **not** a substitute for server-side least privilege | owner-only, no group/other access (`0600`/`0400`) |
| `known_hosts` | the pinned `known_hosts` file used to verify the host-key fingerprint | owner-only writable |
| `binding.json` | JSON with exactly `{organization_id, execution_target_id, onboarding_id, enrollment_id, authorization_id, authorization_version}` — the **non-secret** authorization anchor (no host/account/key/endpoint). Binds this bundle to the exact job it may process | owner-only writable |

The mount directory and every file must be:

- owned by the worker's runtime UID;
- a **regular file** / real directory — **no symlinks, no hardlinks** (`st_nlink == 1`), on the mount's
  own device;
- within the fixed mount (no path traversal — file names are fixed constants);
- **bounded** in size (oversized files fail closed);
- well-formed (a malformed JSON file fails closed).

Under the controlled-live profile the worker validates every file **by descriptor** (`openat` /
`fstat`, `O_NOFOLLOW`), **requires a read-only filesystem**, and copies the validated `id_key` /
`known_hosts` bytes into a fresh worker-private directory so the host-key verifier and ssh consume the
exact validated inode — immune to a post-validation mount swap (TOCTOU). Any failed check refuses with a
**closed reason code** that never echoes a raw bundle value, and the source falls back to sealed. See
`secp_worker/mounted_bundle.py`.

## Bundle-to-job authorization binding (before any SSH)

Before probing, `secp_worker/target_discovery/binding.py` proves the mounted bundle is authorized for
the **exact** claimed job, or refuses fail-closed with no snapshot/plan:

- `binding.json`'s `organization_id` / `execution_target_id` / `onboarding_id` / `enrollment_id` must
  equal the claimed enrollment's — a bundle mounted for target/org A can never process a job for B
  (`bundle_organization_mismatch` / `bundle_target_mismatch` / `bundle_onboarding_mismatch` /
  `bundle_enrollment_mismatch`);
- the referenced **live-read authorization** is independently re-verified (reusing the SECP-002B-1B-6
  verifier): approved, unexpired, version-valid, connection-hash and boundary-hash matching, target and
  onboarding active (`live_read_authorization_*`).

## Mandatory worker identity (before any SSH)

Live discovery requires **exactly one approved worker-identity registration** for the organization,
checked **before** host contact and **re-checked after probing** (a revocation or version bump
mid-discovery fails closed and mints no plan). A candidate plan that binds worker-identity version `0`
is **never approvable**.

## Host-key binding (before any SSH)

Before SSH is invoked, `secp_worker/known_hosts.py` proves, by parsing the mounted `known_hosts`:

- an entry matches the bundle's **exact** target host + port (plaintext or hashed `|1|` HMAC-SHA1);
- that entry's **SHA-256 host-key fingerprint equals** the manifest's expected fingerprint;
- no wildcard, negated, `@cert-authority`, `@revoked`-for-our-key, unbound, malformed, or
  duplicate-conflicting entry can satisfy the pin.

If the binding cannot be proven, discovery refuses **before** any ssh call.

## Isolation and secrecy requirements (deployment)

- The bundle mount MUST be mounted **only** into the worker container — **not** the API or UI
  containers — and **read-only**. The API/UI have no read access to the mount, and no API route or UI
  field accepts any bundle field (SSH host/account/port/key/known_hosts/fingerprint, Proxmox
  endpoint/token).
- **No secret is committed** to this repository. The bundle is supplied out of band by the operator.
- SSH bundle fields (host/account/port/key/known_hosts/fingerprint) never reach the API, UI, database,
  plans, evidence, audit, events, logs, exceptions, `repr`, or response objects (the SSH bundle has a
  redacted `repr`, is non-serializable, and only closed reason codes are surfaced). The `binding.json`
  anchor holds **only** non-secret control-plane IDs.
- A missing/invalid bundle leaves discovery **sealed**.

## Truthful observability (audit + logs)

The discovery-completion audit event and the worker snapshot carry the **real** per-run execution
signals — never a hardcoded value: `bundle_available` (was a live bundle engaged) and `contact_state`
(one of `sealed` / `identity_refused` / `binding_refused` / `bundle_unavailable` / `host_key_refused` /
`contacted`). A security operator can therefore distinguish a sealed run, a refusal, and a real
read-only host contact. The audit payload contains **no** host/account/key/fingerprint/known_hosts/
endpoint/output. The worker runtime log reports the actual configured mode (sealed vs controlled-live),
never a false "no infrastructure" claim while the live profile is enabled.

## Exact permitted remote commands (read-only)

Over the reviewed system-OpenSSH channel (fixed executable paths, `BatchMode`, pinned host keys, no
shell, publickey-only, bounded timeout), discovery may run **only**:

- `pvesh get /version`
- `pvesh get /cluster/status`
- `pvesh get /nodes`
- `pvesh get /nodes/{node}/status`
- `pvesh get /nodes/{node}/storage`
- `pvesh get /cluster/resources --type vm`
- `cat /sys/module/{kvm_intel|kvm_amd}/parameters/nested`
- `pvesh get` of the exact candidate **bridge / firewall-group / user** presence path
- `pvesh get /nodes/{node}/qemu/{vmid}/status/current` — a lightweight guest **existence/status**
  read (never the full guest config)

No `pvesh` write verb (`create`/`set`/`delete`/`push`), no HTTP client, Proxmox token, package
manager, host helper, artifact pipeline, mutation transport, deployment-apply path, or OpenBao code is
importable or reachable from discovery (proven by `tests/test_discovery_boundary.py`).

## First controlled live read-only discovery run (after merge)

1. Merge this PR.
2. In SECP (normal API), for the exact target: register + approve **one worker identity** for the org,
   and create + approve a **live-read authorization** for the target/onboarding.
3. Supply the worker-local bundle out of band (SSH `manifest.json`/`id_key`/`known_hosts` for a
   **scoped read-only** account + the `binding.json` naming the org/target/onboarding/enrollment +
   approved authorization), and mount it **read-only** into the **worker** container at the fixed path;
   set `SECP_DISCOVERY_CONTROLLED_INTEGRATION_ENABLED=true` on the worker.
4. In SECP, the operator requests target discovery for that enrolled, active target (creating the
   enrollment named in `binding.json`).
5. The worker claims the durable discovery job and, **before any SSH**, proves: exactly one approved
   worker identity; the bundle's anchor matches the claimed job; the live-read authorization is
   approved/current; the mounted bundle validates (descriptor checks, read-only mount); and the pinned
   host-key binding holds. Only then does it run the closed read-only probe set.
6. Typed, bounded, secret-free evidence persists (with truthful `bundle_available`/`contact_state`);
   SECP generates the exact **non-executable** candidate plan bound to the approved worker identity; the
   operator reviews and approves the exact plan.
7. **No mutation occurs.** Live deployment apply remains sealed pending a later controlled
   deployment-enablement phase.
