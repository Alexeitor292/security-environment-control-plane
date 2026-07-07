# SECP-B6 — Worker-Mounted Read-Only Discovery Bundle

This document describes the **one** operator action required to enable the already-reviewed SECP-B5
read-only discovery worker to perform its first real, strictly **read-only** SSH discovery run against
an operator's Proxmox host, and the safety properties of the mount.

Discovery **cannot** create, modify, delete, restart, reload, install, upload, download, configure, or
otherwise alter host or Proxmox state — it runs only the closed read-only probe set (see below). The
discovery-derived candidate plan remains **non-executable**; it is the exact input for a later,
separately reviewed controlled deployment-enablement phase.

## The single operator action

Mount **one** worker-local bootstrap bundle directory into the **worker** container at the fixed path
`SECP_DISCOVERY_BOOTSTRAP_MOUNT` (default `/var/run/secp/discovery-bundle`), and set the deployment-
local profile flag `SECP_DISCOVERY_CONTROLLED_INTEGRATION_ENABLED=true` on the **worker** container.

Nothing else is required. **No** manual Proxmox bridge, VM, firewall, token, user, storage, or network
setup is needed — discovery is read-only and creates nothing.

- If the flag is unset/false, or the mount is absent/invalid, discovery stays **sealed** (zero host
  contact, no plan).
- The flag and mount path are **deployment-local only** — set in the worker's deploy manifest. They
  are never controlled by the API, UI, or database, and they carry **no** SSH/credential material.

## Bundle mount contract (no live values are shown here)

The mount is a directory containing exactly three files:

| File | Purpose | Required mode (POSIX) |
|------|---------|-----------------------|
| `manifest.json` | JSON with exactly `{ssh_host, ssh_port, account, host_key_fingerprint}` — safe tokens, bounded int port, `SHA256:` fingerprint | owner-only writable (not group/other-writable) |
| `id_key` | the OpenSSH **private key** file (referenced by path; never read into the app, never logged) | owner-only, no group/other access (`0600`/`0400`) |
| `known_hosts` | the pinned `known_hosts` file used to verify the host-key fingerprint | owner-only writable |

The mount directory and every file must be:

- owned by the worker's runtime UID;
- a **regular file** / real directory — **no symlinks**;
- within the fixed mount (no path traversal — file names are fixed constants);
- **bounded** in size (oversized files fail closed);
- well-formed (a malformed `manifest.json` fails closed).

Any failed check refuses with a **closed reason code** that never echoes a raw bundle value, and the
source falls back to sealed. See `secp_worker/mounted_bundle.py`.

## Host-key binding (before any SSH)

Before SSH is invoked, `secp_worker/known_hosts.py` proves, by parsing the mounted `known_hosts`:

- an entry matches the bundle's **exact** target host + port (plaintext or hashed `|1|` HMAC-SHA1);
- that entry's **SHA-256 host-key fingerprint equals** the manifest's expected fingerprint;
- no wildcard, negated, `@cert-authority`, `@revoked`-for-our-key, unbound, malformed, or
  duplicate-conflicting entry can satisfy the pin.

If the binding cannot be proven, discovery refuses **before** any ssh call.

## Isolation and secrecy requirements (deployment)

- The bundle mount MUST be mounted **only** into the worker container — **not** the API or UI
  containers. The API/UI have no read access to the mount, and no API route or UI field accepts any
  bundle field (SSH host/account/port/key/known_hosts/fingerprint, Proxmox endpoint/token).
- **No secret is committed** to this repository. The bundle is supplied out of band by the operator.
- Bundle fields never reach the API, UI, database, plans, evidence, audit, events, logs, exceptions,
  `repr`, or response objects (the bundle has a redacted `repr`, is non-serializable, and only closed
  reason codes are surfaced).
- A missing/invalid bundle leaves discovery **sealed**.

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
2. Supply the worker-local bundle out of band and mount it read-only into the **worker** container at
   the fixed path; set `SECP_DISCOVERY_CONTROLLED_INTEGRATION_ENABLED=true` on the worker.
3. In SECP, the operator requests target discovery for an enrolled, active target.
4. The worker claims the durable discovery job, validates the mounted bundle + host-key binding, and
   runs the closed read-only probe set.
5. Typed, bounded, secret-free evidence persists; SECP generates the exact **non-executable** candidate
   plan; the operator reviews and approves the exact plan.
6. **No mutation occurs.** Live deployment apply remains sealed pending a later controlled
   deployment-enablement phase.
