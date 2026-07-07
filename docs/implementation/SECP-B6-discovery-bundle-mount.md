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
| `binding.json` | JSON with exactly `{organization_id, execution_target_id, onboarding_id, enrollment_id, authorization_id, authorization_version, endpoint_binding_hash}` — the **non-secret** authorization anchor (no host/account/key). `endpoint_binding_hash` is the opaque `sha256:` SSH-endpoint digest (MB-2). Binds this bundle to the exact job **and** endpoint it may use | owner-only writable |

Additionally, on the **worker** container (not the mount), deployment-local settings provide the
worker's control-plane admission identity material (MB-1):

- `SECP_DISCOVERY_ADMISSION_ENDPOINT` — the internal admission endpoint the worker calls (it does
  **not** import the admission service in-process). It is strictly validated: **`https` only**, a
  plain host[:port], with **no** userinfo / query / fragment / non-root path / malformed port. A
  plain-`http://`, `file://`, unix-socket, or `user@`-style trick URL fails closed at construction —
  before any request, key read, or SSH;
- `SECP_DISCOVERY_WORKER_IDENTITY_KEY` — path to the worker's **Ed25519 private key** (hex) that
  signs the server-issued nonce;
- `SECP_DISCOVERY_WORKER_IDENTITY_ANCHOR` — path to the worker's **Ed25519 public anchor** (hex),
  presented and pinned by fingerprint;
- `SECP_DISCOVERY_ADMISSION_CA` — **required** deployment-local CA bundle. Server TLS is verified
  against this **exact** bundle (a worker-local trust anchor for the internal control plane) — never
  the public/system trust store and never disabled. The transport sets `trust_env=False` (ambient
  `*_PROXY` / `SSL_CERT_*` env cannot alter routing or trust) and refuses redirects.

Worker authentication is the **Ed25519 signed-nonce proof-of-possession** carried in the request
bodies — **not** X.509 client-certificate mTLS (the transport is CA-pinned server TLS; the identity
proof is the signature). A generic HTTP `200` is **not** trusted: each phase response is validated
for the exact lifecycle status (`admitted` / `valid` / `consumed`), an admission-id + job + endpoint
echo matching the request, a strictly-positive identity version, and a genuinely future expiry —
anything else fails closed. When the endpoint, the identity material, **or the CA bundle** is
absent / unreadable / malformed / invalid — or the endpoint is not strict HTTPS — the admission
client is **sealed** and live discovery fails closed **without reading the SSH `id_key` /
`known_hosts`**. The private key never leaves the worker and is never logged/serialized, and the raw
endpoint / CA path is never placed in `repr`, exceptions, audit, events, plans, or logs. (These
settings were previously mis-named `*_MTLS_*`; renamed to describe the Ed25519 material honestly
since no X.509 client-cert verification is done.)

**Deployment requirement:** the CA bundle must be provisioned on the worker (out of band) and must
sign the control-plane admission endpoint's server certificate; without it the profile stays sealed.

The mount directory and every file must be:

- owned by the worker's runtime UID;
- a **regular file** / real directory — **no symlinks, no hardlinks** (`st_nlink == 1`), on the mount's
  own device;
- within the fixed mount (no path traversal — file names are fixed constants);
- **bounded** in size (oversized files fail closed);
- well-formed (a malformed JSON file fails closed).

Under the controlled-live profile the worker validates every file **by descriptor** (`openat` /
`fstat`, `O_NOFOLLOW`), **requires a read-only filesystem**, and — in **two phases** so no private key
material is touched before admission — first validates only the **non-secret** `manifest.json` /
`binding.json` (enough to compute the endpoint digest and cross admission), then, **only after the
control-plane admission succeeds**, copies the validated `id_key` / `known_hosts` bytes into a fresh
worker-private directory from the **same pinned descriptor snapshot** so the host-key verifier and ssh
consume the exact validated inode — immune to a post-validation mount swap (TOCTOU). A refused
admission leaves the private key **unread** and invokes **zero SSH**. Any failed check refuses with a
**closed reason code** that never echoes a raw bundle value, and the source falls back to sealed. See
`secp_worker/mounted_bundle.py` (`prepare_metadata` → `finalize_key_material`).

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

## MB-1 — Control-plane-verified worker admission (before any SSH)

An **approved DB registration is not proof** that the running worker holds the registered identity.
The admission is a real **control-plane boundary**, not an in-process shortcut: the worker crosses it
over the internal HTTPS route
`POST /internal/worker-discovery-admission/{begin,complete,assert,consume}` and **never imports**
`secp_api.services.worker_admission` or passes a DB `Session` to its admission client (enforced by
`apps/api/tests/test_discovery_admission_boundary.py`). The control plane owns the identity
**decision** and the
authoritative **clock** (a client-supplied time is never trusted):

1. **begin** — the verifier issues a durable, **single-use nonce** bound to the job / organization /
   registration / identity-version / endpoint digest;
2. **complete** — the worker signs it with its private key; the control plane **verifies the Ed25519
   signature against the registration's pinned public-anchor fingerprint** (never a self-asserted key)
   and marks a one-time `WorkerDiscoveryAdmission` `admitted`;
3. **assert** — pre-probe, the engine binds that admission to the **exact** claimed job + endpoint;
4. **consume** — post-probe, the engine **consumes it once** (a replay fails closed) before a plan
   persists.

At **every** phase (begin, complete, assert, consume) the control plane re-checks that the worker
registration is approved **and unexpired** at the pinned version **and** re-runs the authoritative
live-read verifier (status / expiry / target-active / onboarding-active / connection-hash /
boundary-hash). So an admission whose registration **expires**, or whose authorization is **revoked /
drifts**, between the pre-probe admission and the post-probe consume mints **no plan**. A
missing/invalid/expired/replayed/wrong-key/wrong-worker/cross-job/cross-org admission fails closed with
**zero SSH**. Exactly one approved worker-identity registration must exist; a revocation or
identity-version bump between admission and plan persistence fails closed and mints no plan. A
candidate plan is bound to the exact registration **id + version** and is **never approvable** at
version `0` or against a rotated/different identity. Nothing but a closed reason code / safe ID is
persisted or audited — never a certificate, key, anchor, signature, or challenge byte.

**Database authority (item-2).** Issuing a `WorkerDiscoveryAdmission` and every status transition is a
control-plane authority enforced **in PostgreSQL**, not only by the ORM: migration `d4e8a1c6f9b2`
installs a `BEFORE INSERT/UPDATE/DELETE` trigger that raises `insufficient_privilege` unless the
current DB role is a member of the `secp_control_plane` role. A restricted **worker DB role** therefore
cannot forge or transition an `admitted` record even by bypassing the ORM (proven by
`apps/api/tests/test_worker_admission_postgres.py`). **Deployment requirement:** the control-plane API
DB role must be `GRANT`ed membership in `secp_control_plane` (a superuser is implicitly a member); the
worker's DB role must **not** be a member and should hold at most `SELECT` on the table.

## MB-2 — SSH endpoint bound to the approved target authorization (before any SSH)

The SSH destination is cryptographically bound to the authoritative target authorization. The control
plane stores **only** an opaque `sha256:` **endpoint-binding digest** over `(normalized target host,
ssh_host, ssh_port, host-key fingerprint)` — never a raw host/port/fingerprint — as an **immutable**
authorization binding fact, produced by an operator-side, secret-free bundle-preparation tool. Before
probing, the worker requires the manifest `ssh_host` to equal the authoritative target host and the
digest recomputed from the validated manifest to equal **both** the bundle's `binding.json` digest
**and** the approved authorization's stored digest (`bundle_target_endpoint_mismatch` /
`endpoint_binding_manifest_mismatch` / `endpoint_binding_unauthorized`). A changed host / port /
fingerprint fails closed and **requires a new live-read authorization** (the digest is immutable).

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

## Live B6 remains disabled unless ALL of these pass (before any host contact)

1. strict **read-only** descriptor-validated mount (owner-only, no symlink/hardlink, RO filesystem);
2. `binding.json` anchor matches the claimed job's org/target/onboarding/enrollment;
3. the recomputed **SSH endpoint-binding digest** equals the bundle's `binding.json` digest **and**
   the approved authorization's stored digest (MB-2), and the manifest `ssh_host` is the target host;
4. a valid, approved, current **live-read authorization** (SECP-002B-1B-6 re-verification);
5. a valid **control-plane-verified worker admission** — the worker's Ed25519 signature over a
   server-issued single-use nonce, verified against the pinned registration anchor (MB-1);
6. the pinned **host-key binding** holds;
7. the closed **read-only command policy** (`assert_read_only`).

If any fails, discovery refuses with **zero SSH**, no snapshot, and no plan.

## First controlled live read-only discovery run (after merge)

1. Merge this PR.
2. In SECP (normal API), for the exact target: register + approve **one worker identity** for the org
   (its verification anchor is the worker's Ed25519 public key), and create + approve a **live-read
   authorization** for the target/onboarding, supplying the operator-computed **endpoint-binding
   digest** for the exact SSH host/port/host-key.
3. Provision the worker's deployment-local **admission identity material** (Ed25519 key/anchor +
   internal-admission-endpoint/CA settings). Supply the worker-local bundle out of band (SSH
   `manifest.json`/`id_key`/`known_hosts` for a **scoped read-only** account + `binding.json` naming
   the org/target/onboarding/enrollment/authorization + the endpoint digest), and mount it
   **read-only** into the **worker** container; set `SECP_DISCOVERY_CONTROLLED_INTEGRATION_ENABLED=true`.
4. In SECP, the operator requests target discovery for that enrolled, active target (creating the
   enrollment named in `binding.json`).
5. The worker claims the durable discovery job and satisfies **all** of the seven gates above —
   including a control-plane-verified admission and the SSH endpoint binding — **before any SSH**.
6. Typed, bounded, secret-free evidence persists (with truthful `bundle_available`/`contact_state`);
   SECP generates the exact **non-executable** candidate plan bound to the exact approved worker
   identity (registration id + version); the operator reviews and approves the exact plan.
7. **No mutation occurs.** Live deployment apply remains sealed pending a later controlled
   deployment-enablement phase.
