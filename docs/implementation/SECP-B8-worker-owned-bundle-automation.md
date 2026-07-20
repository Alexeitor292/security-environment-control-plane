# SECP-B8 — Worker-Owned Live Discovery Bundle Automation

SECP-B8 is the existing worker-owned, read-only Proxmox discovery flow. The browser's existing
**Read-Only Bootstrap** wizard creates `ProxmoxReadOnlyBootstrapSession` records and renders the
existing idempotent Proxmox bootstrap script. `WorkerDiscoveryNode`, `bundle_manager`,
`discovery_bundle_runtime`, the strict mounted-bundle source, worker admission, endpoint binding,
and the discovery engine remain the one authoritative enrollment and execution path.

SECP-PR5F adds the narrow repository-owned `secp_discovery_activation` production activation package
for that path. It does not
create another enrollment system, replace the wizard, install or start the controlled-live operator,
compose a controlled-live OpenTofu plan runtime, or add apply/destroy capability. The package is
implemented in the repository but **has not been installed or exercised on a real controller or
worker by this change**.

## Why B8 was needed

A clean first-time run proved the app/bootstrap/live-read-authorization side worked, but discovery
failed `probe_source_sealed` (worker `mode=SEALED`) because no worker-owned bundle/profile automation
existed. B7 automated the control-plane side; B8 added the worker side.

## Existing Proxmox strap and the one target-side action

The intended production Proxmox target is already structurally strapped with the restricted Linux
account, forced-command wrapper, `SECPDiscoveryReadOnly` audit-only role, and root ACL. PR5F neither
recreates nor replaces that contract.

The key currently present on that host must **not** be assumed to match a surviving worker private
key. After PR5F activation generates the worker's fresh persistent key, an operator uses the existing
Read-Only Bootstrap wizard to create a fresh bootstrap session and runs its existing idempotent script
once as root. On the already-strapped host this is a **key-rotation and binding step**: it replaces the
SECP-managed authorized key with the newly published worker public key while revalidating the same
restricted account, wrapper, role, and ACL. There is no manual `ssh-keygen`, private-key copying, role
rebuild, or second bootstrap mechanism.

No script was run and no Proxmox host was contacted while implementing PR5F.

## Worker-owned persistent state

The fixed durable host state is `/var/lib/secp/discovery-worker`, bind-mounted to the worker-private
container root `/var/run/secp`. The production activation owns exactly this container layout:

```text
/var/run/secp/
├── worker-keys/
└── discovery-bundle/
```

The state is durable across ordinary-worker recreation and is mounted read-write only into the
ordinary worker. It is not mounted into the API, web, controller services, unrelated containers, or
any operator container. Fixed paths, real-directory/regular-file requirements, exact worker UID,
restrictive modes, `O_NOFOLLOW`-style validation, and single-link requirements protect key and bundle
material. Unsafe, foreign, symlinked, hardlinked, special-file, wrong-owner, or permissive pre-existing
state is refused before a Docker operation. Private key bytes never enter output, evidence, logs,
exceptions, or the control-plane database.

The root-controlled activation profile and rendered artifacts live beneath
`/etc/secp/discovery-activation`; authenticated evidence and the transaction journal live beneath
`/var/lib/secp/discovery-activation`. These paths are fixed by the package, never caller-selected.
The narrow overrides always compose with fixed root-owned base files at
`/etc/secp/controller/docker-compose.yml` and `/etc/secp/worker/docker-compose.yml`; each base file's
content digest, uid, gid, and mode are captured in the role-local journal and compare-and-swap checked
before every Compose mutation and rollback.

## Production worker configuration

The separately reviewable production worker override enables exactly the existing B8 settings:

```text
SECP_DISCOVERY_CONTROLLED_INTEGRATION_ENABLED=true
SECP_DISCOVERY_WORKER_MANAGED_BUNDLE=true
SECP_DISCOVERY_WORKER_KEY_DIR=/var/run/secp/worker-keys
SECP_DISCOVERY_BOOTSTRAP_MOUNT=/var/run/secp/discovery-bundle
SECP_DISCOVERY_WORKER_IDENTITY_KEY=/var/run/secp/worker-keys/admission_key
SECP_DISCOVERY_WORKER_IDENTITY_ANCHOR=/var/run/secp/worker-keys/admission_anchor
```

The organization UUID, stable worker-node label, internal HTTPS admission endpoint, and pinned CA
path are deployment-local inputs. No deployment hostname, IP address, organization id, certificate
identity, certificate, or private key is committed.

The activation profile defaults `activation_enabled` to `false`; imports, profile parsing, planning,
and rendering never activate or contact anything. Installation remains a separate reviewed host
action.

The ordinary worker keeps its exact old reviewed base image, health check, hardening, and sole
Temporal queue `secp-orchestration`. The old image is **not** the whole activated runtime. PR5F builds
one deterministic, bounded, content-addressed ZIP containing the complete reviewed `secp_api` and
`secp_worker` source inventories and canonical per-file manifest. It imports that ZIP only from
`/etc/secp/discovery-activation/import/secp-pr5f-runtime-overlay.zip`, installs it as root-owned `0644`,
mounts it read-only at `/opt/secp/secp-pr5f-runtime-overlay.zip`, and sets that exact path as
`PYTHONPATH`. The profile pins its digest, and the in-container probe proves the mounted digest and
package/module origins; there is no partial overlay, base-image fallback, or image-only readiness
claim.

The controller is different: preflight first binds the exact reviewed current
`controller_api_baseline_image_digest` at Alembic head `c4e2f9a1b7d3`; its fixed `api` Compose
service must then use a newly built digest-qualified `controller_api_image` containing the PR5F
routes/services and migration. Actual API runtime identity,
hardening/Compose ownership and gate mount are reobserved, and its in-container Alembic head must be
exactly `d8f1a2b3c4e5`. The separately digest-pinned admission proxy and the worker are also accepted
only from bounded actual runtime projections of image, configuration, mounts, networks and Compose
ownership. Rendered YAML by itself is not proof of the running identities.

The `d8f1a2b3c4e5` PostgreSQL migration also installs and validates a named `CHECK` constraint that
rejects new `ed25519_signed_nonce` registrations. That durable database fence stays engaged while
the controller offer is transported, the worker is recreated, and the signed worker result is
returned; a momentary compatibility read is not treated as rollback safety.

The worker never polls `secp-controlled-live-v1` and carries no operator registration.
Both generic B1-A subprocess seals remain `True`; the dedicated plan-only process seal remains
`False`; real provisioning remains disabled.

## Internal HTTPS admission boundary

The production surface exposes only the existing worker-discovery-admission route family through a
dedicated internal TLS listener or equivalently narrow proxy. It uses the exact deployment-local
server certificate/private key and a worker-pinned CA, validates the certificate identity/SAN, follows
no redirects, inherits no ambient proxy, and has no system-trust or verification-disable fallback.
Unrelated API routes are denied on this listener. Requests, responses, and timeouts are bounded.

Worker identity remains the existing Ed25519 signed-nonce proof-of-possession. This is server-authenticated
TLS with an application-layer signed-nonce proof; it is **not client-certificate mTLS**. Server private
keys remain root-controlled and unreadable by the worker; the worker receives only the CA certificate.
Certificate installation is an explicit transactional host action; the library's optional generator
is pure and in-memory, not a production file-writing CLI operation. Status/evidence exposes only safe
fingerprints, identities, and presence metadata.

Production commands are import-only. The controller reads the exact CA, certificate and private key
under `/etc/secp/discovery-activation/import/` with `root:root` modes `0644`, `0644`, and `0600`; the
worker receives only the CA copy. The endpoint DNS name is exactly the certificate SNI/SAN identity,
but the listener binds an independently validated private IP literal on the same port. Host probes
connect directly to that IP while presenting the DNS identity, and the worker has exactly one
`extra_hosts` DNS-to-listener-IP binding. The server certificate and key are never transferred to the
worker.

## Authenticated two-host activation

Controller and worker have separate host-local Ed25519 evidence keys whose public key ids are first
prepared under an `activation_enabled=false` profile and independently pinned in the final profile.
Activation then follows a fixed detached-signed chain: the controller installs and emits its
`controller-offer` payload/attestation from the fixed outbox; an operator copies that exact pair as
`root:root 0640` into the fixed worker inbox; the worker authenticates it, installs/recreates only the
ordinary worker, and emits its predecessor-bound `worker-result` pair; the operator copies that exact
pair into the fixed controller inbox; and a second controller install authenticates the complete chain
and revalidates the live controller runtime. That second install first commits and independently
authenticates aggregate evidence while the database rollback fence remains engaged through the exact
current API generation at head `d8f1a2b3c4e5`; only then does it release and freshly observe the
fence. Evidence-committed/fence-engaged is a durable `awaiting-finalization` state that the same
install safely resumes. The first controller install, worker install, and all read operations never
release it. The package transports nothing between hosts itself. A partial,
stale, expired, cross-transaction replayed, wrongly pinned or out-of-order pair fails closed; an exact
same-transaction retry is idempotent. See the PR5F runbook for the exact paths and sequence.

## The production first-time flow

`plan` and `render` are non-mutating and contact no external service; they read only fixed local
profile/import files. `inspect` is also non-mutating, but it executes fixed bounded role-local probes
and can read control-plane state or connect to the configured internal admission listener, so it is
not a pure operation. `verify` and `status` likewise remain read-only: they reobserve and authenticate
state but neither engages nor releases the rollback fence. Before the steps below, a separately
confirmed installation validates the exact worker/image/queue/health posture, operator absence, TLS
material, persistent state, and complete rollback plan; recreates only the ordinary worker; and proves
that worker is healthy with fresh persistent keys and a public-only node publication.

The exact post-activation operator flow is:

1. Wait for the worker to publish its `WorkerDiscoveryNode`.
2. Open the existing **Read-Only Bootstrap** wizard.
3. Select the published worker public key.
4. Create a new `ProxmoxReadOnlyBootstrapSession`.
5. Generate the existing idempotent Proxmox bootstrap script.
6. Run that script once as root on the already-strapped Proxmox host.
7. Confirm the returned proof and host public key in the existing wizard.
8. Complete the wizard's composite three-review worker-identity approval/link for the exact node,
   then approve and bind the separate live-read authorization to the completed session.
9. Create/request the existing discovery enrollment.
10. Verify a real immutable snapshot records `bundle_available=true` and
    `contact_state=contacted`.
11. Verify the discovery-derived candidate plan remains `executable=false`.

The worker bundle-prep loop assembles the strict mounted bundle only after the existing session,
proof, identity, authorization and binding gates pass. Signed admission, endpoint binding, pinned
host-key validation and strict mounted-bundle validation all precede read-only SSH. Nothing is
inferred from flags or script success alone.

For the composite identity step, a resumed session is re-matched to exactly one node by its
server-recorded SSH public-key fingerprint. The operator supplies safe opaque deployment binding,
proof id, and issuer metadata; reviews the exact node revision plus SSH/admission-anchor fingerprints;
and separately confirms deployment binding, verification anchor, and rotation/revocation. The server
requires discovery management, identity management, and separate identity approval permissions and
locks/rechecks the current records. Draft, stale, foreign, ambiguous, or mismatched state refuses. An
exact current approved identity may be reused. Under the same explicit rotation/revocation review,
an exact terminal expired/revoked same-node Ed25519 link is CAS-cleared and replaced by a new
monotonic identity version while its historical evidence remains immutable; ambiguous, live, draft,
or lost-CAS state refuses atomically. Only the explicitly reviewed same-label old-anchor case may be
revoked and replaced. Publication, identity link, bootstrap bind, and live-read authorization remain
separate authorities.

Flags alone never mean discovery-ready. Production status distinguishes disabled/prepared/TLS-ready,
worker recreation/startup, key generation/public-node publication, the bootstrap/proof/authorization/
bundle waits, bundle-ready, discovery-contacted, and recovery-required.

## Transactional activation and rollback

Before worker recreation, the package captures and validates the exact container identity,
generation, image, health, ordinary queue, mount/config identities, and operator absence. After
recreation it requires a healthy ordinary worker on the same reviewed image and queue, the exact B8
configuration and mount isolation, a started bundle-prep loop, correctly protected persistent keys,
and a public-only `WorkerDiscoveryNode`.

Runtime observation deliberately has two configuration bindings. The public evidence digest is a
redacted projection (configuration shape and environment variable names, never values). A
domain-separated HMAC over the complete Docker `Config` and `HostConfig` is derived from the
root-controlled evidence key, stored only in the root-owned `0600` rollback journal, omitted from
repr/status/evidence/handoffs, and compared in constant time. Mount isolation is also object-based,
not merely string-based: production walks every absolute mount source without following symlinks,
binds device/inode/type identities, compares them with every protected controller and worker path,
and requires the two runtime samples to retain the same classification. Symlink, bind-mount,
hardlink, ancestor/descendant alias, unresolvable source, and between-sample identity drift all
refuse closed.

Any failed health check, TLS failure, queue or mount drift, missing/unsafe node publication,
unexpected operator appearance, or incomplete evidence restores the prior ordinary-worker
configuration/container. A missing or malformed receipt is never treated as proof of no effects. If
restoration cannot be proven, status is `recovery-required`; foreign state is never overwritten or
removed.

A controller or worker rollback after its Compose runtime may have started requires the exact current,
complete role-local rollback journal; evidence or an offline/stale journal is not sufficient. The
fixed compatibility probe first proves that no PR5F-only Ed25519 mechanism row exists, but that
read-only observation is only a preliminary refusal gate. Through the exact transaction-owned API
container (controller) or still-mounted worker overlay (worker), rollback then engages the durable
PostgreSQL `CHECK` fence. Internal compensation rebinds the exact runtime, repeats the compatibility
proof, and re-engages the fence immediately before the first artifact or runtime mutation. The
controller downgrade independently locks the table, canonicalizes and validates the same fence, and
leaves it installed while the pre-PR5F runtime is live. Any missing journal, incompatible row,
runtime substitution, fence failure, or incomplete observation becomes `recovery-required` before
rollback mutation. Artifact-only compensation does not recreate a runtime.
Superseded key bindings use the old-compatible terminal bootstrap value `refused` plus an audited
`worker_key_rotated` outcome.

Bundle assembly independently compares the ready session descriptor's server-recorded worker SSH
public-key fingerprint with the fingerprint freshly derived from the worker's current local public
key. A missing or stale fingerprint refuses before the fixed bundle directory is touched; only a new
run of the existing wizard script for the current published key can authorize assembly. Live
discovery counts current Ed25519 signed-nonce identities within that mechanism, so an unrelated
mTLS identity does not create false global ambiguity. The composite same-label approval path still
refuses an active non-Ed25519 collision and never revokes or reinterprets that foreign mechanism.

## Preserved safety invariants

- The API never stores or reads an SSH private key, SSHes to Proxmox, or runs a provider command.
- The worker contacts Proxmox only after the complete existing gate chain passes.
- Worker-managed mount mode relaxes only the filesystem read-only requirement; owner-only modes,
  regular-file/real-directory checks, no symlinks, one hardlink, descriptor pinning, same-device and
  bounded-size checks remain.
- No root SSH runtime account or arbitrary-command surface exists.
- The controlled-live operator is absent and is not installed or activated by PR5F. Its installation
  remains the next separately reviewed deployment step.
- No controlled-live plan composition is installed. No real OpenTofu plan has run. Apply and destroy
  remain unavailable, and PR6 remains frozen.

See `apps/worker/secp_worker/bundle_manager.py`,
`apps/worker/secp_worker/discovery_bundle_runtime.py`,
`apps/worker/secp_worker/mounted_bundle.py`, and
`apps/api/secp_api/services/bootstrap_discovery.py`. The prior manual bundle flow is documented in
`docs/implementation/SECP-B6-discovery-bundle-mount.md`; production activation operations are in
`docs/runbooks/pr5f-b8-production-activation.md`.
