# B8 production read-only discovery activation (SECP-PR5F)

> **REPOSITORY IMPLEMENTATION — NOT AN EXECUTED DEPLOYMENT RECORD.** This runbook describes the
> reviewed contract implemented by `secp_discovery_activation`. PR5F did not install the package,
> recreate a worker, import or generate a production certificate, SSH to a host, run the Proxmox
> bootstrap script, submit a workflow, contact PostgreSQL/Temporal/OpenBao/a state backend/Proxmox,
> or run OpenTofu. All deployment hostnames, IP addresses, organization ids, image identities,
> certificate identities, and credentials remain deployment-local.

This package activates only the existing B8 worker-owned, **read-only** SSH discovery flow. It does
not create a new enrollment system and does not replace `WorkerDiscoveryNode`,
`ProxmoxReadOnlyBootstrapSession`, the browser Read-Only Bootstrap wizard, worker admission, endpoint
binding, `bundle_manager`, `discovery_bundle_runtime`, the mounted-bundle source, or the discovery
engine.

The runtime is deliberately **not image-only**. The ordinary worker continues to use its exact
previously reviewed base image, while one complete, content-addressed ZIP overlay supplies the
reviewed `secp_api` and `secp_worker` source trees at runtime. The controller API must move to a new,
digest-qualified image containing the PR5F API surface and Alembic head `d8f1a2b3c4e5`. The profile
pins both of those facts; neither an old worker image by itself nor a new API tag is an acceptable
activation artifact.

The shared repository Python image (`infra/dev/Dockerfile.python`), from which the controller API
image is built, contains the **complete `pyproject.toml` local-package closure** required at runtime:
the API (`secp_api`), the admission proxy (`secp-admission-proxy` → `secp_discovery_activation.proxy`),
the discovery-activation CLI (`secp-discovery-activation` → `secp_discovery_activation.cli`), and the
management (`secp_management`), commissioning (`secp_commissioning`), and deployment
(`secp_operator_deployment`, `secp_discovery_activation`) package imports. A dedicated CI job builds
the exact repository Dockerfile and, in a network-disabled, read-only, capability-dropped container,
proves every production package imports, the console-script files resolve, the runtime user is
`10001:10001`, the sole Alembic head is `d8f1a2b3c4e5`, and the runtime overlay builds
deterministically. **This is a repository and CI correction only — no image has been built for or
pushed to any environment, and nothing here has been deployed.** The ordinary worker's base-image
deployment contract is unchanged: PR5F keeps it on its previously reviewed image plus the separately
content-addressed runtime overlay; this correction does not replace the running worker image.

## Starting deployment truth

At the time of this repository change, the ordinary worker still has both B8 flags false, no
`/var/run/secp` persistent mount, no worker keys or discovery bundle, and no published B8 durable
records. No operator service/package is installed. Separately, the read-only Proxmox host strap
already exists. Its currently installed public key is not evidence that the corresponding private key
survived; it must be replaced through the existing wizard flow after the activated worker generates
its fresh persistent key.

## Scope and fixed production layout

The root-controlled activation profile is fixed at:

```text
/etc/secp/discovery-activation/profile.json
/etc/secp/discovery-activation/host-role
```

The profile is `root:root 0640`. The host-role file is `root:root 0644` and contains exactly
`controller\n` or `worker\n`; the CLI never accepts a role or path argument.

Reviewed worker Compose-override and internal-admission-listener artifacts are rendered/installed
beneath `/etc/secp/discovery-activation`. Evidence and the transactional journal live beneath
`/var/lib/secp/discovery-activation`. The worker's durable host state is the fixed real directory:

```text
/var/lib/secp/discovery-worker
```

It is bind-mounted read-write into **only** the ordinary worker at `/var/run/secp`, where B8 owns:

```text
/var/run/secp/worker-keys
/var/run/secp/discovery-bundle
```

The worker-pinned CA is root-installed at
`/etc/secp/discovery-activation/tls/admission-ca.pem` and mounted read-only into the ordinary worker at
`/etc/secp/admission-ca.pem`. Server private keys remain root-controlled and are never mounted into
the worker. No discovery state or TLS private key is mounted into API, web, controller, unrelated,
or future operator containers.

The narrow overrides are always composed with, and never replace, these existing base files:

```text
controller: /etc/secp/controller/docker-compose.yml
worker:     /etc/secp/worker/docker-compose.yml
```

Each base file must be a nonempty, single-link, root-owned regular file with mode `0600`, `0640`, or
`0644`. Its content digest, uid, gid, and mode are captured in the role-local rollback journal and
compare-and-swap checked before every Compose mutation and again before rollback. Any drift refuses;
the package never guesses another Compose project or base path.

The controller base Compose file interpolates fixed `${SECP_*}` variables. Because the production
command runner uses a fixed child environment (`PATH`, `LC_ALL`) and never inherits the ambient
process/shell environment or depends on the current working directory, those values are supplied
explicitly with a single code-owned fixed environment file — never a profile-provided path:

```text
controller environment: /etc/secp/controller/secp.env   (always supplied with --env-file)
```

Every controller Compose invocation — initial activation, idempotent retry, compensation, and
rollback to the baseline — runs with `--env-file /etc/secp/controller/secp.env`. The worker is
unaffected: it keeps its existing service-level `env_file` contract and never receives the controller
environment file. The environment file is a secret-bearing, immutable transaction input: it must be a
nonempty, single-link, root-owned (`uid 0`) regular file with mode `0600` or `0640` under a
root-controlled ancestor chain, and before any controller mutation the package proves it defines
every `${SECP_*}` the base Compose file interpolates (an unsupported interpolation form refuses before
staging). Its format is deliberately narrow and is proved sound against compose-go's dotenv
semantics: only single-line `NAME=value` assignments (full-line `#` comments and blank lines are
allowed; a leading UTF-8 BOM is tolerated). A value must resolve to a non-empty literal that Compose
would use verbatim, so the following are refused before staging because Compose would otherwise
silently produce an empty or altered value:

- **empty** values (`NAME=`), and multi-line/quoted-spanning values;
- values containing a `$` variable reference (`NAME=${OTHER}`, `NAME=$OTHER`, `NAME="${OTHER}"`) —
  compose-go expands `$VAR`/`${VAR}` in unquoted **and** double-quoted values, and because the
  runner uses a fixed child environment the reference resolves to the empty string;
- unquoted values bearing `#` (an inline comment Compose would strip) or a stray quote;
- `export NAME=…` and inline comments after a value.

To carry a literal containing `$`, `#`, `"` or spaces, **single-quote** it (`NAME='p$a#s"s'`);
compose-go treats single quotes as fully literal. A name is counted as covered only when the file
defines it this way, so a name can never pass the gate while Compose blank-substitutes it. Multi-line
secrets such as certificates are imported through the TLS import paths, not this file. Only the two
repository-owned base Compose files, this environment file, and the fixed worker runtime-overlay
import are the code-owned fixed paths the hardened reader may open; they are not deployment knobs. Only a private content-digest/uid/gid/mode binding is recorded in the root-owned `0600`
journal — never the file bytes — and it is re-proven immediately before every controller Compose
mutation and again before rollback; any change, disappearance, replacement, symlink, hardlink,
owner/mode, or content drift refuses closed. The contents are never journaled, logged, echoed, or
placed in any status, evidence, exception, or command line, and ambient environment and the working
directory are irrelevant. Deployment must atomically copy the already-reviewed protected controller
environment file to this canonical path before installation; that host operation is out of scope here.

The fixed import and installed paths are:

```text
controller TLS imports:
  /etc/secp/discovery-activation/import/admission-ca.pem
  /etc/secp/discovery-activation/import/admission-server.pem
  /etc/secp/discovery-activation/import/admission-server.key

worker runtime-overlay import:
  /etc/secp/discovery-activation/import/secp-pr5f-runtime-overlay.zip
worker installed overlay:
  /var/lib/secp/discovery-activation/runtime/secp-pr5f-runtime-overlay.zip
worker read-only container mount:
  /opt/secp/secp-pr5f-runtime-overlay.zip
```

The worker receives only a separately transferred copy of `admission-ca.pem` at its same fixed import
path. It must not receive either server artifact. Import metadata is exact: CA and server certificate
are `root:root 0644`, the server private key is `root:root 0600`, and the overlay ZIP is
`root:root 0644`; every file must be regular, single-link, and reached through safe root-controlled
ancestors.

All paths above are code-owned constants. The profile supplies no arbitrary write path and there is
no generic shell/exec endpoint.

## Closed operation surface

`secp_discovery_activation` exposes deterministic, machine-readable operations equivalent to:

| Operation | Contract |
| --- | --- |
| `inspect` | Read-only role-local observation. On a controller it inspects the API/proxy runtime, migration, listener, route gate, TLS and artifacts; on a worker it inspects the ordinary container/image/generation/health/queue, operator absence, state, keys, publication and artifacts. It executes fixed bounded probes and may therefore read the control-plane database or connect to the configured internal admission listener. |
| `plan` | Derive the exact fixed role-local writes, runtime change, verification gates, and rollback contract. It reads only fixed local input files and performs no mutation or external-service contact. |
| `render` | Render the separately reviewable role-local artifacts from validated non-secret inputs. It reads only fixed local input files and performs no mutation or external-service contact. |
| `install` | With explicit reviewed host authority, transactionally install role-local artifacts and either replace the controller API/add the proxy or recreate only the ordinary worker, after all preconditions and rollback material are proven. |
| `verify` | Reobserve and require the complete role-local postconditions: controller runtime/migration/listener/route/TLS facts or worker runtime/mount/queue/seal/key/publication facts. |
| `status` | Revalidate authenticated evidence plus fresh host/control-plane facts and report one truthful lifecycle status. |
| `rollback` | Restore the exact prior role-local runtime and artifact posture and remove only transaction-created, authenticated objects; never remove foreign state. |
| `evidence` | Return bounded authenticated non-secret identities, digests, fingerprints, ownership classifications, and lifecycle facts. |

The fixed console surface is `secp-discovery-activation <operation> [--json]`. `install` additionally
requires both `--write --confirm` and one bounded, non-secret `--installation-identity <opaque-id>`;
`rollback` requires `--write --confirm`. There is no host, role, path, command, Compose project, or
container argument.

Repository import and dependency construction perform no host mutation or external contact. `plan`
and `render` read only the fixed profile/import files and likewise perform no mutation or
external-service contact. `inspect` is non-mutating but is deliberately not pure: its fixed bounded
role-local probes can inspect Docker/runtime state, read control-plane state from inside the reviewed
container, and perform a pinned handshake to the configured internal admission listener. `verify`
and `status` are also read-only: they reobserve and authenticate current state but neither engages nor
releases the PostgreSQL rollback fence.
Installation is always a separate, explicit, reviewed root action.

## Required deployment-local profile

The reviewed profile supplies, without committing their values:

- exact ordinary-worker image identity and runtime UID/GID;
- exact complete worker runtime-overlay SHA-256 digest, the current controller API baseline image
  digest, and a digest-qualified target controller API image;
- stable worker-node label and organization UUID;
- strict internal HTTPS admission endpoint, listener bind, controller API upstream, and expected
  server certificate DNS identity/SAN;
- exact pinned admission-proxy image/runtime identity;
- exact pinned container-runtime and Compose executable identities.

Code-owned layout fixes the container/service names, queue, paths, mount destinations, admission
routes and bounds. The TLS transaction separately consumes the exact root-controlled CA/server
certificate/server-key inputs and verifies them before any installation.

The transaction/evidence layer separately binds the installation identity, timestamp, and reviewed
evidence-authenticator identity; those are not browser or target-enrollment inputs.

`activation_enabled` defaults to `false`. Parsing or rendering a profile never activates anything;
the reviewed production profile must opt in explicitly, and install remains a separate confirmed host
action.

The rendered ordinary-worker override enables exactly:

```text
SECP_DISCOVERY_CONTROLLED_INTEGRATION_ENABLED=true
SECP_DISCOVERY_WORKER_MANAGED_BUNDLE=true
SECP_DISCOVERY_WORKER_KEY_DIR=/var/run/secp/worker-keys
SECP_DISCOVERY_BOOTSTRAP_MOUNT=/var/run/secp/discovery-bundle
SECP_DISCOVERY_WORKER_IDENTITY_KEY=/var/run/secp/worker-keys/admission_key
SECP_DISCOVERY_WORKER_IDENTITY_ANCHOR=/var/run/secp/worker-keys/admission_anchor
```

It also supplies the deployment-local organization, label, HTTPS admission endpoint, and CA mount.
The worker keeps its current reviewed image, hardening and health contract and polls only
`secp-orchestration`. It never receives an operator registration or polls `secp-controlled-live-v1`.

## Controller API and worker runtime artifacts

The controller preflight accepts only the deployment-reviewed
`controller_api_baseline_image_digest` with the exact pre-PR5F Alembic head `c4e2f9a1b7d3`; those
facts are captured in the rollback journal before any write. The controller override then selects
the fixed Compose service `api` with `controller_api_image`. That
value must be a digest-qualified reference, not a tag, and the running API's actual image digest,
Compose ownership, hardened runtime projection, and admission-gate mount are reobserved. After the
controller Compose step, `python -m alembic current` runs inside that exact API container and must
report `d8f1a2b3c4e5` as the sole head. The migration adds the monotonic public-node revision,
truthful discovery contact state, and one-live-bound-session database boundary needed by PR5F. An
unreviewed baseline image, wrong baseline head, old post-install image, or any other migration head
fails closed.

On PostgreSQL that migration also takes the required table lock, installs and validates the named
`ck_worker_identity_pr5f_ed25519_rollback_fence` `CHECK` constraint, and leaves it engaged. While the
two signed handoffs are in flight, the database therefore rejects every new
`ed25519_signed_nonce` registration that a pre-PR5F runtime could not deserialize.

The worker override intentionally does not select another image. Its activation runtime is the exact
old reviewed worker base image **plus** the reviewed overlay. Release preparation calls
`build_runtime_overlay` against the final reviewed checkout; that pure builder returns a deterministic
ZIP containing the complete `.py` inventories of both `secp_api` and `secp_worker`, a canonical
manifest, per-file digests, and the critical PR5F modules. It writes no file, imports no packaged code,
and contacts nothing. A controlled release process must atomically place those exact bytes at the
fixed import path and pin `runtime_overlay_sha256(...)` as `worker_runtime_overlay_digest` in the
profile.

The importer accepts only that bounded canonical ZIP dialect and checks the whole manifest, inventory,
syntax, metadata, sizes, compression bounds, and caller-pinned digest before the root-owned `0644`
installed copy is created. The worker receives it read-only and receives exactly:

```text
PYTHONPATH=/opt/secp/secp-pr5f-runtime-overlay.zip
SECP_DISCOVERY_RUNTIME_OVERLAY_SHA256=<the reviewed profile digest>
```

The in-container activation probe then hashes the mounted archive and proves that both package roots
and the probe module were loaded from that exact ZIP. There is no partial-module overlay and no
fallback claim that the old base image alone contains the final PR5F runtime.

## Internal admission TLS

The dedicated internal listener:

- accepts only the existing worker-discovery-admission route family and denies unrelated API routes;
- proxies only to the existing controller API;
- validates the exact deployment-local certificate, private key, CA chain and server identity/SAN;
- gives the worker only the CA certificate — never the server key;
- permits no redirect, ambient proxy inheritance, system-trust fallback, or TLS-disable switch;
- has bounded request/response sizes and bounded timeouts;
- is not publicly exposed.

`admission_listener_bind` is an exact private, non-loopback IP literal and port. The canonical
`admission_endpoint` uses a DNS name whose port matches that listener and whose hostname exactly
matches the one certificate DNS SAN. The proxy publishes only on the private IP. Host-side probes
connect directly to that IP while presenting the DNS name for SNI/SAN validation; the worker override
adds exactly one `extra_hosts` mapping from that DNS name to that private IP, and the observed worker
runtime must contain that exact mapping. This avoids ambient DNS selection without weakening
certificate-name verification.

Worker authentication remains the existing Ed25519 signed-nonce proof-of-possession above
server-authenticated TLS. It is **not X.509 client-certificate mTLS**.

The production CLI is import-only: it reads the three exact controller import files above and the
worker reads only the exact CA import. The library's optional generator is pure and in-memory; it is
not a production file-install command. Validation precedes installation, partial writes compensate,
and output/evidence contain fingerprints, presence, validity, and identity only, never a raw
certificate when a fingerprint suffices and never a private key. The installed server key is
root-owned `0640` for only the proxy runtime group; the worker never receives it.

## Two-host preparation and signed handoff

The controller and worker never share a private evidence key. First install an
`activation_enabled=false` profile and fixed `host-role` (`controller\n` or `worker\n`) on each host,
then run the write-confirmed `install` operation once on each host. In disabled mode that operation
only creates the host-local Ed25519 evidence key and reports its safe SHA-256 public key id; it starts
no activation effect and recreates no container. Independently review those two key ids, pin them as
`controller_evidence_key_id` and `worker_evidence_key_id`, then install the final enabled profile on
both hosts. Merely transporting an included public key never makes it trusted: every detached
signature is accepted only when its key id matches the independently reviewed profile pin.

The activation is a two-host protocol. There is no remote deployer and no network handoff inside the
package. An operator must transport each payload and its detached attestation together, without
editing either, through exactly this sequence:

1. On the controller, run the write-confirmed `install`. It validates the fixed controller base
   Compose binding, installs the new digest-pinned API plus the pinned admission proxy and TLS
   artifacts, proves API/proxy runtime identity, route restriction, private listener, pinned TLS, and
   migration head `d8f1a2b3c4e5`, including the migration-engaged PostgreSQL rollback fence, then
   emits:

   ```text
   /var/lib/secp/discovery-activation/outbox/controller-offer.json
   /var/lib/secp/discovery-activation/outbox/controller-offer.attestation.json
   ```

2. Copy exactly those two root-owned `0640` regular, single-link files to the worker as:

   ```text
   /etc/secp/discovery-activation/inbox/controller-offer.json
   /etc/secp/discovery-activation/inbox/controller-offer.attestation.json
   ```

   Keep them `root:root 0640`. The worker authenticates the pair, its controller key pin, sequence,
   transaction/predecessor bindings, profile/plan/render and artifact digests, TLS identity and
   fingerprint, object classifications, 24-hour expiry, installation metadata, and forbidden-effect
   booleans before any worker mutation.

3. On the worker, run the write-confirmed `install`. It validates the fixed worker base Compose
   binding, CA and runtime-overlay imports, stages a content-bound rollback journal, proves host-side
   pinned TLS, installs the worker override/CA/overlay, and force-recreates only Compose service
   `worker` with `--no-deps --no-build --pull never`. After all worker postconditions pass it emits:

   ```text
   /var/lib/secp/discovery-activation/outbox/worker-result.json
   /var/lib/secp/discovery-activation/outbox/worker-result.attestation.json
   ```

4. Copy exactly those two root-owned `0640` regular, single-link files to the controller as:

   ```text
   /etc/secp/discovery-activation/inbox/worker-result.json
   /etc/secp/discovery-activation/inbox/worker-result.attestation.json
   ```

   Keep them `root:root 0640`. Do not copy a payload without its attestation or reuse either file for
   another transaction.

5. On the controller, rerun the same write-confirmed `install`. It reauthenticates the stored offer
   and returned result, verifies their predecessor and controller/worker transaction identities and
   the fresh live controller posture. While the exact current API container at Alembic head
   `d8f1a2b3c4e5` still proves the PostgreSQL rollback fence engaged, it durably writes aggregate
   evidence plus its detached attestation, reloads and authenticates that pair, and reconstructs the
   complete signed handoff chain. Only then does it release the fence and freshly reverify both the
   aggregate chain and the live released state. A restart after evidence commit resumes only this
   authenticated finalization; a restart after release proves evidence plus the live released state
   without releasing twice. Only that complete proof is `installed`. Finish with role-local
   read-only `verify`, `status`, and `evidence`; do not infer success from files, command success, an
   outbox file, or a true feature flag.

The controller offer binds controller and worker artifact digests but contains no endpoint value,
certificate, credential, raw environment, private key, or Docker inspect payload. The worker result
adds the exact worker image/generation/queue, overlay, state and public-node evidence. Missing,
partial, expired, stale, wrongly signed, cross-transaction replayed, ambiguous, or out-of-order
handoffs fail closed; an exact same-transaction retry is idempotent. Once an effect is possible, an
unprovable state is `recovery-required`, never a clean no-op.

## Transactional worker activation

Before recreating the ordinary worker, `install` must prove all of the following from one coherent
observation:

1. the exact current container identity, generation and healthy state;
2. the exact reviewed image identity;
3. the sole ordinary queue is `secp-orchestration`;
4. no operator service, container, registration, or operator-queue polling is present;
5. TLS and persistent-state artifacts are safe and complete;
6. the state mount will reach only the ordinary worker;
7. the fixed base Compose file still matches its captured content/metadata binding;
8. the complete overlay is validated and the actual worker runtime projection still proves its exact
   image, Compose ownership, hardening, mounts, networks, and DNS-to-listener binding;
9. a complete content-bound rollback plan and durable receipt/journal exist.

After recreation, verification requires a running, healthy and coherent new ordinary-worker
generation; the exact base image plus active overlay and queue; true B8 flags; exact worker-only
mounts; a started bundle-prep loop; protected persistent worker keys; and a `WorkerDiscoveryNode`
containing public material only. Controller verification independently proves the actual digest-pinned
API/proxy runtime projections, migration head, listener, route gate, and exact mounts; rendered
configuration alone is not runtime identity evidence.
Both generic B1-A subprocess seals remain `True`, the dedicated plan-only process seal remains
`False`, and real provisioning stays disabled.

A failed health check, TLS failure, queue/mount/config drift, missing or unsafe public-node
publication, unexpected operator appearance, or incomplete evidence restores the prior worker
deployment. A missing/malformed receipt is never treated as proof of no effects. Unprovable rollback
ends in `recovery-required`; no foreign discovery directory is overwritten, deleted, or adopted as
transaction-owned state.

Rollback is role-local, write-confirmed, and journal-bound. A rollback-capable host must retain the
exact current, complete, live role-local journal and receipt for that transaction; detached evidence
alone, an offline copy, a stale receipt, or a reconstructed journal is not rollback authority. For a
complete two-host unwind, roll back the worker first and prove its prior container/configuration
posture, then roll back the controller and prove its prior API/proxy/artifact posture. A committed
worker result or aggregate evidence is trusted only after its detached signature verifies. Before
changing anything, rollback revalidates the fixed profile, captured base Compose content/metadata,
all current managed-object bytes/metadata/classification, pinned executables, the saved runtime
baseline, and the exact transaction-owned current container generation. It restores exact prior
files (or removes only authenticated objects this transaction created), runs the fixed base-only
Compose action that restores the admitted baseline without activating a dormant override, and
reobserves the saved runtime posture; a recreated worker must have a coherent replacement generation
with the prior image/configuration posture, not falsely reuse the old container id. The worker's
durable key/bundle state is retained after a recreation so rollback cannot destroy the newly generated
private identity.

The runtime binding used for rollback is intentionally stronger than the safe digest printed in
status/evidence. Public output exposes only a redacted configuration shape. The complete Docker
configuration is bound by a domain-separated HMAC kept only in the root-owned `0600` live journal,
and rollback compares that MAC in constant time. The installer also resolves every mounted host
source by no-follow device/inode/type identity against the fixed protected TLS, state, journal,
handoff, and overlay paths on both observations. A textual alias, bind-mount alias, hardlink,
symlink, unresolved source, ancestor/descendant overlap, or identity change is a refusal; matching
path strings alone are never accepted as proof of mount isolation.

Before restoring either pre-PR5F runtime, the fixed
`secp_api.discovery_activation_rollback_probe` performs a preliminary read through the exact current
API generation for controller rollback or the exact current ordinary-worker generation and its
still-mounted overlay for worker rollback. It refuses if an `ed25519_signed_nonce` registration
already exists, but this momentary read is not sufficient rollback authorization. On a compatible
result, the fixed `secp_api.discovery_activation_rollback_fence engage` operation serializes against
writers and installs/validates the durable PostgreSQL `CHECK` fence through that exact owned
container. Internal compensation then rebinds the exact runtime, repeats the compatibility proof,
and re-engages the fence immediately before the first artifact or runtime mutation. The controller
Alembic downgrade independently locks the table, canonicalizes and validates the same fence, and
leaves it installed for the entire pre-PR5F interval. A row conflict, missing or incomplete journal,
runtime substitution, noncanonical helper response, or failed observation reports
`recovery-required` before changing Compose. This applies to automatic compensation once the journal
says a Compose runtime effect may have started; artifact-only failures compensate without recreating
a container. Key rotation marks an old bootstrap session with the
pre-existing `refused` value (and revokes its authorization), so historical session rows remain
readable by the prior controller.
Any missing receipt, drift, partial pair, failed restoration, unknown Compose effect, or baseline
mismatch reports `recovery-required` and requires manual recovery; it is never reported as a
successful no-op.

## Truthful status model

Status is derived from authenticated installed evidence **and fresh observations**. It reports one of
these lifecycle states:

| Status | Meaning |
| --- | --- |
| `disabled` | No reviewed activation is installed; B8 remains off. |
| `prepared` | Safe state/config material is prepared, but admission TLS is not yet proven ready. |
| `TLS-ready` | The dedicated listener, server identity and worker-pinned CA are valid; worker recreation has not completed. |
| `worker-recreation-required` | Reviewed artifacts differ from the running ordinary-worker generation. |
| `worker-starting` | Recreation occurred, but the complete healthy/publication gate has not passed. |
| `keys-generated` | Persistent key metadata is valid; no public node has yet been proven. |
| `public-node-published` | The matching public-only `WorkerDiscoveryNode` exists. |
| `awaiting-finalization` | Authenticated aggregate evidence is durably committed, but the exact live rollback fence is still engaged; rerun the write-confirmed controller `install` to resume finalization. |
| `awaiting-bootstrap-session` | A fresh session for the published key has not been created. |
| `awaiting-proof` | The session exists but the existing script proof/host public key is incomplete. |
| `awaiting-authorization` | Proof is complete, but the existing worker-identity approval/link and live-read authorization/binding are not all current. |
| `awaiting-bundle` | Authorization is current; the worker bundle is not yet available. |
| `bundle-ready` | The strict worker-owned bundle is available; no contacted discovery snapshot is yet proven. |
| `discovery-contacted` | A real immutable snapshot proves `bundle_available=true` and `contact_state=contacted`. |
| `recovery-required` | Effects or rollback cannot be proven safe; manual recovery is required. |

Flags being true never produce a discovery-ready claim.

## Exact post-activation operator flow

The existing B8 post-activation operator flow remains exactly:

1. Wait for the worker to publish its `WorkerDiscoveryNode`.
2. Open the existing **Read-Only Bootstrap** wizard.
3. Select the published worker public key.
4. Create a new `ProxmoxReadOnlyBootstrapSession`.
5. Generate the existing idempotent Proxmox bootstrap script.
6. Run that script once as root on the already-strapped Proxmox host.
7. Confirm the returned proof and host public key in the existing wizard.
8. In the same wizard, complete the composite three-review worker-identity approval/link described
   below; then approve and bind the separate live-read authorization to the completed session.
9. Create/request the existing discovery enrollment.
10. Verify a real immutable snapshot records `bundle_available=true` and
    `contact_state=contacted`.
11. Verify the discovery-derived candidate plan remains `executable=false`.

The worker writes no bundle unless the bound session descriptor's recorded SSH public-key
fingerprint exactly matches the fingerprint freshly derived from its current local key. A descriptor
for the old installed Proxmox key, or a legacy descriptor without that fingerprint, is left inert and
the existing bundle is not modified. Return to steps 2–8 and run the existing script for the current
published node; do not copy a private key or repair the descriptor manually.

Step 6 is a key-rotation/binding step for the already-existing host strap. It requires no manual key
generation or private-key copy and does not rebuild the Proxmox account, forced-command wrapper,
role, or ACL. The PR5F implementation did not perform any of these eleven deployment operations.

At step 8 the browser re-matches a new or resumed session to exactly one current published node by
the session's server-recorded SSH public-key fingerprint; zero or multiple matches disable binding.
The operator reviews the displayed node revision, SSH fingerprint, and admission-anchor fingerprint,
supplies safe opaque `deployment_binding`, `proof_id`, and `issuer` metadata, and explicitly confirms
all three independent checks: deployment binding, verification anchor, and rotation/revocation.

The browser submits the node id plus the expected revision and both fingerprints to the composite
identity-approval-link API. The server requires `target_discovery:manage`,
`worker_identity:manage`, and the deliberately separate `worker_identity:approve` permission, locks
the current node and same-label registrations, and compares every expected value. Publication alone
grants nothing. A draft registration, changed/stale node, foreign organization, multiple current
registrations, stale/ambiguous live link, incomplete review, or metadata mismatch refuses. An exact
already-approved registration is reused only when its deployment binding, anchor, complete evidence,
proof id, and issuer all match. Under the same explicit rotation/revocation review, an exact link to
an expired or revoked same-node Ed25519 registration is CAS-cleared and replaced with a new monotonic
identity version; the terminal registration and evidence remain immutable audit history. A lost CAS,
draft, live mismatch, or partial renewal rolls back the whole request. The same-label old-anchor
rotation case is revoked before the new identity is registered, fully evidenced, approved, and
linked in the same transaction. The bootstrap-session bind and live-read authorization/binding
remain distinct gates.

## Evidence and residual boundary

The authenticated offer/result/aggregate evidence chain binds both base Compose content/metadata
inputs; the actual controller API,
admission-proxy, and ordinary-worker image/generation/config/mount/network/Compose runtime
projections; controller migration head `d8f1a2b3c4e5`; the exact worker base-image digest, overlay
digest, container generation and ordinary queue; rendered artifact digests; persistent-state
metadata; CA and server-certificate fingerprints/identity; worker public-key fingerprints;
`WorkerDiscoveryNode` id/revision; separate controller/worker installation identities, the aggregate
installation timestamp, and the signed handoff chronology; and created-versus-adopted classification.
It excludes private keys, raw environment files, database
or endpoint credentials, server keys, raw certificates where a fingerprint is enough, Proxmox
endpoint values, and full container-inspect payloads. Ownership, content, and mode are verified before
classification is trusted, and the aggregate evidence is not trusted until its detached Ed25519
attestation verifies against the reviewed controller key pin.

PR5F activates only the deployable **read-only discovery** surface. The controlled-live operator is
absent; installing its already-reviewed package is the next separate deployment step. No
controlled-live plan composition is installed, no real OpenTofu plan has run, apply/destroy remain
unavailable, and PR6 remains frozen.

Repository completion is not deployment completion: a deployment owner must still build and publish
the reviewed digest-qualified controller API/proxy images, build and transfer the exact overlay,
provision both evidence-key pins and the enabled profile, import deployment-local TLS material, run
the signed two-host activation sequence, rotate the target's SECP-managed public key through the
wizard, and observe the first contacted snapshot. PR5F performed none of those deployment steps and
made no SSH, Proxmox, workflow, Temporal, PostgreSQL, OpenBao, state-backend, registry, or other
external-service contact.
