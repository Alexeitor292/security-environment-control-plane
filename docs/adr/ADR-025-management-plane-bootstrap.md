# ADR-025 — management-plane bootstrap foundation + the three-plane hierarchy

- **Status:** Accepted for SECP-PR5E. Introduces the repository-owned management-plane bootstrap
  package `secp_management` and the customer-facing `secpctl` command: a signed offline release-bundle
  contract, closed controller/worker roles, local human-supervised controller + worker bootstrap, safe
  adoption of already-deployed installations, strict nonsecret evidence, and revalidating status. It is
  **local-first** — never a remote root-SSH deployment service — and it never activates the sealed
  controlled-live operator, constructs a Temporal `Worker`, submits a workflow, runs OpenTofu, or
  contacts any external infrastructure. Every host effect (observation and mutation) flows through
  **closed, typed, role-specific adapters** whose SHIPPED defaults are **SEALED** — so in the shipped
  repository (and on any host without reviewed real adapters installed) bootstrap, adoption, status,
  and rollback all **fail closed**, never reporting a false success.
- **Date:** 2026-07-18
- **Milestone:** SECP-002B-1B — **PR5E** (management-plane bootstrap foundation; follows PR5D
  operator-deployment package), with its roadmap corrected by **PR5F**. The B7/B8 browser Read-Only
  Bootstrap enrollment already exists; PR5F is the narrow production activation of that existing
  worker-owned read-only discovery flow. It is not a new generic browser-enrollment system and not a
  new Proxmox bootstrap contract. Operator package installation/activation remains separate;
  **PR6 (first apply) remains frozen**.
- **Related:** [ADR-024](ADR-024-operator-deployment-package.md) (sealed operator deployment package,
  reused verbatim); [ADR-023](ADR-023-commissioning-automation-foundation.md) (commissioning engine,
  reused for evidence/hardened-fs idioms); [ADR-001](ADR-001-monorepo.md) (package layout); runbook
  `docs/runbooks/pr5e-management-bootstrap.md`; PR5F runbook
  `docs/runbooks/pr5f-b8-production-activation.md`; STATUS `docs/STATUS.md`.

## The three SECP planes (product decision)

SECP is organized into three strict planes, ranked so a **lower plane may never create, mutate, reset,
adopt, or destroy an object in a higher plane**:

1. **Management plane** — controller hosts, site-worker hosts, management databases/API/UI/Temporal/
   MinIO/Keycloak, the ordinary worker, and the sealed controlled-live operator. SECP operates FROM
   here.
2. **Infrastructure plane** — Proxmox, vCenter, Kubernetes, cloud accounts, future managed targets.
3. **Scenario plane** — lab VMs/LXCs, scenario networks, vulnerable workloads, offensive tools, scoring.

SECP's management plane orchestrates the lower planes (it provisions scenario labs on the
infrastructure plane); the reverse is forbidden. **The controller and workers are MANAGEMENT-plane
objects — never scenario workloads or scenario deployment targets — even when a customer physically
hosts management VMs on the same Proxmox cluster used for scenarios.** This invariant is enforced by
`secp_management.planes` (`may_mutate`, `assert_not_scenario_target`) and by a static AST boundary test
(`tests/test_management_plane_boundary.py`) proving no scenario-plane plugin and no control-plane API
file imports the management-bootstrap write adapters — a lower plane can never receive the bootstrap
filesystem/service mutation capabilities.

## Local-first, human-supervised bootstrap

Controller bootstrap and worker bootstrap run **only locally** and are **human-supervised**: every
mutation defaults to dry-run and requires BOTH `--write` and `--confirm`. There is deliberately **no
default remote-root SSH**, no worker enrollment over the network, and no browser onboarding in PR5E.
Container deployment IS automated (from verified image archives, never a registry pull). Adoption
exists as a first-class operation for the already-deployed development installation.

That statement is historical scope for PR5E, not a claim that enrollment was still missing. B7/B8
already provide `WorkerDiscoveryNode`, `ProxmoxReadOnlyBootstrapSession`, and the browser Read-Only
Bootstrap wizard. PR5F reuses those exact records and UI after the ordinary worker has generated its
fresh persistent key. The currently strapped read-only Proxmox host must then adopt that public key
only through the existing idempotent wizard-generated script; this is key rotation/binding, not a new
generic browser flow or a second target-side initialization model.

## Signed offline release bundle

A release bundle is a directory carrying a canonical-JSON `release-manifest.json`, a detached
`release-manifest.sig.json` Ed25519 signature envelope, and a CLOSED inventory of reviewed artifacts
(compose templates, image archives, wheels, SBOMs). **Every image and security-sensitive wheel is
bound to exactly one closed, role-scoped PURPOSE** (`controller/<component>` for each stack component;
`worker/ordinary`, `worker/operator`, `worker/deployment-package`) — a missing, duplicate, unknown,
kind-mismatched, role-incompatible, or incomplete purpose set is refused. The controller component→
image mapping and the worker ordinary/operator images are therefore derived from this SIGNED mapping,
never from set membership or the observed host mapping, so a swap between two otherwise-valid release
images — or an ordinary worker running the operator image — is caught. The manifest binds every
artifact's exact SHA-256, so signing the canonical manifest signs the whole release (purposes
included); the aggregate release digest is the manifest's own canonical digest. **An image archive
carries BOTH its archive-content SHA-256 AND a separate signed expected loaded-image digest**; the
typed `VerifiedArtifact` carries both plus the signed purpose, and the mutation adapter proves the
image it actually LOADED equals the signed purpose-specific image digest — reading the right archive
bytes is necessary but not sufficient, the resulting image must match too
(`verified_artifact_image_digest_mismatch`). Parsing is fail-closed
(canonical JSON, duplicate-key rejection,
unknown-field rejection, strict typing, bounded values, forbidden-secret scan, relative safe names
only, no traversal). Verification anchors trust in a **code-owned `ReleaseTrustRoot`**; the SHIPPED
production trust root is **empty**, so a production bundle is refused until a reviewed anchor is pinned
by a separately-reviewed change. Production commits **no private release-signing key**; tests mint an
ephemeral, visibly test-only keypair. The signature is verified **before any artifact is trusted**, and
every artifact digest (+ size + non-symlink/non-hardlink/regular trust through the hardened filesystem)
is verified **before any host write**. **No floating image tag is ever trusted; no registry is
contacted; no network is used during verification.**

## Closed, TYPED effect adapters (no direct host effect in the engine)

The engine performs **no** host effect directly. It drives reviewed operations through four injected
seams — a read-only `ManagementHostObserver` and three mutation adapters (`ControllerBootstrapAdapter`,
`WorkerBootstrapAdapter`, `ManagementRollbackAdapter`). Every mutation op consumes an **exact typed
input** derived by the engine ONLY from the verified release: a `VerifiedArtifact` (role/kind/name/
digest/size + a hardened, digest-checked byte reader — never a bare name or an abstract digest), a
`ReviewedConfig`/`ReviewedUnit` (deterministic verified bytes + a content-bound identity), a typed
`ControllerBootstrapPlan`/`WorkerBootstrapPlan`, or a specific reviewed scalar (migration identity,
expected component set). No adapter exposes a generic subprocess/shell/argv/path/Compose-project/
systemd-unit/container verb. Each mutation adapter accumulates a `BootstrapReceipt` of the objects it
actually created and exposes a closed `compensate(receipt)` that removes **only** those objects and
returns a `CompensationResult` (proven, or a residual that forces `recovery_required`). **Once any
host op has been attempted, failure to obtain a VALID receipt is itself `recovery_required`** — a
receipt that cannot be retrieved, is malformed, or whose compensation raises/returns a residual is
NEVER read as proof that no effect occurred, and no compensation exception is ever swallowed. Only an
EXPLICIT empty receipt (a sealed adapter's proven no-effect refusal) proves nothing happened and
skips compensation. The SHIPPED
defaults are **sealed** (every call raises a bounded reason and returns an empty/proven receipt), so production fails closed until reviewed
real adapters — which compose the PR5C/PR5D read-only host adapters and wrap the pinned container-
runtime / `systemctl` seams and can consume these exact inputs and compensate partial effects — are
installed out of band. `EngineDeps` resolves these; **tests inject exact closed fakes; a `secpctl`
user can neither select nor inject an adapter** (the only path argument anywhere is the read-only
release-bundle source).

## Transaction model + evidence

Explicit phases, never implicitly chained: `verify → preflight → classify pre-existing → run closed
typed host ops → write documents → FINAL reobservation → commit-evidence+attestation → COMMIT GATE`.
**Before any host op** the write CLASSIFIES all **FIVE** target documents (identity, installed-release
manifest, signature, evidence, and the **evidence attestation** — a first-class owned document) and
permits only an ALL-FIVE-ABSENT (fresh) or an EXACT, fully revalidated idempotent same-release install —
refusing a partial (including an attestation-only/orphan state, the four core documents without the
attestation, or the attestation with only a subset of core docs), foreign, drifted, changed-release,
adopted, or disagreeing pre-existing state without touching the host, and NEVER trusting the evidence
mode/classification before the detached attestation has verified. It then executes the closed adapter
operations **in the reviewed order** (image load+digest → config/unit → `daemon-reload` →
migrations/start), writes the identity document
FIRST and the fixed **installed-release record** (the signed manifest + detached signature status later
rebinds to), and only then performs a **final coherent reobservation of the COMPLETE canonical end
state**: not just service booleans but the installed **config/unit/component/migration/deployment-
package identities**, the exact component→image mapping, AND a **mandatory, strictly-SHA-256
generation marker over a validated-COMPLETE raw generation tuple**. A matching marker is not
sufficient: the engine validates the raw facts BEFORE deriving/comparing the marker — for a worker a
nonempty ordinary container id, a nonnegative-integer restart count, a nonempty valid start timestamp,
a nonzero numeric PID while running, and a defined operator InvocationID for the present operator; for
a controller per-component container-id/restart-count/image maps whose keys EXACTLY equal the signed
component set, every id nonempty, every restart count a nonnegative integer — so a correctly-hashed but
incomplete tuple is refused. Plus — for a worker — `prepared` +
`sealed_prepared`, the operator disabled/stopped, and the ordinary worker not polling the operator
queue. Evidence is committed **last**, immediately followed by its **detached signed evidence
attestation**, and **only if** every check passes. **The attestation is the true commit point: a final
COMMIT GATE then re-reads the COMPLETE installed five-document state through the hardened filesystem,
re-parses the installed attestation, verifies the canonical evidence bytes + the Ed25519 signature
against the reviewed anchor, and confirms the expected key id / role / installation id / release
aggregate / mode plus exact owner/mode/type/link-count metadata — bootstrap/adoption returns success
ONLY when this gate passes.** On a sealed adapter, a failed
op, a failed reobservation, or a failed commit gate the write refuses; it compensates **only the
documents this invocation newly created** (a pre-existing/adopted object is never removed) AND the host
effects the adapter receipt records. Document compensation is **proven, not best-effort**: it restores
each overwritten document to its exact original bytes/metadata (re-read + re-lstat) and proves each
newly-created document absent; any restore/removal/reverification failure — or any unprovable host
compensation — forces `recovery_required` rather than an ordinary refusal after a mutation. The ordinary
worker is never restarted as compensation. Evidence and the identity document are strict
(`extra='forbid'`, frozen, strict), canonical, digest-bearing, and **nonsecret**: they carry only
identities, digests, topology-safe path bindings (never a raw path), the installed-artifact identities,
a **content-bound per-object ownership record** for each of the **five** documents (role/kind/binding/
content-SHA-256/uid/gid/mode/created-or-adopted; the evidence and attestation records self-bind — their
content is authenticated by re-canonicalization and the detached Ed25519 signature respectively),
queue names, seal states, and narrowly scoped effect booleans
(`forbidden_infrastructure_contacts_performed`/`workflows_submitted`/
`run_plan_generation_called`/`opentofu_executed`/`proxmox_contacted`, all `false`).

## Revalidating status + real rollback

All **five** managed documents (identity, installed-release manifest, signature, evidence, evidence
attestation) are checked by
ONE shared **installed-document integrity verifier** — fixed path binding, regular-file/no-symlink,
single link, exact UID/GID/mode, AND (for the three signed documents) exact content against digests
derived **INDEPENDENTLY** of
evidence: the manifest/signature from the signature-verified release record, the identity from its
release-binding. Evidence is **not** self-authenticated by mere canonicalization — its recorded
per-object digests are cross-checked against those independent digests, so a canonical but re-authored
evidence that rewrote the expected digests is caught (`evidence_object_record_forged`). The evidence and
attestation are self/independently-verified records (no embedded content digest): the attestation's own
binding/UID/GID/mode/type/link-count are authenticated by the verifier, its content by its Ed25519
signature. The verifier is
invoked from status, pre-existing classification, adoption classification, and rollback (object_records
are not rollback-only).

Above these cross-checks sits an **independent, detached signed evidence attestation** — a **fully-owned
FIFTH managed document** (its own `ManagedObjectRecord` carries its binding/UID/GID/mode/classification,
so pre-existing classification counts it and rollback removes it ONLY when its authenticated ownership
record proves the transaction CREATED it — an orphan/foreign/pre-existing attestation is never
overwritten or deleted). It is a closed-typed document signed by a reviewed
`ManagementEvidenceAuthenticator` (SHIPPED sealed; tests use an ephemeral test-only Ed25519 key) over a
canonical message covering the **canonical evidence bytes, the canonical identity digest, the signed
release aggregate, role, installation id, install/adopt mode, transaction timestamp, and every managed
object record**. Evidence is **not trusted until its attestation verifies against a reviewed, provisioned
anchor** — so status, `evidence`, pre-existing classification, adoption classification, and rollback all
verify the attestation BEFORE trusting the evidence mode/classification/ownership/timestamps/object
records/created_records, and a forged/missing/wrong-key attestation refuses
(`evidence_attestation_untrusted`, `attestation_unreadable`) before any effect. Because the attestation
binds the mode, a canonical evidence
rewrite from adopted→installed (which would otherwise make an adopted install look rollback-owned) is
refused before any mode-specific logic or rollback planning. A sealed authenticator makes a production
bootstrap/adoption fail closed (`evidence_authenticator_not_provisioned`) before any evidence is written;
production commits no authenticator private key.

`secpctl status` independently reloads the evidence, the management identity, and the installed-release
record (**reverifying its Ed25519 signature against the code-owned trust root**, with no caller-supplied
bundle), runs the shared verifier, and compares a **fresh coherent observation** to the COMPLETE
end state **derived from the SIGNED record** — the installed config/unit/component/migration/deployment-
package identities and the EXACT signed component/ordinary/operator image mapping — so a changed config,
unit, image, mapping, migration, or package aggregate produces drift and refuses; a worker additionally
consumes the observer-composed **real PR5C commissioning status and PR5D deployment verification**.
Stored booleans and historical effect flags never satisfy status without live reobservation.
`secpctl rollback` verifies the attestation FIRST (before trusting the mode/created_records), then runs
the shared verifier — refusing a re-authored /
drifted / substituted document or a metadata drift BEFORE any removal — then removes **only** the
transaction-created documents (each resolved from its authenticated `created` ownership record — the
attestation among them, never appended unconditionally) through the closed rollback adapter and
**reverifies each is gone**.
Removal is **transactional**: it captures every planned document's exact bytes/metadata first, removes
in a fixed order (identity, manifest, signature, attestation, **evidence last** — preserved until every
other removal succeeds), and if ANY removal or post-removal verification fails it RESTORES every
already-removed document and proves each restoration, returning an ordinary refusal only after the
installation is fully restored — never leaving a partially-removed installation behind. If a
restoration cannot be proven it reports `recovery_required`. It returns
`written` only when real removals are proven, refuses an adopted installation, and returns a bounded
`rollback_not_implemented` when the sealed adapter is in place (a no-op adapter is caught as
`rollback_removal_incomplete`). It never restarts the ordinary worker and never removes controller
persistent data.

## Adoption is a COMPLETE, non-dead-end state

Adoption refuses unless the host ALREADY matches the **complete canonical prepared end state** a
successful bootstrap would produce — for a worker: coherent observation, ordinary present/running/
healthy on the exact image, config + health-command identities, operator present/disabled/stopped on
the exact unit identity, the deployment-package aggregate, no operator-queue polling, package trusted,
real commissioning `prepared` AND deployment `sealed_prepared`, safe seals; for a controller: coherent,
the exact expected component set all running + healthy on release images, config + unit + migration
identities, no unknown privileged service. (The reobservation gate and the adoption precondition share
one code path, so an adoption can never be a dead end while bootstrap-over-adopted is refused.) Its
writes are transactional AND **TOCTOU-closed**: it classifies all FIVE target documents, installs
identity + the signed release record, then obtains a FINAL coherent observation and proves its ABA
generation marker is UNCHANGED from the admission observation (nothing restarted/replaced in between)
AND re-runs the complete end-state predicate — and only THEN writes evidence + attestation last, gated
by the same COMMIT GATE (re-read + full five-document + attestation verification) as bootstrap. A worker
restart, an operator start, a health degradation, or a controller generation change between admission
and commit — or a commit-gate failure — refuses and compensates the newly created documents (no partial
adoption, no evidence). It runs NO
mutation adapter op, loads no image, restarts nothing, and never modifies the ordinary worker.

## Worker prepared-state reconciliation

The worker bootstrap leaves the ordinary worker running (queue `secp-orchestration`) and the
controlled-live operator **present, disabled, and stopped** (queue `secp-controlled-live-v1`), with the
operator systemd unit rendered from a hardened template that has **no `[Install]`/`WantedBy` and no
auto-start** — mirroring the operator-activation seal. The worker write starts **only** the ordinary
worker; there is no adapter op or plan step that starts or enables the operator. `secpctl status worker`
consumes BOTH the commissioning `prepared` state (PR5C) and the deployment `sealed_prepared` state
(PR5D) as composed by the observer from the SAME coherent, generation-checked host observation, so an
ABA restart, a changed PID, an enabled/running operator, an untrusted package, or an unhealthy ordinary
worker fails both dimensions closed. PR5E does not weaken PR5D package trust and exposes no path that
starts the operator.

## Preserved safety invariants

`_OPERATOR_ACTIVATION_SEALED = True`, `_PLAN_ONLY_PROCESS_SEALED = False`, both
`_B1A_SUBPROCESS_SEALED = True`; ordinary queue `secp-orchestration`, operator queue
`secp-controlled-live-v1` (distinct; the ordinary worker never polls the operator queue); no operator
Temporal `Worker` construction; no workflow submission; no `run_plan_generation`; no OpenTofu; no
apply/destroy; no Proxmox mutation; no OpenBao contact. **PR5E adds no activation command.** PR6 frozen.

## Consequences

- A new importable package `secp_management` (+ `apps/management/tests`) is wired into the hatch wheel
  packages, the `secpctl` console script, pytest `pythonpath`/`testpaths`, mypy `mypy_path` + the CI
  type-check target, the `.ci/pytest-suite.json` sharding roots, and a dedicated `backend-management-root`
  CI job (sudo + fail-closed ancestor preflight + JUnit zero-skip gate) in the aggregate backend gate.
- The lower planes stay decoupled: no scenario plugin or API file imports the bootstrap write adapters
  (boundary-tested).
- PR5F adds the separate, narrow `secp_discovery_activation` package for production deployment of the
  existing B8 read-only path. It supplies no new enrollment model and does not make the general PR5E
  bootstrap adapters real. The externally completed Proxmox read-only strap is adopted by rotating
  its SECP-managed key through the existing wizard script after persistent worker-key generation.
- PR5F also resolves the deployed-code gap without pretending that the old worker image alone is the
  final runtime: the exact old reviewed image remains the base, while a complete content-addressed
  `secp_api` + `secp_worker` ZIP is mounted read-only under an exact `PYTHONPATH`. The controller uses
  a new digest-qualified API image and must report Alembic head `d8f1a2b3c4e5`. Fixed controller and
  worker base Compose inputs are content/metadata CAS-bound, actual API/proxy/worker runtime
  projections are reobserved, and the two role-local transactions are joined only by detached-signed
  fixed outbox/inbox handoffs.
- The internal admission listener binds only the reviewed private IP, while TLS continues to verify
  the exact endpoint DNS name as SNI/SAN; the worker's sole `extra_hosts` entry binds that DNS name to
  the listener IP. The browser reuses the existing node/session records and performs an exact-node,
  three-review identity approval/link before the separate live-read authorization/bind gate. This is
  the roadmap replacement for the previously imagined generic browser enrollment.
- After PR5F, installing the already-reviewed controlled-live operator package is the next separate
  deployment step. A controlled-live plan composition and operator activation remain absent; no real
  OpenTofu plan has run, apply/destroy remain unavailable, and PR6 remains frozen.

## Management-plane bootstrap: SUPPORTED, NOT EXERCISED

The engine's orchestration — the signed purpose-mapping derivation, the complete typed image contract
(archive digest + signed loaded-image digest + purpose, with the loaded image proven against the signed
digest), the FIVE-document pre-existing-install
classification (the detached attestation a fully-owned document, verified before the mode/classification
is trusted), the ordered typed operations, the final-reobservation gate over the complete end state
(exact signed image mapping + config/unit/component/migration/package identities + a SHA-256 generation
marker over a validated-COMPLETE raw generation tuple), the post-write COMMIT GATE that re-reads and
fully verifies the installed five-document state + attestation signature/fields/metadata before
returning success, the PROVEN compensation of
only newly-created documents AND the fail-closed adapter-receipt host compensation (with
`recovery_required` on any lost/malformed receipt or unprovable compensation), the release-record
rebinding, the detached signed evidence attestation + the shared independently-authenticated
installed-document verifier, the identity-revalidating status, the complete non-dead-end + TOCTOU-closed
adoption, and the transactional content-bound rollback (attestation bound to its created record, evidence
last, full restore-on-failure) — is implemented and tested end to end against an in-memory
(and, under root CI, a real) hardened filesystem, exact closed **fake** adapters that consume the typed
inputs, and an ephemeral test-only signing key. This PR establishes the safe engine + the closed TYPED adapter contract; the leaf real
adapters that perform the actual Docker/Compose/systemd effects are a **later, separately reviewed
milestone** and are **not shipped**. The shipped observer/mutation/rollback defaults are **sealed**, so
**no real host is currently bootstrap-capable from the shipped repository** — a production bootstrap/
adoption/status/rollback **fails closed** rather than reporting a false success. **No successful
adoption ever represents an incomplete worker, and no rollback ever removes content that has drifted.**
Nothing here has bootstrapped or adopted a real controller or worker, contacted any host, or activated
anything; no release has been signed with a production key (none exists). Documentation and fixtures
use RFC-reserved / documentation values only — the real deployment-local controller/worker host
addresses are never committed.

PR5F does not retroactively change those PR5E claims. The general `secp_management` host adapters
remain sealed and unexercised. `secp_discovery_activation` is a separate, fixed-purpose package for
only the ordinary worker's B8 state/runtime overlay, the digest-qualified PR5F controller API and
migration, internal admission TLS, signed cross-host coordination, and transactional worker
recreation; its repository implementation likewise was not installed or exercised by PR5F. The
existing Proxmox strap still requires post-activation key rotation through the existing idempotent
wizard script. PR5F installs no operator, constructs no controlled-live plan composition, and
authorizes no OpenTofu/apply/destroy action.
