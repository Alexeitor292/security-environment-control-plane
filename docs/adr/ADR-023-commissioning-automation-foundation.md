# ADR-023 — commissioning automation foundation

- **Status:** Accepted for SECP-PR5C. Establishes a versioned, testable commissioning ENGINE that
  prepares a deployment and stops at **PREPARED, NEVER ACTIVATED**. It unseals nothing, starts no
  operator worker, submits no workflow, runs no OpenTofu, and contacts no Proxmox / OpenBao / remote
  state / Temporal / PostgreSQL. `_PLAN_ONLY_PROCESS_SEALED` stays exactly `False`; both
  `_B1A_SUBPROCESS_SEALED` constants stay exactly `True`; `SECP_ENABLE_REAL_PROVISIONING` and the
  generic-OpenTofu-subprocess flag stay `false`; controlled discovery and worker-managed bundle mode
  stay disabled. There is deliberately **no `activate` command** in this milestone.
- **Date:** 2026-07-17
- **Milestone:** SECP-002B-1B — First Real Disposable-Lab Lifecycle, **PR5C** (commissioning
  automation; follows ADR-022 PR5B). PR6 (first apply) remains frozen.
- **Related:** [ADR-022](ADR-022-plan-only-activation-and-process-boundary.md) (plan-only activation
  + operator bootstrap + task-queue routing §12); [ADR-020](ADR-020-first-real-disposable-lab-lifecycle.md)
  (B1-B architecture lock, phased unsealing, activation dossier §D); [ADR-021](ADR-021-remote-state-and-jit-secret-readiness.md)
  (readiness evidence disciplines); [ADR-001](ADR-001-monorepo.md) (package
  layout); operator flow doc `docs/runbooks/pr5c-commissioning-experience.md`; architecture
  `docs/architecture/secp-002b-1b-real-lab-lifecycle.md`; STATUS `docs/STATUS.md`.

> **Nothing here activates anything.** This PR adds a repository-owned commissioning tool
> (`python -m secp_commissioning`). Merely importing, planning, rendering, or even running
> `install-prepared --write` **cannot** start an operator worker, submit a workflow, call
> `run_plan_generation`, run OpenTofu, resolve a credential, or contact Proxmox / OpenBao / a remote
> state backend / Temporal / PostgreSQL. No such call exists in the package — proven by the static +
> behavioral automation-boundary tests. The operator entrypoint it renders is installed **disabled**
> and **fails closed** (`controlled_live_composition_not_installed`) until a separately-reviewed
> deployment package supplies the typed controlled-live compositions.

> **The running ordinary worker is never touched.** The exact reviewed PR5B ordinary-worker image
> (source `63440c93957afd3f4d106115f19aee2924df9c68`) keeps running unchanged. Commissioning writes
> ONLY operator-preparation material under a root-controlled directory; the ordinary worker's files
> and container are outside the installer's write and rollback ownership sets, and the entrypoint
> never reads `temporal_operator_task_queue` — so no commissioning path can restart, re-point, or
> re-register it.

> **Second-iteration hardening addendum (current truth, 2026-07-17).** A pre-merge boundary review of
> PR #55 found and closed multiple merge-blockers; the design below is amended accordingly (the
> earlier decisions stand where unqualified):
> 1. **No arbitrary root write targets.** The descriptor no longer carries ANY absolute install path
>    (`entrypoint_install_path` and `managed_directories` are removed). A trusted, executable-owned
>    `CommissioningLocations` fixes the descriptor path, the evidence path, and the single operator
>    root; every install basename is executable-owned and resolved strictly beneath that root, beneath
>    NO protected root (ordinary-worker, control-plane, release, database, Docker, systemd-global,
>    SSH, `/etc`, `/root`, `/boot`, system bin dirs). The CLI exposes no `--descriptor`/`--evidence`/
>    `--staging` flag; tests inject alternate locations via typed DI. A fuzz test asserts every
>    writable + rollback-owned target stays under the operator root under arbitrary inputs.
> 2. **Symlink-safe root installation.** The filesystem backend walks every path component refusing
>    symlinks + non-directory ancestors, opens `O_NOFOLLOW` via `dir_fd`/`openat`, re-validates the
>    parent by `fstat`, refuses a final target that already exists as a symlink/dir/device/socket/
>    FIFO/foreign hardlink, never follows a symlink during `chmod`/`chown`, and removes temporaries on
>    every failure. Reads use the exact `fstat` size with short-read/growth/inode-change refusal.
> 3. **Drift is REFUSED, never repaired.** Absent → create; already-correct-and-matching → idempotent;
>    a foreign/drifted pre-existing file or directory is refused WITHOUT modification. Evidence records
>    the ACTUAL transaction ownership set (which roles THIS install created); rollback removes only
>    those (verified by re-derived path binding + on-disk digest), files then dirs, then the evidence
>    record LAST. Nothing pre-existing/foreign/modified/ordinary-worker is ever removed.
> 4. **Strict, topology-safe evidence.** Evidence stores NO raw path — each object is a stable ROLE +
>    a topology-safe `path_binding` digest; status/rollback re-derive the path from the trusted
>    locations. The record is pydantic-strict (`extra="forbid"` + `strict=True`, so JSON `true`/`false`
>    only, closed role vocabulary, unique roles, exact digest/version shapes) + forbidden-secret
>    scanned, and is read through the hardened filesystem reader (never a raw `json.loads` on an
>    arbitrary path). Reason codes never echo a value, key, or caller-controlled path.
> 5. **Truthful service/process state.** The default adapter fails closed as "inspection unavailable";
>    planning refuses unless the operator is inspected + disabled + not-running + absent, and install
>    RE-CHECKS the adapter immediately before the first write AND before committing evidence, so a
>    stale fact can never write a false-healthy record.
> 6. **Independent identity pins.** `ExpectedIdentities` independently pins the release source + tree
>    (+ optional parent) SHAs, the three image digests, runtime UID/GID, both queue names, the ordinary
>    health command, and the entrypoint-template digest; the descriptor must MATCH — it is never the
>    sole source of truth. Any mismatch fails before render or write.
>
> **Third-iteration hardening addendum (current truth, 2026-07-17).** A final independent boundary
> review found and closed additional merge-blocking defects; the design below is amended accordingly:
> 1. **Image readiness gates EVERY non-refusal result.** Install observes each of the three exact image
>    digests EXACTLY once per check (one immutable `ImagePresenceSnapshot`, so a stateful runtime cannot
>    answer inconsistently), refuses `image_not_present` BEFORE any `already_prepared`/`dry_run`/`written`
>    outcome, RE-observes presence immediately before committing evidence, and rolls back exactly the
>    objects it created if an image vanished mid-write. Status reports drift if an image later disappears.
> 2. **Ordinary-worker readiness is required, atomically.** The service adapter returns ONE immutable
>    `ServiceStateSnapshot` per observation (never several methods that can disagree). Planning refuses
>    `ordinary_worker_not_running`; install re-checks in every mode (a read-only preview cannot report
>    `already_prepared` while the operator is active or the ordinary worker is down); status reports
>    invalid. Commissioning never contacts, starts, or modifies the ordinary worker.
> 3. **Root-controlled filesystem ancestors.** Every managed read/write/remove fstat-verifies that `/`
>    and EVERY ancestor is a real, root-owned, non-group/other-writable directory (opened `dir_fd` +
>    `O_DIRECTORY` + `O_NOFOLLOW`); a missing ancestor is refused (a managed write never relies on an
>    absent parent — the bootstrap-owned evidence parent must pre-exist root-owned + restrictive). The
>    in-memory backend models the SAME refusals (including `sha256`/`list_dir`) so the invariant is
>    tested cross-platform; the real backend is exercised POSIX-root only.
> 4. **Transactional `makedir`.** If any post-mkdir validation/open/chmod/chown fails, the directory
>    THIS call created is removed through the still-open trusted parent `dir_fd`; a pre-existing
>    directory is never removed and the original bounded reason is preserved. **Caveat:** if the
>    compensating `rmdir` itself fails, a distinct `fs_makedir_cleanup_failed` is raised and absolute
>    atomicity cannot be guaranteed past that point (the half-created directory may remain and is
>    reported by a subsequent status/preflight as drift) — this is the one documented boundary of the
>    makedir transaction.
> 5. **Evidence semantic completeness.** A `prepared` record must bind EXACTLY the reviewed role set
>    (four file roles + one directory role, no missing/extra/duplicate) with exact per-role root
>    ownership + mode, distinct queues, the EXACT current tool version + contract version + entrypoint-
>    template digest (not merely a valid shape), and a real timezone-aware ISO-8601 instant (parsed, not
>    regex-only). Status additionally compares the record's implementation identities to the CURRENT
>    running implementation before reporting `prepared`.
> 6. **Rollback verifies the WHOLE created set first.** Before removing the first object, rollback
>    verifies every created file (role/path binding, regular, `nlink==1`, exact recorded uid/gid/mode,
>    exact digest) and every created directory (real non-symlink dir, exact recorded uid/gid/mode, and a
>    safe enumeration proving NO foreign child). A hardlinked, metadata-modified, or foreign-child-bearing
>    object aborts the whole rollback with nothing removed; evidence is removed last.
> 7. **Complete trusted-identity enforcement.** Planning additionally requires `expected.tool_version`
>    == current tool version, `expected.contract_version` == current contract version, the fixed reviewed
>    `operator_registration_symbol`, the current entrypoint-template digest, and binds `control_plane.source`
>    to the SAME trusted release identity as the ordinary worker's.
> 8. **Staging-root hardening.** The renderer validates the staging root's type + trusted ownership +
>    restrictive (non-group/other-writable) mode through an injectable seam, writes fixed basenames with
>    `O_EXCL`/`O_NOFOLLOW`, and unlinks a partially-written staging file on short-write/error. The staging
>    bundle is NOT the authoritative install input — `install-prepared` writes the in-memory `RenderResult`
>    content through the hardened filesystem backend to the operator root — so staging is an inspection
>    artifact, not a path by which content can reach the operator root.

## Context

The final installation must be **plug-and-play**. The only expected manual infrastructure action is
running one initial bootstrap script on the Proxmox environment; everything afterward must be driven
by an idempotent installer and, eventually, by the SECP web onboarding wizard.

The lengthy manual procedures used during PR5B activation (detached release checkout, source/tree
verification, image build + OCI labels, image export/checksum/transfer/load, worker environment +
Compose validation, readiness-health installation, startup/rollback, Temporal queue/session proof,
database-role/outbox proof, operator-absence proof, evidence recording) are **validation prototypes
and a golden specification** — not an acceptable final installation experience. They are shell-driven,
non-idempotent, non-evidential, and easy to run partially or out of order.

This PR converts that golden specification into a reusable, versioned, tested Python engine, without
activating an operator worker or contacting external infrastructure.

## Decision — locked

### 1. One Proxmox bootstrap script, then an idempotent engine, then the web wizard

The product contract is: **one** manual Proxmox initialization script → browser onboarding wizard →
environment inspection → an immutable commissioning plan → explicit administrator confirmation →
automated installation + validation → first supervised plan-only operation → separate human
approval. This PR implements the software spine of the middle of that flow (inspect → plan → render →
verify → install-prepared → status → rollback-prepared → evidence) and marks the rest as future work.

### 2. One engine, two front ends (CLI now, web wizard later) — they cannot diverge

The commissioning logic lives entirely in tested Python (`apps/commissioning/secp_commissioning`).
`python -m secp_commissioning <phase>` is the administrator CLI; every phase also emits deterministic
`--json`, so the future web onboarding wizard calls the SAME engine and the SAME output rather than
reimplementing commissioning logic. A behavioral test asserts the CLI's plan digest equals the
engine's directly-computed digest (**web/CLI convergence**). Thin shell wrappers are acceptable, but
the validation, planning, idempotency, safety, and evidence logic is Python, not shell.

### 3. Explicit phases; NO activate

The modelled phases are `inspect`, `plan`, `render`, `verify`, `install-prepared`, `status`,
`rollback-prepared`, `evidence`. There is **no `activate`**. `status` can only ever report
`absent | invalid | drifted | prepared | activation_not_supported`; the last is the honest terminal
answer to any request that would activate the operator.

### 4. Separated commissioning for control-plane, ordinary worker, and operator worker

The versioned descriptor has three distinct sections — `control_plane`, `ordinary_worker`,
`operator_preparation` — each with its own pinned source/image/runtime/resources. Only
`operator_preparation` material is rendered and installed by this PR (disabled). The `ordinary_worker`
section is **descriptive**: it pins the already-running worker's source SHA + shipped queue so the
plan can *refuse* a descriptor that contradicts the reviewed pins, but commissioning installs no
ordinary-worker file and never restarts it.

### 5. Exact-image + source-revision pinning; air-gapped image transfer

Every image is pinned by BOTH a documentation reference AND a `sha256:` content digest. The plan
refuses unless the `ordinary_worker.source.source_sha` equals the reviewed pin. `install-prepared`
verifies the exact image DIGESTS are present via an **injected local container-runtime adapter** — it
NEVER pulls or contacts a registry (the shipped default reports every image absent, so a real image
check requires an explicitly injected adapter). This models the air-gapped flow: images are exported,
checksummed, transferred, and `load`ed out of band; commissioning only *verifies presence by digest*.

### 6. Idempotency, drift, overwrite refusal

The plan is deterministic and canonically hashable over its **intent** (descriptor + reviewed pins),
excluding observed drift, so a host change (e.g. an image being loaded between runs) never flips the
plan digest. `install-prepared` is idempotent: a re-run against an identical plan makes **no change**
and preserves the evidence byte-for-byte (across timestamps). A **different** plan digest **refuses**
silent overwrite (`plan_digest_changed_refusing_overwrite`). `status` re-verifies file digests +
ownership/mode + image presence + operator-service-disabled independently — never inferring readiness
from configuration presence.

### 7. Root-controlled deployment-local material; dry-run by default

Rendered material targets root-owned, non-world-writable directories. `install-prepared` and
`rollback-prepared` default to **dry-run**; a real write requires BOTH `--write` and `--confirm`
(noninteractive-automation friendly). Writes are atomic (`os.replace`) and a **partial** write rolls
back atomically (created files then created directories, reverse order). `rollback-prepared` removes
ONLY the files the matching plan created (verified by recorded digest) plus the now-empty managed
directories; a **foreign or modified** file is refused (`rollback_foreign_object` /
`rollback_modified_file`), and the ordinary-worker paths are never in the ownership set.

### 8. Secret handling — secret-free by contract AND by scanner

The descriptor carries **no** credential, token, password, private key, secret reference, OpenBao
path, state key, or provider credential. It is `extra="forbid"`, bounded, and rejects blank /
wildcard / placeholder / sentinel values; an explicit forbidden-field + forbidden-pattern scanner
rejects secret-like field NAMES at any depth and secret-material VALUE patterns (PEM keys, `vault:` /
`openbao:` refs, bearer tokens, cloud keys, JWTs) **before** the schema is even constructed. No
secret ever appears in CLI arguments, environment output, logs, evidence, fixtures, or test
snapshots. Every failure is a bounded closed reason code that names a NON-secret field path — never a
value. Repository fixtures use only RFC-reserved names (`example.test`) and RFC 5737 documentation
address ranges.

### 9. Root-controlled descriptor + evidence reader hardening

The descriptor is read from a FIXED root-controlled path by a reader that mirrors the repo's most
hardened mounted-bundle reader: every path component is `lstat`-ed and any symlink is refused; the
final file is opened `O_NOFOLLOW` and re-validated **by descriptor** (`fstat`: regular file, root
owner, restrictive mode, single hard link, bounded size) so a post-`lstat` replacement race is
defeated; the size is bounded BEFORE the single read; and JSON is parsed with duplicate-key
rejection. All OS interaction goes through an injectable seam, so the full hardening is tested without
real root or real symlinks. The reader reads **exactly once**.

### 10. Evidence generation — secret-free, immutable, topology-safe

`install-prepared` writes an immutable, canonically-serialized evidence record: contract + tool
version; source revision + tree; the three image content DIGESTS; the descriptor / plan /
render-manifest digests; a bounded list of installed-file digests + ownership/mode expectations; the
ordinary + operator queue NAMES; an `activation_status` that is EXACTLY `not_started` or `prepared`;
and REAL boolean seals (never `0/1`) proving `operator_service_enabled=false`,
`operator_service_running=false`, `external_contacts_performed=false`, `workflows_submitted=false`,
`plan_execution_performed=false`; plus a timestamp. It records **no** image registry reference (a
registry host is topology — only the digest), **no** site/environment label, and **no** raw
descriptor value that could expose deployment topology. A tampered on-disk record (flipped seal,
injected status, bad digest) fails closed on load.

### 11. Failure recovery + upgrade strategy

A refusal never leaves partial state (writes roll back; evidence is written last). Re-running any
phase is safe (inspect/plan/render/verify are side-effect free; install-prepared/rollback-prepared
are idempotent). An **upgrade** re-runs `install-prepared` against a new descriptor: an unchanged
plan digest is a no-op; a changed plan digest refuses silent overwrite, so an operator explicitly
`rollback-prepared`s the old plan (removing only its files) before installing the new one — history
is never mutated. The descriptor `contract_version` is exact-match; there is no best-effort upgrade of
an out-of-contract descriptor.

### 12. Why development PR/CI operations are NOT customer installation steps

Building the image, running CI shards, checking out a detached release, and force-pushing a review
branch are **developer** actions performed against source control and a build host. A customer
installs from a pinned, checksummed, air-gapped image + a signed descriptor; they never build from
source, never run pytest, and never touch Git. The commissioning engine is the customer-facing
boundary; the manual PR5B scripts are its golden specification, mapped below to their final automated
owner.

## Manual-to-automation ledger

| Manual PR5B procedure (golden spec) | Final automated owner (this PR unless noted) |
|---|---|
| Exact detached release checkout | Out of band (build host); the descriptor pins `source_sha` + `source_tree_sha`; the plan **refuses** a mismatch (`ordinary_worker_source_mismatch`). |
| Source / parent / tree verification | Descriptor `SourceRevision` (40/64-hex) + plan pin enforcement; recorded in evidence (`source_sha`, `source_tree_sha`). |
| Image build + OCI revision labels | Out of band (build host). The descriptor pins `image.reference` + `image.digest`; commissioning verifies the digest via the injected runtime adapter. |
| Image export / checksum / transfer / load (air-gapped) | Out of band (operator). `install-prepared` verifies exact image **digest presence** via the injected adapter — never pulls (`image_not_present` on absence). |
| Worker environment + Compose validation | `render` (ordinary-worker config, descriptive) + `verify` (descriptor + plan preconditions). |
| Readiness-health installation | `render` (operator service definition, **disabled**) + `install-prepared` (installs disabled). Ordinary-worker health command is pinned in the descriptor + evidence. |
| Startup + rollback | `install-prepared` (dry-run default; `--write --confirm`) + `rollback-prepared` (removes only planned files; refuses foreign/modified). Operator service is installed disabled and **never started**. |
| Temporal queue / session proof | Plan + evidence pin `ordinary_task_queue` (`secp-orchestration`) and the DISTINCT `operator_task_queue`; the rendered operator entrypoint resolves the queue only via the reviewed resolver. Live proof remains a future operator step. |
| Database-role + outbox proof | Descriptor `ordinary_worker.db_role` (role NAME only); recorded in the ordinary-worker config bundle. No DB contact occurs (future operator step). |
| Operator absence proof | `status` re-verifies `operator_service_enabled=false` + `operator_service_running=false` via the injected service-state adapter; evidence seals assert the same. |
| Evidence recording | `install-prepared` writes the immutable, secret-free evidence record (§10). |
| Upgrade + rollback | §11: idempotent re-install; changed-plan overwrite refusal; explicit rollback of the prior plan. |

## Threat model

| Threat | Prevention | Refusal reason code | Residual risk |
|---|---|---|---|
| Secret smuggled into the descriptor (field name or value) | Forbidden-field + forbidden-pattern scanner runs before schema; `extra="forbid"` | `forbidden_secret_field:<path>`, `forbidden_secret_value:<path>` | A novel secret encoding not in the pattern set — mitigated by evidence carrying only digests + closed vocabularies. |
| Symlinked/replaced descriptor (TOCTOU) | Per-component `lstat` + `O_NOFOLLOW` open + `fstat` re-validation of the opened descriptor | `descriptor_symlink`, `descriptor_path_symlink`, `descriptor_not_root_owned`, `descriptor_hardlinked` | A compromised root can defeat any root-controlled reader — out of scope (root is the trust anchor). |
| Oversized / malformed / duplicate-key descriptor | Bounded size before read; strict UTF-8 + JSON; duplicate-key rejection | `descriptor_size_invalid`, `descriptor_malformed_json`, `descriptor_duplicate_key` | — |
| Descriptor contradicts the reviewed ordinary-worker pins | Plan enforces source SHA + queue equality | `ordinary_worker_source_mismatch`, `ordinary_worker_queue_mismatch` | — |
| Operator queue == ordinary queue (queue confusion) | Descriptor model validator + plan check | `operator_queue_not_distinct` | — |
| Accidental operator activation | No activate command; entrypoint installed disabled + fails closed; boundary tests forbid Worker construction / service start | `controlled_live_composition_not_installed` | An operator manually editing + starting the unit is out of scope (requires a reviewed deployment package first). |
| Accidental external contact | No `subprocess`/`temporalio`/HTTP-client import anywhere in the package (AST-proven); injected sealed adapters | (import-time impossibility) | — |
| Ordinary-worker modification | Only operator-preparation paths are written; entrypoint never reads the operator queue setting; boundary test asserts writes stay under the operator dir | — | — |
| Silent overwrite of a differently-planned deployment | Evidence plan-digest comparison | `plan_digest_changed_refusing_overwrite` | — |
| Rollback deleting a foreign/modified file | Per-file recorded-digest verification before any removal | `rollback_foreign_object`, `rollback_modified_file` | — |
| Evidence leaking deployment topology | Evidence stores digests + closed vocabularies only; no reference/label/path-to-endpoint; redacted repr | — | — |

## Adversarial-review findings — confirmed and fixed in this slice

| # | Defect | Fix |
|---|---|---|
| 1 | Plan digest included observed drift (image present/absent), so a host change flipped the digest and broke idempotency | `CommissioningPlan.digest()` hashes an **intent** projection excluding `action`/`state`/`changes`. |
| 2 | Reader trusted the `lstat` result for the final file (replacement race) | The opened descriptor is re-validated by `fstat`; ownership/type/nlink/size come from the descriptor, not the path. |
| 3 | Evidence timestamp broke idempotent re-install | Evidence `digest()` excludes `recorded_at`; install compares plan digests and preserves the record on a match. |
| 4 | Forbidden-secret scanner could echo a value in the reason code | Reason codes carry a sanitized, bounded FIELD PATH only; a value never appears. |
| 5 | Rendered operator entrypoint could have embedded the descriptor's queue/values | The entrypoint is a FIXED template that interpolates nothing and resolves the queue only via the reviewed resolver; a test asserts it contains no descriptor value and no shipped-only workflow. |

## Accepted, disclosed residual risks

1. **A compromised root** can defeat any root-controlled reader/installer; root is the trust anchor,
   not a threat this PR defends against.
2. **The container-runtime + service-state adapters are injected**; the shipped defaults fail closed
   (image absent, operator disabled). A real deployment must supply reviewed adapters — a passing
   in-memory test is NOT evidence that a real host's images are present or its operator is disabled.
3. **The operator entrypoint is a template.** It is inert until a separately-reviewed deployment
   package supplies the typed controlled-live compositions + the run hook; this PR neither writes nor
   reviews that package.

## Consequences

- A new importable package `secp_commissioning` (+ `apps/commissioning/tests` test root) is wired
  into the build, pytest, mypy, and CI sharding manifests.
- The commissioning engine is decoupled: it imports no `secp_api`/`secp_worker`/`temporalio`; the
  reviewed operator seams are referenced only inside the rendered entrypoint TEMPLATE string.
- Future work: the web onboarding wizard front end; the reviewed deployment package that supplies the
  typed controlled-live compositions; the operator activation flow (a separate, reviewed milestone).

## Commissioning: SUPPORTED, NOT EXERCISED / HAS NOT OCCURRED

The commissioning engine is implemented and tested against **in-memory fakes and documentation-only
fixtures**. It has **not** been run against a real host, a real image store, a real service manager,
or a real descriptor. No operator worker exists; no operator service has been installed on a real
host; no real deployment has been prepared; nothing has been activated. A passing test proves the
MECHANISM only. The first real commissioning of a real deployment — and any operator activation —
remains future, human-supervised work that **HAS NOT OCCURRED**. `_PLAN_ONLY_PROCESS_SEALED` remains
exactly `False`; both `_B1A_SUBPROCESS_SEALED` constants remain exactly `True`; PR6 remains frozen.

## Non-goals

This PR does not: start or configure an operator worker; modify or restart the running ordinary
worker; submit any workflow or call `run_plan_generation`; contact Proxmox, OpenBao/Vault, a remote
state backend, Temporal, or PostgreSQL; run OpenTofu or a generic subprocess; resolve any credential;
create an execution lease/attempt/result/approval; modify any process seal; enable real provisioning
or generic OpenTofu subprocess execution; begin PR6; commit any endpoint, hostname, IP, VM-ID, node,
storage, bridge, token, secret reference, state key, CA file, credential, or deployment-specific real
path; or supply the reviewed deployment package of controlled-live compositions. No environment
variable, backend kind, URL, installed SDK, PATH entry, database row, caller flag, descriptor field,
or dossier label alone creates a capability — only a separately-reviewed code seal change plus the
full runtime gate ever could, and this PR changes no seal.
