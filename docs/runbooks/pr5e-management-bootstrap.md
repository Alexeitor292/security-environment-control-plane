# SECP management-plane bootstrap — conceptual runbook (SECP-PR5E)

> **THIS DESCRIBES A LOCAL, HUMAN-SUPERVISED SEQUENCE, NOT AN ACTIVATION GUIDE.** It contains no real
> host addresses, credentials, or values. Real controller/worker addresses live ONLY in the operator's
> deployment-local records, never in source control (documentation addresses like `198.51.100.10` /
> `203.0.113.20` are used here purely as placeholders). Nothing here starts the operator, submits a
> workflow, runs OpenTofu, or contacts any infrastructure. See
> [ADR-025](../adr/ADR-025-management-plane-bootstrap.md).

## Planes

- **Management plane** — the controller + site workers, management databases/API/UI/Temporal/MinIO/
  Keycloak, the ordinary worker, and the sealed operator. SECP runs FROM here.
- **Infrastructure plane** — Proxmox (PR5G), vCenter, Kubernetes, cloud.
- **Scenario plane** — lab VMs/LXCs, scenario networks, vulnerable workloads.

A lower plane may never mutate a higher one. The controller and workers are management-plane objects,
never scenario targets — even when hosted on the same Proxmox cluster.

## `secpctl` command surface

There is no `activate`/`apply`/`destroy`/`proxmox`/`ssh`/`exec`/`shell`. Every mutation defaults to
dry-run; a real write requires **both** `--write` and `--confirm`. `--json` prints deterministic JSON.
There is **no flag to select or inject a host adapter**: the only path argument anywhere is the
read-only release-bundle source.

```
secpctl release verify --bundle DIR
secpctl host inspect
secpctl bootstrap controller|worker --bundle DIR   [--write --confirm]
secpctl adopt     controller|worker --bundle DIR    [--write --confirm]
secpctl status    controller|worker
secpctl evidence  controller|worker
secpctl rollback  controller|worker                 [--write --confirm]
```

## Local controller bootstrap (human-supervised, on the controller host)

1. **Obtain + verify the signed offline release bundle** (no network): `secpctl release verify
   --bundle /var/lib/secp/bootstrap/release/<r>`. Verification checks the Ed25519 signature against the
   pinned trust root, then every artifact digest, before trusting anything.
2. **Dry-run the plan**: `secpctl bootstrap controller --bundle <r>` — inspect host prerequisites,
   review the deterministic managed-object plan.
3. **Confirm the write** (requires root): `secpctl bootstrap controller --bundle <r> --write
   --confirm` — it first CLASSIFIES any pre-existing documents across ALL FIVE managed paths (identity,
   installed-release manifest, signature, evidence, and the evidence attestation), permitting only a
   fresh install (all five absent) or an exact idempotent same-release reinstall; a partial (incl. an
   attestation-only/orphan state, four core docs without the attestation, or the attestation with only
   a subset of core docs), foreign, drifted, changed-release, or adopted state is refused before any
   host op — and the evidence mode is never trusted before the detached attestation verifies. Then,
   through the closed controller adapter, it loads only verified
   image archives by content digest (passed as typed `VerifiedArtifact`s, never a bare name or a
   registry pull), installs the reviewed config + systemd wrapper (typed `ReviewedConfig`/
   `ReviewedUnit`), runs `daemon-reload`, runs the reviewed migration command (`alembic upgrade head`),
   and starts the stack (the adapter proves each LOADED image equals the signed purpose-specific image
   digest, not just the archive digest); it then writes the identity + installed-release record,
   performs a **final
   coherent reobservation of the complete end state** (exact component set all running + healthy on
   release images, config + unit + migration identities bound, and a strict SHA-256 generation marker
   over a validated-COMPLETE raw generation tuple — a matching marker over incomplete facts, e.g. maps
   whose keys differ from the signed component set or an empty container id, is refused), and commits
   evidence **last** — followed by its **detached signed evidence attestation**. The attestation is the
   TRUE commit point: a final **commit gate** re-reads the complete installed five-document state,
   re-verifies the attestation signature + expected key id / role / installation id / release aggregate
   / mode + exact metadata, and only then returns `written`. A failed op, reobservation, or commit gate
   compensates only what it created, PROVING each
   restore/removal; any lost/malformed adapter receipt, unprovable host compensation, or unprovable
   document restore reports `recovery_required` rather than a false refusal. Absent a reviewed
   controller adapter the write **refuses** (`controller_bootstrap_adapter_not_provisioned`), nothing
   written; absent a provisioned evidence authenticator (or with a bad one — malformed/invalid/wrong-key
   signature) it refuses (`evidence_authenticator_not_provisioned` / `evidence_attestation_untrusted`)
   and never returns `written`.
4. **Verify**: `secpctl status controller --json` reloads evidence + identity + the installed-release
   record (reverifying its signature), reobserves the stack, and reports release binding, container
   topology, image identity, migrations, service health, unknown-privileged services, and drift.

## Local worker bootstrap (human-supervised, on a site-worker host)

1. `secpctl release verify --bundle <r>`.
2. `secpctl bootstrap worker --bundle <r>` (dry-run) → review the plan: the ordinary worker is
   configured to start (queue `secp-orchestration`); the operator is prepared **present, disabled,
   stopped** (queue `secp-controlled-live-v1`) with no auto-start.
3. `secpctl bootstrap worker --bundle <r> --write --confirm` (root) → through the closed worker adapter
   it loads verified images, installs the ordinary config, installs the PR5D package + prepared
   operator unit, runs the required `daemon-reload`, and starts **only** the ordinary worker; it then
   writes the identity + installed-release record and performs a final reobservation, committing
   evidence **last** only if the ordinary worker is running + healthy on the right image, the operator
   is present-disabled-stopped and not polling the operator queue, the package is trusted, and the
   observer reports `commissioning = prepared` AND `deployment = sealed_prepared`. Absent a reviewed
   worker adapter the write **refuses** (`worker_bootstrap_adapter_not_provisioned`), writing nothing.
4. `secpctl status worker --json` — reloads evidence + identity + the reverified installed-release
   record and reobserves; worker success requires BOTH `commissioning = prepared` AND `deployment =
   sealed_prepared` (as composed by the observer from the real PR5C/PR5D checks) over the same coherent
   observation, plus a matching image and no operator-queue polling.

## Adopting the existing development installation

Our current development deployment already exists. Use adoption (a first-class inspect-only operation,
not a bootstrap alias):

```
secpctl adopt worker --bundle <r>                  # dry-run: reobserve topology, compare to the release
secpctl adopt worker --bundle <r> --write --confirm  # writes the ADOPTION documents (evidence + detached attestation last)
```

Adoption is a COMPLETE state: it refuses unless the host ALREADY matches the full canonical prepared
end state a successful bootstrap would produce (ordinary running/healthy on the exact image + config +
health-command identities; operator present/disabled/stopped on the exact unit; the deployment-package
aggregate; no operator-queue polling; package trusted; commissioning `prepared` AND deployment
`sealed_prepared`; safe seals — controller: exact component set all running/healthy on release images
with config/unit/migration identities and no unknown privileged service). It is refused with
`adoption_incomplete:<reason>` on any gap, so an adoption can never be a permanent dead end. With
`--write --confirm` it is transactional AND TOCTOU-closed: it installs identity + the signed release
record, then takes a FINAL observation, proves the ABA generation is UNCHANGED since admission and
re-runs the complete end-state predicate, and only THEN writes evidence last — a worker restart,
operator start, health degradation, or controller generation change between admission and commit
refuses (`adoption_generation_changed` / `adoption_final:<reason>`) and compensates, leaving no partial
adoption. It runs no mutation adapter op, restarts nothing, loads no image, and never modifies the
ordinary worker; adopted objects are never rollback-owned.

## Rollback (removing a fresh bootstrap)

```
secpctl rollback worker                            # dry-run: list the exact created documents
secpctl rollback worker --write --confirm          # remove them, verified + reverified
```

Rollback first verifies the **detached signed evidence attestation** BEFORE trusting the evidence mode
or created records (so a re-authored evidence — or a
canonical adopted→installed rewrite that would make an adopted install look rollback-owned — is refused
with `evidence_attestation_untrusted` before any mode-specific logic or planning), then runs the ONE
shared installed-document integrity verifier over all FIVE documents — it authenticates every document
against digests derived INDEPENDENTLY from the signature-verified release record + the release-bound
identity (never from the re-authorable evidence, so a forged evidence that rewrote the recorded digests
is caught: `evidence_object_record_forged`) and checks fixed path binding, regular-file/no-symlink,
single link, exact UID/GID/mode, AND exact content — BEFORE any removal. Removal is **transactional**:
it captures each document's exact bytes first, removes in a fixed order (identity, manifest, signature,
attestation, **evidence last**) — each resolved from its authenticated `created` ownership record, so a
pre-existing/orphan attestation is never deleted — reverifying each is gone, and if ANY removal or
reverification fails it
RESTORES every already-removed document and proves each restoration — returning an ordinary refusal only
after a full restore, or `recovery_required` if a restoration cannot be proven, never leaving a
partially-removed installation. Any content or metadata drift refuses BEFORE any object is removed;
it returns `written` only when real removals are proven. It refuses an adopted installation, refuses a
drifted object, and returns a bounded `rollback_not_implemented` when no reviewed rollback adapter is
installed. It never restarts the ordinary worker and never removes controller persistent data.

## What stays sealed

`_OPERATOR_ACTIVATION_SEALED` = `True`; `_PLAN_ONLY_PROCESS_SEALED` = `False`; both
`_B1A_SUBPROCESS_SEALED` = `True`; the ordinary worker never polls the operator queue; no operator
`Worker` is constructed; no workflow is submitted; no OpenTofu runs; PR6 remains frozen. Browser
enrollment is PR5F; Proxmox initialization is PR5G; operator activation is later.

## Production requires reviewed adapters (shipped state fails closed)

The shipped host-effect adapters are **sealed**: with no reviewed real observer/mutation/rollback
adapter installed, `bootstrap`, `adopt`, `status`, and `rollback` all fail closed with a bounded reason
(`host_observer_not_available`, `*_bootstrap_adapter_not_provisioned`, `rollback_not_implemented`)
rather than reporting a false success — so **no real host is currently bootstrap-capable from the
shipped repository**. The shipped `ManagementEvidenceAuthenticator` is likewise sealed, so a production
bootstrap/adoption fails closed (`evidence_authenticator_not_provisioned`) before any evidence is
written; production commits no authenticator or release-signing private key. This PR establishes the
safe engine and the closed TYPED adapter contract
(`VerifiedArtifact` with a hardened digest-checked reader plus a signed expected loaded-image digest,
`ReviewedConfig`/`ReviewedUnit`, typed
plans, and a `BootstrapReceipt` + typed `CompensationResult` compensation path). Installing the reviewed real
adapters (which compose the PR5C/PR5D read-only host adapters, consume these exact typed inputs, wrap
the pinned container-runtime / `systemctl` seams, and compensate partial effects without any generic
path/subprocess surface) is a **later, separately reviewed milestone** out of scope for PR5E.
