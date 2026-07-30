"""The management-bootstrap ENGINE (SECP-PR5E) — the single engine behind human + JSON output.

Every ``secpctl`` verb resolves to one of these engine functions and returns a deterministic
``(exit_code, report_dict)`` pair; the CLI only chooses formatting. The engine performs the explicit
phases (verify → classify pre-existing → run closed typed host ops → reobserve → commit-evidence),
enforces the dry-run vs ``--write --confirm`` gate, isolates roles, verifies the signed release
before
any host trust, keeps the sealed operator disabled, and writes strict nonsecret evidence LAST.

The engine performs NO host effect directly. All observation and mutation flow through the injected
closed adapters in :mod:`secp_management.adapters`, driven by EXACT typed inputs (verified
artifacts,
reviewed config/unit bytes, typed plans) the engine derives ONLY from the verified release. Each
mutation adapter accumulates a receipt and exposes a closed ``compensate`` so a partial host effect
is
rolled back or reported as ``recovery_required``. The SHIPPED defaults are SEALED, so a real
bootstrap/adoption/status/rollback on the shipped repository FAILS CLOSED (never a false success)
until reviewed real adapters are installed out of band. Tests inject exact closed fakes through
:class:`EngineDeps`; a CLI user can neither select nor inject an adapter. The engine constructs no
Temporal Worker, submits no workflow, calls no ``run_plan_generation``, runs no OpenTofu, and
contacts
no infrastructure.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from secp_commissioning.canonical import (
    canonical_json,
    is_sha256_digest,  # noqa: F401
    sha256_bytes,
    sha256_digest,
)
from secp_commissioning.enrollment_signer_marker import parse_marker_bytes_or_none
from secp_commissioning.runtime import FileStat

from secp_management import BOOTSTRAP_CONTRACT_VERSION, ManagementError
from secp_management.adapters import (
    BootstrapReceipt,
    CompensationResult,
    ControllerBootstrapAdapter,
    ControllerBootstrapPlan,
    ControllerObservation,
    ManagementEvidenceAuthenticator,
    ManagementHostObserver,
    ManagementRollbackAdapter,
    PlatformFacts,
    ReviewedConfig,
    ReviewedUnit,
    SealedControllerBootstrapAdapter,
    SealedEvidenceAuthenticator,
    SealedHostObserver,
    SealedRollbackAdapter,
    SealedWorkerBootstrapAdapter,
    VerifiedArtifact,
    WorkerBootstrapAdapter,
    WorkerBootstrapPlan,
    WorkerObservation,
    controller_generation_marker,
    is_generation_marker,
    worker_generation_marker,
)
from secp_management.controller_compose_validation import (
    assert_controller_compose_contract,
    controller_compose_contract_reason,
)
from secp_management.controller_install import (
    ControllerInstallOptions,
    build_controller_install_options,
)
from secp_management.evidence import (
    CLASSIFICATION_ADOPTED,
    CLASSIFICATION_CREATED,
    CLASSIFY_EXACT_SAME_RELEASE,
    CLASSIFY_FRESH,
    CLASSIFY_MANAGED_UPGRADE,
    FINALIZATION_SCHEMA_VERSION,
    FINALIZATION_STATE_COMMITTED,
    FINALIZATION_STATE_PREPARED,
    MODE_ADOPTED,
    MODE_INSTALLED,
    OBJECT_EVIDENCE,
    OBJECT_EVIDENCE_ATTESTATION,
    OBJECT_IDENTITY,
    OBJECT_RELEASE_MANIFEST,
    OBJECT_RELEASE_SIGNATURE,
    BootstrapEvidence,
    EvidenceAttestation,
    FinalizationEffectRecord,
    FinalizationEvidence,
    ManagedObjectRecord,
    ManagementPlaneIdentity,
    attestation_bytes,
    attestation_from_dict,
    canonical_bytes,
    evidence_attestation_message,
    evidence_from_dict,
    health_command_identity,
    identity_from_dict,
    parse_document_bytes,
    path_binding_digest,
)
from secp_management.finalization import (
    FINALIZATION_EFFECTS,
    ApiSignerMarker,
    ControllerEnrollmentFinalizationAdapter,
    ControllerEnrollmentFinalizationPlan,
    ControllerFinalizationReceipt,
    ControllerIdentityActivation,
    ReviewedSignerRole,
    SealedControllerEnrollmentFinalizationAdapter,
)
from secp_management.hostview import HostProbe, LocalHostProbe
from secp_management.layout import ManagementLocations
from secp_management.planes import Plane, Role, parse_role
from secp_management.release_bundle import (
    WORKER_OPERATOR_PURPOSE,
    WORKER_ORDINARY_PURPOSE,
    signed_controller_image_map,
    signed_deployment_package,
    signed_worker_image,
)
from secp_management.release_verify import (
    VerifiedRelease,
    verify_release_bundle,
    verify_release_record,
)
from secp_management.signing import SHIPPED_TRUST_ROOT, ReleaseTrustRoot
from secp_management.systemd import (
    render_operator_unit_disabled,
    render_service_unit,
    unit_identity,
)
from secp_management.topology import (
    CONTROLLER_STACK_ENTRYPOINT,
    OPERATOR_ENTRYPOINT,
    OPERATOR_SERVICE_NAME,
    OPERATOR_TASK_QUEUE,
    ORDINARY_CONTAINER_NAME,
    ORDINARY_HEALTH_COMMAND,
    ORDINARY_TASK_QUEUE,
    read_seals,
)
from secp_management.transaction import (
    EXIT_OK,
    EXIT_REFUSED,
    MODE_DRY_RUN,
    MODE_REFUSED,
    MODE_WRITTEN,
    WriteGate,
)

_SUPPORTED_OS = frozenset({"linux"})
_SUPPORTED_ARCH = frozenset({"x86_64", "arm64"})
_ROOT_UID = 0
_MANAGED_FILE_MODE = 0o640
_RUNTIME_UID = 10001
_RUNTIME_GID = 10001
_MAX_DOC_BYTES = 256 * 1024
_MAX_RECORD_BYTES = 1 * 1024 * 1024
_MAX_SIG_BYTES = 4 * 1024


@dataclass(frozen=True)
class EngineDeps:
    """Injected dependencies. Production resolves REAL/SEALED implementations itself; tests inject
    exact fakes. There is NO arbitrary Python DI through CLI arguments — the CLI constructs a
    default :class:`EngineDeps` with the sealed production adapters and never exposes selection."""

    locations: ManagementLocations = field(default_factory=ManagementLocations)
    trust_root: ReleaseTrustRoot = SHIPPED_TRUST_ROOT
    probe: HostProbe = field(default_factory=LocalHostProbe)  # OS/arch/root local facts only
    observer: ManagementHostObserver = field(default_factory=SealedHostObserver)
    controller_adapter: ControllerBootstrapAdapter = field(
        default_factory=SealedControllerBootstrapAdapter
    )
    worker_adapter: WorkerBootstrapAdapter = field(default_factory=SealedWorkerBootstrapAdapter)
    rollback_adapter: ManagementRollbackAdapter = field(default_factory=SealedRollbackAdapter)
    # the controller-enrollment finalization seam (TLS/locator/signer-role/enrollment-key/broker/
    # api-signer/identity-activation). SHIPPED sealed → finalization fails closed until composed.
    finalization_adapter: ControllerEnrollmentFinalizationAdapter = field(
        default_factory=SealedControllerEnrollmentFinalizationAdapter
    )
    # the plan-bound, single-use finalization FACTORY (2b-3c). The real adapter freezes its
    # generation + transaction id at construction and is single-use, so a fresh instance must be
    # built per install from the derived, authenticated plan. Production sets this ONLY through the
    # root-only install composition; steady-state and bare EngineDeps leave it None so finalization
    # stays SEALED (a controller install with no factory refuses `finalization_not_composed`).
    finalization_factory: (
        Callable[[ControllerEnrollmentFinalizationPlan], ControllerEnrollmentFinalizationAdapter]
        | None
    ) = None
    # R1: the read-only PRE-MUTATION finalization inventory (every fixed object + the dedicated DB
    # role/identity through the fixed read-only API one-shot). None -> a driven controller install
    # REFUSES: fresh can never be inferred from the five documents + marker alone again.
    finalization_inventory: Callable[[], Any] | None = None
    # R3: the read-only LIVE finalization state observer used by exact replay + managed-upgrade
    # eligibility. None -> those paths REFUSE rather than trusting documents/marker alone.
    finalization_state_observer: Callable[..., Any] | None = None
    # the management signing seam that attests evidence, and the anchor that verifies the
    # attestation.
    # SHIPPED sealed / empty → production cannot attest or verify → bootstrap/status fail closed.
    evidence_authenticator: ManagementEvidenceAuthenticator = field(
        default_factory=SealedEvidenceAuthenticator
    )
    evidence_trust_root: ReleaseTrustRoot = SHIPPED_TRUST_ROOT
    fs: object | None = None  # a hardened FilesystemBackend; None → resolved to RealFilesystem
    clock: object | None = None  # Callable[[], str] → iso tz-aware; None → real UTC clock
    expected_uid: int = _ROOT_UID

    def now(self) -> str:
        if self.clock is not None:
            return self.clock()  # type: ignore[operator]
        import datetime as _dt

        return _dt.datetime.now(tz=_dt.UTC).isoformat()

    def filesystem(self) -> object:
        if self.fs is not None:
            return self.fs
        from secp_commissioning.runtime import RealFilesystem

        return RealFilesystem()


def _seal_section() -> dict:
    s = read_seals()
    return {
        "operator_activation_sealed": s.operator_activation_sealed,
        "plan_only_process_sealed": s.plan_only_process_sealed,
        "b1a_subprocess_sealed_activation": s.b1a_subprocess_sealed_activation,
        "b1a_subprocess_sealed_executor": s.b1a_subprocess_sealed_executor,
        "safe": s.safe,
    }


def _installation_id(role: str, aggregate: str) -> str:
    h = sha256_digest({"v": "secp.management.install/v1", "role": role, "release": aggregate})
    return "secp-mgmt-" + h[len("sha256:") : len("sha256:") + 16]


def _component_image_identity(mapping: dict[str, str]) -> str:
    """A single content digest binding the EXACT controller component -> image-digest map, so any
    changed component, added/removed service, or swapped image produces drift."""
    items = sorted((component, digest) for component, digest in mapping.items())
    return sha256_digest({"v": "secp.management.controller-images/v1", "map": items})


# The five root-controlled documents a transaction owns, mapped to their fixed-layout accessor, in
# the order rollback removes them (the detached attestation just before the authenticating evidence,
# which is LAST).
_KIND_PATH = {
    OBJECT_IDENTITY: "identity_path",
    OBJECT_RELEASE_MANIFEST: "release_record_path",
    OBJECT_RELEASE_SIGNATURE: "release_sig_path",
    OBJECT_EVIDENCE_ATTESTATION: "evidence_attestation_path",
    OBJECT_EVIDENCE: "evidence_path",
}
_DOC_ORDER = (
    OBJECT_IDENTITY,
    OBJECT_RELEASE_MANIFEST,
    OBJECT_RELEASE_SIGNATURE,
    OBJECT_EVIDENCE_ATTESTATION,
    OBJECT_EVIDENCE,
)


# --------------------------------------------------------------------------- typed-plan derivation


def _artifact_reader(bundle_dir: str, name: str, size: int, deps: EngineDeps):  # noqa: ANN202
    fs = deps.filesystem()
    uid = deps.expected_uid
    path = posixpath.join(bundle_dir, name)

    def _read() -> bytes:
        return fs.safe_read(path, max_bytes=size, expected_uid=uid)  # type: ignore[attr-defined]

    return _read


def _verified_artifact(art, bundle_dir: str, deps: EngineDeps) -> VerifiedArtifact:  # noqa: ANN001
    return VerifiedArtifact(
        role=art.role,
        kind=art.kind,
        name=art.name,
        digest=art.sha256,
        size=art.size,
        reader=_artifact_reader(bundle_dir, art.name, art.size, deps),
        purpose=art.purpose or "",
        image_digest=art.image_digest or "",  # signed loaded-image digest for an image archive
    )


def _image_artifacts(
    vr: VerifiedRelease, bundle_dir: str, deps: EngineDeps
) -> tuple[VerifiedArtifact, ...]:
    return tuple(
        _verified_artifact(a, bundle_dir, deps)
        for a in vr.manifest.artifacts
        if a.kind == "image_archive" and a.image_digest
    )


def _compose_config(
    role: Role, vr: VerifiedRelease, bundle_dir: str, deps: EngineDeps
) -> ReviewedConfig:
    kind = f"{role.value}_compose_template"
    matches = [a for a in vr.manifest.artifacts if a.kind == kind]
    if len(matches) != 1:
        raise ManagementError("release_compose_template_missing")
    content = _verified_artifact(matches[0], bundle_dir, deps).read()
    if role is Role.CONTROLLER:
        # the plan may not even be BUILT from a controller template that fails the contract --
        # this runs before any image load, config install, unit install or stack start.
        assert_controller_compose_contract(content)
    return ReviewedConfig(identity=sha256_bytes(content), content=content)


def _deployment_package(vr: VerifiedRelease, bundle_dir: str, deps: EngineDeps) -> VerifiedArtifact:
    return _verified_artifact(signed_deployment_package(vr.manifest), bundle_dir, deps)


def _operator_unit() -> ReviewedUnit:
    text = render_operator_unit_disabled(
        exec_argv=OPERATOR_ENTRYPOINT, user="secp-operator", group="secp-operator"
    )
    return ReviewedUnit(identity=unit_identity(text), content=text.encode("utf-8"))


def _controller_unit() -> ReviewedUnit:
    text = render_service_unit(
        description="SECP controller stack supervisor",
        exec_argv=CONTROLLER_STACK_ENTRYPOINT,
        user="root",
        group="root",
        read_write_paths=(),
        wanted_by=None,
    )
    return ReviewedUnit(identity=unit_identity(text), content=text.encode("utf-8"))


def _build_worker_plan(
    vr: VerifiedRelease, bundle_dir: str, deps: EngineDeps
) -> WorkerBootstrapPlan:
    return WorkerBootstrapPlan(
        role=Role.WORKER.value,
        image_artifacts=_image_artifacts(vr, bundle_dir, deps),
        ordinary_config=_compose_config(Role.WORKER, vr, bundle_dir, deps),
        deployment_package=_deployment_package(vr, bundle_dir, deps),
        deployment_aggregate=vr.manifest.implementation_aggregate,
        operator_unit=_operator_unit(),
        ordinary_image=signed_worker_image(vr.manifest, WORKER_ORDINARY_PURPOSE),
        operator_image=signed_worker_image(vr.manifest, WORKER_OPERATOR_PURPOSE),
    )


def _build_controller_plan(
    vr: VerifiedRelease, bundle_dir: str, deps: EngineDeps
) -> ControllerBootstrapPlan:
    component_images = signed_controller_image_map(vr.manifest)
    return ControllerBootstrapPlan(
        role=Role.CONTROLLER.value,
        image_artifacts=_image_artifacts(vr, bundle_dir, deps),
        config=_compose_config(Role.CONTROLLER, vr, bundle_dir, deps),
        unit=_controller_unit(),
        migration_identity=vr.manifest.migration_identity,
        expected_components=tuple(sorted(component_images)),
        component_images=component_images,
    )


# --------------------------------------------------------------------------- read-only verbs


def release_verify(bundle_dir: str, deps: EngineDeps) -> tuple[int, dict]:
    """``secpctl release verify`` — offline signature + digest verification. No host write."""
    try:
        vr = verify_release_bundle(
            bundle_dir,
            trust_root=deps.trust_root,
            fs=deps.filesystem(),
            expected_uid=deps.expected_uid,
        )
    except ManagementError as exc:
        return EXIT_REFUSED, {
            "command": "release_verify",
            "trusted": False,
            "reason_code": exc.reason_code,
        }
    return EXIT_OK, {
        "command": "release_verify",
        "trusted": True,
        "role": vr.role,
        "release_aggregate_digest": vr.aggregate_digest,
        "signing_anchor_id": vr.signature_key_id,
        "artifact_count": len(vr.manifest.artifacts),
        "external_contacts_performed": False,
    }


def host_inspect(deps: EngineDeps) -> tuple[int, dict]:
    """``secpctl host inspect`` — read-only local host facts (no infrastructure contact). OS, arch,
    and root come from the local probe; Docker/Compose presence requires the production observer and
    is reported ``unavailable`` when no reviewed observer is installed (the shipped posture)."""
    v = deps.probe.observe()
    docker_present: bool | None = None
    compose_present: bool | None = None
    observer_available = True
    try:
        pf = deps.observer.platform()
        docker_present = pf.docker_present
        compose_present = pf.compose_present
    except ManagementError:
        observer_available = False
    return EXIT_OK, {
        "command": "host_inspect",
        "os": v.os_name,
        "arch": v.arch,
        "is_root": v.is_root,
        "observer_available": observer_available,
        "docker_present": docker_present,
        "compose_present": compose_present,
        "os_supported": v.os_name in _SUPPORTED_OS,
        "arch_supported": v.arch in _SUPPORTED_ARCH,
        "external_contacts_performed": False,
    }


# --------------------------------------------------------------------------- preflight + plan


def _platform_or_refuse(deps: EngineDeps) -> PlatformFacts:
    """The production observer is the sole truthful source of Docker/Compose presence. A sealed
    observer fails closed (``host_observer_not_available``) so nothing runs on a placeholder."""
    return deps.observer.platform()


def _preflight(pf: PlatformFacts, *, need_root: bool) -> str | None:
    if pf.os_name not in _SUPPORTED_OS:
        return "host_os_unsupported"
    if pf.arch not in _SUPPORTED_ARCH:
        return "host_arch_unsupported"
    if not pf.docker_present:
        return "docker_missing"
    if not pf.compose_present:
        return "compose_missing"
    if need_root and not pf.is_root:
        return "root_required_for_write"
    return None


def _verify_release_for_role(role: Role, bundle_dir: str, deps: EngineDeps) -> VerifiedRelease:
    vr = verify_release_bundle(
        bundle_dir, trust_root=deps.trust_root, fs=deps.filesystem(), expected_uid=deps.expected_uid
    )
    if vr.role != role.value:  # a controller bundle can never bootstrap a worker (and vice-versa)
        raise ManagementError("release_role_mismatch")
    return vr


def _managed_plan_summary(role: Role, vr: VerifiedRelease, deps: EngineDeps) -> list[dict]:
    """The deterministic managed-object plan SHOWN for a dry run. The write path executes these as
    closed typed operations through the role adapter; no step ever starts/enables the operator."""
    loc = deps.locations
    plan: list[dict[str, object]] = [
        {
            "kind": "directory",
            "binding": path_binding_digest(role.value, loc.role_root(role.value)),
        },
        {"kind": "file", "object": "management_identity"},
        {"kind": "file", "object": "installed_release_record"},
    ]
    for art in vr.manifest.artifacts:
        if art.kind == "image_archive":
            plan.append({"kind": "image_load", "digest": art.image_digest, "from_archive": True})
    if role is Role.WORKER:
        plan.append({"kind": "deployment_package_install", "verify_trust": True})
        plan.append({"kind": "container_configure", "name": ORDINARY_CONTAINER_NAME, "start": True})
        plan.append({"kind": "operator_unit", "state": "present_disabled_stopped", "start": False})
    else:
        plan.append({"kind": "migrations", "verify_identity": True})
        plan.append({"kind": "stack_start", "start": True})
    return plan


# --------------------------------------------------------------------------- bootstrap


def bootstrap(
    role_value: str, bundle_dir: str, gate: WriteGate, deps: EngineDeps
) -> tuple[int, dict]:
    """``secpctl bootstrap controller|worker`` — deterministic local bootstrap. Dry-run by default;
    a real write classifies pre-existing documents, executes the closed typed host operations
    through
    the role adapter, reobserves, and commits evidence ONLY if the reobservation confirms the
    complete
    canonical end state — otherwise it refuses and compensates only what it created."""
    try:
        role = parse_role(role_value)
        partial = gate.refusal_reason()
        if partial is not None:
            raise ManagementError(partial)
        vr = _verify_release_for_role(role, bundle_dir, deps)
        pf = _platform_or_refuse(deps)
        pfx = _preflight(pf, need_root=gate.is_write)
        if pfx is not None:
            raise ManagementError(pfx)
        if not read_seals().safe:
            raise ManagementError("seals_unsafe")
        summary = _managed_plan_summary(role, vr, deps)
    except ManagementError as exc:
        return EXIT_REFUSED, _refused("bootstrap", role_value, exc.reason_code)

    base = {
        "command": "bootstrap",
        "role": role.value,
        "release_aggregate_digest": vr.aggregate_digest,
        "plan": summary,
        "code_seals": _seal_section(),
        "operator_started": False,
        "operator_enabled": role is not Role.WORKER,  # worker leaves operator disabled
        "external_contacts_performed": False,
        "workflows_submitted": False,
        "run_plan_generation_called": False,
        "opentofu_executed": False,
        "proxmox_contacted": False,
    }
    if not gate.is_write:
        base["mode"] = MODE_DRY_RUN
        return EXIT_OK, base

    # --- write phase (only reached with --write --confirm) ---
    try:
        ident, ev = _write_transaction(role, vr, deps, bundle_dir)
    except ManagementError as exc:
        return EXIT_REFUSED, _refused("bootstrap", role_value, exc.reason_code)
    base["mode"] = MODE_WRITTEN
    base["installation_id"] = ident.installation_id
    base["evidence_digest"] = ev.digest()
    base["reobserved_healthy"] = True
    return EXIT_OK, base


def controller_install(
    public_origin: str | None,
    tls_mode: str | None,
    bundle_dir: str,
    gate: WriteGate,
    deps: EngineDeps,
) -> tuple[int, dict]:
    """``secpctl controller install`` — the supported root-only controller-enrollment installation
    (SECP-PR5H-B2 2b-3c). Dry-run by default (verify the release + host, classify the prior state,
    derive the planned generation, and print ONLY nonsecret plan facts — no finalization mutation,
    no
    recovery journal, no secret). ``--write --confirm`` drives the combined bootstrap + finalization
    write transaction for a FRESH install, or a deterministic idempotent replay for an exact
    same-release state. It reaches the real finalization factory ONLY through the root-gated install
    composition; every steady-state command keeps finalization sealed."""
    role = Role.CONTROLLER
    try:
        partial = gate.refusal_reason()
        if partial is not None:
            raise ManagementError(partial)
        options = build_controller_install_options(public_origin=public_origin, tls_mode=tls_mode)
        vr = _verify_release_for_role(role, bundle_dir, deps)
        pf = _platform_or_refuse(deps)
        pfx = _preflight(pf, need_root=gate.is_write)
        if pfx is not None:
            raise ManagementError(pfx)
        if not read_seals().safe:
            raise ManagementError("seals_unsafe")
        summary = _managed_plan_summary(role, vr, deps)
        install_cls = _classify_controller_install(vr, deps)  # classify BEFORE any mutation
        if install_cls.reason is not None:
            raise ManagementError(install_cls.reason)
    except ManagementError as exc:
        return EXIT_REFUSED, _refused("controller-install", role.value, exc.reason_code)

    base = {
        "command": "controller-install",
        "role": role.value,
        "release_aggregate_digest": vr.aggregate_digest,
        "plan": summary,
        "install_options": options.safe_summary(),  # public origin + mode (public deployment facts)
        "classification": install_cls.classification,
        "planned_generation": install_cls.generation,
        "finalization_steps": list(FINALIZATION_EFFECTS),  # nonsecret ordered step names
        "code_seals": _seal_section(),
        "operator_started": False,
        "operator_enabled": True,
        "external_contacts_performed": False,
        "workflows_submitted": False,
        "run_plan_generation_called": False,
        "opentofu_executed": False,
        "proxmox_contacted": False,
    }
    if not gate.is_write:
        base["mode"] = MODE_DRY_RUN
        return EXIT_OK, base

    # --- write phase (only reached with --write --confirm) ---
    try:
        if install_cls.classification == CLASSIFY_EXACT_SAME_RELEASE:
            ident, ev = _controller_install_replay(vr, deps, install_cls)  # NO mutation
            base["idempotent_replay"] = True
        elif install_cls.classification in (CLASSIFY_FRESH, CLASSIFY_MANAGED_UPGRADE):
            # a fresh install and an authenticated managed upgrade take the SAME driven write
            # transaction; the upgrade path activates generation N+1 against the prior identity and
            # rolls the prior generation back on a post-activation failure.
            ident, ev = _write_transaction(
                role, vr, deps, bundle_dir, install=options, install_cls=install_cls
            )
            base["idempotent_replay"] = False
        else:  # unreachable — classification is one of the closed set above or already refused
            raise ManagementError("controller_install_unsupported_classification")
    except ManagementError as exc:
        return EXIT_REFUSED, _refused("controller-install", role.value, exc.reason_code)
    base["mode"] = MODE_WRITTEN
    base["installation_id"] = ident.installation_id
    base["evidence_digest"] = ev.digest()
    base["finalization_generation"] = ev.finalization.generation if ev.finalization else 0
    base["marker_path_binding"] = path_binding_digest(
        role.value, deps.locations.api_signer_marker_path()
    )
    # TRUTHFUL reporting: only a driven write (fresh install / managed upgrade) performs the live
    # reobservation + the authoritative post-marker runtime proof. The idempotent replay path
    # re-authenticates the on-disk documents + marker binding ONLY and reobserves no live runtime,
    # so it must not claim it did.
    base["reobserved_healthy"] = not base["idempotent_replay"]
    return EXIT_OK, base


def _controller_install_replay(
    vr: VerifiedRelease, deps: EngineDeps, install_cls: _ControllerInstallClassification
) -> tuple[ManagementPlaneIdentity, BootstrapEvidence]:
    """Exact same-release idempotent replay (2b-3c). Re-authenticates all five documents + the
    finalization extension + the marker binding + the recomputed bootstrap_binding_digest, mutating
    NOTHING (no host op, no credential rotation, no new identity, no evidence rewrite), and returns
    the existing authenticated identity + evidence. A partially-correct same-release state already
    refused during classification — it is never silently repaired by ordinary replay."""
    role = Role.CONTROLLER
    commit_reason = _verify_committed_transaction(
        role, deps, expected_mode=MODE_INSTALLED, expected_aggregate=vr.aggregate_digest
    )
    if commit_reason is not None:
        raise ManagementError(commit_reason)
    ev = install_cls.prior_evidence
    ident, _ir = _load_identity(role, deps)
    if ev is None or ident is None or ev.finalization is None:
        raise ManagementError("controller_install_replay_incoherent")
    if ev.finalization.bootstrap_binding_digest != ev.bootstrap_binding_digest():
        raise ManagementError("controller_install_binding_drift")
    marker_reason = _verify_marker_binding(deps, ev)
    if marker_reason is not None:
        raise ManagementError(marker_reason)
    # R3: an exact replay must ALSO prove the LIVE signer system (single active identity, marker
    # binding, dedicated role + credential, broker transport, API runtime, generation agreement).
    # This observation is mutation-free, so the replay remains mutation-free.
    live_reason = _live_state_refusal(ev, ident, vr, deps)
    if live_reason is not None:
        raise ManagementError(live_reason)
    return ident, ev


def _verify_marker_binding(deps: EngineDeps, ev: BootstrapEvidence) -> str | None:
    """Cross-check the on-disk enablement marker against the authenticated finalization evidence —
    the
    nonsecret marker/identity/generation binding a status/replay independently revalidates. Returns
    a
    bounded reason code or None. Skipped (None) when there is no finalization extension."""
    fin = ev.finalization
    if fin is None:
        return None
    loc = deps.locations
    fs = deps.filesystem()
    path = loc.api_signer_marker_path()
    st = fs.lstat(path)  # type: ignore[attr-defined]
    if st is None or st.is_symlink or not st.is_regular or st.nlink != 1 or st.uid != _ROOT_UID:
        return "controller_marker_unsafe"
    try:
        raw = fs.safe_read(path, max_bytes=_MAX_DOC_BYTES, expected_uid=_ROOT_UID)  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 - an unreadable marker is drift, not a crash
        return "controller_marker_unreadable"
    # R7: parse through the ONE plane-neutral STRICT contract (canonical bytes, duplicate-key
    # rejection, extra/missing-field rejection, exact types + grammar, fixed role + UDS contract),
    # so management can never accept a marker the API's own loader refuses.
    parsed = parse_marker_bytes_or_none(raw)
    if parsed is None:
        return "controller_marker_unreadable"
    subset = {
        "installation_id": parsed.installation_id,
        "release_digest": parsed.release_digest,
        "active_identity_row_id": parsed.active_identity_row_id,
        "controller_key_id": parsed.controller_key_id,
        "uds_contract_identity": parsed.uds_contract_identity,
        "signer_role_name": parsed.signer_role_name,
        "locator_ca_digest": parsed.locator_ca_digest,
        "bootstrap_evidence_digest": parsed.bootstrap_evidence_digest,
        "management_identity_digest": parsed.management_identity_digest,
        "api_uid": parsed.api_uid,
        "api_gid": parsed.api_gid,
    }
    token = parsed.activation_token
    if _sep_digest("secp.management.api-signer-marker/v1", subset) != fin.marker_identity:
        return "controller_marker_identity_drift"
    token_digest = _sep_digest("secp.management.activation-token/v1", token)
    if token_digest != fin.activation_concurrency_digest:
        return "controller_marker_token_drift"
    if subset["bootstrap_evidence_digest"] != fin.bootstrap_binding_digest:
        return "controller_marker_binding_drift"
    if subset["active_identity_row_id"] != fin.active_identity_row_id:
        return "controller_marker_identity_disagreement"
    return None


def _run_worker_ops(plan: WorkerBootstrapPlan, deps: EngineDeps) -> None:
    """Execute the closed worker bootstrap operations IN ORDER, each on its exact typed input.
    The operator unit is installed DISABLED + STOPPED and is NEVER started or enabled; only the
    ordinary worker is started. A sealed adapter raises on the first op → the transaction stops."""
    ad = deps.worker_adapter
    for artifact in plan.image_artifacts:
        ad.load_image(artifact)
    ad.install_ordinary_config(plan.ordinary_config)
    ad.install_deployment_package(plan.deployment_package, aggregate=plan.deployment_aggregate)
    ad.install_operator_unit_disabled(plan.operator_unit)
    ad.daemon_reload()
    ad.start_ordinary()


def _run_controller_ops(plan: ControllerBootstrapPlan, deps: EngineDeps) -> None:
    ad = deps.controller_adapter
    for artifact in plan.image_artifacts:
        ad.load_image(artifact)
    ad.install_config(plan.config)
    ad.install_unit(plan.unit)
    ad.daemon_reload()
    ad.run_migrations(migration_identity=plan.migration_identity)
    ad.start_stack(expected_components=plan.expected_components)


@dataclass(frozen=True)
class _ExpectedWorker:
    ordinary_image: str
    operator_image: str
    ordinary_config_identity: str
    operator_unit_identity: str
    health_command_identity: str
    deployment_aggregate: str


@dataclass(frozen=True)
class _ExpectedController:
    component_images: dict[str, str]
    expected_components: tuple[str, ...]
    config_identity: str
    unit_identity: str
    migration_identity: str


def _compose_artifact_sha(manifest, role_value: str) -> str:  # noqa: ANN001
    kind = f"{role_value}_compose_template"
    for a in manifest.artifacts:
        if a.kind == kind:
            return a.sha256
    raise ManagementError("release_compose_template_missing")


def _expected_worker(manifest) -> _ExpectedWorker:  # noqa: ANN001
    """The COMPLETE canonical worker end state, derived ONLY from the signed manifest + code (never
    from evidence): ordinary/operator images from the signed purposes, config from the signed
    compose
    artifact digest, unit from the code-rendered unit, package from the signed aggregate."""
    return _ExpectedWorker(
        ordinary_image=signed_worker_image(manifest, WORKER_ORDINARY_PURPOSE),
        operator_image=signed_worker_image(manifest, WORKER_OPERATOR_PURPOSE),
        ordinary_config_identity=_compose_artifact_sha(manifest, "worker"),
        operator_unit_identity=_operator_unit().identity,
        health_command_identity=health_command_identity(ORDINARY_HEALTH_COMMAND),
        deployment_aggregate=manifest.implementation_aggregate,
    )


def _expected_controller(manifest) -> _ExpectedController:  # noqa: ANN001
    comp = signed_controller_image_map(manifest)
    return _ExpectedController(
        component_images=comp,
        expected_components=tuple(sorted(comp)),
        config_identity=_compose_artifact_sha(manifest, "controller"),
        unit_identity=_controller_unit().identity,
        migration_identity=manifest.migration_identity,
    )


def _worker_generation(obs: WorkerObservation) -> str:
    """The engine's own derivation of the worker generation marker from the RAW observed facts, so a
    missing/empty/malformed/placeholder marker (one that does not track the real generation tuple)
    is
    detectable — the observer's marker must equal this."""
    return worker_generation_marker(
        container_id=obs.ordinary_container_id,
        running_pid=obs.ordinary_pid,
        restart_count=obs.ordinary_restart_count,
        started_at=obs.ordinary_started_at,
        operator_invocation_id=obs.operator_invocation_id,
    )


def _controller_generation(obs: ControllerObservation) -> str:
    return controller_generation_marker(
        container_ids=obs.container_ids,
        restart_counts=obs.restart_counts,
        images=obs.container_image_digests,
        migration_identity=obs.migration_identity,
    )


_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")


def _is_nonneg_int(value: str) -> bool:
    """A canonical nonnegative integer string (no sign, no whitespace)."""
    return isinstance(value, str) and value.isdigit()


def _is_positive_int(value: str) -> bool:
    return _is_nonneg_int(value) and int(value) > 0


def _valid_timestamp(value: str) -> bool:
    return isinstance(value, str) and bool(_TIMESTAMP_RE.match(value))


def _worker_generation_complete(obs: WorkerObservation) -> bool:
    """A matching SHA-256 marker is NOT sufficient when it was computed from an INCOMPLETE
    generation tuple. Validate the RAW facts BEFORE deriving/comparing the marker: a nonempty
    ordinary container
    id, a nonnegative-integer restart count, a nonempty valid start timestamp, a nonzero numeric PID
    while running, and — the reviewed rule for a present (disabled+stopped) operator — a defined
    (nonempty) operator InvocationID. No generation component may be missing."""
    if not obs.ordinary_container_id:
        return False
    if not _is_nonneg_int(obs.ordinary_restart_count):
        return False
    if not _valid_timestamp(obs.ordinary_started_at):
        return False
    if obs.ordinary_running and not _is_positive_int(obs.ordinary_pid):
        return False
    # a present operator (the canonical prepared posture is present + disabled + STOPPED) still
    # exposes a defined InvocationID generation fact; its absence is a missing generation component.
    if obs.operator_present and not obs.operator_invocation_id:
        return False
    return True


def _controller_generation_complete(obs: ControllerObservation, expected: tuple[str, ...]) -> bool:
    """The per-component generation maps must cover EXACTLY the signed expected component set (no
    unknown or missing component), every container id nonempty, and every restart count a
    nonnegative integer — checked BEFORE deriving/comparing the SHA-256 marker."""
    exp_set = set(expected)
    if set(obs.container_ids) != exp_set:
        return False
    if set(obs.restart_counts) != exp_set:
        return False
    if set(obs.container_image_digests) != exp_set:
        return False
    if any(not cid for cid in obs.container_ids.values()):
        return False
    if any(not _is_nonneg_int(rc) for rc in obs.restart_counts.values()):
        return False
    return True


def _worker_generation_ok(obs: WorkerObservation) -> bool:
    return (
        _worker_generation_complete(obs)
        and is_generation_marker(obs.generation_marker)
        and obs.generation_marker == _worker_generation(obs)
    )


def _controller_generation_ok(obs: ControllerObservation, exp: _ExpectedController) -> bool:
    return (
        _controller_generation_complete(obs, exp.expected_components)
        and is_generation_marker(obs.generation_marker)
        and obs.generation_marker == _controller_generation(obs)
    )


def _worker_end_state_reason(obs: WorkerObservation, exp: _ExpectedWorker) -> str | None:
    """None only when the worker host is in the COMPLETE canonical prepared end state a successful
    bootstrap produces — used by the bootstrap reobservation gate, the adoption precondition (so
    adoption is never a dead end), AND status. Images are matched to the EXACT signed purpose, never
    set membership: the ordinary container must run the signed worker/ordinary image and the
    operator
    the signed worker/operator image (so the ordinary worker can never run the operator image)."""
    if not obs.coherent:
        return "worker_reobservation_incoherent"
    if not _worker_generation_ok(obs):
        return "worker_generation_marker_invalid"
    if not (obs.ordinary_present and obs.ordinary_running and obs.ordinary_healthy):
        return "worker_ordinary_not_ready"
    if obs.ordinary_image_digest != exp.ordinary_image:
        return "worker_ordinary_image_mismatch"
    if obs.ordinary_config_identity != exp.ordinary_config_identity:
        return "worker_ordinary_config_mismatch"
    if obs.ordinary_health_command_identity != exp.health_command_identity:
        return "worker_health_command_mismatch"
    if not (obs.operator_present and not obs.operator_enabled and not obs.operator_running):
        return "worker_operator_not_disabled_stopped"
    if obs.operator_image_digest != exp.operator_image:
        return "worker_operator_image_mismatch"
    if obs.operator_unit_identity != exp.operator_unit_identity:
        return "worker_operator_unit_mismatch"
    if obs.deployment_package_aggregate != exp.deployment_aggregate:
        return "worker_deployment_package_mismatch"
    if obs.ordinary_polls_operator_queue:
        return "worker_ordinary_polls_operator_queue"
    if not obs.package_trusted:
        return "worker_operator_package_untrusted"
    if obs.commissioning_status != "prepared":
        return "worker_commissioning_not_prepared"
    if obs.deployment_status != "sealed_prepared":
        return "worker_deployment_not_sealed_prepared"
    return None


def _controller_end_state_reason(
    obs: ControllerObservation, exp: _ExpectedController
) -> str | None:
    """Images are matched to the EXACT signed component->image mapping, never set membership or
    subset, so a swap BETWEEN two otherwise-valid release images is caught. The component set +
    image
    mapping are checked FIRST (so a genuine stack mismatch keeps its specific reason); the
    generation
    marker completeness/derivation is validated once the component set is known correct."""
    if not obs.coherent:
        return "controller_reobservation_incoherent"
    if obs.unknown_privileged:
        return "controller_unknown_privileged_service"
    if tuple(sorted(obs.container_image_digests)) != tuple(sorted(exp.expected_components)):
        return "controller_component_set_mismatch"
    if obs.container_image_digests != exp.component_images:
        return "controller_component_image_mismatch"
    # the generation tuple must be COMPLETE (per-component ids/restarts cover the expected set, each
    # nonempty/nonnegative) AND the observer's SHA-256 marker must equal the engine's own derivation
    if not _controller_generation_ok(obs, exp):
        return "controller_generation_marker_invalid"
    if not all(obs.running.get(c, False) for c in exp.expected_components):
        return "controller_not_all_running"
    if not all(obs.healthy.get(c, False) for c in exp.expected_components):
        return "controller_not_all_healthy"
    if obs.config_identity != exp.config_identity:
        return "controller_config_mismatch"
    if obs.unit_identity != exp.unit_identity:
        return "controller_unit_mismatch"
    if obs.migration_identity != exp.migration_identity:
        return "controller_migration_mismatch"
    return None


@dataclass(frozen=True)
class _Classification:
    reason: str | None
    fresh: bool


def _classify_preexisting(
    role: Role, vr: VerifiedRelease, deps: EngineDeps, *, mode: str
) -> _Classification:
    """Before ANY host op, classify ALL FIVE target documents (identity, release manifest, release
    signature, evidence, evidence attestation). Permit only ALL-FIVE-ABSENT (fresh) or an EXACT,
    fully revalidated idempotent same-release install of the intended mode; refuse a partial (incl.
    an attestation-only/orphan state, the four core docs without the attestation, or the attestation
    with only a subset of core docs), foreign, drifted, changed-release, or mode-crossed
    pre-existing
    state — and NEVER trust ev.mode/classification before the detached attestation has verified."""
    fs = deps.filesystem()
    loc = deps.locations
    paths = (
        loc.identity_path(role.value),
        loc.release_record_path(role.value),
        loc.release_sig_path(role.value),
        loc.evidence_path(role.value),
        loc.evidence_attestation_path(role.value),
    )
    present = [fs.lstat(p) is not None for p in paths]  # type: ignore[attr-defined]
    n = sum(present)
    if n == 0:
        return _Classification(None, True)
    if n != len(paths):
        # covers attestation-only/orphan, four-core-without-attestation, and attestation+subset
        return _Classification("preexisting_partial_install", False)

    ev, ev_reason = _load_evidence(role, deps)
    if ev is None:
        return _Classification("preexisting_foreign_record", False)
    ident, _ir = _load_identity(role, deps)
    if ident is None:
        return _Classification("preexisting_foreign_record", False)
    record, _rr = _load_release_record(role, deps)
    if record is None:
        return _Classification("preexisting_foreign_record", False)
    if (
        ident.installation_id != ev.installation_id
        or ident.release_digest != ev.release_aggregate_digest
    ):
        return _Classification("preexisting_identity_evidence_disagreement", False)
    expected_install = _installation_id(role.value, vr.aggregate_digest)
    same_release = (
        ev.release_aggregate_digest == vr.aggregate_digest
        and record.aggregate_digest == vr.aggregate_digest
        and ident.release_digest == vr.aggregate_digest
        and ident.installation_id == expected_install
    )
    if not same_release:
        return _Classification("preexisting_changed_release", False)
    # verify the detached evidence attestation BEFORE trusting the pre-existing mode/classification
    # (a re-authored evidence — including an adopted→installed mode rewrite — fails the signature
    # and
    # is refused here, never as a mode-specific refusal).
    if _verify_evidence_attestation(role, deps, ev, ident, record) is not None:
        return _Classification("preexisting_evidence_unauthenticated", False)
    # only NOW is ev.mode authenticated and safe to branch on
    if mode == MODE_INSTALLED and ev.mode == MODE_ADOPTED:
        return _Classification("bootstrap_over_adopted_refused", False)
    if mode == MODE_ADOPTED and ev.mode == MODE_INSTALLED:
        return _Classification("adopt_over_installed_refused", False)
    if _record_binding_reason(role, ev, ident, record) is not None:
        return _Classification("preexisting_drifted_install", False)
    # all FIVE existing documents must ALSO be intact + independently authenticated (a
    # modified-but-parseable identity/record/signature/evidence/attestation — including a
    # wrong-owner/mode/type/link attestation — is caught by the shared verifier).
    if _verify_installed_documents(role, deps, ev, ident, record) is not None:
        return _Classification("preexisting_drifted_install", False)
    return _Classification(None, False)  # exact idempotent same-release install


# --------------------------------------------------------------------------- write transaction


def _install_doc(fs: object, loc: ManagementLocations, path: str, data: bytes) -> None:
    loc.assert_writable(path)
    fs.atomic_install(path, data, uid=_ROOT_UID, gid=_ROOT_UID, mode=_MANAGED_FILE_MODE)  # type: ignore[attr-defined]


def _reverify_doc(deps: EngineDeps, path: str, expected: bytes, reason: str) -> None:
    reread = deps.filesystem().safe_read(path, max_bytes=_MAX_DOC_BYTES, expected_uid=_ROOT_UID)  # type: ignore[attr-defined]
    if reread != expected:
        raise ManagementError(reason)


def _proven_document(fs: object, path: str, expected: bytes) -> bool:
    """Prove an on-disk document is exactly ``expected``: present, regular, no symlink, single link,
    root-owned, mode 0640, AND byte-identical content."""
    try:
        stt = fs.lstat(path)  # type: ignore[attr-defined]
        if stt is None or stt.is_symlink or not stt.is_regular or stt.nlink != 1:
            return False
        if (
            stt.uid != _ROOT_UID
            or stt.gid != _ROOT_UID
            or (stt.mode & 0o7777) != _MANAGED_FILE_MODE
        ):
            return False
        data = fs.safe_read(path, max_bytes=_MAX_RECORD_BYTES, expected_uid=_ROOT_UID)  # type: ignore[attr-defined]
        return data == expected
    except Exception:
        return False


class _DocWriter:
    """A restore-on-failure document writer. It captures the ORIGINAL bytes of each target before an
    atomic install; ``compensate()`` removes newly-created documents (proving each is absent) AND
    restores overwritten ones (PROVING the restored digest/owner/mode/type/link-count), never
    swallows
    an exception, and returns a typed :class:`CompensationResult` (any unproven restore/removal ⇒ a
    residual, which forces the transaction to report ``recovery_required``). So a failed idempotent
    re-install/re-adoption never silently leaves a pre-existing document mutated."""

    def __init__(self, fs: object, loc: ManagementLocations) -> None:
        self._fs = fs
        self._loc = loc
        self._journal: list[tuple[str, bytes | None]] = []

    def install(self, path: str, data: bytes) -> None:
        try:
            original: bytes | None = self._fs.safe_read(  # type: ignore[attr-defined]
                path, max_bytes=_MAX_RECORD_BYTES, expected_uid=_ROOT_UID
            )
        except Exception:
            original = None  # did not pre-exist (or is not a trusted regular file) → newly created
        _install_doc(self._fs, self._loc, path, data)
        self._journal.append((path, original))

    def compensate(self) -> CompensationResult:
        residual: list[str] = []
        for path, original in reversed(self._journal):
            try:
                if original is None:
                    self._fs.remove_file(path)  # type: ignore[attr-defined]
                    if self._fs.lstat(path) is not None:  # type: ignore[attr-defined]
                        residual.append(path)  # newly-created object still present
                else:
                    _install_doc(self._fs, self._loc, path, original)
                    if not _proven_document(self._fs, path, original):
                        residual.append(path)  # restoration not provable
            except Exception:
                residual.append(path)  # never swallow: an exception is an unproven compensation
        return CompensationResult(proven=(not residual), residual=tuple(residual))


def _record_bytes(vr: VerifiedRelease) -> tuple[bytes, bytes]:
    manifest_bytes = vr.manifest.canonical().encode("utf-8")
    sig_bytes = canonical_json(
        {
            "algorithm": vr.signature.algorithm,
            "key_id": vr.signature.key_id,
            "signature": vr.signature.signature,
        }
    ).encode("utf-8")
    return manifest_bytes, sig_bytes


def _build_identity(role: Role, vr: VerifiedRelease, now: str) -> ManagementPlaneIdentity:
    return ManagementPlaneIdentity(
        bootstrap_contract_version=BOOTSTRAP_CONTRACT_VERSION,
        plane=Plane.MANAGEMENT.value,
        role=role.value,
        installation_id=_installation_id(role.value, vr.aggregate_digest),
        organization_site=None,
        release_digest=vr.aggregate_digest,
        source_sha=vr.manifest.source_sha,
        source_tree_sha=vr.manifest.source_tree_sha,
        parent_sha=vr.manifest.parent_sha,
        installed_artifact_digests=tuple(a.sha256 for a in vr.manifest.artifacts),
        created_at=now,
    )


def _object_records(
    role: Role,
    loc: ManagementLocations,
    *,
    identity_bytes: bytes,
    manifest_bytes: bytes,
    sig_bytes: bytes,
    classification: str,
) -> tuple[ManagedObjectRecord, ...]:
    r = role.value
    specs = (
        (OBJECT_IDENTITY, loc.identity_path(r), sha256_bytes(identity_bytes)),
        (OBJECT_RELEASE_MANIFEST, loc.release_record_path(r), sha256_bytes(manifest_bytes)),
        (OBJECT_RELEASE_SIGNATURE, loc.release_sig_path(r), sha256_bytes(sig_bytes)),
        (OBJECT_EVIDENCE, loc.evidence_path(r), None),  # self-binding: no embedded digest
        # the detached attestation is a first-class owned document; its content is authenticated by
        # its own Ed25519 signature, so like evidence it carries no embedded content digest here.
        (OBJECT_EVIDENCE_ATTESTATION, loc.evidence_attestation_path(r), None),
    )
    return tuple(
        ManagedObjectRecord(
            role=r,
            kind=kind,
            binding=path_binding_digest(r, path),
            content_sha256=digest,
            uid=_ROOT_UID,
            gid=_ROOT_UID,
            mode=_MANAGED_FILE_MODE,
            classification=classification,
        )
        for (kind, path, digest) in specs
    )


def _build_evidence(
    role: Role,
    vr: VerifiedRelease,
    ident: ManagementPlaneIdentity,
    deps: EngineDeps,
    *,
    mode: str,
    classification: str,
    identity_bytes: bytes,
    manifest_bytes: bytes,
    sig_bytes: bytes,
    config_identity: str,
    unit_identity_value: str,
    deployment_aggregate: str | None,
    expected_components: tuple[str, ...],
    component_image_identity: str | None,
    finalization: FinalizationEvidence | None = None,
) -> BootstrapEvidence:
    seals = read_seals()
    loc = deps.locations
    image_digests = tuple(a.image_digest for a in vr.manifest.artifacts if a.image_digest)
    wheel_digests = tuple(a.sha256 for a in vr.manifest.artifacts if a.kind == "python_wheel")
    path_bindings = tuple(
        path_binding_digest(role.value, p)
        for p in (
            loc.role_root(role.value),
            loc.identity_path(role.value),
            loc.release_record_path(role.value),
            loc.evidence_path(role.value),
        )
    )
    records = _object_records(
        role,
        loc,
        identity_bytes=identity_bytes,
        manifest_bytes=manifest_bytes,
        sig_bytes=sig_bytes,
        classification=classification,
    )
    return BootstrapEvidence(
        bootstrap_contract_version=BOOTSTRAP_CONTRACT_VERSION,
        mode=mode,
        role=role.value,
        plane=Plane.MANAGEMENT.value,
        installation_id=ident.installation_id,
        release_aggregate_digest=vr.aggregate_digest,
        signing_anchor_id=vr.signature_key_id,
        source_sha=vr.manifest.source_sha,
        source_tree_sha=vr.manifest.source_tree_sha,
        parent_sha=vr.manifest.parent_sha,
        image_digests=image_digests,
        wheel_digests=wheel_digests,
        implementation_aggregate=vr.manifest.implementation_aggregate,
        path_bindings=path_bindings,
        container_identities=(ORDINARY_CONTAINER_NAME,) if role is Role.WORKER else (),
        service_identities=(OPERATOR_SERVICE_NAME,) if role is Role.WORKER else (),
        config_identity=config_identity,
        unit_identity=unit_identity_value,
        deployment_package_aggregate=deployment_aggregate,
        expected_components=expected_components,
        component_image_identity=component_image_identity,
        runtime_uid=_RUNTIME_UID,
        runtime_gid=_RUNTIME_GID,
        ordinary_task_queue=ORDINARY_TASK_QUEUE,
        operator_task_queue=OPERATOR_TASK_QUEUE,
        health_command_identity=health_command_identity(ORDINARY_HEALTH_COMMAND),
        object_records=records,
        commissioning_evidence_digest=None,
        operator_activation_sealed=seals.operator_activation_sealed,
        plan_only_process_sealed=seals.plan_only_process_sealed,
        b1a_subprocess_sealed_activation=seals.b1a_subprocess_sealed_activation,
        b1a_subprocess_sealed_executor=seals.b1a_subprocess_sealed_executor,
        finalization=finalization,
        transaction_timestamp=deps.now(),
        external_contacts_performed=False,
        workflows_submitted=False,
        run_plan_generation_called=False,
        opentofu_executed=False,
        proxmox_contacted=False,
    )


def _worker_evidence(
    role: Role,
    vr: VerifiedRelease,
    ident: ManagementPlaneIdentity,
    plan: WorkerBootstrapPlan,
    deps: EngineDeps,
    *,
    mode: str,
    classification: str,
    identity_bytes: bytes,
    manifest_bytes: bytes,
    sig_bytes: bytes,
) -> BootstrapEvidence:
    return _build_evidence(
        role,
        vr,
        ident,
        deps,
        mode=mode,
        classification=classification,
        identity_bytes=identity_bytes,
        manifest_bytes=manifest_bytes,
        sig_bytes=sig_bytes,
        config_identity=plan.ordinary_config.identity,
        unit_identity_value=plan.operator_unit.identity,
        deployment_aggregate=plan.deployment_aggregate,
        expected_components=(),
        component_image_identity=None,
    )


def _controller_evidence(
    role: Role,
    vr: VerifiedRelease,
    ident: ManagementPlaneIdentity,
    plan: ControllerBootstrapPlan,
    deps: EngineDeps,
    *,
    mode: str,
    classification: str,
    identity_bytes: bytes,
    manifest_bytes: bytes,
    sig_bytes: bytes,
    finalization: FinalizationEvidence | None = None,
) -> BootstrapEvidence:
    return _build_evidence(
        role,
        vr,
        ident,
        deps,
        mode=mode,
        classification=classification,
        identity_bytes=identity_bytes,
        manifest_bytes=manifest_bytes,
        sig_bytes=sig_bytes,
        config_identity=plan.config.identity,
        unit_identity_value=plan.unit.identity,
        deployment_aggregate=None,
        expected_components=plan.expected_components,
        # bind the SIGNED component->image mapping (never the observed host mapping)
        component_image_identity=_component_image_identity(plan.component_images),
        finalization=finalization,
    )


# ------------------------------------------------------------------- controller finalization
# (2b-3c)

#: the bounded number of staging transaction directories the R5 sweep will probe; more than
#: this cannot be proven absent and is reported as a residual.
_MAX_STAGING_TRANSACTIONS = 64
_FINALIZATION_TXID_SCHEMA = "secp.management.finalization-txid/v1"

# Activation failures whose outcome is DETERMINATE: the refusal was REPORTED (or raised by an engine
# pre-check) BEFORE the API could durably commit, so no identity was activated and an ordinary
# bounded refusal is truthful. EVERY OTHER failure once the activation was attempted is
# INDETERMINATE — the API commits inside the one-shot and parses its receipt afterwards, so a
# transport fault, a timeout, non-canonical output, or a receipt mismatch may have left a durably
# active candidate with no receipt. Those force recovery_required (never a false ordinary error).
_ACTIVATION_DETERMINATE_REASONS = frozenset(
    {
        "finalization_activation_refused",  # the one-shot REPORTED a refusal payload (no commit)
        "activation_generation_out_of_order",  # durable per-row generation CAS refused it
        "activation_generation_not_fresh",
        "activation_predecessor_conflict",
        "activation_predecessor_receipt_missing",
        "activation_candidate_already_active",
        "finalization_activation_generation_mismatch",  # engine pre-check, before the one-shot
        "finalization_predecessor_conflict",  # engine pre-check, before the one-shot
        "finalization_handoff_posture_invalid",  # before the one-shot
        "finalization_transaction_sealed",
    }
)


@dataclass(frozen=True)
class _ControllerInstallClassification:
    """The closed controller-install classification + the authenticated prior state it derived.
    Every
    field is nonsecret."""

    reason: str | None
    classification: str | None  # CLASSIFY_FRESH / EXACT_SAME_RELEASE / MANAGED_UPGRADE
    generation: int
    prior_evidence: BootstrapEvidence | None


@dataclass
class _DriveState:
    """A MUTABLE holder the finalization drive publishes into AS ops progress — the bound adapter as
    soon as it is built, the ATTEMPT flag before the durable activation one-shot, and the activation
    receipt as soon as it returns — so the engine's combined compensation can reach the adapter and
    know a candidate identity may be durably active even when a later op raises mid-drive.

    ``activation_attempted`` is set BEFORE the one-shot because the API commits the new active
    identity durably INSIDE that call and only then is its receipt parsed: a raise in that window
    (non-canonical output, a post-commit timeout, a receipt mismatch) leaves a durably activated
    candidate with NO receipt and NO recorded effect. Compensation must therefore treat
    attempted-but-unconfirmed as an UNPROVEN residual (recovery_required), never as no-effect."""

    adapter: object | None = None
    arec: object | None = None
    activation_attempted: bool = False


def _sep_digest(schema: str, value: object) -> str:
    """A domain-separated sha256 digest under a versioned schema identity."""
    return sha256_digest({"v": schema, "value": value})


def _classify_controller_install(
    vr: VerifiedRelease, deps: EngineDeps
) -> _ControllerInstallClassification:
    """Extend the bootstrap classification with the finalization prior state WITHOUT weakening any
    existing refusal. Closed outcomes: FRESH (all five docs absent AND no managed finalization
    state); EXACT_SAME_RELEASE (an exact, fully authenticated bootstrap replay PLUS a present,
    verified prior finalization extension whose bootstrap_binding_digest recomputes and whose marker
    exists); MANAGED_UPGRADE (a changed release that is an authenticated linear successor of a
    complete prior B2 install → generation N+1); REFUSED (partial/foreign/drift/unauthenticated/
    mode-crossed/non-successor/downgrade/finalization-orphan/legacy-without-finalization). A changed
    release is NEVER an unconditional upgrade -- only an authenticated linear successor."""
    base = _classify_preexisting(Role.CONTROLLER, vr, deps, mode=MODE_INSTALLED)
    fs = deps.filesystem()
    loc = deps.locations
    marker_present = fs.lstat(loc.api_signer_marker_path()) is not None  # type: ignore[attr-defined]
    # R1: classify the COMPLETE finalization installation before ANY mutation. Fresh now means every
    # installer-owned object is absent (TLS set, locator, credential, enrollment key, broker unit /
    # service / socket, both handoffs, marker, recovery journal, staging + backups) AND the
    # dedicated
    # signer role, active identity and activation/generation state are absent. Any orphan or partial
    # set refuses with its own bounded, object-specific reason instead of being silently adopted.
    inv = deps.finalization_inventory() if deps.finalization_inventory is not None else None
    if inv is None:
        return _ControllerInstallClassification(
            "finalization_inventory_not_composed", None, 0, None
        )
    if base.fresh:
        if marker_present:  # a clean bootstrap host must ALSO carry no managed finalization state
            return _ControllerInstallClassification(
                "controller_install_finalization_orphan", None, 0, None
            )
        if not inv.is_fresh:
            return _ControllerInstallClassification(inv.orphan_reason, None, 0, None)
        return _ControllerInstallClassification(None, CLASSIFY_FRESH, 0, None)
    if inv.has_transient_state:
        # a handoff / recovery journal / staging object means an INTERRUPTED transaction, never a
        # complete install that may be replayed or upgraded.
        return _ControllerInstallClassification(inv.transient_reason, None, 0, None)
    if not inv.is_complete:
        return _ControllerInstallClassification(inv.complete_reason, None, 0, None)
    if base.reason == "preexisting_changed_release":
        # a changed release is the ONLY case eligible for a managed upgrade — and only after the
        # prior complete B2 install is fully re-authenticated and the new release is proven a linear
        # successor. The base classifier returned this reason BEFORE the attestation verify, so the
        # upgrade path re-authenticates everything from scratch.
        return _classify_upgrade_eligibility(vr, deps)
    if base.reason is not None:  # every OTHER bootstrap refusal is preserved verbatim
        return _ControllerInstallClassification(base.reason, None, 0, None)
    # exact idempotent same-release bootstrap: base already authenticated all five docs +
    # attestation
    ev, _ = _load_evidence(Role.CONTROLLER, deps)
    if ev is None or ev.finalization is None:
        # legacy/pre-2b-3c controller evidence (no finalization extension) is readable for status/
        # rollback but is NOT automatically eligible for a B2 managed replay.
        return _ControllerInstallClassification(
            "controller_install_finalization_missing", None, 0, None
        )
    if not marker_present:
        return _ControllerInstallClassification("controller_install_marker_absent", None, 0, None)
    if ev.finalization.bootstrap_binding_digest != ev.bootstrap_binding_digest():
        return _ControllerInstallClassification("controller_install_binding_drift", None, 0, None)
    return _ControllerInstallClassification(
        None, CLASSIFY_EXACT_SAME_RELEASE, ev.finalization.generation, ev
    )


def _classify_upgrade_eligibility(
    vr: VerifiedRelease, deps: EngineDeps
) -> _ControllerInstallClassification:
    """A changed release qualifies as a MANAGED_UPGRADE only when the PRIOR complete B2 install is
    fully re-authenticated (evidence + attestation + record binding + document integrity + present,
    coherent marker + finalization extension) AND the new release is proven an authenticated LINEAR
    SUCCESSOR of the prior (``new.parent_sha == prior.source_sha`` — both signed). Generation
    becomes
    the prior authenticated finalization generation + 1. Every other changed-release state refuses.
    The durable per-row generation CAS in the API activation one-shot is the independent anti-
    downgrade / anti-skip backstop during the drive."""
    ev, ident, record, reason = _revalidate_records(Role.CONTROLLER, deps)
    if reason is not None:  # prior unreadable / unauthenticated / binding drift
        return _ControllerInstallClassification(
            "controller_upgrade_prior_unauthenticated", None, 0, None
        )
    assert ev is not None and ident is not None and record is not None
    if _verify_installed_documents(Role.CONTROLLER, deps, ev, ident, record) is not None:
        return _ControllerInstallClassification("controller_upgrade_prior_drifted", None, 0, None)
    if ev.finalization is None:  # a plain (non-B2) prior install is not eligible for a B2 upgrade
        return _ControllerInstallClassification(
            "controller_upgrade_prior_not_finalized", None, 0, None
        )
    if ev.finalization.bootstrap_binding_digest != ev.bootstrap_binding_digest():
        return _ControllerInstallClassification("controller_install_binding_drift", None, 0, None)
    marker_reason = _verify_marker_binding(deps, ev)  # prior marker present + binds prior identity
    if marker_reason is not None:
        return _ControllerInstallClassification(marker_reason, None, 0, None)
    # linear-successor trust-window rule: the new release must descend from the prior installed one.
    prior_source = record.manifest.source_sha
    if not vr.manifest.parent_sha or vr.manifest.parent_sha != prior_source:
        return _ControllerInstallClassification(
            "controller_upgrade_not_linear_successor", None, 0, None
        )
    # R3: the prior installation must be LIVE-PROVEN before it may be upgraded -- exactly one
    # verified ACTIVE identity, the exact marker binding, the dedicated role + credential, the
    # broker
    # transport and the API signer runtime, with every generation field in agreement. Documents and
    # the marker file alone are never sufficient.
    live_reason = _live_state_refusal(ev, ident, record, deps)
    if live_reason is not None:
        return _ControllerInstallClassification(live_reason, None, 0, None)
    generation = ev.finalization.generation + 1
    return _ControllerInstallClassification(None, CLASSIFY_MANAGED_UPGRADE, generation, ev)


def _live_state_refusal(
    ev: BootstrapEvidence,
    ident: ManagementPlaneIdentity,
    record: VerifiedRelease,
    deps: EngineDeps,
) -> str | None:
    """R3: independently observe the LIVE finalization state and return a bounded refusal reason, or
    None when every proof holds. Mutation-free. A missing observer seam REFUSES (never skips)."""
    fin = ev.finalization
    if fin is None:
        return "controller_install_finalization_missing"
    if deps.finalization_state_observer is None:
        return "finalization_state_observer_not_composed"
    from secp_management.controller_finalization_state import ExpectedControllerState

    try:
        api_image = signed_controller_image_map(record.manifest).get("api", "")
    except ManagementError:
        api_image = ""
    expected = ExpectedControllerState(
        generation=fin.generation,
        installation_id=ident.installation_id,
        release_digest=ev.release_aggregate_digest,
        controller_key_id=fin.enrollment_key_id,
        active_identity_row_id=fin.active_identity_row_id,
        management_identity_digest=ident.digest(),
        bootstrap_binding_digest=fin.bootstrap_binding_digest,
        enrollment_key_proof_id=fin.enrollment_key_proof_id,
        locator_ca_digest=fin.locator_ca_digest,
        api_image_digest=api_image,
    )
    try:
        state = deps.finalization_state_observer(expected=expected)
    except Exception:  # noqa: BLE001 - an unobservable live state is never a proven one
        return "controller_state_unobservable"
    return state.refusal_reason(expected)


def _expected_api_image_digest(vr: VerifiedRelease) -> str:
    """The expected controller API image, taken ONLY from the SIGNED controller/api purpose mapping
    of the verified release (the same closed helper the bootstrap plan + end-state gate use). Not a
    new manifest field, an unsigned Compose scan, an environment variable, a Docker observation, the
    marker, or a caller-selectable argument. A release whose signed mapping has no controller/api
    image refuses rather than yielding an empty (unprovable) expectation."""
    digest = signed_controller_image_map(vr.manifest).get("api", "")
    if not is_sha256_digest(digest):
        raise ManagementError("finalization_expected_api_image_unavailable")
    return digest


def _build_controller_finalization_plan(
    vr: VerifiedRelease,
    ident: ManagementPlaneIdentity,
    ev0: BootstrapEvidence,
    install: ControllerInstallOptions,
    loc: ManagementLocations,
    generation: int,
) -> ControllerEnrollmentFinalizationPlan:
    """Build the closed, nonsecret finalization plan from already-verified inputs. Binds the
    explicit
    domain-separated ``bootstrap_binding_digest`` (never a partial evidence digest) that the
    identity
    activation + marker will carry. Refuses a missing signed TLS policy or an operator mode outside
    the signed policy's allowed modes."""
    from secp_commissioning.enrollment_signer_role import ENROLLMENT_SIGNER_DB_ROLE

    from secp_management.controller_compose_contract import render_broker_reviewed_unit

    policy = vr.manifest.controller_tls_policy
    if policy is None:
        raise ManagementError("finalization_tls_policy_missing")
    if install.tls_mode not in policy.allowed_modes:
        raise ManagementError("finalization_tls_mode_not_permitted")
    return ControllerEnrollmentFinalizationPlan(
        role=Role.CONTROLLER.value,
        tls_policy=policy,
        canonical_origin=install.canonical_origin,
        tls_mode=install.tls_mode,
        signer_role=ReviewedSignerRole(
            role_name=ENROLLMENT_SIGNER_DB_ROLE,
            credential_source_path=loc.enrollment_signer_credential_path(),
        ),
        broker_unit=render_broker_reviewed_unit(loc),
        controller_installation_id=ident.installation_id,
        release_digest=vr.aggregate_digest,
        management_identity_digest=ident.digest(),
        bootstrap_evidence_digest=ev0.bootstrap_binding_digest(),
        generation=generation,
        # R4: bind the observation to the SIGNED candidate api image and to the authenticated
        # generation of the controller stack that R2 applied + proved before finalization began.
        expected_api_image_digest=_expected_api_image_digest(vr),
        # the controller stack this plan is bound to was applied AND proven at exactly this
        # generation by the R2 candidate-stack step, which runs to completion (including the exact
        # signed component/image-map reobservation) BEFORE finalization begins.
        controller_stack_generation=generation,
    )


@dataclass
class _PreparedFinalization:
    """The ONE plan-bound finalization adapter, built early so the readiness gate exists before the
    first Compose start that mounts it. Carries no state of its own beyond that binding."""

    plan: ControllerEnrollmentFinalizationPlan
    adapter: ControllerEnrollmentFinalizationAdapter


def _prepare_readiness_gate(
    vr: VerifiedRelease,
    ident: ManagementPlaneIdentity,
    ev0: BootstrapEvidence,
    install: ControllerInstallOptions,
    loc: ManagementLocations,
    generation: int,
    deps: EngineDeps,
    state: _DriveState,
) -> _PreparedFinalization:
    """Create/adopt and PROVE the readiness gate before any Compose operation that mounts it.

    The signed controller template binds the gate with ``create_host_path: false``, so a start with
    the gate absent fails rather than letting Docker fabricate a directory at a secret's path. The
    adapter is published to ``state`` BEFORE the gate step runs, so a failure in the gate step
    itself -- and every later bootstrap, image-load or stack-start failure -- compensates the gate
    through the same single receipt that owns it.

    Fresh install: generated from the OS CSPRNG, installed atomically, re-read and proven. Exact
    replay and managed upgrade: adopted UNCHANGED, so neither rotates a live API's authorization."""
    if deps.finalization_factory is None:
        raise ManagementError("finalization_not_composed")
    plan = _build_controller_finalization_plan(vr, ident, ev0, install, loc, generation)
    adapter = deps.finalization_factory(plan)
    state.adapter = adapter  # compensatable from this instant, before the first mutation
    adapter.install_readiness_gate()
    return _PreparedFinalization(plan=plan, adapter=adapter)


def _drive_controller_finalization(
    vr: VerifiedRelease,
    ident: ManagementPlaneIdentity,
    ev0: BootstrapEvidence,
    install: ControllerInstallOptions,
    loc: ManagementLocations,
    generation: int,
    classification: str,
    deps: EngineDeps,
    *,
    previous_active_row_id: str | None = None,
    state: _DriveState | None = None,
    prepared: _PreparedFinalization | None = None,
) -> tuple[object, ControllerFinalizationReceipt, FinalizationEvidence]:
    """Drive the corrected finalization adapter through its exact reviewed order (fresh install ⇒
    previous_active_row_id None + generation 0; managed upgrade ⇒ the prior active row + generation
    N+1), then build the authenticated FinalizationEvidence from the typed receipt + observed facts.
    The optional ``state`` holder is published AS ops progress (the bound adapter as soon as it is
    built, the activation receipt as soon as it returns) so a mid-drive failure is visible to the
    engine's combined compensation. Any step raises -> combined compensation runs (marker-first)."""
    from secp_commissioning.controller_enrollment_signer import ENROLLMENT_SIGNER_SOCKET_PATH
    from secp_commissioning.enrollment_signer_role import ENROLLMENT_SIGNER_DB_ROLE

    if deps.finalization_factory is None:
        raise ManagementError(
            "finalization_not_composed"
        )  # never fall through to the sealed default
    if prepared is not None:
        # the SAME adapter that already created/adopted the readiness gate before the API started.
        # Rebuilding here would produce a second single-use adapter, a second receipt, and a second
        # gate -- exactly the split ownership this ordering fix must not introduce.
        plan, fadapter = prepared.plan, prepared.adapter
    else:
        plan = _build_controller_finalization_plan(vr, ident, ev0, install, loc, generation)
        fadapter = deps.finalization_factory(plan)  # ONE fresh, plan-bound, single-use adapter
    binding = plan.bootstrap_evidence_digest
    if state is not None:
        state.adapter = fadapter  # visible to compensation the moment the adapter exists
    fs = deps.filesystem()

    fadapter.install_tls_material(
        policy=plan.tls_policy, canonical_origin=plan.canonical_origin, tls_mode=plan.tls_mode
    )
    ca_bytes = fs.safe_read(  # type: ignore[attr-defined]
        loc.controller_ca_bundle_path(), max_bytes=_MAX_DOC_BYTES, expected_uid=_ROOT_UID
    )
    ca_digest = sha256_bytes(ca_bytes)  # the ACTUAL installed CA (must equal the marker's binding)
    fadapter.record_locator(canonical_origin=plan.canonical_origin)
    fadapter.provision_signer_role(plan.signer_role)
    key = fadapter.prepare_enrollment_key()
    if prepared is None:
        # The readiness-origin GATE, BEFORE anything can recreate the API. On the prepared path it
        # already ran (it HAD to: the signed Compose mounts it with create_host_path:false, so the
        # stack could not have started without it), and running it again would be a second effect
        # for one object.
        fadapter.install_readiness_gate()
    fadapter.install_broker_unit(plan.broker_unit)
    fadapter.start_broker()
    fadapter.verify_signer_operational(key_identity=key)
    op_id = _sep_digest(
        "secp.management.activation-op/v1",
        {"install": ident.installation_id, "generation": generation, "binding": binding},
    )
    activation = ControllerIdentityActivation(
        controller_installation_id=ident.installation_id,
        controller_key_id=key.controller_key_id,
        controller_trust_anchor_hex=key.controller_trust_anchor_hex,
        controller_origin=plan.canonical_origin,
        release_digest=vr.aggregate_digest,
        management_identity_digest=ident.digest(),
        bootstrap_evidence_digest=binding,
        enrollment_key_proof_id=key.enrollment_key_proof_id,
        operation_id=op_id,
        generation=generation,
        previous_active_row_id=previous_active_row_id,  # None fresh; prior active row on upgrade
    )
    if state is not None:
        # BEFORE the durable one-shot: the API commits the activation inside this call and parses
        # its
        # receipt afterwards, so a raise in that window leaves a durably active candidate with no
        # receipt. Publishing the ATTEMPT makes that window an unproven residual, never a no-effect.
        state.activation_attempted = True
    arec = fadapter.activate_controller_identity(activation)
    if state is not None:
        state.arec = arec  # the candidate identity is CONFIRMED active (row + token known)
    marker = ApiSignerMarker(
        marker_path=loc.api_signer_marker_path(),
        installation_id=ident.installation_id,
        release_digest=vr.aggregate_digest,
        active_identity_row_id=arec.resulting_row_id,
        activation_token=arec.activation_token,
        controller_key_id=key.controller_key_id,
        uds_contract_identity=ENROLLMENT_SIGNER_SOCKET_PATH,
        api_uid=_RUNTIME_UID,
        api_gid=_RUNTIME_GID,
        signer_role_name=ENROLLMENT_SIGNER_DB_ROLE,
        locator_ca_digest=ca_digest,
        management_identity_digest=ident.digest(),
        bootstrap_evidence_digest=binding,
    )
    fadapter.enable_api_signer(marker)  # LAST — writes marker, restarts API, proves runtime sealed
    freceipt = fadapter.receipt()
    fin_ev = _finalization_evidence_from(
        plan, key, activation, arec, marker, ca_digest, freceipt, classification
    )
    return fadapter, freceipt, fin_ev


def _finalization_evidence_from(
    plan: ControllerEnrollmentFinalizationPlan,
    key: object,
    activation: ControllerIdentityActivation,
    arec: object,
    marker: ApiSignerMarker,
    ca_digest: str,
    freceipt: ControllerFinalizationReceipt,
    classification: str,
) -> FinalizationEvidence:
    """Build the strict PUBLIC finalization evidence from the plan + typed receipt + observed facts.
    Every concurrency token is stored as a domain-separated digest; no secret byte is included."""
    effects = tuple(
        FinalizationEffectRecord(
            effect=e.effect,
            object_identity=e.object_identity,
            disposition=e.disposition,
            candidate_digest=(e.candidate_digest or None),
        )
        for e in freceipt.effects
    )
    cred = freceipt.of("signer_credential")
    cred_binding = (
        _sep_digest("secp.management.signer-credential-binding/v1", cred.ownership_evidence)
        if cred is not None and cred.ownership_evidence
        else None
    )
    marker_public = {
        "installation_id": marker.installation_id,
        "release_digest": marker.release_digest,
        "active_identity_row_id": marker.active_identity_row_id,
        "controller_key_id": marker.controller_key_id,
        "uds_contract_identity": marker.uds_contract_identity,
        "signer_role_name": marker.signer_role_name,
        "locator_ca_digest": marker.locator_ca_digest,
        "bootstrap_evidence_digest": marker.bootstrap_evidence_digest,
        "management_identity_digest": marker.management_identity_digest,
        "api_uid": marker.api_uid,
        "api_gid": marker.api_gid,
    }
    marker_identity = _sep_digest("secp.management.api-signer-marker/v1", marker_public)
    receipt_digest = _sep_digest(
        "secp.management.finalization-receipt/v1",
        [
            [e.effect, e.object_identity, e.disposition, e.candidate_digest]
            for e in freceipt.effects
        ],
    )
    return FinalizationEvidence(
        schema_version=FINALIZATION_SCHEMA_VERSION,
        role=Role.CONTROLLER.value,
        mode=MODE_INSTALLED,
        classification=classification,
        generation=plan.generation,
        transaction_id_digest=_sep_digest(_FINALIZATION_TXID_SCHEMA, freceipt.transaction_id),
        bootstrap_binding_digest=plan.bootstrap_evidence_digest,
        finalization_receipt_digest=receipt_digest,
        canonical_origin_digest=_sep_digest(
            "secp.management.controller-origin/v1", plan.canonical_origin
        ),
        tls_mode=plan.tls_mode,
        tls_policy_identity=_sep_digest(
            "secp.management.controller-tls-policy/v1", plan.tls_policy.model_dump(mode="json")
        ),
        locator_ca_digest=ca_digest,
        signer_role_identity=_sep_digest(
            "secp.management.enrollment-signer-role/v1",
            {"role": plan.signer_role.role_name, "cred": plan.signer_role.credential_source_path},
        ),
        signer_login_binding_digest=cred_binding,
        enrollment_key_id=key.controller_key_id,  # type: ignore[attr-defined]
        enrollment_key_proof_id=key.enrollment_key_proof_id,  # type: ignore[attr-defined]
        broker_unit_identity=plan.broker_unit.identity,
        broker_transport_identity=_sep_digest(
            "secp.management.broker-transport/v1", marker.uds_contract_identity
        ),
        active_identity_row_id=arec.resulting_row_id,  # type: ignore[attr-defined]
        activation_concurrency_digest=_sep_digest(
            "secp.management.activation-token/v1",
            arec.activation_token,  # type: ignore[attr-defined]
        ),
        activation_operation_digest=_sep_digest(
            "secp.management.activation-op-binding/v1", activation.operation_id
        ),
        marker_identity=marker_identity,
        runtime_observation_identity=_sep_digest(
            "secp.management.api-runtime-observation/v1",
            {"marker": marker_identity, "generation": plan.generation},
        ),
        # R5: this is the PREPARED checkpoint — written BEFORE finalization cleanup, so it must not
        # claim the journal/staging objects are absent. The COMMITTED record is authored only after
        # cleanup runs AND its absence is independently observed.
        finalization_commit_state=FINALIZATION_STATE_PREPARED,
        recovery_journal_absent=False,
        staging_objects_absent=False,
        marker_last=True,
        api_runtime_proven=True,  # enable_api_signer returns only after a proven observation
        no_mixed_generation=True,
        operator_sealed=True,
        controlled_live_sealed=True,
        isolation_boundaries_proven=True,
        effects=effects,
    )


def _finalization_compensation_proven(fadapter: object) -> bool:
    """Combined-compensation helper mirroring :func:`_compensate_host`, on the finalization receipt.
    Returns a bool and NEVER raises so the engine can run it FIRST (the adapter reseals the marker
    first internally) before the doc/host unwind. A lost/malformed receipt is NOT proof of no effect
    → unproven; an empty receipt proves no effect → proven; otherwise drive ``compensate`` and
    require
    a proven, residual-free result."""
    try:
        receipt = fadapter.receipt()  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 - a lost receipt is unproven, never no-effect
        return False
    if type(receipt) is not ControllerFinalizationReceipt:
        return False
    if not receipt.effects:
        return True
    try:
        result = fadapter.compensate(receipt)  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 - a compensation exception is recovery_required
        return False
    return bool(getattr(result, "proven", False)) and not getattr(result, "residual", ("x",))


def _compensate_rollback_participant(rb_state: _DriveState, reason: str | None = None) -> bool:
    """R6: ALWAYS compensate the ROLLBACK participant when any rollback-drive / runtime / evidence /
    attestation / commit-gate / adapter-commit step fails. The rollback adapter may already have
    mutated state (marker, identity, broker, filesystem), so returning a bare False would strand its
    own partial effects. This reverses it MARKER-FIRST through the adapter's own reverse-order
    compensation (which removes/restores the marker and restarts the API back to sealed), preserves
    the exact typed residual classification, and accounts for an attempted-but-INDETERMINATE
    activation. Returns True only when the participant is proven fully reversed; a confirmed
    rollback activation truthfully retains an identity residual (→ False → recovery_required) while
    still guaranteeing the API is sealed and no marker remains enabled."""
    adapter = rb_state.adapter
    if adapter is None:
        # nothing was constructed -> no participant effect to reverse; the caller still fails closed
        return rb_state.activation_attempted is False
    proven = _finalization_compensation_proven(adapter)  # marker-first, never raises
    if rb_state.activation_attempted and rb_state.arec is None:
        # the rollback activation may have durably committed with no receipt -> unprovable
        return False
    if reason is not None and reason in _ACTIVATION_DETERMINATE_REASONS:
        return proven  # a determinate refusal committed nothing beyond what compensation reversed
    return proven


# ------------------------------------------------- R2: real controller STACK upgrade (2b-3c-c)


@dataclass(frozen=True)
class ControllerStackUpgradePlan:
    """The closed typed candidate controller-stack upgrade (R2). It carries the AUTHENTICATED prior
    stack facts needed to restore it and the SIGNED candidate facts to apply. Nonsecret only."""

    candidate: ControllerBootstrapPlan
    prior_config: ReviewedConfig  # exact prior compose config, restorable
    prior_unit: ReviewedUnit  # exact prior supervisor unit, restorable
    prior_migration_identity: str
    prior_component_images: tuple[tuple[str, str], ...]  # signed component -> image digest
    prior_expected_components: tuple[str, ...]
    prior_running: bool


@dataclass(frozen=True)
class ControllerStackUpgradeReceipt:
    """The typed record of what the candidate stack upgrade actually did, so the transaction can
    restore the prior stack and report residuals truthfully."""

    loaded_image_digests: tuple[str, ...]  # candidate images this transaction introduced
    prior_config_identity: str
    prior_unit_identity: str
    prior_migration_identity: str
    candidate_config_identity: str
    candidate_unit_identity: str
    migration_transition: str  # "unchanged" is the only supported transition (see R2)
    config_applied: bool
    unit_applied: bool
    stack_started: bool


def _reviewed_config_from_disk(deps: EngineDeps, path: str) -> ReviewedConfig | None:
    """The controller Compose config currently ON DISK, or ``None`` when it cannot be TRUSTED.

    Used for exact same-release replay, for the prior stack a managed upgrade must be able to
    restore, and for proving the restored config after a rollback. The contract is asserted here
    too: a prior stack whose config does not carry the reviewed mounts cannot be restored and then
    claimed proven, and an out-of-band edit that removed the gate mount is not a stack this
    transaction may adopt, replay against, or roll back to."""
    try:
        data = deps.filesystem().safe_read(  # type: ignore[attr-defined]
            path, max_bytes=_MAX_DOC_BYTES, expected_uid=_ROOT_UID
        )
    except Exception:  # noqa: BLE001 - an unreadable prior object cannot be restored -> refuse
        return None
    if controller_compose_contract_reason(data) is not None:
        return None  # an on-disk config that fails the contract is never a restorable prior stack
    return ReviewedConfig(identity=sha256_bytes(data), content=data)


def _reviewed_unit_from_disk(deps: EngineDeps, path: str) -> ReviewedUnit | None:
    try:
        data = deps.filesystem().safe_read(  # type: ignore[attr-defined]
            path, max_bytes=_MAX_DOC_BYTES, expected_uid=_ROOT_UID
        )
    except Exception:  # noqa: BLE001 - an unreadable prior object cannot be restored -> refuse
        return None
    return ReviewedUnit(identity=sha256_bytes(data), content=data)


def _plan_controller_stack_upgrade(
    candidate: ControllerBootstrapPlan,
    prior_record: VerifiedRelease,
    deps: EngineDeps,
) -> ControllerStackUpgradePlan:
    """Build the candidate stack-upgrade plan from the AUTHENTICATED prior installation + the SIGNED
    candidate release, enforcing the supported MIGRATION TRANSITION LIMIT.

    Supported transition: the candidate migration identity EQUALS the authenticated prior migration
    identity, so applying the candidate stack cannot advance the schema past the point where the
    prior binaries still run -- restoring the prior stack stays genuinely possible. A CHANGED
    migration identity has no signed reversible/compatible contract in the manifest, so it REFUSES
    with controller_upgrade_migration_transition_unsupported rather than running an irreversible
    schema transition while claiming prior-stack rollback."""
    loc = deps.locations
    prior_config = _reviewed_config_from_disk(deps, loc.controller_compose_path())
    prior_unit = _reviewed_unit_from_disk(deps, loc.controller_unit_path())
    if prior_config is None or prior_unit is None:
        raise ManagementError("controller_upgrade_prior_stack_unreadable")
    prior_migration = prior_record.manifest.migration_identity
    if candidate.migration_identity != prior_migration:
        raise ManagementError("controller_upgrade_migration_transition_unsupported")
    prior_expected = _expected_controller(prior_record.manifest)
    prior_images = tuple(sorted(prior_expected.component_images.items()))
    try:
        obs = deps.observer.observe_controller()
        prior_running = _controller_end_state_reason(obs, prior_expected) is None
    except ManagementError:
        prior_running = False
    if not prior_running:
        # the prior stack must be genuinely operational before it may be upgraded (and before any
        # claim that it can be restored) -- an already-broken stack is not a valid upgrade base.
        raise ManagementError("controller_upgrade_prior_stack_not_operational")
    return ControllerStackUpgradePlan(
        candidate=candidate,
        prior_config=prior_config,
        prior_unit=prior_unit,
        prior_migration_identity=prior_migration,
        prior_component_images=prior_images,
        prior_expected_components=prior_expected.expected_components,
        prior_running=prior_running,
    )


def _apply_controller_stack_upgrade(
    plan: ControllerStackUpgradePlan, vr: VerifiedRelease, deps: EngineDeps
) -> ControllerStackUpgradeReceipt:
    """Actually UPGRADE the controller stack through the reviewed adapter ops: load the signed
    candidate images, install + verify the candidate compose config and supervisor unit (the prior
    ones are retained in the plan for restoration), daemon-reload, apply the identity-unchanged
    migration transition, start/recreate the candidate stack, and reobserve the EXACT signed
    candidate component/image map before finalization is allowed to proceed."""
    ad = deps.controller_adapter
    loaded: list[str] = []
    for artifact in plan.candidate.image_artifacts:
        ad.load_image(artifact)
        if artifact.image_digest:
            loaded.append(artifact.image_digest)
    ad.install_config(plan.candidate.config)
    ad.install_unit(plan.candidate.unit)
    ad.daemon_reload()
    ad.run_migrations(migration_identity=plan.candidate.migration_identity)
    ad.start_stack(expected_components=plan.candidate.expected_components)
    reason = _controller_end_state_reason(
        deps.observer.observe_controller(), _expected_controller(vr.manifest)
    )
    if reason is not None:
        raise ManagementError(reason)  # candidate stack did not reach the exact signed end state
    return ControllerStackUpgradeReceipt(
        loaded_image_digests=tuple(loaded),
        prior_config_identity=plan.prior_config.identity,
        prior_unit_identity=plan.prior_unit.identity,
        prior_migration_identity=plan.prior_migration_identity,
        candidate_config_identity=plan.candidate.config.identity,
        candidate_unit_identity=plan.candidate.unit.identity,
        migration_transition="unchanged",
        config_applied=True,
        unit_applied=True,
        stack_started=True,
    )


def _restore_controller_stack(
    plan: ControllerStackUpgradePlan, deps: EngineDeps
) -> tuple[bool, tuple[str, ...]]:
    """Restore the EXACT prior controller stack after a failed candidate: reinstall the prior
    compose config + supervisor unit, daemon-reload, restart it, and PROVE the prior image map /
    config / unit / migration identity is operational again. Returns (proven, residuals).

    A candidate image this transaction introduced is NOT deleted: proving exclusive ownership and
    non-use of a shared image layer is not possible in-plane, so a harmless bounded residual is
    reported truthfully instead of risking deletion of an image another workload uses."""
    residual: list[str] = []
    ad = deps.controller_adapter
    try:
        ad.install_config(plan.prior_config)
        ad.install_unit(plan.prior_unit)
        ad.daemon_reload()
        ad.run_migrations(migration_identity=plan.prior_migration_identity)
        ad.start_stack(expected_components=plan.prior_expected_components)
    except ManagementError:
        return False, ("controller_stack_restore_failed",)
    try:
        obs = deps.observer.observe_controller()
    except ManagementError:
        return False, ("controller_stack_restore_unobservable",)
    expected = _ExpectedController(
        component_images=dict(plan.prior_component_images),
        expected_components=plan.prior_expected_components,
        config_identity=plan.prior_config.identity,
        unit_identity=plan.prior_unit.identity,
        migration_identity=plan.prior_migration_identity,
    )
    reason = _controller_end_state_reason(obs, expected)
    if reason is not None:
        return False, ("controller_stack_restore_unproven",)
    if plan.candidate.image_artifacts:
        residual.append("candidate_image_cache_residual")  # bounded, harmless, truthful
    return True, tuple(residual)


def _compensate_rollback_documents(holder: list[_DocWriter]) -> bool:
    """Reverse the ROLLBACK participant's own document writes (R6). A rollback that installed
    evidence but failed before its attestation verified must not leave that pair installed and
    unclassified. Never raises: the caller already fails closed to recovery_required."""
    if not holder:
        return True
    try:
        return bool(holder[-1].compensate().proven)
    except Exception:  # noqa: BLE001 - an unprovable document unwind is never proof of cleanliness
        return False


def _upgrade_rollback(
    prior_ev: BootstrapEvidence,
    install: ControllerInstallOptions | None,
    loc: ManagementLocations,
    generation: int,
    writer: _DocWriter,
    drive: _DriveState,
    deps: EngineDeps,
) -> bool:
    """Roll a managed upgrade that FAILED AFTER the candidate identity activated back to the prior
    generation, PROVING it healthy — else return False (→ recovery_required). Engine-owned because
    the 2b-3b-iv adapter deliberately defers identity reactivation. Historical activation receipts
    stay immutable (every activation appends a new row):

      1. compensate the forward adapter (marker-first: restores the prior marker + reseals/restarts
         the API; on an upgrade the adopted TLS/locator/credential/broker are left, so the ONLY
         residual is the candidate identity — resolved by the reactivation below);
      2. restore the prior release's five documents byte-exact (evidence still binds the prior row);
      3. REACTIVATE the prior identity's facts as a NEW row at generation N+2 (predecessor = the
         failed candidate row) through a fresh factory adapter, write the corresponding rollback
         marker, and prove the runtime healthy (enable_api_signer's authoritative observation);
      4. re-author the prior evidence to bind the NEW active row (the byte-restored evidence bound
         the OLD row; the live marker now binds the new row) + re-sign;
      5. commit-gate the prior-release-at-N+2 state; any unproven step → False."""
    if install is None or prior_ev.finalization is None:
        return False
    forward_adapter = drive.adapter
    arec_c = drive.arec
    if forward_adapter is None or arec_c is None:
        return False
    c_row = getattr(arec_c, "resulting_row_id", None)
    if not c_row:
        return False
    # (1) reverse the forward finalization effects (marker-first)
    try:
        fwd_result = forward_adapter.compensate(forward_adapter.receipt())  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 - a forward-compensation fault is unrecoverable in-plane
        return False
    residual = set(getattr(fwd_result, "residual", ("unproven",)))
    if not getattr(fwd_result, "proven", False) and (residual - {"identity_activation"}):
        return False  # any residual beyond the expected identity residual is unrecoverable
    # (2) restore the prior release's documents byte-exact
    if not writer.compensate().proven:
        return False
    ident_a, _ia = _load_identity(Role.CONTROLLER, deps)
    record_a, _ra = _load_release_record(Role.CONTROLLER, deps)
    if ident_a is None or record_a is None:
        return False
    # (3) reactivate the prior identity as a NEW row at N+2 (predecessor = the failed candidate) +
    #     write the rollback marker + prove the runtime healthy
    rb_state = _DriveState()
    # the rollback's OWN document writer, published as it is created so every failure path below can
    # reverse a half-written or ungated rollback evidence/attestation pair.
    rb_writer_holder: list[_DocWriter] = []
    try:
        _rb_adapter, _rb_receipt, rb_fin_ev = _drive_controller_finalization(
            record_a,
            ident_a,
            prior_ev,
            install,
            loc,
            generation + 1,
            CLASSIFY_MANAGED_UPGRADE,
            deps,
            previous_active_row_id=c_row,
            state=rb_state,
        )
    except Exception as exc:  # noqa: BLE001 - ANY fault (incl. FilesystemError, which is NOT a
        # ManagementError) must compensate the rollback participant; letting one escape would strand
        # its marker/identity effects and surface a traceback instead of recovery_required.
        _compensate_rollback_participant(rb_state, getattr(exc, "reason_code", None))
        _compensate_rollback_documents(rb_writer_holder)
        return False
    # (4) re-author the prior evidence to bind the new active row + re-sign, then (5) commit-gate it
    evidence_a_prime = prior_ev.model_copy(
        update={"finalization": rb_fin_ev, "transaction_timestamp": deps.now()}
    )
    rb_writer = _DocWriter(deps.filesystem(), loc)
    rb_writer_holder.append(rb_writer)
    try:
        _write_evidence_and_attestation(
            Role.CONTROLLER,
            evidence_a_prime,
            canonical_bytes(ident_a),
            record_a.aggregate_digest,
            deps,
            rb_writer,
        )
    except Exception as exc:  # noqa: BLE001 - see above: a filesystem fault is not a ManagementError
        _compensate_rollback_participant(rb_state, getattr(exc, "reason_code", None))
        _compensate_rollback_documents(rb_writer_holder)
        return False
    try:
        gate = _verify_committed_transaction(
            Role.CONTROLLER,
            deps,
            expected_mode=MODE_INSTALLED,
            expected_aggregate=record_a.aggregate_digest,
        )
        if gate is not None:
            raise ManagementError(gate)
        if _verify_marker_binding(deps, evidence_a_prime) is not None:
            raise ManagementError("controller_marker_identity_drift")
        # the rollback adapter's own cleanup is a participant effect too: an unproven commit means
        # its staging/journal state is unaccounted for.
        if rb_state.adapter is not None and not rb_state.adapter.commit():  # type: ignore[attr-defined]
            raise ManagementError("recovery_required")
    except Exception as exc:  # noqa: BLE001 - total containment: no fault may escape unclassified
        _compensate_rollback_participant(rb_state, getattr(exc, "reason_code", None))
        _compensate_rollback_documents(rb_writer_holder)
        return False
    return True


def _write_transaction(
    role: Role,
    vr: VerifiedRelease,
    deps: EngineDeps,
    bundle_dir: str,
    *,
    install: ControllerInstallOptions | None = None,
    install_cls: _ControllerInstallClassification | None = None,
) -> tuple[ManagementPlaneIdentity, BootstrapEvidence]:
    """Classify pre-existing documents, execute the closed typed host operations, write the
    root-controlled documents (identity FIRST, evidence LAST), gate evidence on a FINAL coherent
    reobservation of the COMPLETE end state, and on any failure RESTORE any document this invocation
    overwrote and remove any it newly created AND compensate the host effects the adapter receipt
    records (reporting recovery_required if host compensation cannot be proven) — so a failed
    idempotent re-install never leaves a pre-existing document mutated. For a driven controller
    install this ALSO drives the finalization adapter (fresh = generation 0; managed upgrade =
    generation N+1 against the prior identity, finalization-only, with an engine-owned rollback-
    reactivation of the prior generation on a post-activation failure)."""
    loc = deps.locations
    generation = 0
    classification = CLASSIFY_FRESH
    previous_active_row_id: str | None = None
    prior_ev: BootstrapEvidence | None = None
    if install is not None:
        # the driven controller-install path. controller_install classified the state and passes it
        # here; re-classify defensively if it did not. Only FRESH or an authenticated
        # MANAGED_UPGRADE
        # reach the write path (exact replay is short-circuited earlier).
        if role is not Role.CONTROLLER:
            raise ManagementError("controller_install_role_invalid")
        cls = install_cls if install_cls is not None else _classify_controller_install(vr, deps)
        if cls.reason is not None:
            raise ManagementError(cls.reason)
        if cls.classification not in (CLASSIFY_FRESH, CLASSIFY_MANAGED_UPGRADE):
            raise ManagementError("controller_install_unsupported_classification")
        classification = cls.classification
        generation = cls.generation
        if cls.classification == CLASSIFY_MANAGED_UPGRADE:
            prior_ev = cls.prior_evidence
            assert prior_ev is not None and prior_ev.finalization is not None
            previous_active_row_id = prior_ev.finalization.active_identity_row_id
            # An ordinary managed upgrade may NOT change the controller's canonical origin or TLS
            # mode: the prior evidence stores only their DIGESTS, so a changed value could not be
            # restored on a rollback (the rollback re-drives with these same options). Refuse rather
            # than silently re-record the locator with the new origin while reverting to the prior
            # release. Changing either is a distinct, separately reviewed operation.
            if prior_ev.finalization.canonical_origin_digest != _sep_digest(
                "secp.management.controller-origin/v1", install.canonical_origin
            ):
                raise ManagementError("controller_upgrade_origin_change_unsupported")
            if prior_ev.finalization.tls_mode != install.tls_mode:
                raise ManagementError("controller_upgrade_tls_mode_change_unsupported")
    else:
        classify = _classify_preexisting(role, vr, deps, mode=MODE_INSTALLED)
        if classify.reason is not None:
            raise ManagementError(classify.reason)

    ident = _build_identity(role, vr, deps.now())
    identity_bytes = canonical_bytes(ident)
    manifest_bytes, sig_bytes = _record_bytes(vr)
    id_path = loc.identity_path(role.value)
    rr_path = loc.release_record_path(role.value)
    sig_path = loc.release_sig_path(role.value)

    if role is Role.WORKER:
        plan_w = _build_worker_plan(vr, bundle_dir, deps)
        adapter: object = deps.worker_adapter
    else:
        plan_c = _build_controller_plan(vr, bundle_dir, deps)
        adapter = deps.controller_adapter

    writer = _DocWriter(deps.filesystem(), loc)
    host_effected = False
    finalization_effected = False
    drive = _DriveState()  # publishes the bound adapter + activation receipt AS ops progress (R3)

    def _compensate(reason: str | None = None) -> None:
        # COMBINED marker-first compensation: finalization FIRST (the corrected adapter reverses its
        # effects in reverse order — resealing the marker + restarting the API before anything
        # else), THEN the managed documents, THEN the bootstrap host effects. Any unproven residual
        # in ANY participant → recovery_required (never an ordinary transaction error, never a false
        # success). The candidate marker can never remain enabled after a failed transaction.
        if (
            classification == CLASSIFY_MANAGED_UPGRADE
            and drive.arec is not None
            and prior_ev is not None
        ):
            # a managed upgrade failed AFTER the candidate identity activated → the engine owns the
            # rollback-reactivation of the PRIOR generation (the adapter defers identity
            # reactivation
            # to the engine); it re-commits the prior release + restores its documents itself.
            # ORDER MATTERS: restore the PRIOR controller stack FIRST. The rollback reactivation
            # re-drives finalization for the PRIOR release, and its authoritative R4 observation
            # requires the running API to be on the PRIOR release's signed image. While the
            # candidate stack is still up, that proof can never hold, so a rollback would always
            # escalate to recovery_required instead of completing the provable restoration.
            ok = True
            if stack_plan is not None and stack_upgraded:
                stack_ok, _sr = _restore_controller_stack(stack_plan, deps)
                ok = stack_ok
            ok = _upgrade_rollback(prior_ev, install, loc, generation, writer, drive, deps) and ok
            if not ok:
                raise ManagementError("recovery_required")
            return
        fin_unproven = False
        if finalization_effected and drive.adapter is not None:
            fin_unproven = not _finalization_compensation_proven(drive.adapter)
        # The activation was ATTEMPTED but never confirmed (the API commits durably inside the
        # one-shot and parses the receipt afterwards): the candidate identity MAY be active with no
        # receipt, no recorded effect, and — on an upgrade — no known candidate row to reverse. That
        # is an UNPROVEN residual, so refuse recovery_required rather than an ordinary error. An
        # adopted-only receipt compensating "proven" must never mask this window.
        activation_unproven = (
            drive.activation_attempted
            and drive.arec is None
            and reason not in _ACTIVATION_DETERMINATE_REASONS
        )
        stack_unproven = False
        if stack_plan is not None and stack_upgraded:
            # R2 rollback: restore + PROVE the exact prior controller stack (config, unit, migration
            # identity, image map) rather than leaving a half-upgraded stack behind.
            stack_proven, _stack_residual = _restore_controller_stack(stack_plan, deps)
            stack_unproven = not stack_proven
        doc_result = writer.compensate()
        host_unproven = False
        if host_effected:
            try:
                _compensate_host(
                    adapter
                )  # raises recovery_required if host compensation is unproven
            except ManagementError:
                host_unproven = True
        if (
            fin_unproven
            or activation_unproven
            or stack_unproven
            or host_unproven
            or not doc_result.proven
        ):
            raise ManagementError("recovery_required")

    # R2: a managed upgrade performs a REAL candidate STACK upgrade inside this transaction (signed
    # candidate images, compose config, supervisor unit, the identity-unchanged migration transition
    # and the candidate stack start), retaining the exact prior config/unit/runtime facts so the
    # prior stack can be restored and PROVEN on failure. No externally upgraded stack qualifies.
    def _pre_evidence() -> BootstrapEvidence:
        """The pre-finalization evidence core the finalization PLAN binds. Pure: derived from the
        signed release, the identity and the plan -- it observes no host state, so it is identical
        whether computed here or at the drive site."""
        return _controller_evidence(
            role,
            vr,
            ident,
            plan_c,
            deps,
            mode=MODE_INSTALLED,
            classification=CLASSIFICATION_CREATED,
            identity_bytes=identity_bytes,
            manifest_bytes=manifest_bytes,
            sig_bytes=sig_bytes,
        )

    def _prepare_gate() -> _PreparedFinalization:
        """Create/adopt and PROVE the readiness gate immediately before the first Compose operation
        that MOUNTS it, and AFTER every pre-flight refusal, so a refusal decided without touching
        the host still touches nothing.

        The signed controller template binds the gate with ``create_host_path: false``, so a start
        with the gate absent fails closed rather than letting Docker fabricate a DIRECTORY at a
        secret's path. The adapter is published to the drive state BEFORE the step runs, so any
        later image-load, config-install, migration or stack-start failure compensates the gate
        through the SAME single-use adapter and the SAME receipt that owns it -- one gate, never
        two. Only the B2 installation path reaches here: a bootstrap without ``--install`` composes
        no finalization and is already ineligible for B2 installation."""
        assert install is not None  # noqa: S101 - guarded at both call sites
        return _prepare_readiness_gate(
            vr, ident, _pre_evidence(), install, loc, generation, deps, drive
        )

    stack_plan: ControllerStackUpgradePlan | None = None
    stack_upgraded = False
    prepared: _PreparedFinalization | None = None
    try:
        # 1. closed typed host operations (image load -> config -> unit/package -> reload -> start)
        if classification == CLASSIFY_MANAGED_UPGRADE:
            prior_record_v, _prr = _load_release_record(Role.CONTROLLER, deps)
            if prior_record_v is None:
                raise ManagementError("controller_upgrade_prior_stack_unreadable")
            stack_plan = _plan_controller_stack_upgrade(plan_c, prior_record_v, deps)
            # NOTE: host_effected stays False on the managed-upgrade path. The bootstrap adapter's
            # own compensate() is a fresh-install TEARDOWN (compose down + remove the unit, the
            # compose config and every loaded image). On an upgrade the prior stack must be
            # RESTORED,
            # not torn down, and _restore_controller_stack below owns exactly that participant --
            # running both would stop the just-restored prior stack and delete its fixed objects.
            if install is not None:
                prepared = _prepare_gate()
                finalization_effected = True
            _apply_controller_stack_upgrade(stack_plan, vr, deps)
            stack_upgraded = True
        else:
            host_effected = True
            if role is Role.WORKER:
                _run_worker_ops(plan_w, deps)
            else:
                if install is not None:
                    prepared = _prepare_gate()
                    finalization_effected = True
                _run_controller_ops(plan_c, deps)
        # 2. identity FIRST, reverified before anything downstream trusts it
        writer.install(id_path, identity_bytes)
        _reverify_doc(deps, id_path, identity_bytes, "identity_reverify_mismatch")
        # 3. the fixed installed-release record (manifest + detached signature) status rebinds to
        writer.install(rr_path, manifest_bytes)
        writer.install(sig_path, sig_bytes)
        # 4. FINAL coherent reobservation of the COMPLETE canonical end state (expectations derived
        #    ONLY from the signed release, never from evidence)
        if role is Role.WORKER:
            wobs = deps.observer.observe_worker()
            reason = _worker_end_state_reason(wobs, _expected_worker(vr.manifest))
            if reason is not None:
                raise ManagementError(reason)
            ev = _worker_evidence(
                role,
                vr,
                ident,
                plan_w,
                deps,
                mode=MODE_INSTALLED,
                classification=CLASSIFICATION_CREATED,
                identity_bytes=identity_bytes,
                manifest_bytes=manifest_bytes,
                sig_bytes=sig_bytes,
            )
        else:
            cobs = deps.observer.observe_controller()
            reason = _controller_end_state_reason(cobs, _expected_controller(vr.manifest))
            if reason is not None:
                raise ManagementError(reason)
            finalization_ev: FinalizationEvidence | None = None
            if install is not None:
                # 4b. build the PRE-finalization evidence core → the stable domain-separated
                #     bootstrap_binding_digest the identity activation + marker bind, THEN drive the
                #     corrected finalization adapter in its exact reviewed order (marker LAST).
                ev0 = _controller_evidence(
                    role,
                    vr,
                    ident,
                    plan_c,
                    deps,
                    mode=MODE_INSTALLED,
                    classification=CLASSIFICATION_CREATED,
                    identity_bytes=identity_bytes,
                    manifest_bytes=manifest_bytes,
                    sig_bytes=sig_bytes,
                )
                finalization_effected = True  # combined compensation now drives the adapter
                # ev0 must equal the evidence core the prepared plan was bound to: the plan is
                # single-use and its bootstrap_binding_digest is already fixed.
                _fa, _freceipt, finalization_ev = _drive_controller_finalization(
                    vr,
                    ident,
                    ev0,
                    install,
                    loc,
                    generation,
                    classification,
                    deps,
                    previous_active_row_id=previous_active_row_id,
                    state=drive,
                    prepared=prepared,
                )
            ev = _controller_evidence(
                role,
                vr,
                ident,
                plan_c,
                deps,
                mode=MODE_INSTALLED,
                classification=CLASSIFICATION_CREATED,
                identity_bytes=identity_bytes,
                manifest_bytes=manifest_bytes,
                sig_bytes=sig_bytes,
                finalization=finalization_ev,
            )
        # 5. evidence LAST, then its detached attestation (the true commit point) — a sealed
        #    authenticator refuses here, so evidence is never written unauthenticated
        _write_evidence_and_attestation(role, ev, identity_bytes, vr.aggregate_digest, deps, writer)
        # 6. THE COMMIT GATE: re-read + fully verify the installed five-document state + attestation
        #    signature/fields/metadata before returning; a bad authenticator or drifted install here
        #    compensates and refuses rather than reporting a false ``written``.
        commit_reason = _verify_committed_transaction(
            role, deps, expected_mode=MODE_INSTALLED, expected_aggregate=vr.aggregate_digest
        )
        if commit_reason is not None:
            raise ManagementError(commit_reason)
        result = (ident, ev)
    except ManagementError as exc:
        _compensate(exc.reason_code)
        raise
    except Exception:
        _compensate()  # unknown fault -> no determinate reason -> attempted activation is unproven
        raise ManagementError("bootstrap_transaction_error") from None
    # 7. R5 CLEANUP PHASE — the evidence written above is the durable PREPARED checkpoint (it makes
    #    NO cleanup-absence claim). Only now is cleanup performed, its absence independently
    #    OBSERVED, and the COMMITTED evidence + attestation authored and re-gated. Runs OUTSIDE the
    #    compensating try: the install itself is committed and working, so a cleanup fault is
    #    reported truthfully as recovery_required (with the prepared checkpoint preserved for the
    #    deterministic finalize-prepared path) rather than destructively tearing it down.
    if finalization_effected and drive.adapter is not None:
        ident_c, ev_c = _finalize_prepared_checkpoint(role, vr, deps, drive.adapter, result[1])
        return ident_c or result[0], ev_c
    return result


def _finalization_cleanup_absent(deps: EngineDeps) -> bool:
    """Independently OBSERVE that the finalization recovery journal and every staging/backup object
    is gone (R5). The committed evidence may claim absence ONLY when this returns True.

    This performs its OWN strict sweep rather than reusing the R1 inventory's counter: that counter
    is deliberately fail-OPEN (an enumeration fault yields 0, and entries beyond a bound are not
    probed) because there the staging root's mere presence already fails freshness closed.
    Here the root's presence is NOT a failure, so the same behaviours would let a signed
    `staging_objects_absent=True` be claimed while real backups remained on disk. Every uncertainty
    below is therefore treated as a RESIDUAL, never as an absence."""
    from secp_management.controller_finalization_inventory import (
        _STAGING_BACKUP_HANDLES,
        finalization_recovery_journal_path,
        finalization_staging_root,
    )

    loc = deps.locations
    fs = deps.filesystem()
    try:
        if fs.lstat(finalization_recovery_journal_path(loc)) is not None:  # type: ignore[attr-defined]
            return False
        root = finalization_staging_root(loc)
        if fs.lstat(root) is None:  # type: ignore[attr-defined]
            return True  # never created (or already swept) -> nothing staged remains
        entries = fs.list_dir(root)  # type: ignore[attr-defined]
        if entries is None:
            return False
        if len(entries) > _MAX_STAGING_TRANSACTIONS:
            # more transaction directories than can be bounded-probed: unprovable, so NOT absent.
            return False
        for entry in entries:
            for handle in _STAGING_BACKUP_HANDLES:
                if fs.lstat(f"{root}/{entry}/{handle}") is not None:  # type: ignore[attr-defined]
                    return False
        return True
    except Exception:  # noqa: BLE001 - an unprovable sweep is NOT proof of absence
        return False


def _finalize_prepared_checkpoint(
    role: Role,
    vr: VerifiedRelease,
    deps: EngineDeps,
    fadapter: object,
    prepared: BootstrapEvidence,
) -> tuple[ManagementPlaneIdentity | None, BootstrapEvidence]:
    """R5 cleanup phase: drive ``commit()``, prove the journal + staging objects absent, author the
    COMMITTED finalization evidence + detached attestation, and re-run the complete commit gate.
    Any unproven step raises ``recovery_required`` leaving the PREPARED checkpoint durable, so the
    operation is deterministically resumable and no attestation claims an unobserved absence."""
    try:
        committed_clean = bool(fadapter.commit())  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 - a cleanup fault is recovery_required, never an ordinary error
        raise ManagementError("recovery_required") from None
    if not committed_clean or not _finalization_cleanup_absent(deps):
        raise ManagementError("recovery_required")  # prepared checkpoint preserved for resume
    fin = prepared.finalization
    if fin is None:
        return None, prepared
    committed_fin = fin.model_copy(
        update={
            "finalization_commit_state": FINALIZATION_STATE_COMMITTED,
            "recovery_journal_absent": True,
            "staging_objects_absent": True,
        }
    )
    ev_committed = prepared.model_copy(update={"finalization": committed_fin})
    ident, _ir = _load_identity(role, deps)
    if ident is None:
        raise ManagementError("recovery_required")
    writer = _DocWriter(deps.filesystem(), deps.locations)
    try:
        _write_evidence_and_attestation(
            role, ev_committed, canonical_bytes(ident), vr.aggregate_digest, deps, writer
        )
    except ManagementError:
        raise ManagementError("recovery_required") from None
    if (
        _verify_committed_transaction(
            role, deps, expected_mode=MODE_INSTALLED, expected_aggregate=vr.aggregate_digest
        )
        is not None
    ):
        raise ManagementError("recovery_required")
    return ident, ev_committed


def _write_evidence_and_attestation(
    role: Role,
    ev: BootstrapEvidence,
    identity_bytes: bytes,
    release_aggregate: str,
    deps: EngineDeps,
    writer: _DocWriter,
) -> None:
    """Sign a detached attestation over the evidence (canonical evidence + identity digests, release
    aggregate, role, installation id, mode, timestamp, every object record) with the reviewed
    management key, then write evidence and the attestation LAST. A sealed authenticator refuses
    (``evidence_authenticator_not_provisioned``) before any evidence is written."""
    loc = deps.locations
    message = evidence_attestation_message(ev, identity_bytes, release_aggregate)
    key_id = deps.evidence_authenticator.key_id()
    signature = deps.evidence_authenticator.attest(message)
    att = attestation_bytes("ed25519", key_id, signature)
    writer.install(loc.evidence_path(role.value), canonical_bytes(ev))
    writer.install(loc.evidence_attestation_path(role.value), att)


def _load_attestation(
    role: Role, deps: EngineDeps
) -> tuple[EvidenceAttestation | None, str | None]:
    fs = deps.filesystem()
    path = deps.locations.evidence_attestation_path(role.value)
    try:
        raw = fs.safe_read(path, max_bytes=_MAX_SIG_BYTES, expected_uid=_ROOT_UID)  # type: ignore[attr-defined]
    except Exception as exc:
        return None, getattr(exc, "reason_code", "attestation_unreadable")
    try:
        return parse_document_bytes(raw, attestation_from_dict, "attestation"), None
    except ManagementError as exc:
        return None, exc.reason_code


def _verify_committed_transaction(
    role: Role, deps: EngineDeps, *, expected_mode: str, expected_aggregate: str
) -> str | None:
    """The TRUE commit gate (blocker 2): AFTER evidence + attestation are written, treat the
    detached attestation as the commit point. Re-read the COMPLETE installed five-document state
    through the
    hardened filesystem, re-parse the installed attestation, verify canonical evidence bytes and its
    Ed25519 signature over the recomputed message against ``evidence_trust_root``, and confirm the
    expected key id, role, installation id, release aggregate and mode plus exact
    owner/mode/type/link-count metadata for every document. Bootstrap/adoption may return success
    ONLY
    when this returns None; any failure compensates the transaction and refuses (recovery_required
    if
    compensation cannot be proven)."""
    # re-reads evidence/identity/record from disk AND verifies the attestation signature over the
    # recomputed message (canonical evidence bytes + identity digest + release aggregate)
    ev, ident, record, reason = _revalidate_records(role, deps)
    if reason is not None:
        return reason
    if ev is None or ident is None or record is None:
        return "commit_records_incomplete"
    # the complete installed five-document state: fixed binding,
    # type/symlink/link-count/UID/GID/mode,
    # and exact content against the INDEPENDENTLY authenticated digests
    integ = _verify_installed_documents(role, deps, ev, ident, record)
    if integ is not None:
        return integ
    if ev.role != role.value:
        return "commit_role_mismatch"
    if ev.mode != expected_mode:
        return "commit_mode_mismatch"
    if ev.release_aggregate_digest != expected_aggregate:
        return "commit_release_mismatch"
    if ev.installation_id != _installation_id(role.value, expected_aggregate):
        return "commit_installation_mismatch"
    # the committed attestation must be signed by the EXPECTED authenticator key id (not merely any
    # provisioned anchor)
    att, att_reason = _load_attestation(role, deps)
    if att is None:
        return att_reason or "commit_attestation_unreadable"
    if att.key_id != deps.evidence_authenticator.key_id():
        return "commit_attestation_key_mismatch"
    return None


def _compensate_host(adapter: object) -> None:
    """Roll back the adapter's partial host effects. Once host ops have been ATTEMPTED, failure to
    obtain a VALID receipt is treated as recovery_required — a lost/malformed receipt is NOT proof
    that no effect occurred. Only an EXPLICIT empty receipt (a sealed adapter's proven no-effect
    refusal) skips compensation; any non-empty receipt is compensated and any unproven/residual
    compensation is recovery_required. No compensation exception is ever swallowed."""
    try:
        receipt = adapter.receipt()  # type: ignore[attr-defined]
    except Exception:
        raise ManagementError("recovery_required") from None  # cannot account for host effects
    if not isinstance(receipt, BootstrapReceipt):
        raise ManagementError("recovery_required")  # malformed receipt → cannot prove no effect
    if not (
        receipt.operations
        or receipt.loaded_images
        or receipt.installed_configs
        or receipt.installed_units
        or receipt.installed_packages
        or receipt.started_services
    ):
        return  # an EXPLICIT empty receipt PROVES no effect occurred → nothing to compensate
    try:
        result = adapter.compensate(receipt)  # type: ignore[attr-defined]
    except Exception:
        raise ManagementError("recovery_required") from None
    if not isinstance(result, CompensationResult) or not result.proven or result.residual:
        raise ManagementError("recovery_required")


def _refused(command: str, role_value: str, reason: str) -> dict:
    return {"command": command, "role": role_value, "mode": MODE_REFUSED, "reason_code": reason}


# ------------------------------------------------------------------------- adoption (observe-only)


def adopt(role_value: str, bundle_dir: str, gate: WriteGate, deps: EngineDeps) -> tuple[int, dict]:
    """``secpctl adopt controller|worker`` — a FIRST-CLASS observe-only operation: reobserve the
    current topology, refuse unless it ALREADY matches the COMPLETE canonical prepared end state a
    successful bootstrap would produce (so an adoption is never a dead end), and — only with
    --write --confirm — transactionally write the four ADOPTION documents (identity, release record,
    signature, evidence), evidence last. It runs NO mutation adapter op: it loads no image,
    installs/
    configures no service, restarts nothing, and rewrites no drift. The ordinary worker is never
    modified or restarted."""
    admission_worker: WorkerObservation | None = None
    admission_controller: ControllerObservation | None = None
    try:
        role = parse_role(role_value)
        partial = gate.refusal_reason()
        if partial is not None:
            raise ManagementError(partial)
        vr = _verify_release_for_role(role, bundle_dir, deps)
        if gate.is_write:
            pf = _platform_or_refuse(deps)
            pfx = _preflight(pf, need_root=True)
            if pfx is not None:
                raise ManagementError(pfx)
        if not read_seals().safe:
            raise ManagementError("seals_unsafe")
        if role is Role.WORKER:
            admission_worker = deps.observer.observe_worker()
            mismatch = _worker_end_state_reason(admission_worker, _expected_worker(vr.manifest))
        else:
            admission_controller = deps.observer.observe_controller()
            mismatch = _controller_end_state_reason(
                admission_controller, _expected_controller(vr.manifest)
            )
        if mismatch is not None:
            raise ManagementError("adoption_incomplete:" + mismatch)
    except ManagementError as exc:
        return EXIT_REFUSED, _refused("adopt", role_value, exc.reason_code)

    base = {
        "command": "adopt",
        "role": role.value,
        "release_aggregate_digest": vr.aggregate_digest,
        "code_seals": _seal_section(),
        "restarted_anything": False,
        "loaded_image": False,
        "rewrote_drift": False,
        "external_contacts_performed": False,
    }
    if not gate.is_write:
        base["mode"] = MODE_DRY_RUN
        return EXIT_OK, base

    try:
        ident, ev = _adopt_transaction(
            role,
            vr,
            deps,
            bundle_dir,
            admission_worker=admission_worker,
            admission_controller=admission_controller,
        )
    except ManagementError as exc:
        return EXIT_REFUSED, _refused("adopt", role_value, exc.reason_code)
    base["mode"] = MODE_ADOPTED
    base["installation_id"] = ident.installation_id
    base["evidence_digest"] = ev.digest()
    return EXIT_OK, base


def _adopt_transaction(
    role: Role,
    vr: VerifiedRelease,
    deps: EngineDeps,
    bundle_dir: str,
    *,
    admission_worker: WorkerObservation | None = None,
    admission_controller: ControllerObservation | None = None,
) -> tuple[ManagementPlaneIdentity, BootstrapEvidence]:
    """Transactionally write the four ADOPTION documents, closing the admission→commit TOCTOU: after
    installing identity + the signed release record, obtain a FINAL coherent observation, prove its
    ABA generation marker is UNCHANGED from admission (nothing restarted/replaced in between) AND
    re-run the COMPLETE end-state predicate, and only then write evidence LAST. Any
    final-observation
    failure RESTORES any document it overwrote and removes any it newly created (no partial
    adoption,
    and a failed idempotent re-adoption never leaves a pre-existing document mutated). Runs NO host
    op."""
    loc = deps.locations
    classify = _classify_preexisting(role, vr, deps, mode=MODE_ADOPTED)
    if classify.reason is not None:
        raise ManagementError(classify.reason)

    ident = _build_identity(role, vr, deps.now())
    identity_bytes = canonical_bytes(ident)
    manifest_bytes, sig_bytes = _record_bytes(vr)
    id_path = loc.identity_path(role.value)
    rr_path = loc.release_record_path(role.value)
    sig_path = loc.release_sig_path(role.value)

    writer = _DocWriter(deps.filesystem(), loc)

    try:
        # install identity + the signed release record FIRST
        writer.install(id_path, identity_bytes)
        _reverify_doc(deps, id_path, identity_bytes, "identity_reverify_mismatch")
        writer.install(rr_path, manifest_bytes)
        writer.install(sig_path, sig_bytes)
        # FINAL coherent observation: prove the generation is unchanged since admission AND re-run
        # the complete end-state predicate BEFORE committing evidence (closes the adoption TOCTOU).
        if role is Role.WORKER:
            final_w = deps.observer.observe_worker()
            if (
                admission_worker is None
                or final_w.generation_marker != admission_worker.generation_marker
            ):
                raise ManagementError("adoption_generation_changed")
            final_reason = _worker_end_state_reason(final_w, _expected_worker(vr.manifest))
            if final_reason is not None:
                raise ManagementError("adoption_final:" + final_reason)
            plan_w = _build_worker_plan(vr, bundle_dir, deps)
            ev = _worker_evidence(
                role,
                vr,
                ident,
                plan_w,
                deps,
                mode=MODE_ADOPTED,
                classification=CLASSIFICATION_ADOPTED,
                identity_bytes=identity_bytes,
                manifest_bytes=manifest_bytes,
                sig_bytes=sig_bytes,
            )
        else:
            final_c = deps.observer.observe_controller()
            if (
                admission_controller is None
                or final_c.generation_marker != admission_controller.generation_marker
            ):
                raise ManagementError("adoption_generation_changed")
            final_reason = _controller_end_state_reason(final_c, _expected_controller(vr.manifest))
            if final_reason is not None:
                raise ManagementError("adoption_final:" + final_reason)
            plan_c = _build_controller_plan(vr, bundle_dir, deps)
            ev = _controller_evidence(
                role,
                vr,
                ident,
                plan_c,
                deps,
                mode=MODE_ADOPTED,
                classification=CLASSIFICATION_ADOPTED,
                identity_bytes=identity_bytes,
                manifest_bytes=manifest_bytes,
                sig_bytes=sig_bytes,
            )
        # evidence LAST + its detached attestation, only after the final observation confirmed an
        # unchanged complete end state (a sealed authenticator refuses before evidence is written)
        _write_evidence_and_attestation(role, ev, identity_bytes, vr.aggregate_digest, deps, writer)
        # THE COMMIT GATE: re-read + fully verify the installed five-document state + attestation
        # before returning adopted; a bad authenticator or drifted install compensates and refuses.
        commit_reason = _verify_committed_transaction(
            role, deps, expected_mode=MODE_ADOPTED, expected_aggregate=vr.aggregate_digest
        )
        if commit_reason is not None:
            raise ManagementError(commit_reason)
        return ident, ev
    except Exception:
        doc_result = writer.compensate()
        if not doc_result.proven:
            raise ManagementError("recovery_required") from None
        raise


# --------------------------------------------------------------------------- status (revalidating)


def status(role_value: str, deps: EngineDeps) -> tuple[int, dict]:
    """``secpctl status controller|worker`` — independently revalidate the stored evidence, the
    management identity, and the fixed installed-release record (reverifying its signature +
    artifact identities), AND the installed config/unit/component/migration/package identities,
    against a FRESH observation. Stored booleans and effect flags never satisfy status alone; a
    worker consumes the observer-composed real commissioning + deployment statuses."""
    try:
        role = parse_role(role_value)
    except ManagementError as exc:
        return EXIT_REFUSED, _refused("status", role_value, exc.reason_code)
    if role is Role.WORKER:
        return _worker_status(deps)
    return _controller_status(deps)


def _revalidate_records(
    role: Role, deps: EngineDeps
) -> tuple[
    BootstrapEvidence | None, ManagementPlaneIdentity | None, VerifiedRelease | None, str | None
]:
    """Load + cross-bind evidence, the management identity (always written by both bootstrap and
    adoption), and the reverified installed-release record. ``reason`` is None only when all three
    are present and mutually consistent."""
    ev, r = _load_evidence(role, deps)
    if ev is None:
        return None, None, None, r or "evidence_absent"
    ident, ri = _load_identity(role, deps)
    if ident is None:
        return ev, None, None, ri or "identity_absent"
    if ident.role != ev.role or ident.installation_id != ev.installation_id:
        return ev, ident, None, "identity_evidence_installation_mismatch"
    if ident.release_digest != ev.release_aggregate_digest:
        return ev, ident, None, "identity_evidence_release_mismatch"
    record, rr = _load_release_record(role, deps)
    if record is None:
        return ev, ident, None, rr or "release_record_absent"
    # The detached evidence attestation is verified BEFORE any of the evidence's
    # mode/classification/
    # ownership/timestamps/object-records are trusted (a re-authored evidence — including an
    # adopted→installed rewrite — fails the signature and is refused here).
    att_reason = _verify_evidence_attestation(role, deps, ev, ident, record)
    if att_reason is not None:
        return ev, ident, record, att_reason
    drift = _record_binding_reason(role, ev, ident, record)
    if drift is not None:
        return ev, ident, record, drift
    return ev, ident, record, None


def _verify_evidence_attestation(
    role: Role,
    deps: EngineDeps,
    ev: BootstrapEvidence,
    ident: ManagementPlaneIdentity,
    record: VerifiedRelease,
) -> str | None:
    """Load the detached attestation and verify its Ed25519 signature over the recomputed
    evidence-attestation message against the reviewed evidence anchor. Any tamper to evidence (mode,
    classification, object records, timestamp), identity, or release aggregate changes the message
    and fails the signature. A missing/unverifiable attestation (the shipped empty anchor) fails
    closed."""
    fs = deps.filesystem()
    path = deps.locations.evidence_attestation_path(role.value)
    try:
        raw = fs.safe_read(path, max_bytes=_MAX_SIG_BYTES, expected_uid=_ROOT_UID)  # type: ignore[attr-defined]
    except Exception as exc:
        return getattr(exc, "reason_code", "attestation_unreadable")
    try:
        att = parse_document_bytes(raw, attestation_from_dict, "attestation")
    except ManagementError as exc:
        return exc.reason_code
    message = evidence_attestation_message(ev, canonical_bytes(ident), record.aggregate_digest)
    if not deps.evidence_trust_root.verify(
        key_id=att.key_id, message=message, signature_hex=att.signature
    ):
        return "evidence_attestation_untrusted"
    return None


def _record_binding_reason(
    role: Role,
    ev: BootstrapEvidence,
    ident: ManagementPlaneIdentity | None,
    record: VerifiedRelease,
) -> str | None:
    if record.role != role.value:
        return "release_record_role_mismatch"
    if record.aggregate_digest != ev.release_aggregate_digest:
        return "release_record_aggregate_mismatch"
    if record.signature_key_id != ev.signing_anchor_id:
        return "release_record_anchor_mismatch"
    if record.manifest.source_sha != ev.source_sha:
        return "release_record_source_mismatch"
    if record.manifest.source_tree_sha != ev.source_tree_sha:
        return "release_record_tree_mismatch"
    if (record.manifest.parent_sha or None) != (ev.parent_sha or None):
        return "release_record_parent_mismatch"
    if record.manifest.implementation_aggregate != ev.implementation_aggregate:
        return "release_record_implementation_mismatch"
    rec_images = tuple(sorted(a.image_digest for a in record.manifest.artifacts if a.image_digest))
    if rec_images != tuple(sorted(ev.image_digests)):
        return "release_record_image_mismatch"
    if ident is not None:
        if tuple(a.sha256 for a in record.manifest.artifacts) != ident.installed_artifact_digests:
            return "release_record_artifact_mismatch"
        # every provenance field of the identity is authenticated against the SIGNED release (not
        # self-referential): a modified-but-parseable identity that altered any of these is caught.
        if record.manifest.source_sha != ident.source_sha:
            return "identity_record_source_mismatch"
        if record.manifest.source_tree_sha != ident.source_tree_sha:
            return "identity_record_tree_mismatch"
        if (record.manifest.parent_sha or None) != (ident.parent_sha or None):
            return "identity_record_parent_mismatch"
    return None


def _independent_expected_digests(
    deps: EngineDeps, ident: ManagementPlaneIdentity, record: VerifiedRelease
) -> dict[str, str | None]:
    """The INDEPENDENTLY authenticated expected on-disk content digest for each document, from
    the SIGNATURE-VERIFIED release record and the RELEASE-AUTHENTICATED identity — NEVER from a
    (re-authorable) evidence document. The evidence self is None (authenticated by its binding + a
    canonical-form check + the cross-check that its recorded sub-digests equal these)."""
    manifest_bytes, sig_bytes = _record_bytes(record)
    return {
        OBJECT_IDENTITY: sha256_bytes(canonical_bytes(ident)),
        OBJECT_RELEASE_MANIFEST: sha256_bytes(manifest_bytes),
        OBJECT_RELEASE_SIGNATURE: sha256_bytes(sig_bytes),
        OBJECT_EVIDENCE: None,  # authenticated by canonical-form + cross-check
        OBJECT_EVIDENCE_ATTESTATION: None,  # authenticated by its own Ed25519 signature
    }


def _assert_doc_metadata(stt: FileStat, rec: ManagedObjectRecord) -> str | None:
    if stt.is_symlink:
        return "document_symlink"
    if not stt.is_regular:
        return "document_not_regular"
    if stt.nlink != 1:
        return "document_hardlinked"
    if stt.uid != rec.uid or stt.gid != rec.gid:
        return "document_untrusted_owner"
    if (stt.mode & 0o7777) != rec.mode:
        return "document_mode_drift"
    return None


def _verify_installed_documents(
    role: Role,
    deps: EngineDeps,
    ev: BootstrapEvidence,
    ident: ManagementPlaneIdentity,
    record: VerifiedRelease,
) -> str | None:
    """The ONE shared installed-document integrity verifier (blocker 3): for every managed document
    it checks the on-disk file's fixed-path binding, type, symlink, link count, UID/GID, mode AND
    exact content against the INDEPENDENTLY authenticated expected digest (blocker 2) — so a
    canonical-but-re-authored evidence can never rewrite the digests. Called from status,
    pre-existing
    classification, adoption classification, and rollback. Returns a bounded reason or None."""
    fs = deps.filesystem()
    loc = deps.locations
    independent = _independent_expected_digests(deps, ident, record)
    for kind in _DOC_ORDER:
        rec = ev.record_for(kind)
        if rec is None:
            return "evidence_object_record_missing"
        path = getattr(loc, _KIND_PATH[kind])(role.value)
        if rec.binding != path_binding_digest(role.value, path):
            return "document_binding_mismatch"
        stt = fs.lstat(path)  # type: ignore[attr-defined]
        if stt is None:
            return "document_absent"
        meta = _assert_doc_metadata(stt, rec)
        if meta is not None:
            return meta
        try:
            data = fs.safe_read(path, max_bytes=_MAX_RECORD_BYTES, expected_uid=_ROOT_UID)  # type: ignore[attr-defined]
        except Exception as exc:
            return getattr(exc, "reason_code", "document_unreadable")
        exp = independent[kind]
        if kind == OBJECT_EVIDENCE_ATTESTATION:
            # a SELF/independently-verified record: it carries no embedded content digest and its
            # content is authenticated by its own Ed25519 signature
            # (`_verify_evidence_attestation`);
            # here we authenticate only its fixed binding + type/symlink/link-count/UID/GID/mode
            # (already checked above) and that the record is genuinely self-binding.
            if rec.content_sha256 is not None:
                return "attestation_self_record_forged"
        elif kind == OBJECT_EVIDENCE:
            # self record must carry no embedded digest; authenticate by canonical form (the
            # recorded
            # manifest/identity/signature sub-digests are cross-checked below against
            # `independent`).
            if rec.content_sha256 is not None:
                return "evidence_self_record_forged"
            if data != canonical_bytes(ev):
                return "evidence_content_drift"
        else:
            if sha256_bytes(data) != exp:
                return kind + "_content_drift"
            # a re-authored evidence that recorded a DIFFERENT digest is caught here, before removal
            if rec.content_sha256 != exp:
                return "evidence_object_record_forged"
    return None


def _worker_status(deps: EngineDeps) -> tuple[int, dict]:
    role = Role.WORKER
    seals = read_seals()
    ev, ident, record, drift = _revalidate_records(role, deps)
    documents_authenticated = False
    if drift is None and ev is not None and ident is not None and record is not None:
        integ = _verify_installed_documents(role, deps, ev, ident, record)
        documents_authenticated = integ is None
        if integ is not None:
            drift = integ
    obs = None
    obs_reason: str | None = None
    try:
        obs = deps.observer.observe_worker()
    except ManagementError as exc:
        obs_reason = exc.reason_code
    if drift is None and obs_reason is not None:
        drift = obs_reason
    # the COMPLETE expected end state is derived from the SIGNATURE-VERIFIED record, never evidence
    if drift is None and record is not None and obs is not None:
        end = _worker_end_state_reason(obs, _expected_worker(record.manifest))
        if end is not None:
            drift = end

    exp = _expected_worker(record.manifest) if record is not None else None
    commissioning = obs.commissioning_status if obs else "unavailable"
    deployment = obs.deployment_status if obs else "unavailable"

    def _b(cond: bool) -> bool:
        return bool(obs is not None and exp is not None and cond)

    dims = {
        "installation_evidence": ev is not None,
        "management_identity": ident is not None,
        "release_record": record is not None,
        "documents_authenticated": documents_authenticated,
        "observation_available": obs is not None,
        "ordinary_worker_identity": bool(
            obs and obs.ordinary_present and obs.ordinary_container_id
        ),
        "ordinary_health": bool(obs and obs.ordinary_healthy),
        "ordinary_container_generation": bool(obs and obs.coherent),
        "ordinary_image_binding": _b(
            obs is not None and exp is not None and obs.ordinary_image_digest == exp.ordinary_image
        ),
        "operator_image_binding": _b(
            obs is not None and exp is not None and obs.operator_image_digest == exp.operator_image
        ),
        "ordinary_config_binding": _b(
            obs is not None
            and exp is not None
            and obs.ordinary_config_identity == exp.ordinary_config_identity
        ),
        "health_command_binding": _b(
            obs is not None
            and exp is not None
            and obs.ordinary_health_command_identity == exp.health_command_identity
        ),
        "operator_unit_binding": _b(
            obs is not None
            and exp is not None
            and obs.operator_unit_identity == exp.operator_unit_identity
        ),
        "deployment_package_binding": _b(
            obs is not None
            and exp is not None
            and obs.deployment_package_aggregate == exp.deployment_aggregate
        ),
        "ordinary_queue": ORDINARY_TASK_QUEUE,
        "no_operator_queue_polling": bool(obs and not obs.ordinary_polls_operator_queue),
        "operator_package_trust": bool(obs and obs.package_trusted),
        "operator_service_present": bool(obs and obs.operator_present),
        "operator_disabled": obs is not None and not obs.operator_enabled,
        "operator_stopped": obs is not None and not obs.operator_running,
        "operator_queue": OPERATOR_TASK_QUEUE,
        "code_seals": _seal_section(),
        "commissioning": commissioning if commissioning == "prepared" else "not_prepared",
        "deployment": deployment if deployment == "sealed_prepared" else "not_prepared",
        "drift": drift,
    }
    ok = bool(
        seals.safe
        and drift is None
        and ev is not None
        and ident is not None
        and record is not None
        and obs is not None
    )
    return (EXIT_OK if ok else EXIT_REFUSED), {
        "command": "status",
        "role": "worker",
        "ok": ok,
        "dimensions": dims,
        "external_contacts_performed": False,
    }


def _finalized_controller_drift(
    ev: BootstrapEvidence,
    ident: ManagementPlaneIdentity | None,
    record: VerifiedRelease | None,
    deps: EngineDeps,
) -> str | None:
    """Phase 8 (2b-3c-c): the complete status contract for a FINALIZED controller. Returns a bounded
    drift reason or None. Documents alone can never make status healthy, and a PREPARED evidence
    checkpoint is explicitly NOT an installed/healthy state."""
    fin = ev.finalization
    if fin is None:
        return None  # worker / adopt / legacy evidence: unchanged behaviour
    # 1. the finalization extension must be COMMITTED -- a prepared checkpoint means cleanup was
    #    never proven, so the installation is not complete.
    if fin.finalization_commit_state != FINALIZATION_STATE_COMMITTED:
        return "controller_finalization_prepared_not_committed"
    # 2. its attested cleanup claims must actually hold, and be independently observable NOW.
    if not (fin.recovery_journal_absent and fin.staging_objects_absent):
        return "controller_finalization_cleanup_unproven"
    if not _finalization_cleanup_absent(deps):
        return "controller_finalization_cleanup_residual"
    # 3. the domain-separated bootstrap binding must recompute from the parsed evidence.
    if fin.bootstrap_binding_digest != ev.bootstrap_binding_digest():
        return "controller_install_binding_drift"
    # 4. strict marker bytes + the exact marker binding (shared plane-neutral contract).
    marker_drift = _verify_marker_binding(deps, ev)
    if marker_drift is not None:
        return marker_drift
    # 5. the LIVE signer system: exactly one verified ACTIVE identity, the dedicated role +
    #    credential, broker transport, API signer runtime readiness, the exact signed API image and
    #    complete generation agreement. A dead broker, sealed/unhealthy API, wrong image, stale
    #    socket/marker or identity drift each yields its own bounded reason.
    if ident is None or record is None:
        return "controller_status_records_incomplete"
    return _live_state_refusal(ev, ident, record, deps)


def _controller_status(deps: EngineDeps) -> tuple[int, dict]:
    role = Role.CONTROLLER
    seals = read_seals()
    ev, ident, record, drift = _revalidate_records(role, deps)
    documents_authenticated = False
    if drift is None and ev is not None and ident is not None and record is not None:
        integ = _verify_installed_documents(role, deps, ev, ident, record)
        documents_authenticated = integ is None
        if integ is not None:
            drift = integ
    obs = None
    obs_reason: str | None = None
    try:
        obs = deps.observer.observe_controller()
    except ManagementError as exc:
        obs_reason = exc.reason_code
    if drift is None and obs_reason is not None:
        drift = obs_reason
    if drift is None and record is not None and obs is not None:
        end = _controller_end_state_reason(obs, _expected_controller(record.manifest))
        if end is not None:
            drift = end
    # INDEPENDENTLY revalidate the authenticated finalization extension (2b-3c): recompute the
    # domain-separated bootstrap binding digest from the parsed evidence and cross-check the live
    # root-owned enablement marker against it — the attested finalization facts are NEVER trusted
    # alone. Absent on worker/adopt/legacy evidence → skipped, so their status is unchanged.
    if drift is None and ev is not None and ev.finalization is not None:
        drift = _finalized_controller_drift(ev, ident, record, deps)

    exp = _expected_controller(record.manifest) if record is not None else None
    observed_components = tuple(sorted(obs.container_image_digests)) if obs else ()

    def _b(cond: bool) -> bool:
        return bool(obs is not None and exp is not None and cond)

    dims = {
        "installation_evidence": ev is not None,
        "management_identity": ident is not None,
        "release_record": record is not None,
        "documents_authenticated": documents_authenticated,
        "observation_available": obs is not None,
        "container_topology": list(observed_components),
        "component_set": _b(
            exp is not None and observed_components == tuple(sorted(exp.expected_components))
        ),
        "image_identity": _b(
            obs is not None
            and exp is not None
            and obs.container_image_digests == exp.component_images
        ),
        "config_binding": _b(
            obs is not None and exp is not None and obs.config_identity == exp.config_identity
        ),
        "unit_binding": _b(
            obs is not None and exp is not None and obs.unit_identity == exp.unit_identity
        ),
        "migrations": (obs.migration_identity or None) if obs else None,
        "migration_identity_bound": _b(
            obs is not None and exp is not None and obs.migration_identity == exp.migration_identity
        ),
        "service_health": _b(
            exp is not None
            and obs is not None
            and all(obs.running.get(c, False) for c in exp.expected_components)
            and all(obs.healthy.get(c, False) for c in exp.expected_components)
        ),
        "no_unknown_privileged_service": obs is not None and not obs.unknown_privileged,
        "code_seals": _seal_section(),
        "drift": drift,
        "management_plane": Plane.MANAGEMENT.value,
    }
    ok = bool(
        seals.safe
        and drift is None
        and ev is not None
        and ident is not None
        and record is not None
        and obs is not None
    )
    return (EXIT_OK if ok else EXIT_REFUSED), {
        "command": "status",
        "role": "controller",
        "ok": ok,
        "dimensions": dims,
        "external_contacts_performed": False,
    }


# --------------------------------------------------------------------------- evidence + rollback


def read_evidence(role_value: str, deps: EngineDeps) -> tuple[int, dict]:
    """``secpctl evidence controller|worker`` — read the stored evidence, but report its
    mode/installation-id ONLY after its detached attestation + record binding + document integrity
    verify (so a re-authored evidence is never reported as trusted)."""
    try:
        role = parse_role(role_value)
    except ManagementError as exc:
        return EXIT_REFUSED, _refused("evidence", role_value, exc.reason_code)
    ev, ident, record, reason = _revalidate_records(role, deps)
    integ = None
    if reason is None and ev is not None and ident is not None and record is not None:
        integ = _verify_installed_documents(role, deps, ev, ident, record)
    if ev is None or reason is not None or integ is not None:
        return EXIT_REFUSED, {
            "command": "evidence",
            "role": role.value,
            "present": ev is not None,
            "authenticated": False,
            "reason_code": reason or integ,
        }
    return EXIT_OK, {
        "command": "evidence",
        "role": role.value,
        "present": True,
        "authenticated": True,
        "mode": ev.mode,
        "installation_id": ev.installation_id,
        "release_aggregate_digest": ev.release_aggregate_digest,
        "evidence_digest": ev.digest(),
        "code_seals": _seal_section(),
    }


def rollback(role_value: str, gate: WriteGate, deps: EngineDeps) -> tuple[int, dict]:
    """``secpctl rollback controller|worker`` — remove ONLY the documents proven by authenticated
    evidence to have been CREATED by the exact bootstrap transaction. It first runs the shared
    installed-document integrity verifier, which authenticates every document against the
    INDEPENDENTLY derived digests (signature-verified record + release-bound identity), so a
    re-authored / drifted / substituted document — or a forged evidence that rewrote the expected
    digests — is refused BEFORE any removal. Removal is through the closed rollback adapter
    (evidence
    LAST) and each object is reverified GONE. A sealed rollback adapter refuses with
    ``rollback_not_implemented`` (never a false ``written``). Never restarts the ordinary worker;
    never removes controller persistent data; never touches an adopted object."""
    try:
        role = parse_role(role_value)
        partial = gate.refusal_reason()
        if partial is not None:
            raise ManagementError(partial)
        ev, ident, record, reason = _revalidate_records(role, deps)
        if ev is None:
            raise ManagementError(reason or "evidence_absent")
        if ident is None or record is None:
            raise ManagementError(reason or "rollback_records_incomplete")
        # verify-before-trust: the detached attestation (part of `reason`) must verify BEFORE
        # ev.mode,
        # classification or created_records are trusted — so a forged mode/classification rewrite
        # fails as evidence_attestation_untrusted, never as a mode-specific refusal or rollback
        # plan.
        if reason is not None:
            raise ManagementError(reason)
        if ev.mode == MODE_ADOPTED:
            raise ManagementError("rollback_refused_adopted_installation")
        if not ev.created_records():
            raise ManagementError("rollback_no_created_objects")
        integ = _verify_installed_documents(role, deps, ev, ident, record)
        if integ is not None:
            raise ManagementError("rollback_" + integ)
        plan = _rollback_plan(role, ev, deps)
    except ManagementError as exc:
        return EXIT_REFUSED, _refused("rollback", role_value, exc.reason_code)

    base = {
        "command": "rollback",
        "role": role.value,
        "removable_bindings": [b for (b, _p, _k) in plan],
        "adopted_bindings_preserved": [],
        "ordinary_worker_restarted": False,
        "controller_persistent_data_removed": False,
        "code_seals": _seal_section(),
    }
    if not gate.is_write:
        base["mode"] = MODE_DRY_RUN
        return EXIT_OK, base
    try:
        removed = _execute_rollback(plan, deps)
    except ManagementError as exc:
        return EXIT_REFUSED, _refused("rollback", role_value, exc.reason_code)
    base["mode"] = MODE_WRITTEN
    base["removed_bindings"] = removed
    return EXIT_OK, base


def _rollback_plan(
    role: Role, ev: BootstrapEvidence, deps: EngineDeps
) -> list[tuple[str, str, str]]:
    """Build the ordered removal list: identity, manifest, signature, then the detached attestation,
    with EVIDENCE LAST (preserved until every other removal succeeds). EVERY entry — including the
    attestation — is included ONLY when its authenticated ownership record proves this transaction
    CREATED it (never appended unconditionally), so a pre-existing/adopted/orphan attestation is
    never removed. Integrity + authentication were already proven by the shared verifier +
    attestation; here we only resolve fixed paths from the created records."""
    loc = deps.locations
    created = {r.kind: r for r in ev.created_records()}
    plan: list[tuple[str, str, str]] = []
    for kind in (
        OBJECT_IDENTITY,
        OBJECT_RELEASE_MANIFEST,
        OBJECT_RELEASE_SIGNATURE,
        OBJECT_EVIDENCE_ATTESTATION,
        OBJECT_EVIDENCE,  # LAST: the authenticating evidence is preserved until all others removed
    ):
        rec = created.get(kind)
        if rec is not None:
            plan.append((rec.binding, getattr(loc, _KIND_PATH[kind])(role.value), kind))
    return plan


def _execute_rollback(plan: list[tuple[str, str, str]], deps: EngineDeps) -> list[str]:
    """Transactional removal: capture every planned document's exact bytes FIRST, remove each
    through the closed rollback adapter reverifying it is GONE, and if ANY removal/verification
    fails RESTORE
    every already-removed document (proving each restoration) and re-raise the ordinary failure — so
    the installation is either fully removed or fully restored, never partial. If a restoration
    cannot
    be proven, report recovery_required. A sealed adapter refuses on the first removal
    (``rollback_not_implemented``, nothing removed); a no-op adapter leaves an object present and is
    caught as ``rollback_removal_incomplete`` (nothing removed)."""
    fs = deps.filesystem()
    loc = deps.locations
    captured: list[tuple[str, str, bytes]] = []
    for binding, path, _kind in plan:
        try:
            data = fs.safe_read(path, max_bytes=_MAX_RECORD_BYTES, expected_uid=_ROOT_UID)  # type: ignore[attr-defined]
        except Exception as exc:
            raise ManagementError(
                "rollback_" + getattr(exc, "reason_code", "capture_failed")
            ) from None
        captured.append((binding, path, data))

    removed: list[tuple[str, str, bytes]] = []
    try:
        for binding, path, data in captured:
            deps.rollback_adapter.remove_object(binding=binding, kind="file")
            if fs.lstat(path) is not None:  # type: ignore[attr-defined]
                raise ManagementError("rollback_removal_incomplete")
            removed.append((binding, path, data))
    except ManagementError:
        residual = _restore_removed(fs, loc, removed)
        if residual:
            raise ManagementError("recovery_required") from None
        raise  # ordinary refusal — the installation was fully restored (never left partial)
    except Exception:
        # a NON-ManagementError (e.g. a real rollback adapter surfacing the hardened filesystem's
        # own
        # FilesystemError on a mid-transaction fault) must never defeat the transactional guarantee:
        # restore every already-removed document, else report recovery_required — mirroring the
        # bootstrap write path, which likewise pairs `except ManagementError` with `except
        # Exception`.
        residual = _restore_removed(fs, loc, removed)
        if residual:
            raise ManagementError("recovery_required") from None
        raise ManagementError("rollback_transaction_error") from None
    return [b for (b, _p, _d) in removed]


def _restore_removed(
    fs: object, loc: ManagementLocations, removed: list[tuple[str, str, bytes]]
) -> list[str]:
    """Re-install each already-removed document (reverse order) and PROVE each restoration; return
    the paths whose restoration could not be proven."""
    residual: list[str] = []
    for _binding, path, data in reversed(removed):
        try:
            _install_doc(fs, loc, path, data)
            if not _proven_document(fs, path, data):
                residual.append(path)
        except Exception:
            residual.append(path)
    return residual


def _load_evidence(role: Role, deps: EngineDeps) -> tuple[BootstrapEvidence | None, str | None]:
    fs = deps.filesystem()
    path = deps.locations.evidence_path(role.value)
    try:
        raw = fs.safe_read(path, max_bytes=_MAX_DOC_BYTES, expected_uid=_ROOT_UID)  # type: ignore[attr-defined]
    except Exception as exc:
        return None, getattr(exc, "reason_code", "evidence_unreadable")
    try:
        ev = parse_document_bytes(raw, evidence_from_dict, "evidence")
    except ManagementError as exc:
        return None, exc.reason_code
    if ev.role != role.value:
        return None, "evidence_role_mismatch"
    return ev, None


def _load_identity(
    role: Role, deps: EngineDeps
) -> tuple[ManagementPlaneIdentity | None, str | None]:
    fs = deps.filesystem()
    path = deps.locations.identity_path(role.value)
    try:
        raw = fs.safe_read(path, max_bytes=_MAX_DOC_BYTES, expected_uid=_ROOT_UID)  # type: ignore[attr-defined]
    except Exception as exc:
        return None, getattr(exc, "reason_code", "identity_unreadable")
    try:
        ident = parse_document_bytes(raw, identity_from_dict, "identity")
    except ManagementError as exc:
        return None, exc.reason_code
    if ident.role != role.value:
        return None, "identity_role_mismatch"
    return ident, None


def _load_release_record(role: Role, deps: EngineDeps) -> tuple[VerifiedRelease | None, str | None]:
    fs = deps.filesystem()
    loc = deps.locations
    try:
        manifest_bytes = fs.safe_read(  # type: ignore[attr-defined]
            loc.release_record_path(role.value), max_bytes=_MAX_RECORD_BYTES, expected_uid=_ROOT_UID
        )
        sig_bytes = fs.safe_read(  # type: ignore[attr-defined]
            loc.release_sig_path(role.value), max_bytes=_MAX_SIG_BYTES, expected_uid=_ROOT_UID
        )
    except Exception as exc:
        return None, getattr(exc, "reason_code", "release_record_unreadable")
    try:
        record = verify_release_record(manifest_bytes, sig_bytes, trust_root=deps.trust_root)
    except ManagementError as exc:
        return None, exc.reason_code
    if record.role != role.value:
        return None, "release_record_role_mismatch"
    return record, None
