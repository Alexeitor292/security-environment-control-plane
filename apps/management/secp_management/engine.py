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
from dataclasses import dataclass, field

from secp_commissioning.canonical import canonical_json, sha256_bytes, sha256_digest
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
from secp_management.evidence import (
    CLASSIFICATION_ADOPTED,
    CLASSIFICATION_CREATED,
    MODE_ADOPTED,
    MODE_INSTALLED,
    OBJECT_EVIDENCE,
    OBJECT_EVIDENCE_ATTESTATION,
    OBJECT_IDENTITY,
    OBJECT_RELEASE_MANIFEST,
    OBJECT_RELEASE_SIGNATURE,
    BootstrapEvidence,
    EvidenceAttestation,
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
    )


def _write_transaction(
    role: Role, vr: VerifiedRelease, deps: EngineDeps, bundle_dir: str
) -> tuple[ManagementPlaneIdentity, BootstrapEvidence]:
    """Classify pre-existing documents, execute the closed typed host operations, write the
    root-controlled documents (identity FIRST, evidence LAST), gate evidence on a FINAL coherent
    reobservation of the COMPLETE end state, and on any failure RESTORE any document this invocation
    overwrote and remove any it newly created AND compensate the host effects the adapter receipt
    records (reporting recovery_required if host compensation cannot be proven) — so a failed
    idempotent re-install never leaves a pre-existing document mutated."""
    loc = deps.locations
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

    def _compensate() -> None:
        doc_result = writer.compensate()
        if host_effected:
            _compensate_host(adapter)  # raises recovery_required if host compensation is unproven
        if not doc_result.proven:
            raise ManagementError("recovery_required")  # document restore/removal not proven

    try:
        # 1. closed typed host operations (image load → config → unit/package → reload → start)
        host_effected = True
        if role is Role.WORKER:
            _run_worker_ops(plan_w, deps)
        else:
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
        return ident, ev
    except ManagementError:
        _compensate()
        raise
    except Exception:
        _compensate()
        raise ManagementError("bootstrap_transaction_error") from None


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
