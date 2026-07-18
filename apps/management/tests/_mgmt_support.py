"""Shared test support for the management-plane bootstrap package (SECP-PR5E).

Builds an EPHEMERAL, visibly test-only signed release bundle (round 4: every image + the PR5D wheel
bound to a closed SIGNED purpose) over an in-memory hardened filesystem, plus EXACT closed FAKE
adapters injected through :class:`EngineDeps`. The :class:`FakeObserver` reports per-purpose images,
installed-artifact identities, an ABA generation marker, and the observer-composed commissioning/
deployment statuses; it can also apply a scheduled change BETWEEN the adoption admission and the
final
observation (to exercise the adoption TOCTOU close). No real key material, host address, container
runtime, systemd, or external infrastructure is ever touched. The fakes exercise the SAME engine
code
path production uses — only the leaf host effects are simulated.
"""

from __future__ import annotations

from secp_commissioning.canonical import canonical_json, sha256_bytes
from secp_commissioning.runtime import InMemoryFilesystem
from secp_management import BOOTSTRAP_CONTRACT_VERSION, ManagementError
from secp_management.adapters import (
    BootstrapReceipt,
    CompensationResult,
    ControllerObservation,
    PlatformFacts,
    ReviewedConfig,
    ReviewedUnit,
    VerifiedArtifact,
    WorkerObservation,
    controller_generation_marker,
    worker_generation_marker,
)
from secp_management.engine import EngineDeps
from secp_management.evidence import health_command_identity, path_binding_digest
from secp_management.hostview import HostView, StaticHostProbe
from secp_management.layout import ManagementLocations
from secp_management.release_bundle import ReleaseManifest, manifest_signing_message
from secp_management.signing import ReleaseTrustRoot, TrustAnchor, generate_keypair, sign_ed25519
from secp_management.systemd import (
    render_operator_unit_disabled,
    render_service_unit,
    unit_identity,
)
from secp_management.topology import (
    CONTROLLER_STACK_ENTRYPOINT,
    EXPECTED_CONTROLLER_COMPONENTS,
    OPERATOR_ENTRYPOINT,
    ORDINARY_HEALTH_COMMAND,
    read_seals,
)

TEST_KEY_ID = "secp-test-release-anchor/v1"
FIXED_TIME = "2026-07-18T00:00:00+00:00"
_CID = "3f2a" + "0" * 60
_MIGRATION = "c4e2f9a1b7d3"
_IMPL_AGGREGATE = (
    "sha256:" + "1" * 64
)  # == manifest.implementation_aggregate == deployment aggregate

_COMPOSE_BYTES = b"# compose template\n"
_WHEEL_BYTES = b"fake wheel package\n"

# Per-PURPOSE container image digests (distinct, so a swap between two valid release images is
# detectable). These are the SIGNED image digests the manifest binds by purpose.
WORKER_ORDINARY_IMAGE = sha256_bytes(b"image:worker/ordinary")
WORKER_OPERATOR_IMAGE = sha256_bytes(b"image:worker/operator")
CONTROLLER_COMPONENT_IMAGE = {
    c: sha256_bytes(f"image:controller/{c}".encode()) for c in EXPECTED_CONTROLLER_COMPONENTS
}

# Expected installed-artifact identities (deterministic, code-derived) a prepared host must observe.
_CONFIG_IDENTITY = sha256_bytes(_COMPOSE_BYTES)
_OPERATOR_UNIT_IDENTITY = unit_identity(
    render_operator_unit_disabled(
        exec_argv=OPERATOR_ENTRYPOINT, user="secp-operator", group="secp-operator"
    )
)
_CONTROLLER_UNIT_IDENTITY = unit_identity(
    render_service_unit(
        description="SECP controller stack supervisor",
        exec_argv=CONTROLLER_STACK_ENTRYPOINT,
        user="root",
        group="root",
        read_write_paths=(),
        wanted_by=None,
    )
)
_HEALTH_COMMAND_IDENTITY = health_command_identity(ORDINARY_HEALTH_COMMAND)

# Per-component controller container ids (fixed, distinct) used for the generation marker.
CONTROLLER_CONTAINER_ID = {
    c: "cid" + sha256_bytes(c.encode())[7:39] for c in EXPECTED_CONTROLLER_COMPONENTS
}

# An ephemeral, session-stable test-only Ed25519 management key that attests evidence, plus the
# matching evidence trust anchor. No production key is ever committed.
_EVIDENCE_KEY_ID = "secp-test-evidence-anchor/v1"
_EV_PRIV, _EV_PUB = generate_keypair()
_EVIDENCE_TRUST = ReleaseTrustRoot(
    anchors=(TrustAnchor(_EVIDENCE_KEY_ID, _EV_PUB),), test_only=True
)


class EphemeralEvidenceAuthenticator:
    """Test-only Ed25519 evidence authenticator (ephemeral key); production ships the sealed one."""

    def key_id(self) -> str:
        return _EVIDENCE_KEY_ID

    def attest(self, message: bytes) -> str:
        return sign_ed25519(_EV_PRIV, message)


# A second valid Ed25519 signer that is NOT provisioned as the evidence anchor.
_WRONG_EV_PRIV, _WRONG_EV_PUB = generate_keypair()


class MalformedHexAuthenticator:
    """Returns a correctly-sized but NON-hex signature (parse fails on re-read)."""

    def key_id(self) -> str:
        return _EVIDENCE_KEY_ID

    def attest(self, message: bytes) -> str:
        return "z" * 128


class InvalidSignatureAuthenticator:
    """Returns 128 valid-hex chars that are NOT a valid Ed25519 signature (verify fails)."""

    def key_id(self) -> str:
        return _EVIDENCE_KEY_ID

    def attest(self, message: bytes) -> str:
        return "00" * 64


class WrongKeyAuthenticator:
    """Returns a VALID Ed25519 signature made with a key that is NOT the provisioned anchor, under
    the correct key id (verify against the anchor's public key fails)."""

    def key_id(self) -> str:
        return _EVIDENCE_KEY_ID

    def attest(self, message: bytes) -> str:
        return sign_ed25519(_WRONG_EV_PRIV, message)


class WrongKeyIdAuthenticator:
    """Signs correctly but declares a key id that has no provisioned anchor."""

    def key_id(self) -> str:
        return "secp-test-evidence-anchor/WRONG"

    def attest(self, message: bytes) -> str:
        return sign_ed25519(_EV_PRIV, message)


class TamperingAuthenticator:
    """Returns a VALID Ed25519 signature but over a DIFFERENT message than the evidence — so the
    installed envelope's signature does not match the installed evidence bytes (the final re-read +
    verify at the commit point catches it)."""

    def key_id(self) -> str:
        return _EVIDENCE_KEY_ID

    def attest(self, message: bytes) -> str:
        return sign_ed25519(_EV_PRIV, message + b"tamper")


def fixed_clock() -> str:
    return FIXED_TIME


def ephemeral_trust_root() -> tuple[ReleaseTrustRoot, str, str, str]:
    """Return ``(trust_root, key_id, private_hex, public_hex)`` for an ephemeral test signer."""
    priv, pub = generate_keypair()
    trust = ReleaseTrustRoot(anchors=(TrustAnchor(TEST_KEY_ID, pub),), test_only=True)
    return trust, TEST_KEY_ID, priv, pub


def manifest_dict(role: str, artifacts: list[dict]) -> dict:
    return {
        "bootstrap_contract_version": BOOTSTRAP_CONTRACT_VERSION,
        "plane": "management",
        "role": role,
        "release_version": "0.1.0",
        "source_sha": "a" * 40,
        "source_tree_sha": "b" * 40,
        "parent_sha": None,
        "migration_identity": _MIGRATION,
        "implementation_aggregate": _IMPL_AGGREGATE,
        "bootstrap_package_identity": "secp-pr5e/management-bootstrap/v1",
        "signing_anchor_id": TEST_KEY_ID,
        "artifacts": artifacts,
    }


def _img_bytes(name: str) -> bytes:
    return f"fake image archive {name}\n".encode()


def _image_artifact(name: str, purpose: str, image_digest: str) -> dict[str, object]:
    data = _img_bytes(name)
    return {
        "name": name,
        "kind": "image_archive",
        "role": "shared",
        "sha256": sha256_bytes(data),
        "size": len(data),
        "image_digest": image_digest,
        "purpose": purpose,
    }


def default_artifacts(role: str) -> list[dict[str, object]]:
    compose: dict[str, object] = {
        "name": f"{role}-compose.yml",
        "kind": f"{role}_compose_template",
        "role": role,
        "sha256": sha256_bytes(_COMPOSE_BYTES),
        "size": len(_COMPOSE_BYTES),
    }
    if role == "controller":
        arts: list[dict[str, object]] = [compose]
        for c in EXPECTED_CONTROLLER_COMPONENTS:
            arts.append(
                _image_artifact(f"images/{c}.tar", f"controller/{c}", CONTROLLER_COMPONENT_IMAGE[c])
            )
        return arts
    return [
        compose,
        _image_artifact("images/ordinary.tar", "worker/ordinary", WORKER_ORDINARY_IMAGE),
        _image_artifact("images/operator.tar", "worker/operator", WORKER_OPERATOR_IMAGE),
        {
            "name": "wheels/secp_operator_deployment.whl",
            "kind": "python_wheel",
            "role": "shared",
            "sha256": sha256_bytes(_WHEEL_BYTES),
            "size": len(_WHEEL_BYTES),
            "purpose": "worker/deployment-package",
        },
    ]


def _artifact_bytes(art: dict) -> bytes:
    kind = art["kind"]
    if kind.endswith("compose_template"):
        return _COMPOSE_BYTES
    if kind == "python_wheel":
        return _WHEEL_BYTES
    return _img_bytes(str(art["name"]))


def _seed_dirs_for(fs: InMemoryFilesystem, bundle_dir: str, arts: list[dict]) -> None:
    dirs = {"/var/lib/secp/bootstrap", "/var/lib/secp/bootstrap/release", bundle_dir}
    for art in arts:
        name = str(art["name"])
        if "/" in name:
            dirs.add(f"{bundle_dir}/{name.rsplit('/', 1)[0]}")
    for d in sorted(dirs):
        fs.seed_dir(d, uid=0, gid=0, mode=0o755)


def seed_signed_bundle(
    fs: InMemoryFilesystem,
    bundle_dir: str,
    role: str,
    key_id: str,
    priv: str,
    artifacts: list[dict] | None = None,
) -> str:
    """Seed a fully-signed release bundle under ``bundle_dir`` and return the aggregate digest."""
    arts = artifacts if artifacts is not None else default_artifacts(role)
    manifest = ReleaseManifest.model_validate(manifest_dict(role, arts))
    sig = sign_ed25519(priv, manifest_signing_message(manifest))
    _seed_dirs_for(fs, bundle_dir, arts)
    fs.seed_file(f"{bundle_dir}/release-manifest.json", manifest.canonical().encode(), mode=0o644)
    fs.seed_file(
        f"{bundle_dir}/release-manifest.sig.json",
        canonical_json({"algorithm": "ed25519", "key_id": key_id, "signature": sig}).encode(),
        mode=0o644,
    )
    for art in arts:
        fs.seed_file(f"{bundle_dir}/{art['name']}", _artifact_bytes(art), mode=0o644)
    from secp_management.release_bundle import manifest_aggregate_digest

    return manifest_aggregate_digest(manifest)


def seed_signed_bundle_real(release_dir: str, role: str, key_id: str, priv: str) -> str:
    """Write a fully-signed release bundle to a REAL directory (root-owned 0644 files), for the
    POSIX/root test. Returns the aggregate digest."""
    import os

    arts = default_artifacts(role)
    manifest = ReleaseManifest.model_validate(manifest_dict(role, arts))
    sig = sign_ed25519(priv, manifest_signing_message(manifest))

    def _write(name: str, data: bytes) -> None:
        path = os.path.join(release_dir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data)
        os.chown(path, 0, 0)
        os.chmod(path, 0o644)

    _write("release-manifest.json", manifest.canonical().encode())
    _write(
        "release-manifest.sig.json",
        canonical_json({"algorithm": "ed25519", "key_id": key_id, "signature": sig}).encode(),
    )
    for art in arts:
        _write(str(art["name"]), _artifact_bytes(art))
    from secp_management.release_bundle import manifest_aggregate_digest

    return manifest_aggregate_digest(manifest)


def seed_write_ancestors(fs: InMemoryFilesystem) -> None:
    """Seed the trusted ancestor + role-root directories a managed write requires."""
    for d in (
        "/opt/secp",
        "/opt/secp/controller",
        "/opt/secp/worker",
        "/opt/secp/bootstrap",
        "/var/lib/secp",
        "/var/lib/secp/bootstrap",
    ):
        fs.seed_dir(d, uid=0, gid=0, mode=0o755)


# --------------------------------------------------------------------------- the fake host world


class FakeWorld:
    """A mutable, shared simulated host. The fake TYPED mutation adapters change it; the observer
    reads it. ``start_*`` flags force the FINAL reobservation to fail; ``fail_on`` makes an op raise
    (partial host effect); ``compensation_fails`` makes compensation unprovable; the
    ``*_before_final`` flags apply a change on the SECOND observation of a role (the adoption final)
    to exercise the admission->commit TOCTOU close."""

    def __init__(
        self,
        *,
        role: str,
        os_name: str = "linux",
        arch: str = "x86_64",
        is_root: bool = True,
        docker_present: bool = True,
        compose_present: bool = True,
        # observed worker state (defaults model a FRESH host before bootstrap)
        ordinary_present: bool = False,
        ordinary_running: bool = False,
        ordinary_healthy: bool = False,
        ordinary_image_digest: str = "",
        ordinary_config_identity: str = "",
        ordinary_health_command_identity: str = "",
        operator_present: bool = False,
        operator_enabled: bool = False,
        operator_running: bool = False,
        operator_unit_identity: str = "",
        operator_image_digest: str = "",
        deployment_package_aggregate: str = "",
        ordinary_polls_operator_queue: bool = False,
        package_trusted: bool = False,
        coherent: bool = True,
        restart_count: str = "0",
        pid: str = "4242",
        invocation_id: str = "a" * 32,
        commissioning_override: str | None = None,
        deployment_override: str | None = None,
        # observed controller state
        controller_containers: dict[str, str] | None = None,
        controller_running: dict[str, bool] | None = None,
        controller_healthy: dict[str, bool] | None = None,
        controller_privileged: tuple[str, ...] = (),
        migration_identity: str = "",
        controller_config_identity: str = "",
        controller_unit_identity: str = "",
        controller_restart_counts: dict[str, str] | None = None,
        generation_marker_override: str | None = None,
        # raw-generation-tuple overrides (emit an INCOMPLETE tuple with a correctly-derived marker)
        worker_container_id_override: str | None = None,
        worker_pid_override: str | None = None,
        worker_started_override: str | None = None,
        controller_container_ids_override: dict[str, str] | None = None,
        controller_restart_counts_override: dict[str, str] | None = None,
        # adapter start behavior (used only by the FRESH-host bootstrap path)
        start_healthy: bool = True,
        start_operator_running: bool = False,
        start_operator_enabled: bool = False,
        start_polls_operator_queue: bool = False,
        package_trusted_on_install: bool = True,
        start_image_digest: str = WORKER_ORDINARY_IMAGE,
        start_operator_image: str = WORKER_OPERATOR_IMAGE,
        stay_incoherent: bool = False,
        bad_installed_config: bool = False,
        bad_installed_unit: bool = False,
        bad_installed_package: bool = False,
        controller_start_running: bool = True,
        controller_start_healthy: bool = True,
        controller_start_images: dict[str, str] | None = None,
        controller_start_migration: str = _MIGRATION,
        controller_start_privileged: tuple[str, ...] = (),
        fail_on: str | None = None,
        load_wrong_image: bool = False,
        compensation_fails: bool = False,
        compensation_raises: bool = False,
        receipt_raises: bool = False,
        receipt_malformed: bool = False,
        # adoption TOCTOU: apply a change on the SECOND (final) observation of the role
        restart_before_final: bool = False,
        operator_start_before_final: bool = False,
        unhealthy_before_final: bool = False,
        controller_regen_before_final: bool = False,
    ) -> None:
        self.role = role
        self.os_name = os_name
        self.arch = arch
        self.is_root = is_root
        self.docker_present = docker_present
        self.compose_present = compose_present
        self.ordinary_present = ordinary_present
        self.ordinary_running = ordinary_running
        self.ordinary_healthy = ordinary_healthy
        self.ordinary_image_digest = ordinary_image_digest
        self.ordinary_config_identity = ordinary_config_identity
        self.ordinary_health_command_identity = ordinary_health_command_identity
        self.operator_present = operator_present
        self.operator_enabled = operator_enabled
        self.operator_running = operator_running
        self.operator_unit_identity = operator_unit_identity
        self.operator_image_digest = operator_image_digest
        self.deployment_package_aggregate = deployment_package_aggregate
        self.ordinary_polls_operator_queue = ordinary_polls_operator_queue
        self.package_trusted = package_trusted
        self.coherent = coherent
        self.restart_count = restart_count
        self.pid = pid
        self.invocation_id = invocation_id
        self.commissioning_override = commissioning_override
        self.deployment_override = deployment_override
        self.controller_containers = controller_containers or {}
        self.controller_running = controller_running or {}
        self.controller_healthy = controller_healthy or {}
        self.controller_privileged = controller_privileged
        self.migration_identity = migration_identity
        self.controller_config_identity = controller_config_identity
        self.controller_unit_identity = controller_unit_identity
        self.controller_restart_counts = controller_restart_counts or {}
        self.generation_marker_override = generation_marker_override
        self.worker_container_id_override = worker_container_id_override
        self.worker_pid_override = worker_pid_override
        self.worker_started_override = worker_started_override
        self.controller_container_ids_override = controller_container_ids_override
        self.controller_restart_counts_override = controller_restart_counts_override
        self.start_healthy = start_healthy
        self.start_operator_running = start_operator_running
        self.start_operator_enabled = start_operator_enabled
        self.start_polls_operator_queue = start_polls_operator_queue
        self.package_trusted_on_install = package_trusted_on_install
        self.start_image_digest = start_image_digest
        self.start_operator_image = start_operator_image
        self.stay_incoherent = stay_incoherent
        self.bad_installed_config = bad_installed_config
        self.bad_installed_unit = bad_installed_unit
        self.bad_installed_package = bad_installed_package
        self.controller_start_running = controller_start_running
        self.controller_start_healthy = controller_start_healthy
        self.controller_start_images = controller_start_images or dict(CONTROLLER_COMPONENT_IMAGE)
        self.controller_start_migration = controller_start_migration
        self.controller_start_privileged = controller_start_privileged
        self.fail_on = fail_on
        self.load_wrong_image = load_wrong_image
        self.compensation_fails = compensation_fails
        self.compensation_raises = compensation_raises
        self.receipt_raises = receipt_raises
        self.receipt_malformed = receipt_malformed
        self.restart_before_final = restart_before_final
        self.operator_start_before_final = operator_start_before_final
        self.unhealthy_before_final = unhealthy_before_final
        self.controller_regen_before_final = controller_regen_before_final
        self.ops: list[str] = []
        self.loaded_images: set[str] = set()

    def apply_final_worker_change(self) -> None:
        if self.restart_before_final:
            self.restart_count = str(int(self.restart_count) + 1)
            self.pid = str(int(self.pid) + 1)
        if self.operator_start_before_final:
            self.operator_running = True
            self.invocation_id = "f" * 32  # a started operator gets a new InvocationID
        if self.unhealthy_before_final:
            self.ordinary_healthy = False  # degrade WITHOUT a restart (generation unchanged)

    def apply_final_controller_change(self) -> None:
        if self.controller_regen_before_final:
            # bump a component's restart count → the generation marker changes (a real regen)
            self.controller_restart_counts = {**self.controller_restart_counts, "api": "1"}


def fresh_worker_world(**overrides: object) -> FakeWorld:
    return FakeWorld(role="worker", **overrides)  # type: ignore[arg-type]


def fresh_controller_world(**overrides: object) -> FakeWorld:
    return FakeWorld(role="controller", **overrides)  # type: ignore[arg-type]


def prepared_worker_world(
    *,
    coherent: bool = True,
    operator_present: bool = True,
    operator_enabled: bool = False,
    operator_running: bool = False,
    ordinary_present: bool = True,
    ordinary_running: bool = True,
    ordinary_healthy: bool = True,
    ordinary_polls_operator_queue: bool = False,
    package_trusted: bool = True,
    image_digest: str = WORKER_ORDINARY_IMAGE,
    operator_image_digest: str = WORKER_OPERATOR_IMAGE,
    config_identity: str = _CONFIG_IDENTITY,
    unit_identity_value: str = _OPERATOR_UNIT_IDENTITY,
    deployment_package_aggregate: str = _IMPL_AGGREGATE,
    health_command_identity_value: str = _HEALTH_COMMAND_IDENTITY,
    commissioning_override: str | None = None,
    deployment_override: str | None = None,
    **extra: object,
) -> FakeWorld:
    """A worker world already in the prepared end state (for status/adoption tests that don't run a
    fresh bootstrap)."""
    return FakeWorld(
        role="worker",
        coherent=coherent,
        ordinary_present=ordinary_present,
        ordinary_running=ordinary_running,
        ordinary_healthy=ordinary_healthy,
        ordinary_image_digest=image_digest,
        ordinary_config_identity=config_identity,
        ordinary_health_command_identity=health_command_identity_value,
        operator_present=operator_present,
        operator_enabled=operator_enabled,
        operator_running=operator_running,
        operator_unit_identity=unit_identity_value,
        operator_image_digest=operator_image_digest,
        deployment_package_aggregate=deployment_package_aggregate,
        ordinary_polls_operator_queue=ordinary_polls_operator_queue,
        package_trusted=package_trusted,
        commissioning_override=commissioning_override,
        deployment_override=deployment_override,
        **extra,  # type: ignore[arg-type]
    )


def prepared_controller_world(
    *,
    coherent: bool = True,
    privileged: tuple[str, ...] = (),
    containers: dict[str, str] | None = None,
    migration_identity: str = _MIGRATION,
    config_identity: str = _CONFIG_IDENTITY,
    unit_identity_value: str = _CONTROLLER_UNIT_IDENTITY,
    all_running: bool = True,
    all_healthy: bool = True,
    **extra: object,
) -> FakeWorld:
    conts = containers if containers is not None else dict(CONTROLLER_COMPONENT_IMAGE)
    return FakeWorld(
        role="controller",
        coherent=coherent,
        controller_containers=conts,
        controller_running={c: all_running for c in conts},
        controller_healthy={c: all_healthy for c in conts},
        controller_privileged=privileged,
        migration_identity=migration_identity,
        controller_config_identity=config_identity,
        controller_unit_identity=unit_identity_value,
        **extra,  # type: ignore[arg-type]
    )


class FakeObserver:
    """Reads the shared :class:`FakeWorld`, composing the commissioning + deployment statuses like
    the real PR5C/PR5D observer would and emitting an ABA generation marker. On the SECOND
    observation
    of a role it applies the world's scheduled adoption-final change first (so the adoption TOCTOU
    close can be exercised)."""

    def __init__(self, world: FakeWorld) -> None:
        self._w = world
        self._worker_calls = 0
        self._controller_calls = 0

    def platform(self) -> PlatformFacts:
        w = self._w
        return PlatformFacts(
            os_name=w.os_name,
            arch=w.arch,
            is_root=w.is_root,
            docker_present=w.docker_present,
            compose_present=w.compose_present,
            docker_version="27.0.0",
            compose_version="2.29.0",
        )

    def observe_controller(self) -> ControllerObservation:
        w = self._w
        self._controller_calls += 1
        if self._controller_calls == 2:
            w.apply_final_controller_change()
        container_ids = (
            dict(w.controller_container_ids_override)
            if w.controller_container_ids_override is not None
            else {c: CONTROLLER_CONTAINER_ID.get(c, "cid-" + c) for c in w.controller_containers}
        )
        restart_counts = (
            dict(w.controller_restart_counts_override)
            if w.controller_restart_counts_override is not None
            else {c: w.controller_restart_counts.get(c, "0") for c in w.controller_containers}
        )
        marker = controller_generation_marker(
            container_ids=container_ids,
            restart_counts=restart_counts,
            images=dict(w.controller_containers),
            migration_identity=w.migration_identity,
        )
        if w.generation_marker_override is not None:
            marker = w.generation_marker_override
        return ControllerObservation(
            coherent=w.coherent,
            container_image_digests=dict(w.controller_containers),
            running=dict(w.controller_running),
            healthy=dict(w.controller_healthy),
            unknown_privileged=tuple(w.controller_privileged),
            migration_identity=w.migration_identity,
            config_identity=w.controller_config_identity,
            unit_identity=w.controller_unit_identity,
            container_ids=container_ids,
            restart_counts=restart_counts,
            generation_marker=marker,
        )

    def observe_worker(self) -> WorkerObservation:
        w = self._w
        self._worker_calls += 1
        if self._worker_calls == 2:
            w.apply_final_worker_change()
        prepared = bool(
            w.coherent
            and w.ordinary_present
            and w.ordinary_running
            and w.ordinary_healthy
            and w.operator_present
            and not w.operator_enabled
            and not w.operator_running
        )
        sealed = bool(prepared and w.package_trusted and read_seals().safe)
        commissioning = (
            w.commissioning_override
            if w.commissioning_override is not None
            else ("prepared" if prepared else "not_prepared")
        )
        deployment = (
            w.deployment_override
            if w.deployment_override is not None
            else ("sealed_prepared" if sealed else "not_prepared")
        )
        container_id = (
            w.worker_container_id_override
            if w.worker_container_id_override is not None
            else (_CID if w.ordinary_present else "")
        )
        running_pid = (
            w.worker_pid_override
            if w.worker_pid_override is not None
            else (w.pid if w.ordinary_running else "0")
        )
        op_inv = w.invocation_id if w.operator_present else ""
        started = (
            w.worker_started_override
            if w.worker_started_override is not None
            else "2026-01-02T03:04:05.000000000Z"
        )
        marker = worker_generation_marker(
            container_id=container_id,
            running_pid=running_pid,
            restart_count=w.restart_count,
            started_at=started,
            operator_invocation_id=op_inv,
        )
        if w.generation_marker_override is not None:
            marker = w.generation_marker_override
        return WorkerObservation(
            coherent=w.coherent,
            ordinary_present=w.ordinary_present,
            ordinary_container_id=container_id,
            ordinary_running=w.ordinary_running,
            ordinary_image_digest=w.ordinary_image_digest,
            ordinary_restart_count=w.restart_count,
            ordinary_started_at=started,
            ordinary_pid=running_pid,
            ordinary_healthy=w.ordinary_healthy,
            ordinary_config_identity=w.ordinary_config_identity,
            ordinary_health_command_identity=w.ordinary_health_command_identity,
            operator_present=w.operator_present,
            operator_enabled=w.operator_enabled,
            operator_running=w.operator_running,
            operator_invocation_id=op_inv,
            operator_unit_identity=w.operator_unit_identity,
            operator_image_digest=w.operator_image_digest,
            deployment_package_aggregate=w.deployment_package_aggregate,
            ordinary_polls_operator_queue=w.ordinary_polls_operator_queue,
            package_trusted=w.package_trusted,
            commissioning_status=commissioning,
            deployment_status=deployment,
            generation_marker=marker,
        )


_WRONG = "sha256:" + "e" * 64


class _ReceiptMixin:
    def __init__(self) -> None:
        self._ops: list[str] = []
        self._images: list[str] = []
        self._configs: list[str] = []
        self._units: list[str] = []
        self._packages: list[str] = []
        self._services: list[str] = []

    def _guard(self, world: FakeWorld, op: str) -> None:
        world.ops.append(op)
        self._ops.append(op)
        if world.fail_on == op:
            raise ManagementError("fake_host_op_failed")

    def receipt(self):  # noqa: ANN201
        w = getattr(self, "_w", None)
        if w is not None and getattr(w, "receipt_raises", False):
            raise ManagementError("fake_receipt_error")
        if w is not None and getattr(w, "receipt_malformed", False):
            return "not-a-receipt"  # malformed (not a BootstrapReceipt) → engine fails closed
        return BootstrapReceipt(
            operations=tuple(self._ops),
            loaded_images=tuple(self._images),
            installed_configs=tuple(self._configs),
            installed_units=tuple(self._units),
            installed_packages=tuple(self._packages),
            started_services=tuple(self._services),
        )


class FakeControllerAdapter(_ReceiptMixin):
    def __init__(self, world: FakeWorld) -> None:
        super().__init__()
        self._w = world

    def load_image(self, artifact: VerifiedArtifact) -> None:
        artifact.read()  # prove the exact verified archive bytes are consumed (digest+size checked)
        assert artifact.purpose.startswith("controller/")  # typed, purpose-bound input
        # a real adapter loads the archive then checks the LOADED image vs the signed image digest;
        # the fake simulates loading exactly the signed image (or a WRONG one when asked).
        loaded = "sha256:" + "c" * 64 if self._w.load_wrong_image else artifact.image_digest
        artifact.verify_loaded_image(loaded)
        self._guard(self._w, f"load_image:{artifact.digest}")
        self._images.append(artifact.digest)
        self._w.loaded_images.add(artifact.digest)

    def install_config(self, config: ReviewedConfig) -> None:
        config.verify()
        self._guard(self._w, "install_config")
        self._configs.append(config.identity)
        self._w.controller_config_identity = (
            _WRONG if self._w.bad_installed_config else config.identity
        )

    def install_unit(self, unit: ReviewedUnit) -> None:
        unit.verify()
        self._guard(self._w, "install_unit")
        self._units.append(unit.identity)
        self._w.controller_unit_identity = _WRONG if self._w.bad_installed_unit else unit.identity

    def daemon_reload(self) -> None:
        self._guard(self._w, "daemon_reload")

    def run_migrations(self, *, migration_identity: str) -> None:
        self._guard(self._w, f"run_migrations:{migration_identity}")

    def start_stack(self, *, expected_components: tuple[str, ...]) -> None:
        w = self._w
        self._guard(w, "start_stack")
        w.controller_containers = dict(w.controller_start_images)
        w.controller_running = {c: w.controller_start_running for c in w.controller_containers}
        w.controller_healthy = {c: w.controller_start_healthy for c in w.controller_containers}
        w.controller_privileged = w.controller_start_privileged
        w.migration_identity = w.controller_start_migration
        self._services.extend(sorted(w.controller_containers))
        if w.stay_incoherent:
            w.coherent = False

    def compensate(self, receipt: BootstrapReceipt) -> CompensationResult:
        w = self._w
        if w.compensation_raises:
            raise ManagementError("fake_compensation_error")
        if w.compensation_fails:
            return CompensationResult(proven=False, residual=("controller_stack",))
        for d in receipt.loaded_images:
            w.loaded_images.discard(d)
        if receipt.started_services:
            w.controller_containers = {}
            w.controller_running = {}
            w.controller_healthy = {}
        return CompensationResult(proven=True)


class FakeWorkerAdapter(_ReceiptMixin):
    def __init__(self, world: FakeWorld) -> None:
        super().__init__()
        self._w = world

    def load_image(self, artifact: VerifiedArtifact) -> None:
        artifact.read()
        assert artifact.purpose.startswith("worker/")
        loaded = "sha256:" + "c" * 64 if self._w.load_wrong_image else artifact.image_digest
        artifact.verify_loaded_image(loaded)  # loaded image vs signed image digest
        self._guard(self._w, f"load_image:{artifact.digest}")
        self._images.append(artifact.digest)
        self._w.loaded_images.add(artifact.digest)

    def install_ordinary_config(self, config: ReviewedConfig) -> None:
        config.verify()
        self._guard(self._w, "install_ordinary_config")
        self._configs.append(config.identity)
        self._w.ordinary_config_identity = (
            _WRONG if self._w.bad_installed_config else config.identity
        )

    def install_deployment_package(self, package: VerifiedArtifact, *, aggregate: str) -> None:
        package.read()
        assert package.purpose == "worker/deployment-package"
        self._guard(self._w, "install_deployment_package")
        self._packages.append(aggregate)
        self._w.package_trusted = self._w.package_trusted_on_install
        self._w.deployment_package_aggregate = (
            _WRONG if self._w.bad_installed_package else aggregate
        )

    def install_operator_unit_disabled(self, unit: ReviewedUnit) -> None:
        unit.verify()
        w = self._w
        self._guard(w, "install_operator_unit_disabled")
        self._units.append(unit.identity)
        w.operator_present = True
        w.operator_enabled = w.start_operator_enabled
        w.operator_running = w.start_operator_running
        w.operator_unit_identity = _WRONG if w.bad_installed_unit else unit.identity
        w.operator_image_digest = w.start_operator_image

    def daemon_reload(self) -> None:
        self._guard(self._w, "daemon_reload")

    def start_ordinary(self) -> None:
        w = self._w
        self._guard(w, "start_ordinary")
        w.ordinary_present = True
        w.ordinary_running = True
        w.ordinary_healthy = w.start_healthy
        w.ordinary_image_digest = w.start_image_digest
        w.ordinary_health_command_identity = _HEALTH_COMMAND_IDENTITY
        w.ordinary_polls_operator_queue = w.start_polls_operator_queue
        self._services.append("ordinary")
        if w.stay_incoherent:
            w.coherent = False

    def compensate(self, receipt: BootstrapReceipt) -> CompensationResult:
        w = self._w
        if w.compensation_raises:
            raise ManagementError("fake_compensation_error")
        if w.compensation_fails:
            return CompensationResult(proven=False, residual=("ordinary",))
        for d in receipt.loaded_images:
            w.loaded_images.discard(d)
        if receipt.started_services:
            w.ordinary_present = False
            w.ordinary_running = False
            w.ordinary_healthy = False
        w.operator_present = False
        w.package_trusted = False
        return CompensationResult(proven=True)


class FakeRollbackAdapter:
    """Removes exactly the bootstrap-created document identified by its binding, mapping the binding
    to its OWN fixed layout path (both roles), through the hardened filesystem."""

    def __init__(self, fs: object, locations: ManagementLocations) -> None:
        self._fs = fs
        self._map: dict[str, tuple[str, str]] = {}
        for role in ("controller", "worker"):
            for path in (
                locations.identity_path(role),
                locations.release_record_path(role),
                locations.release_sig_path(role),
                locations.evidence_path(role),
                locations.evidence_attestation_path(role),
            ):
                self._map[path_binding_digest(role, path)] = (path, "file")
        self.removed: list[str] = []

    def remove_object(self, *, binding: str, kind: str) -> None:
        entry = self._map.get(binding)
        if entry is None:
            raise ManagementError("rollback_unknown_binding")
        path, _kind = entry
        self._fs.remove_file(path)  # type: ignore[attr-defined]
        self.removed.append(binding)


class NoOpRollbackAdapter:
    """A rollback adapter that reports success but removes NOTHING — proves the engine's reverify
    gate refuses a no-op rollback instead of returning a false ``written``."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def remove_object(self, *, binding: str, kind: str) -> None:
        self.calls.append(binding)


class FailingRollbackAdapter(FakeRollbackAdapter):
    """Removes normally until the Nth removal, then raises — for proving transactional rollback
    restores every already-removed document, else reports recovery_required. ``filesystem_error``
    raises a NON-ManagementError (as a real adapter surfacing the hardened filesystem's own fault
    would), proving the transactional guarantee does not depend on the exception TYPE."""

    def __init__(
        self,
        fs: object,
        locations: ManagementLocations,
        *,
        fail_at: int,
        filesystem_error: bool = False,
    ) -> None:
        super().__init__(fs, locations)
        self._fail_at = fail_at
        self._filesystem_error = filesystem_error
        self._n = 0

    def remove_object(self, *, binding: str, kind: str) -> None:
        self._n += 1
        if self._n == self._fail_at:
            if self._filesystem_error:
                from secp_commissioning.runtime import FilesystemError

                raise FilesystemError("fs_remove_file_failed")
            raise ManagementError("fake_removal_failed")
        super().remove_object(binding=binding, kind=kind)


class FlakyFilesystem:
    """Wraps an :class:`InMemoryFilesystem`, delegating everything except the fault-injected op:
    ``fail_remove`` makes ``remove_file`` raise; ``fail_install_after`` makes ``atomic_install``
    raise
    after N successful calls; ``silent_install_after`` makes it a no-op after N calls (so a
    restoration appears to occur but the proof re-read fails). Used to prove document compensation +
    rollback restoration fail closed (recovery_required)."""

    def __init__(
        self,
        inner: InMemoryFilesystem,
        *,
        fail_remove: bool = False,
        fail_install_after: int | None = None,
        silent_install_after: int | None = None,
    ) -> None:
        self._inner = inner
        self._fail_remove = fail_remove
        self._fail_install_after = fail_install_after
        self._silent_install_after = silent_install_after
        self._installs = 0

    def __getattr__(self, name: str):  # noqa: ANN202 — delegate everything not overridden
        return getattr(self._inner, name)

    def remove_file(self, path: str) -> None:
        if self._fail_remove:
            from secp_commissioning.runtime import FilesystemError

            raise FilesystemError("flaky_remove_failed")
        self._inner.remove_file(path)

    def atomic_install(self, path: str, data: bytes, *, uid: int, gid: int, mode: int) -> None:
        self._installs += 1
        if self._fail_install_after is not None and self._installs > self._fail_install_after:
            from secp_commissioning.runtime import FilesystemError

            raise FilesystemError("flaky_install_failed")
        if self._silent_install_after is not None and self._installs > self._silent_install_after:
            return  # pretend to install (no write) → a subsequent content proof fails
        self._inner.atomic_install(path, data, uid=uid, gid=gid, mode=mode)


def _probe_view(world: FakeWorld) -> HostView:
    return HostView(
        os_name=world.os_name,
        arch=world.arch,
        is_root=world.is_root,
        docker_present=False,  # LocalHostProbe never claims docker; the observer is authoritative
        compose_present=False,
    )


def deps_for(
    fs: InMemoryFilesystem,
    world: FakeWorld,
    trust: ReleaseTrustRoot,
    *,
    rollback_adapter: object | None = None,
    locations: ManagementLocations | None = None,
) -> EngineDeps:
    loc = locations or ManagementLocations()
    return EngineDeps(
        locations=loc,
        trust_root=trust,
        probe=StaticHostProbe(_probe_view(world)),
        observer=FakeObserver(world),
        controller_adapter=FakeControllerAdapter(world),
        worker_adapter=FakeWorkerAdapter(world),
        rollback_adapter=rollback_adapter or FakeRollbackAdapter(fs, loc),
        evidence_authenticator=EphemeralEvidenceAuthenticator(),
        evidence_trust_root=_EVIDENCE_TRUST,
        fs=fs,
        clock=fixed_clock,
    )
