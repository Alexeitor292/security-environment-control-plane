"""Closed, typed, role-specific PRODUCTION effect adapters (SECP-PR5E round 3).

The engine performs NO host effect directly. It drives closed, reviewed operations through four
injected seams: a read-only :class:`ManagementHostObserver` (one coherent topology observation for
status/adoption/reobservation) and three mutation adapters (:class:`ControllerBootstrapAdapter`,
:class:`WorkerBootstrapAdapter`, :class:`ManagementRollbackAdapter`). Every mutation op consumes an
EXACT typed input — a :class:`VerifiedArtifact` (role/kind/name/digest/size + a hardened, digest-
checked byte reader), a :class:`ReviewedConfig`/:class:`ReviewedUnit` (deterministic verified bytes
+
a content-bound identity), or a specific reviewed scalar (migration identity, expected component
set)
— never a generic subprocess/shell/argv/path/Compose-project/systemd-unit/container verb. Each
mutation
adapter accumulates a :class:`BootstrapReceipt` of the objects it actually created and exposes a
closed
``compensate(receipt)`` that removes ONLY those objects and returns a :class:`CompensationResult`
(proven, or a residual that forces ``recovery_required``).

The SHIPPED production defaults are SEALED: every observer/mutation/rollback call fails closed with
a
bounded reason. So on the shipped repository (and any host without reviewed real adapters installed)
bootstrap, adoption, status, and rollback ALL fail closed — the engine never reports a false
success.
A real host injects reviewed adapters out of band (the real worker observer composes the PR5C/PR5D
read-only host adapters; the real mutation adapters wrap the pinned container-runtime / systemctl
seams and consume these exact typed inputs). Tests inject exact closed fakes. CLI users can neither
select nor inject an adapter.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

from secp_commissioning.canonical import is_sha256_digest, sha256_bytes, sha256_digest

from secp_management import ManagementError

# --------------------------------------------------------------------- typed mutation inputs


@dataclass(frozen=True)
class VerifiedArtifact:
    """One release artifact already verified against the signed manifest, handed to the adapter as
    an EXACT typed object with a hardened, digest-checked reader (never a bare name or a raw path).
    For an image archive it carries BOTH the archive content ``digest`` AND the signed
    ``image_digest`` (the loaded-image digest), so a real adapter loads the archive and verifies the
    LOADED image against the purpose-specific signed image digest — not merely the archive bytes.
    The
    reader re-reads the verified archive bytes; ``read()`` refuses if they no longer match."""

    role: str
    kind: str
    name: str
    digest: str  # "sha256:..." archive CONTENT digest
    size: int
    reader: Callable[[], bytes]
    purpose: str = ""  # closed signed purpose (e.g. controller/api, worker/ordinary)
    image_digest: str = ""  # signed loaded-image digest (image_archive only; "" otherwise)

    def read(self) -> bytes:
        data = self.reader()
        if len(data) != self.size or sha256_bytes(data) != self.digest:
            raise ManagementError("verified_artifact_content_mismatch")
        return data

    def verify_loaded_image(self, loaded_digest: str) -> None:
        """A real adapter calls this with the digest of the image it actually LOADED from the
        archive; it must equal the signed purpose-specific image digest."""
        if not self.image_digest or loaded_digest != self.image_digest:
            raise ManagementError("verified_artifact_image_digest_mismatch")


# ------------------------------------------------------------- reviewed generation markers


def worker_generation_marker(
    *,
    container_id: str,
    running_pid: str,
    restart_count: str,
    started_at: str,
    operator_invocation_id: str,
) -> str:
    """The reviewed worker generation identity — a SHA-256 over the COMPLETE ABA generation tuple.
    Both the observer and the engine derive it the same way, so a placeholder/constant marker that
    ignores a restart/PID/InvocationID change is detectable (it will not equal this derivation)."""
    return sha256_digest(
        {
            "v": "secp.management.worker-generation/v1",
            "cid": container_id,
            "restart": restart_count,
            "started": started_at,
            "pid": running_pid,
            "operator_invocation_id": operator_invocation_id,
        }
    )


def controller_generation_marker(
    *,
    container_ids: dict[str, str],
    restart_counts: dict[str, str],
    images: dict[str, str],
    migration_identity: str,
) -> str:
    """The reviewed controller generation identity — a SHA-256 over the per-component container
    ids + restart counts + image map + migration identity."""
    return sha256_digest(
        {
            "v": "secp.management.controller-generation/v1",
            "ids": sorted(container_ids.items()),
            "restarts": sorted(restart_counts.items()),
            "images": sorted(images.items()),
            "migration": migration_identity,
        }
    )


def is_generation_marker(marker: str) -> bool:
    return is_sha256_digest(marker)


@dataclass(frozen=True)
class ReviewedConfig:
    """Deterministic verified config bytes plus a content-bound identity (the identity is the
    content digest, so a changed byte changes the identity and is caught by reobservation)."""

    identity: str
    content: bytes

    def verify(self) -> None:
        if self.identity != sha256_bytes(self.content):
            raise ManagementError("reviewed_config_identity_mismatch")


@dataclass(frozen=True)
class ReviewedUnit:
    """A deterministic, code-rendered systemd unit plus a content-bound identity."""

    identity: str
    content: bytes

    def verify(self) -> None:
        if self.identity != sha256_bytes(self.content):
            raise ManagementError("reviewed_unit_identity_mismatch")


@dataclass(frozen=True)
class ControllerBootstrapPlan:
    """The exact typed controller plan, derived by the engine ONLY from the verified release. The
    component -> image-digest map comes from the SIGNED purpose taxonomy, never set membership."""

    role: str
    image_artifacts: tuple[VerifiedArtifact, ...]
    config: ReviewedConfig
    unit: ReviewedUnit
    migration_identity: str
    expected_components: tuple[str, ...]
    component_images: dict[str, str]  # signed component -> exact image digest


@dataclass(frozen=True)
class WorkerBootstrapPlan:
    """The exact typed worker plan, derived by the engine ONLY from the verified release. The
    ordinary and operator images come from the SIGNED purpose taxonomy, never set membership."""

    role: str
    image_artifacts: tuple[VerifiedArtifact, ...]
    ordinary_config: ReviewedConfig
    deployment_package: VerifiedArtifact
    deployment_aggregate: str
    operator_unit: ReviewedUnit
    ordinary_image: str  # signed worker/ordinary image digest
    operator_image: str  # signed worker/operator image digest


# --------------------------------------------------------------------- receipts + compensation


@dataclass(frozen=True)
class BootstrapReceipt:
    """A record of ONLY the host objects an adapter actually created/changed in one transaction, so
    compensation can remove exactly those and nothing else."""

    operations: tuple[str, ...] = ()
    loaded_images: tuple[str, ...] = ()
    installed_configs: tuple[str, ...] = ()
    installed_units: tuple[str, ...] = ()
    installed_packages: tuple[str, ...] = ()
    started_services: tuple[str, ...] = ()


@dataclass(frozen=True)
class CompensationResult:
    """The outcome of a closed compensation. ``proven`` is True only when every object the receipt
    records was verifiably removed; any ``residual`` forces the engine to recovery_required."""

    proven: bool
    residual: tuple[str, ...] = ()


# --------------------------------------------------------------------- observations (read-only)


@dataclass(frozen=True)
class PlatformFacts:
    """OS/architecture/root + Docker/Compose presence + versions (read-only)."""

    os_name: str
    arch: str
    is_root: bool
    docker_present: bool
    compose_present: bool
    docker_version: str = ""
    compose_version: str = ""


@dataclass(frozen=True)
class ControllerObservation:
    """One coherent read-only observation of the controller stack, including the installed artifact
    identities (config/systemd-wrapper) and the exact component -> image-digest mapping — never just
    service booleans. ``coherent`` is False when the before/after generation check failed."""

    coherent: bool
    container_image_digests: dict[str, str] = field(default_factory=dict)  # component -> sha256:...
    running: dict[str, bool] = field(default_factory=dict)
    healthy: dict[str, bool] = field(default_factory=dict)
    unknown_privileged: tuple[str, ...] = ()
    migration_identity: str = ""
    config_identity: str = ""  # observed compose/config content identity
    unit_identity: str = ""  # observed systemd-wrapper content identity
    # raw per-component generation facts the marker is derived from (so the engine can recompute it)
    container_ids: dict[str, str] = field(default_factory=dict)
    restart_counts: dict[str, str] = field(default_factory=dict)
    # ABA generation marker (mandatory SHA-256 over the complete generation tuple); two adoption
    # observations with the SAME marker prove nothing was restarted/replaced between
    # admission+commit.
    generation_marker: str = ""


@dataclass(frozen=True)
class WorkerObservation:
    """One coherent read-only observation of the worker topology, INCLUDING the installed artifact
    identities (ordinary config, operator unit, deployment-package aggregate, health-command) and an
    INDEPENDENT host-readiness predicate the production observer derives directly from the single
    coherent observation (present + running + healthy + operator present/disabled/stopped +
    ordinary-queue-contained).  This is intentionally NARROWER than the full PR5C commissioning +
    PR5D deployment verification engines; the management ENGINE applies the authoritative
    expected-vs-observed verification during adopt/commit — never trusting these host-side hints."""

    coherent: bool
    ordinary_present: bool
    ordinary_container_id: str
    ordinary_running: bool
    ordinary_image_digest: str
    ordinary_restart_count: str
    ordinary_started_at: str
    ordinary_pid: str
    ordinary_healthy: bool
    ordinary_config_identity: str
    ordinary_health_command_identity: str
    operator_present: bool
    operator_enabled: bool
    operator_running: bool
    operator_invocation_id: str
    operator_unit_identity: str
    operator_image_digest: str
    deployment_package_aggregate: str
    # True if the ordinary worker is observed polling the operator (controlled-live) queue — a
    # containment breach; a prepared worker polls ONLY the ordinary queue.
    ordinary_polls_operator_queue: bool
    package_trusted: bool
    # host-side readiness LABELS derived by the observer's own predicate (NOT a call into the PR5C
    # commissioning or PR5D deployment verification engines); the engine re-verifies for real.
    commissioning_status: str  # observer predicate: "prepared" / "not_prepared"
    deployment_status: str  # observer predicate: "sealed_prepared" / "not_prepared"
    # ABA generation marker over the ordinary container id/restart/start/pid + operator
    # InvocationID;
    # two adoption observations with the SAME marker prove nothing restarted between
    # admission+commit.
    generation_marker: str = ""


# --------------------------------------------------------------------------- protocols


class ManagementHostObserver(Protocol):
    def platform(self) -> PlatformFacts: ...
    def observe_controller(self) -> ControllerObservation: ...
    def observe_worker(self) -> WorkerObservation: ...


class ControllerBootstrapAdapter(Protocol):
    def load_image(self, artifact: VerifiedArtifact) -> None: ...
    def install_config(self, config: ReviewedConfig) -> None: ...
    def install_unit(self, unit: ReviewedUnit) -> None: ...
    def daemon_reload(self) -> None: ...
    def run_migrations(self, *, migration_identity: str) -> None: ...
    def start_stack(self, *, expected_components: tuple[str, ...]) -> None: ...
    def receipt(self) -> BootstrapReceipt: ...
    def compensate(self, receipt: BootstrapReceipt) -> CompensationResult: ...


class WorkerBootstrapAdapter(Protocol):
    def load_image(self, artifact: VerifiedArtifact) -> None: ...
    def install_ordinary_config(self, config: ReviewedConfig) -> None: ...
    def install_deployment_package(self, package: VerifiedArtifact, *, aggregate: str) -> None: ...
    def install_operator_unit_disabled(self, unit: ReviewedUnit) -> None: ...
    def daemon_reload(self) -> None: ...
    def start_ordinary(self) -> None: ...
    def receipt(self) -> BootstrapReceipt: ...
    def compensate(self, receipt: BootstrapReceipt) -> CompensationResult: ...


class ManagementRollbackAdapter(Protocol):
    # Remove ONE bootstrap-created object identified by its topology-safe path binding + kind. The
    # adapter maps the binding to its OWN fixed layout path (never an arbitrary caller path) and
    # performs a hardened removal. It exposes no generic delete-any-path verb.
    def remove_object(self, *, binding: str, kind: str) -> None: ...


class ManagementEvidenceAuthenticator(Protocol):
    # Attest a canonical evidence-attestation MESSAGE with the reviewed management signing key,
    # returning the detached signature hex. It signs ONLY the exact message the engine derives from
    # the evidence/identity/release — never arbitrary bytes chosen by a caller path.
    def key_id(self) -> str: ...
    def attest(self, message: bytes) -> str: ...


# --------------------------------------------------------------------------- sealed defaults


class SealedHostObserver:
    """Shipped default: no reviewed production observer is installed, so every observation fails
    closed. Status/adoption/bootstrap therefore refuse in the shipped state instead of trusting a
    placeholder."""

    def platform(self) -> PlatformFacts:
        raise ManagementError("host_observer_not_available")

    def observe_controller(self) -> ControllerObservation:
        raise ManagementError("host_observer_not_available")

    def observe_worker(self) -> WorkerObservation:
        raise ManagementError("host_observer_not_available")


class SealedControllerBootstrapAdapter:
    """Shipped default: no reviewed controller mutation adapter is installed — every op fails
    closed, so a controller bootstrap write refuses (no false success) until one is installed."""

    def load_image(self, artifact: VerifiedArtifact) -> None:
        raise ManagementError("controller_bootstrap_adapter_not_provisioned")

    def install_config(self, config: ReviewedConfig) -> None:
        raise ManagementError("controller_bootstrap_adapter_not_provisioned")

    def install_unit(self, unit: ReviewedUnit) -> None:
        raise ManagementError("controller_bootstrap_adapter_not_provisioned")

    def daemon_reload(self) -> None:
        raise ManagementError("controller_bootstrap_adapter_not_provisioned")

    def run_migrations(self, *, migration_identity: str) -> None:
        raise ManagementError("controller_bootstrap_adapter_not_provisioned")

    def start_stack(self, *, expected_components: tuple[str, ...]) -> None:
        raise ManagementError("controller_bootstrap_adapter_not_provisioned")

    def receipt(self) -> BootstrapReceipt:
        # every op raised before touching the host → an EMPTY receipt PROVES no effect occurred, so
        # the engine refuses with the original reason rather than a false recovery_required.
        return BootstrapReceipt()

    def compensate(self, receipt: BootstrapReceipt) -> CompensationResult:
        return CompensationResult(proven=True)


class SealedWorkerBootstrapAdapter:
    """Shipped default: no reviewed worker mutation adapter is installed — every op fails closed."""

    def load_image(self, artifact: VerifiedArtifact) -> None:
        raise ManagementError("worker_bootstrap_adapter_not_provisioned")

    def install_ordinary_config(self, config: ReviewedConfig) -> None:
        raise ManagementError("worker_bootstrap_adapter_not_provisioned")

    def install_deployment_package(self, package: VerifiedArtifact, *, aggregate: str) -> None:
        raise ManagementError("worker_bootstrap_adapter_not_provisioned")

    def install_operator_unit_disabled(self, unit: ReviewedUnit) -> None:
        raise ManagementError("worker_bootstrap_adapter_not_provisioned")

    def daemon_reload(self) -> None:
        raise ManagementError("worker_bootstrap_adapter_not_provisioned")

    def start_ordinary(self) -> None:
        raise ManagementError("worker_bootstrap_adapter_not_provisioned")

    def receipt(self) -> BootstrapReceipt:
        return BootstrapReceipt()  # empty receipt PROVES no effect occurred (see controller note)

    def compensate(self, receipt: BootstrapReceipt) -> CompensationResult:
        return CompensationResult(proven=True)


class SealedRollbackAdapter:
    """Shipped default: no reviewed rollback adapter is installed, so rollback refuses
    (``rollback_not_implemented``) rather than falsely claim removals occurred."""

    def remove_object(self, *, binding: str, kind: str) -> None:
        raise ManagementError("rollback_not_implemented")


class SealedEvidenceAuthenticator:
    """Shipped default: no reviewed management signing key is provisioned, so evidence cannot be
    attested — a production bootstrap/adoption fails closed
    (``evidence_authenticator_not_provisioned``)
    rather than writing unauthenticated evidence. Production commits NO private key; tests inject an
    ephemeral test-only Ed25519 authenticator."""

    def key_id(self) -> str:
        raise ManagementError("evidence_authenticator_not_provisioned")

    def attest(self, message: bytes) -> str:
        raise ManagementError("evidence_authenticator_not_provisioned")
