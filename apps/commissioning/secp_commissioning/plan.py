"""Immutable commissioning plan engine (SECP-PR5C, ADR-023, deliverables 4 + defects #1, #7).

Produces ONE deterministic, canonically-hashable :class:`CommissioningPlan` from four explicit
inputs:

* the validated descriptor;
* the executable-owned :class:`~secp_commissioning.locations.CommissioningLocations` (fixes the
  operator root + every install basename — the descriptor supplies NO path);
* explicitly-injected :class:`HostFacts` — what ``inspect`` observed, never gathered here;
* the trusted :class:`ExpectedIdentities` — the independent release / image / runtime / queue /
  health / template / version pins the descriptor must MATCH (it is never the sole source of truth).

Planning performs NO writes and NO network/Temporal/DB/Proxmox/OpenBao/state contact. It refuses
closed on ANY identity mismatch, on an enabled/running operator (via the injected facts), on a
non-distinct operator queue, and asserts the STRUCTURAL INVARIANT that every writable + rollback-
owned target is strictly beneath the fixed operator root and beneath no protected root. The plan
digest is INTENT-only (drift-independent), so ``install-prepared`` is idempotent.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from secp_commissioning import TOOL_VERSION
from secp_commissioning.canonical import sha256_digest
from secp_commissioning.descriptor import (
    CONTRACT_VERSION,
    CommissioningDescriptor,
    descriptor_digest,
)
from secp_commissioning.errors import reject
from secp_commissioning.locations import (
    OPERATOR_FILE_LAYOUT,
    OPERATOR_ROOT_MODE,
    ROLE_OPERATOR_ROOT,
    CommissioningLocations,
)
from secp_commissioning.operator_template import entrypoint_template_digest

ACTION_CREATE = "create"
ACTION_ALREADY_CORRECT = "already_correct"
ACTION_DRIFTED = "drifted"

# The ONE reviewed operator-registration entrypoint symbol. A caller-supplied
# ``operator_registration_symbol`` that differs from this fixed value is refused (defect #7); the
# symbol's implementation identity is additionally bound through the pinned entrypoint-template
# digest (the reviewed template names exactly this symbol and nothing else executable).
OPERATOR_REGISTRATION_SYMBOL = "build_operator_worker_registration"


@dataclass(frozen=True)
class DirObservation:
    exists: bool
    owner_uid: int | None = None
    owner_gid: int | None = None
    mode: int | None = None


@dataclass(frozen=True)
class HostFacts:
    """Explicitly-injected, read-only host inspection facts. The plan NEVER gathers these itself."""

    directories: dict[str, DirObservation] = field(default_factory=dict)
    image_digests_present: tuple[str, ...] = ()
    operator_service_present: bool = False
    operator_service_enabled: bool = False
    operator_service_running: bool = False
    ordinary_worker_running: bool = False
    service_state_inspected: bool = False
    installed_files: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ExpectedIdentities:
    """The trusted, independent pins the descriptor must match (executable/deployment-owned)."""

    release_source_sha: str
    source_tree_sha: str
    control_plane_image_digest: str
    ordinary_worker_image_digest: str
    operator_image_digest: str
    ordinary_task_queue: str
    operator_task_queue: str
    ordinary_health_command: tuple[str, ...]
    parent_sha: str | None = None
    ordinary_runtime_uid: int = 10001
    ordinary_runtime_gid: int = 10001
    operator_runtime_uid: int = 10001
    operator_runtime_gid: int = 10001
    contract_version: str = CONTRACT_VERSION
    tool_version: str = TOOL_VERSION
    operator_registration_symbol: str = "build_operator_worker_registration"

    def entrypoint_template_digest(self) -> str:
        return entrypoint_template_digest()


@dataclass(frozen=True)
class PlannedDirectory:
    role: str
    path: str
    owner_uid: int
    owner_gid: int
    mode: int
    action: str


@dataclass(frozen=True)
class PlannedFile:
    role: str
    target_path: str
    owner_uid: int
    owner_gid: int
    mode: int


@dataclass(frozen=True)
class PlannedImage:
    section: str
    digest: str
    state: str  # "present" | "absent"


@dataclass(frozen=True)
class PlannedService:
    name: str
    kind: str
    enabled: bool  # ALWAYS False
    running: bool  # ALWAYS False


@dataclass(frozen=True)
class CommissioningPlan:
    contract_version: str
    tool_version: str
    descriptor_digest: str
    deployment_id: str
    operator_root: str
    ordinary_task_queue: str
    operator_task_queue: str
    ordinary_worker_source_sha: str
    source_tree_sha: str
    ordinary_runtime_uid: int
    ordinary_runtime_gid: int
    operator_runtime_uid: int
    operator_runtime_gid: int
    ordinary_health_command: tuple[str, ...]
    operator_registration_symbol: str
    entrypoint_template_digest: str
    directories: tuple[PlannedDirectory, ...]
    files: tuple[PlannedFile, ...]
    images: tuple[PlannedImage, ...]
    services: tuple[PlannedService, ...]
    rollback_actions: tuple[str, ...]  # role tokens whose objects a rollback would remove
    evidence_preview: dict[str, object]
    changes: tuple[str, ...]

    def canonical(self) -> dict:
        return asdict(self)

    def intent(self) -> dict:
        """The descriptor+pins-derived INTENT the digest is computed over. ALL drift-dependent
        fields (directory ``action``, image ``state``, ``changes``, ``rollback_actions``) are
        excluded, so the digest depends only on the descriptor + pins + fixed layout, never host
        state."""
        data = asdict(self)
        for key in ("changes", "rollback_actions"):
            data.pop(key, None)
        for d in data.get("directories", []):
            d.pop("action", None)
        for image in data.get("images", []):
            image.pop("state", None)
        return data

    def digest(self) -> str:
        return sha256_digest(self.intent())

    def __repr__(self) -> str:
        return f"CommissioningPlan(descriptor={self.descriptor_digest}, digest={self.digest()})"


def _dir_action(obs: DirObservation | None, uid: int, gid: int, mode: int) -> str:
    if obs is None or not obs.exists:
        return ACTION_CREATE
    if obs.owner_uid == uid and obs.owner_gid == gid and obs.mode == mode:
        return ACTION_ALREADY_CORRECT
    return ACTION_DRIFTED


def build_plan(
    *,
    descriptor: CommissioningDescriptor,
    locations: CommissioningLocations,
    facts: HostFacts,
    expected: ExpectedIdentities,
) -> CommissioningPlan:
    """Build the immutable commissioning plan (pure; no writes, no contact). Fail closed on any
    identity mismatch, an active operator, or a structural-invariant violation."""
    cp, ow, op = (
        descriptor.control_plane,
        descriptor.ordinary_worker,
        descriptor.operator_preparation,
    )

    # --- the trusted pins must themselves match the CURRENTLY-RUNNING commissioning implementation
    #     (never the sole source of truth, but a mismatch here means a stale/foreign caller) ---
    _require(expected.tool_version == TOOL_VERSION, "expected_tool_version_mismatch")
    _require(expected.contract_version == CONTRACT_VERSION, "expected_contract_version_mismatch")
    _require(
        expected.operator_registration_symbol == OPERATOR_REGISTRATION_SYMBOL,
        "operator_registration_symbol_mismatch",
    )
    _require(
        expected.entrypoint_template_digest() == entrypoint_template_digest(),
        "expected_entrypoint_template_mismatch",
    )

    # --- independent identity pins: the descriptor must MATCH the trusted expected values ---
    _require(descriptor.contract_version == expected.contract_version, "contract_version_mismatch")
    _require(
        ow.source.source_sha == expected.release_source_sha.lower(), "ordinary_source_mismatch"
    )
    _require(ow.source.source_tree_sha == expected.source_tree_sha.lower(), "source_tree_mismatch")
    if expected.parent_sha is not None:
        _require(ow.source.parent_sha == expected.parent_sha.lower(), "parent_sha_mismatch")
    # control_plane.source is bound to the SAME trusted release identity as the ordinary worker,
    # descriptor-supplied control-plane source metadata cannot drift unverified (defect #7).
    _require(
        cp.source.source_sha == expected.release_source_sha.lower(), "control_plane_source_mismatch"
    )
    _require(
        cp.source.source_tree_sha == expected.source_tree_sha.lower(),
        "control_plane_source_tree_mismatch",
    )
    if expected.parent_sha is not None:
        _require(
            cp.source.parent_sha == expected.parent_sha.lower(), "control_plane_parent_sha_mismatch"
        )
    _require(cp.image.digest == expected.control_plane_image_digest, "control_plane_image_mismatch")
    _require(ow.image.digest == expected.ordinary_worker_image_digest, "ordinary_image_mismatch")
    _require(op.image.digest == expected.operator_image_digest, "operator_image_mismatch")
    _require(ow.runtime.uid == expected.ordinary_runtime_uid, "ordinary_runtime_uid_mismatch")
    _require(ow.runtime.gid == expected.ordinary_runtime_gid, "ordinary_runtime_gid_mismatch")
    _require(op.runtime.uid == expected.operator_runtime_uid, "operator_runtime_uid_mismatch")
    _require(op.runtime.gid == expected.operator_runtime_gid, "operator_runtime_gid_mismatch")
    _require(ow.task_queue == expected.ordinary_task_queue, "ordinary_queue_mismatch")
    _require(op.task_queue == expected.operator_task_queue, "operator_queue_mismatch")
    _require(tuple(ow.health_command) == tuple(expected.ordinary_health_command), "health_mismatch")
    _require(op.task_queue != ow.task_queue, "operator_queue_not_distinct")
    _require(op.enabled is False, "operator_service_must_be_disabled")

    # --- refuse if the operator is already active, the ordinary worker is NOT running/healthy, or
    #     service state was never inspected ---
    _require(facts.service_state_inspected, "service_state_not_inspected")
    _require(not facts.operator_service_enabled, "operator_service_enabled")
    _require(not facts.operator_service_running, "operator_service_running")
    _require(not facts.operator_service_present, "operator_service_present")
    _require(facts.ordinary_worker_running, "ordinary_worker_not_running")

    # --- fixed executable-owned layout (descriptor supplies no path) ---
    operator_root = locations.operator_root
    root_obs = facts.directories.get(operator_root)
    directories = (
        PlannedDirectory(
            role=ROLE_OPERATOR_ROOT,
            path=operator_root,
            owner_uid=0,
            owner_gid=0,
            mode=OPERATOR_ROOT_MODE,
            action=_dir_action(root_obs, 0, 0, OPERATOR_ROOT_MODE),
        ),
    )
    files = tuple(
        PlannedFile(
            role=role,
            target_path=locations.resolve_operator_file(basename),
            owner_uid=0,
            owner_gid=0,
            mode=mode,
        )
        for role, basename, mode in OPERATOR_FILE_LAYOUT
    )

    # --- STRUCTURAL INVARIANT: every writable + rollback-owned target is under the operator root
    # and
    #     under no protected root; targets are unique; no file/dir role overlap. ---
    _assert_structural_invariant(locations, directories, files)

    images = (
        PlannedImage("control_plane", cp.image.digest, _state(cp.image.digest, facts)),
        PlannedImage("ordinary_worker", ow.image.digest, _state(ow.image.digest, facts)),
        PlannedImage("operator_preparation", op.image.digest, _state(op.image.digest, facts)),
    )
    services = (PlannedService("secp-operator-worker", "systemd", False, False),)

    changes: list[str] = []
    rollback_roles: list[str] = []
    for d in directories:
        if d.action == ACTION_CREATE:
            rollback_roles.append(d.role)
        if d.action != ACTION_ALREADY_CORRECT:
            changes.append("directory:" + d.action)
    for f in files:
        rollback_roles.append(f.role)
        if operator_root and f.target_path not in facts.installed_files:
            changes.append("file:create")

    evidence_preview: dict[str, object] = {
        "activation_status": "prepared",
        "operator_service_enabled": False,
        "operator_service_running": False,
        "external_contacts_performed": False,
        "workflows_submitted": False,
        "plan_execution_performed": False,
        "ordinary_task_queue": ow.task_queue,
        "operator_task_queue": op.task_queue,
    }

    return CommissioningPlan(
        contract_version=CONTRACT_VERSION,
        tool_version=TOOL_VERSION,
        descriptor_digest=descriptor_digest(descriptor),
        deployment_id=descriptor.deployment.deployment_id,
        operator_root=operator_root,
        ordinary_task_queue=ow.task_queue,
        operator_task_queue=op.task_queue,
        ordinary_worker_source_sha=ow.source.source_sha,
        source_tree_sha=ow.source.source_tree_sha,
        ordinary_runtime_uid=ow.runtime.uid,
        ordinary_runtime_gid=ow.runtime.gid,
        operator_runtime_uid=op.runtime.uid,
        operator_runtime_gid=op.runtime.gid,
        ordinary_health_command=tuple(ow.health_command),
        operator_registration_symbol=expected.operator_registration_symbol,
        entrypoint_template_digest=expected.entrypoint_template_digest(),
        directories=directories,
        files=files,
        images=images,
        services=services,
        rollback_actions=tuple(rollback_roles),
        evidence_preview=evidence_preview,
        changes=tuple(sorted(set(changes))),
    )


def _require(condition: bool, reason: str) -> None:
    if not condition:
        reject(reason)


def _state(digest: str, facts: HostFacts) -> str:
    return "present" if digest in facts.image_digests_present else "absent"


def _assert_structural_invariant(
    locations: CommissioningLocations,
    directories: tuple[PlannedDirectory, ...],
    files: tuple[PlannedFile, ...],
) -> None:
    root = locations.operator_root
    # Each directory target: the operator root itself (the only managed dir), beneath no protected.
    for d in directories:
        _require(d.path == root, "managed_directory_not_operator_root")
    file_paths = [f.target_path for f in files]
    _require(len(set(file_paths)) == len(file_paths), "duplicate_file_target")
    for f in files:
        locations.assert_writable_target(f.target_path)  # under root, not protected (raises else)
        _require(f.target_path != root, "file_collides_with_operator_root")
    # No basename collisions (the entrypoint must not collide with a reserved sibling name).
    basenames = [p.rsplit("/", 1)[-1] for p in file_paths]
    _require(len(set(basenames)) == len(basenames), "duplicate_file_basename")
