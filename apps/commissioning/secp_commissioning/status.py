"""Machine-readable status + host/service inspection (SECP-PR5C, defects #2, #5, #6, #7, #9).

``status`` independently RE-VERIFIES the prepared state and never infers readiness from config
presence. It reads the evidence through the hardened filesystem reader, takes ONE atomic service-
state snapshot + ONE image-presence snapshot, then requires: the operator is inspected + disabled +
not-running + absent as a process; the exact reviewed ordinary worker is running/healthy; the
evidence carries EXACTLY the expected role set with the exact per-role ownership/mode; the evidence
implementation identities (tool version, entrypoint-template digest, contract version) equal the
CURRENT running commissioning implementation; the ordinary/operator queues are distinct; and every
installed file + managed directory + expected image matches. States: ``absent | invalid | drifted |
prepared | activation_not_supported``.

The service adapter returns ONE immutable :class:`ServiceStateSnapshot` per observation (never many
independently-evaluated methods that can disagree). The default :class:`UnavailableServiceState`
fails closed: ``inspected`` is False and it asserts nothing true about the operator being disabled.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from secp_commissioning import TOOL_VERSION
from secp_commissioning.descriptor import CONTRACT_VERSION, CommissioningDescriptor
from secp_commissioning.evidence import STATUS_PREPARED, path_binding_digest
from secp_commissioning.locations import (
    OPERATOR_FILE_LAYOUT,
    OPERATOR_ROOT_MODE,
    ROLE_OPERATOR_ROOT,
    ROLE_OPERATOR_SERVICE_DISABLED,
    CommissioningLocations,
)
from secp_commissioning.operator_template import entrypoint_template_digest
from secp_commissioning.plan import DirObservation, HostFacts
from secp_commissioning.reader import evidence_exists, read_evidence
from secp_commissioning.runtime import (
    ContainerRuntime,
    FilesystemBackend,
    FilesystemError,
    snapshot_images,
)

STATUS_ABSENT = "absent"
STATUS_INVALID = "invalid"
STATUS_DRIFTED = "drifted"
STATUS_PREPARED_OK = "prepared"
STATUS_ACTIVATION_NOT_SUPPORTED = "activation_not_supported"

_ROLE_BASENAME = {role: basename for role, basename, _m in OPERATOR_FILE_LAYOUT}
_ROLE_MODE = {role: mode for role, _b, mode in OPERATOR_FILE_LAYOUT}
EXPECTED_FILE_ROLES = frozenset(_ROLE_BASENAME)
EXPECTED_DIR_ROLES = frozenset({ROLE_OPERATOR_ROOT})


@dataclass(frozen=True)
class ServiceStateSnapshot:
    """One atomic observation of operator + ordinary-worker service/process state."""

    inspected: bool
    operator_present: bool
    operator_enabled: bool
    operator_running: bool
    ordinary_running: bool


class ServiceStateAdapter(Protocol):
    def snapshot(self) -> ServiceStateSnapshot: ...


class UnavailableServiceState:
    """Shipped default: inspection is UNAVAILABLE (``inspected=False``) and it asserts nothing true
    about the operator being disabled or the ordinary worker running. Planning + install fail closed
    (``service_state_not_inspected``) until a real adapter is injected."""

    def snapshot(self) -> ServiceStateSnapshot:
        return ServiceStateSnapshot(
            inspected=False,
            operator_present=True,
            operator_enabled=True,
            operator_running=True,
            ordinary_running=False,
        )


@dataclass(frozen=True)
class StaticServiceState:
    """A test/deployment adapter returning a fixed snapshot."""

    operator_present: bool = False
    operator_enabled: bool = False
    operator_running: bool = False
    ordinary_running: bool = True
    was_inspected: bool = True

    def snapshot(self) -> ServiceStateSnapshot:
        return ServiceStateSnapshot(
            inspected=self.was_inspected,
            operator_present=self.operator_present,
            operator_enabled=self.operator_enabled,
            operator_running=self.operator_running,
            ordinary_running=self.ordinary_running,
        )


def service_state_refusal(snap: ServiceStateSnapshot) -> str | None:
    """The bounded refusal reason for a service snapshot, or None if it is prepared-safe: the
    operator must be inspected + disabled + not-running + absent, and the ordinary worker up."""
    if not snap.inspected:
        return "service_state_not_inspected"
    if snap.operator_enabled:
        return "operator_service_enabled"
    if snap.operator_running:
        return "operator_service_running"
    if snap.operator_present:
        return "operator_service_present"
    if not snap.ordinary_running:
        return "ordinary_worker_not_running"
    return None


@dataclass(frozen=True)
class StatusReport:
    state: str
    plan_digest: str | None
    evidence_digest: str | None
    findings: tuple[str, ...]

    def canonical(self) -> dict:
        return {
            "state": self.state,
            "plan_digest": self.plan_digest,
            "evidence_digest": self.evidence_digest,
            "findings": list(self.findings),
        }


def _invalid(evidence, finding: str) -> StatusReport:  # noqa: ANN001
    return StatusReport(
        STATUS_INVALID,
        evidence.plan_digest if evidence else None,
        evidence.digest() if evidence else None,
        (finding,),
    )


def commissioning_status(
    *,
    locations: CommissioningLocations,
    fs: FilesystemBackend,
    container_runtime: ContainerRuntime,
    service_state: ServiceStateAdapter,
) -> StatusReport:
    if not evidence_exists(fs, locations.evidence_path):
        return StatusReport(STATUS_ABSENT, None, None, ("evidence_absent",))
    try:
        evidence = read_evidence(fs, locations.evidence_path)
    except Exception:  # a malformed/tampered/unreadable evidence record fails closed to invalid
        return StatusReport(STATUS_INVALID, None, None, ("evidence_unreadable",))

    if evidence.activation_status != STATUS_PREPARED:
        return _invalid(evidence, "status_not_prepared")

    # --- implementation-identity + completeness invariants (stale/incomplete record is INVALID) ---
    if evidence.tool_version != TOOL_VERSION:
        return _invalid(evidence, "stale_tool_version")
    if evidence.entrypoint_template_digest != entrypoint_template_digest():
        return _invalid(evidence, "stale_entrypoint_template")
    if evidence.contract_version != CONTRACT_VERSION:
        return _invalid(evidence, "stale_contract_version")
    if evidence.ordinary_task_queue == evidence.operator_task_queue:
        return _invalid(evidence, "queues_not_distinct")
    file_roles = {r.role for r in evidence.installed_files}
    dir_roles = {d.role for d in evidence.managed_directories}
    if file_roles != EXPECTED_FILE_ROLES or dir_roles != EXPECTED_DIR_ROLES:
        return _invalid(evidence, "incomplete_evidence_role_set")

    # --- one atomic service-state snapshot: operator disabled + ordinary worker running/healthy ---
    snap = service_state.snapshot()
    reason = service_state_refusal(snap)
    if reason:
        return _invalid(evidence, reason)

    findings: list[str] = []
    drifted = False
    images = snapshot_images(
        container_runtime,
        (
            evidence.control_plane_image_digest,
            evidence.ordinary_worker_image_digest,
            evidence.operator_image_digest,
        ),
    )

    disabled_unit_seen = False
    for rec in sorted(evidence.installed_files, key=lambda r: r.role):
        basename = _ROLE_BASENAME.get(rec.role)
        if basename is None:
            findings.append("unknown_file_role")
            drifted = True
            continue
        path = locations.resolve_operator_file(basename)
        if path_binding_digest(rec.role, path) != rec.path_binding:
            findings.append("path_binding_mismatch")
            drifted = True
            continue
        if rec.mode != _ROLE_MODE.get(rec.role) or rec.owner_uid != 0 or rec.owner_gid != 0:
            findings.append("recorded_mode_mismatch")
            drifted = True
        if rec.role == ROLE_OPERATOR_SERVICE_DISABLED:
            disabled_unit_seen = True
        st = fs.lstat(path)
        if st is None or not st.is_regular:
            findings.append("file_missing")
            drifted = True
            continue
        if st.uid != rec.owner_uid or st.gid != rec.owner_gid or st.mode != rec.mode:
            findings.append("file_ownership_mode_drift")
            drifted = True
        if st.nlink != 1:
            findings.append("file_hardlinked")
            drifted = True
        # An unsafe ancestor (symlink / non-root-owned / group-other-writable) makes the content
        # read refuse on the hardened backend — status FAILS CLOSED to drift instead of raising, so
        # a tampered tree can never leave status reporting 'prepared'.
        try:
            content_digest = fs.sha256(path)
        except FilesystemError:
            findings.append("file_unreadable")
            drifted = True
        else:
            if content_digest != rec.sha256:
                findings.append("file_digest_mismatch")
                drifted = True
    if not disabled_unit_seen:
        findings.append("disabled_service_definition_absent")
        drifted = True

    for drec in sorted(evidence.managed_directories, key=lambda r: r.role):
        if drec.role != ROLE_OPERATOR_ROOT:
            findings.append("unknown_directory_role")
            drifted = True
            continue
        path = locations.operator_root
        if path_binding_digest(drec.role, path) != drec.path_binding:
            findings.append("path_binding_mismatch")
            drifted = True
            continue
        if drec.mode != OPERATOR_ROOT_MODE or drec.owner_uid != 0 or drec.owner_gid != 0:
            findings.append("recorded_directory_mode_mismatch")
            drifted = True
        st = fs.lstat(path)
        if st is None or not st.is_dir:
            findings.append("directory_missing")
            drifted = True
            continue
        if st.uid != drec.owner_uid or st.gid != drec.owner_gid or st.mode != drec.mode:
            findings.append("directory_ownership_mode_drift")
            drifted = True

    for digest in (
        evidence.control_plane_image_digest,
        evidence.ordinary_worker_image_digest,
        evidence.operator_image_digest,
    ):
        if not images.is_present(digest):
            findings.append("image_absent")
            drifted = True

    state = STATUS_DRIFTED if drifted else STATUS_PREPARED_OK
    return StatusReport(
        state=state,
        plan_digest=evidence.plan_digest,
        evidence_digest=evidence.digest(),
        findings=tuple(sorted(set(findings))) if findings else ("verified",),
    )


def activation_status_unsupported() -> StatusReport:
    return StatusReport(
        STATUS_ACTIVATION_NOT_SUPPORTED, None, None, ("no_activate_command_in_this_milestone",)
    )


def inspect_host(
    *,
    descriptor: CommissioningDescriptor,
    locations: CommissioningLocations,
    fs: FilesystemBackend,
    container_runtime: ContainerRuntime,
    service_state: ServiceStateAdapter,
) -> HostFacts:
    """Gather injected host facts for the plan engine (read-only; no writes, no network). Takes ONE
    atomic service snapshot + ONE image snapshot."""
    snap = service_state.snapshot()
    root = locations.operator_root
    st = fs.lstat(root)
    directories = {
        root: DirObservation(exists=False)
        if st is None
        else DirObservation(exists=st.is_dir, owner_uid=st.uid, owner_gid=st.gid, mode=st.mode)
    }
    digests = tuple(
        img.digest
        for img in (
            descriptor.control_plane.image,
            descriptor.ordinary_worker.image,
            descriptor.operator_preparation.image,
        )
    )
    images = snapshot_images(container_runtime, digests)
    installed: dict[str, str] = {}
    for _role, basename, _m in OPERATOR_FILE_LAYOUT:
        path = locations.resolve_operator_file(basename)
        fst = fs.lstat(path)
        if fst is not None and fst.is_regular:
            installed[path] = fs.sha256(path)
    return HostFacts(
        directories=directories,
        image_digests_present=tuple(sorted(d for d in set(digests) if images.is_present(d))),
        operator_service_present=snap.operator_present,
        operator_service_enabled=snap.operator_enabled,
        operator_service_running=snap.operator_running,
        ordinary_worker_running=snap.ordinary_running,
        service_state_inspected=snap.inspected,
        installed_files=installed,
    )
