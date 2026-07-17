"""Prepared-only installer + rollback (SECP-PR5C, ADR-023, defects #3, #4, #6).

``install-prepared`` creates the fixed operator root + installs the rendered files beneath it (via
the
symlink-safe filesystem backend), then writes the evidence record LAST. Drift policy is REFUSE,
never
repair: an ABSENT target is created; a target already present, matching this plan's content +
ownership + mode, is idempotent; any FOREIGN or DRIFTED pre-existing target is REFUSED WITHOUT
modification. Evidence records the ACTUAL transaction ownership set (which roles THIS install
created). The service/process adapter is re-checked immediately before the first write AND
immediately
before evidence is committed, so a stale ``HostFacts`` can never let evidence claim a false state.

``rollback_prepared`` removes ONLY the objects the authenticated evidence marks ``created``
(verified
by re-derived path binding + on-disk content digest), files then now-empty directories, then the
evidence record LAST. A pre-existing / modified / foreign / non-created / ordinary-worker object is
never removed. Default is DRY-RUN; a write requires ``--write --confirm``.
"""

from __future__ import annotations

from dataclasses import dataclass

from secp_commissioning import TOOL_VERSION
from secp_commissioning.canonical import canonical_json
from secp_commissioning.descriptor import CONTRACT_VERSION, CommissioningDescriptor
from secp_commissioning.errors import CommissioningError
from secp_commissioning.evidence import (
    STATUS_PREPARED,
    CommissioningEvidence,
    InstalledFileRecord,
    ManagedDirectoryRecord,
    path_binding_digest,
)
from secp_commissioning.locations import (
    OPERATOR_FILE_LAYOUT,
    ROLE_OPERATOR_ROOT,
    CommissioningLocations,
)
from secp_commissioning.plan import CommissioningPlan
from secp_commissioning.reader import evidence_exists, read_evidence
from secp_commissioning.render import RenderResult
from secp_commissioning.runtime import ContainerRuntime, FilesystemBackend, snapshot_images
from secp_commissioning.status import ServiceStateAdapter, service_state_refusal

MODE_DRY_RUN = "dry_run"
MODE_WRITTEN = "written"
MODE_ALREADY_PREPARED = "already_prepared"
MODE_REFUSED = "refused"

_ROLE_BASENAME = {role: basename for role, basename, _m in OPERATOR_FILE_LAYOUT}


@dataclass(frozen=True)
class PlannedOp:
    kind: str
    target: str  # role token (never a raw path)
    detail: str


@dataclass(frozen=True)
class InstallReport:
    mode: str
    plan_digest: str
    operations: tuple[PlannedOp, ...]
    changed: bool
    evidence_digest: str | None = None
    reason_code: str | None = None


def _refused(plan_digest: str, reason: str, ops: tuple[PlannedOp, ...] = ()) -> InstallReport:
    return InstallReport(MODE_REFUSED, plan_digest, ops, False, reason_code=reason)


def _load_existing(fs: FilesystemBackend, locations: CommissioningLocations):  # noqa: ANN201
    if not evidence_exists(fs, locations.evidence_path):
        return None
    return read_evidence(fs, locations.evidence_path)


def _recheck_service_state(service_state: ServiceStateAdapter) -> str | None:
    # ONE atomic observation (defect #2): the operator must be inspected + disabled + not-running +
    # absent, and the ordinary worker running/healthy. A per-method re-read could see a mixed
    # mix across a single check; the snapshot cannot.
    return service_state_refusal(service_state.snapshot())


def _classify_dir(plan: CommissioningPlan, fs: FilesystemBackend) -> tuple[str, str | None]:
    d = plan.directories[0]
    st = fs.lstat(d.path)
    if st is None:
        return "absent", None
    if st.is_symlink:
        return "foreign", "operator_root_symlink"
    if not st.is_dir:
        return "foreign", "operator_root_not_directory"
    if st.uid == d.owner_uid and st.gid == d.owner_gid and st.mode == d.mode:
        return "already_correct", None
    return "drifted", "operator_root_drifted"


def _classify_file(f, fs: FilesystemBackend) -> tuple[str, str | None]:  # noqa: ANN001
    st = fs.lstat(f.target_path)
    if st is None:
        return "absent", None
    if st.is_symlink:
        return "foreign", "file_symlink"
    if not st.is_regular:
        return "foreign", "file_not_regular"
    if (
        st.uid == f.owner_uid
        and st.gid == f.owner_gid
        and st.mode == f.mode
        and fs.sha256(f.target_path) == f.sha256
    ):
        return "already_correct", None
    return "drifted", "file_drifted"


def install_prepared(
    *,
    descriptor: CommissioningDescriptor,
    plan: CommissioningPlan,
    render: RenderResult,
    locations: CommissioningLocations,
    fs: FilesystemBackend,
    container_runtime: ContainerRuntime,
    service_state: ServiceStateAdapter,
    now: str,
    write: bool = False,
    confirm: bool = False,
) -> InstallReport:
    if render.plan_digest != plan.digest():
        return _refused(plan.digest(), "render_plan_digest_mismatch")
    plan_digest = plan.digest()

    existing = _load_existing(fs, locations)
    if existing is not None and existing.plan_digest != plan_digest:
        return _refused(plan_digest, "plan_digest_changed_refusing_overwrite")

    # ONE image-presence snapshot: each of the three exact image digests is observed EXACTLY once
    # (defect #1), so a stateful runtime cannot answer differently for the ops list vs the gate.
    image_digests = tuple(image.digest for image in sorted(plan.images, key=lambda i: i.section))
    images = snapshot_images(container_runtime, image_digests)
    ops: list[PlannedOp] = []
    for image in sorted(plan.images, key=lambda i: i.section):
        present = images.is_present(image.digest)
        ops.append(PlannedOp("verify_image", image.section, "present" if present else "absent"))
    absent_images = [i.section for i in plan.images if not images.is_present(i.digest)]

    dir_state, dir_reason = _classify_dir(plan, fs)
    if dir_reason:
        return _refused(plan_digest, dir_reason, tuple(ops))
    ops.append(PlannedOp("makedir", ROLE_OPERATOR_ROOT, dir_state))

    file_states: dict[str, str] = {}
    for f in sorted(render.files, key=lambda x: x.role):
        state, reason = _classify_file(f, fs)
        if reason:
            return _refused(plan_digest, reason, tuple(ops))
        file_states[f.role] = state
        ops.append(PlannedOp("install_file", f.role, state))

    absent_dir = dir_state == "absent"
    absent_files = [f for f in render.files if file_states[f.role] == "absent"]
    would_change = absent_dir or bool(absent_files)

    # IMAGE READINESS GATES EVERY NON-REFUSAL RESULT (defect #1): a missing image is refused BEFORE
    # any already_prepared / dry_run / written outcome, so install never reports a prepared/idem
    # state while one of the three exact image digests is absent.
    if absent_images:
        return _refused(plan_digest, "image_not_present", tuple(ops))

    # SERVICE READINESS GATES EVERY NON-REFUSAL RESULT TOO (defects #1/#2): the recheck is NOT bound
    # to write-mode. A read-only preview that reports already_prepared / dry_run — or a write —
    # asserts the system IS in a safe prepared posture, so an active operator (enabled/running/
    # present), an uninspected adapter, or a downed ordinary worker refuses in EVERY mode. This
    # closes the idempotent-readiness-bypass where an already_prepared fast path skipped the gate.
    reason = _recheck_service_state(service_state)
    if reason:
        return _refused(plan_digest, reason, tuple(ops))

    if existing is not None and not would_change:
        return InstallReport(
            MODE_ALREADY_PREPARED, plan_digest, tuple(ops), False, evidence_digest=existing.digest()
        )
    if not (write and confirm):
        return InstallReport(MODE_DRY_RUN, plan_digest, tuple(ops), False)

    d = plan.directories[0]
    created_files: list[str] = []
    created_dir = False
    try:
        if absent_dir:
            fs.makedir(d.path, uid=d.owner_uid, gid=d.owner_gid, mode=d.mode)
            created_dir = True
        for f in absent_files:
            fs.atomic_install(
                f.target_path, f.content, uid=f.owner_uid, gid=f.owner_gid, mode=f.mode
            )
            created_files.append(f.target_path)
    except CommissioningError:
        _rollback_created(fs, created_files, [d.path] if created_dir else [])
        raise

    evidence = _build_evidence(
        descriptor=descriptor,
        plan=plan,
        render=render,
        locations=locations,
        created_file_roles={f.role for f in absent_files},
        created_dir=created_dir,
        now=now,
        existing=existing,
    )
    reason = _recheck_service_state(service_state)  # independent recheck before COMMITTING evidence
    if reason:
        _rollback_created(fs, created_files, [d.path] if created_dir else [])
        return _refused(plan_digest, reason, tuple(ops))
    # Re-observe image presence immediately before committing evidence (defect #1): if an image
    # DISAPPEARED after the files were written but before the evidence commit, roll back exactly the
    # objects THIS invocation created and refuse — evidence must never claim prepared over an image
    # that is no longer present.
    recheck_images = snapshot_images(container_runtime, image_digests)
    if any(not recheck_images.is_present(digest) for digest in image_digests):
        _rollback_created(fs, created_files, [d.path] if created_dir else [])
        return _refused(plan_digest, "image_not_present", tuple(ops))
    try:
        fs.atomic_install(
            locations.evidence_path,
            canonical_json(evidence.canonical()).encode("utf-8"),
            uid=0,
            gid=0,
            mode=0o640,
        )
    except CommissioningError:
        _rollback_created(fs, created_files, [d.path] if created_dir else [])
        raise
    return InstallReport(
        MODE_WRITTEN, plan_digest, tuple(ops), True, evidence_digest=evidence.digest()
    )


def _build_evidence(
    *,
    descriptor: CommissioningDescriptor,
    plan: CommissioningPlan,
    render: RenderResult,
    locations: CommissioningLocations,
    created_file_roles: set[str],
    created_dir: bool,
    now: str,
    existing: CommissioningEvidence | None,
) -> CommissioningEvidence:
    ow = descriptor.ordinary_worker
    op = descriptor.operator_preparation
    cp = descriptor.control_plane
    # The created set is CUMULATIVE: once commissioning created an object it stays
    # commissioning-owned
    # across re-installs (an idempotent re-heal of a deleted file must not orphan the objects a
    # prior
    # install created). An object is created==True if a PRIOR evidence marked it created OR this run
    # created it.
    prior_files = {r.role for r in existing.installed_files if r.created} if existing else set()
    prior_dir_created = (
        any(d.role == ROLE_OPERATOR_ROOT and d.created for d in existing.managed_directories)
        if existing
        else False
    )
    file_records = list(
        InstalledFileRecord(
            role=f.role,
            sha256=f.sha256,
            path_binding=path_binding_digest(f.role, f.target_path),
            owner_uid=f.owner_uid,
            owner_gid=f.owner_gid,
            mode=f.mode,
            created=f.role in created_file_roles or f.role in prior_files,
        )
        for f in sorted(render.files, key=lambda x: x.role)
    )
    dir_records = [
        ManagedDirectoryRecord(
            role=ROLE_OPERATOR_ROOT,
            path_binding=path_binding_digest(ROLE_OPERATOR_ROOT, locations.operator_root),
            owner_uid=0,
            owner_gid=0,
            mode=plan.directories[0].mode,
            created=created_dir or prior_dir_created,
        ),
    ]
    return CommissioningEvidence(
        contract_version=CONTRACT_VERSION,
        tool_version=TOOL_VERSION,
        activation_status=STATUS_PREPARED,
        deployment_id=descriptor.deployment.deployment_id,
        source_sha=ow.source.source_sha,
        source_tree_sha=ow.source.source_tree_sha,
        control_plane_image_digest=cp.image.digest,
        ordinary_worker_image_digest=ow.image.digest,
        operator_image_digest=op.image.digest,
        descriptor_digest=plan.descriptor_digest,
        plan_digest=plan.digest(),
        render_manifest_digest=render.manifest_digest(),
        entrypoint_template_digest=plan.entrypoint_template_digest,
        installed_files=file_records,
        managed_directories=dir_records,
        ordinary_task_queue=ow.task_queue,
        operator_task_queue=op.task_queue,
        operator_service_enabled=False,
        operator_service_running=False,
        external_contacts_performed=False,
        workflows_submitted=False,
        plan_execution_performed=False,
        recorded_at=now,
    )


def _rollback_created(fs: FilesystemBackend, files: list[str], dirs: list[str]) -> None:
    for path in reversed(files):
        fs.remove_file(path)
    for path in reversed(dirs):
        fs.remove_dir(path)


# --------------------------------------------------------------------------- rollback-prepared


@dataclass(frozen=True)
class RollbackOp:
    kind: str
    target: str  # role token
    detail: str


@dataclass(frozen=True)
class RollbackReport:
    mode: str
    operations: tuple[RollbackOp, ...]
    changed: bool
    reason_code: str | None = None


def rollback_prepared(
    *,
    evidence: CommissioningEvidence,
    locations: CommissioningLocations,
    fs: FilesystemBackend,
    write: bool = False,
    confirm: bool = False,
) -> RollbackReport:
    """Remove ONLY the objects evidence marks created, files then dirs, evidence LAST.

    The ENTIRE created set is verified BEFORE the first object is removed (defect #6). Per created
    file: exact role/path binding, exists-or-documented-absent, regular file, ``nlink==1``, exact
    recorded uid/gid/mode, exact content digest. Per created directory: exact role/path binding, a
    real non-symlink directory, exact recorded uid/gid/mode, and its immediate entries are safely
    enumerated to prove there is NO foreign child (every child belongs to the verified removal set).
    A hardlinked, metadata-modified, or foreign-child-bearing object aborts the WHOLE rollback with
    nothing removed."""
    ops: list[RollbackOp] = []
    file_removals: list[str] = []
    created_file_basenames: set[str] = set()
    # 1) Verify EVERY created FILE before removing anything (all-or-nothing safety check).
    for rec in sorted(evidence.installed_files, key=lambda r: r.role):
        basename = _ROLE_BASENAME.get(rec.role)
        if basename is None:
            return RollbackReport(MODE_REFUSED, tuple(ops), False, "rollback_unknown_role")
        path = locations.resolve_operator_file(basename)
        if path_binding_digest(rec.role, path) != rec.path_binding:
            return RollbackReport(MODE_REFUSED, tuple(ops), False, "rollback_path_binding_mismatch")
        if not rec.created:
            ops.append(RollbackOp("keep_file", rec.role, "not_created_by_this_install"))
            continue
        created_file_basenames.add(basename)
        st = fs.lstat(path)
        if st is None:
            ops.append(RollbackOp("remove_file", rec.role, "absent"))  # documented absent
            continue
        if not st.is_regular:
            return RollbackReport(MODE_REFUSED, tuple(ops), False, "rollback_foreign_object")
        if st.nlink != 1:
            return RollbackReport(MODE_REFUSED, tuple(ops), False, "rollback_hardlinked_file")
        if st.uid != rec.owner_uid or st.gid != rec.owner_gid or st.mode != rec.mode:
            return RollbackReport(MODE_REFUSED, tuple(ops), False, "rollback_modified_metadata")
        if fs.sha256(path) != rec.sha256:
            return RollbackReport(MODE_REFUSED, tuple(ops), False, "rollback_modified_file")
        ops.append(RollbackOp("remove_file", rec.role, "planned"))
        file_removals.append(path)

    # 2) Verify EVERY created DIRECTORY (metadata + no foreign children) before removing anything.
    dir_removals: list[str] = []
    for drec in sorted(evidence.managed_directories, key=lambda r: r.role):
        if drec.role != ROLE_OPERATOR_ROOT:
            return RollbackReport(MODE_REFUSED, tuple(ops), False, "rollback_unknown_dir_role")
        path = locations.operator_root
        if path_binding_digest(drec.role, path) != drec.path_binding:
            return RollbackReport(MODE_REFUSED, tuple(ops), False, "rollback_path_binding_mismatch")
        if not drec.created:
            ops.append(RollbackOp("keep_directory", drec.role, "not_created_by_this_install"))
            continue
        st = fs.lstat(path)
        if st is None:
            ops.append(RollbackOp("remove_directory", drec.role, "absent"))  # documented absent
            continue
        if st.is_symlink or not st.is_dir:
            return RollbackReport(MODE_REFUSED, tuple(ops), False, "rollback_directory_foreign")
        if st.uid != drec.owner_uid or st.gid != drec.owner_gid or st.mode != drec.mode:
            return RollbackReport(MODE_REFUSED, tuple(ops), False, "rollback_directory_modified")
        children = fs.list_dir(path)
        if children is None:
            return RollbackReport(MODE_REFUSED, tuple(ops), False, "rollback_directory_unreadable")
        # Prove NO foreign child: every immediate entry must belong to the verified created set.
        if any(child not in created_file_basenames for child in children):
            return RollbackReport(MODE_REFUSED, tuple(ops), False, "rollback_foreign_child")
        ops.append(RollbackOp("remove_directory", drec.role, "planned"))
        dir_removals.append(path)

    if not (write and confirm):
        return RollbackReport(MODE_DRY_RUN, tuple(ops), False)

    # 3) Only AFTER the complete preflight does any removal begin: files, then now-empty dirs.
    for path in file_removals:
        fs.remove_file(path)
    for path in dir_removals:
        st = fs.lstat(path)
        if st is not None and st.is_dir:
            fs.remove_dir(path)  # refuses closed if a foreign child appeared post-preflight
    # Evidence is removed LAST — if any removal above failed, evidence remains so status reports
    # drift/invalid rather than a false "absent".
    fs.remove_file(locations.evidence_path)
    return RollbackReport(MODE_WRITTEN, tuple(ops), bool(file_removals or dir_removals))
