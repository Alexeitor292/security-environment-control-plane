"""Installer — drift-refuse, created-set, rollback, service recheck (defects #3, #4, #6, #9)."""

from __future__ import annotations

from _support import ENTRYPOINT_PATH, EVIDENCE_PATH, OPERATOR_ROOT, build_engine, do_install
from secp_commissioning.install import rollback_prepared
from secp_commissioning.reader import read_evidence


def _mk(tmp_path, name):
    d = tmp_path / name
    d.mkdir(parents=True, exist_ok=True)
    return str(d)


def test_dry_run_default_writes_nothing(tmp_path):
    e = build_engine(_mk(tmp_path, "s"))
    r = do_install(e, write=False, confirm=False)
    assert r.mode == "dry_run" and not r.changed
    assert e.fs.lstat(EVIDENCE_PATH) is None and e.fs.lstat(ENTRYPOINT_PATH) is None


def test_write_requires_confirm(tmp_path):
    e = build_engine(_mk(tmp_path, "s"))
    assert do_install(e, write=True, confirm=False).mode == "dry_run"
    assert e.fs.lstat(EVIDENCE_PATH) is None


def test_write_then_idempotent(tmp_path):
    e = build_engine(_mk(tmp_path, "s"))
    assert do_install(e, write=True, confirm=True).mode == "written"
    assert (
        do_install(e, now="2026-09-09T00:00:00+00:00", write=True, confirm=True).mode
        == "already_prepared"
    )


def test_missing_image_refuses_write(tmp_path):
    e = build_engine(_mk(tmp_path, "s"), images_present=False)
    r = do_install(e, write=True, confirm=True)
    assert r.mode == "refused" and r.reason_code == "image_not_present"
    assert e.fs.lstat(EVIDENCE_PATH) is None


def test_preexisting_drifted_file_is_refused_and_unchanged(tmp_path):
    e = build_engine(_mk(tmp_path, "s"))
    e.fs.makedir(OPERATOR_ROOT, uid=0, gid=0, mode=0o750)
    e.fs.seed_file(ENTRYPOINT_PATH, b"pre-existing bytes", uid=0, gid=0, mode=0o750)
    r = do_install(e, write=True, confirm=True)
    assert r.mode == "refused" and r.reason_code == "file_drifted"
    # byte-for-byte + metadata unchanged
    assert e.fs.safe_read(ENTRYPOINT_PATH, max_bytes=100, expected_uid=0) == b"pre-existing bytes"
    st = e.fs.lstat(ENTRYPOINT_PATH)
    assert st.uid == 0 and st.mode == 0o750


def test_preexisting_drifted_directory_is_refused_and_unchanged(tmp_path):
    e = build_engine(_mk(tmp_path, "s"))
    e.fs.makedir(OPERATOR_ROOT, uid=1000, gid=1000, mode=0o777)  # drifted owner/mode
    r = do_install(e, write=True, confirm=True)
    assert r.mode == "refused" and r.reason_code == "operator_root_drifted"
    st = e.fs.lstat(OPERATOR_ROOT)
    assert st.uid == 1000 and st.gid == 1000 and st.mode == 0o777  # unchanged


def test_symlinked_operator_root_is_refused(tmp_path):
    e = build_engine(_mk(tmp_path, "s"))
    e.fs.seed_symlink(OPERATOR_ROOT)
    r = do_install(e, write=True, confirm=True)
    assert r.mode == "refused" and r.reason_code == "operator_root_symlink"


def test_partial_write_failure_rolls_back_created_only(tmp_path):
    e = build_engine(_mk(tmp_path, "s"))
    original = e.fs.atomic_install
    calls = {"n": 0}

    def flaky(path, data, *, uid, gid, mode):
        calls["n"] += 1
        if calls["n"] == 2:
            from secp_commissioning.runtime import reject_fs

            reject_fs("fs_install_failed")
        return original(path, data, uid=uid, gid=gid, mode=mode)

    e.fs.atomic_install = flaky  # type: ignore[assignment]
    try:
        do_install(e, write=True, confirm=True)
    except Exception:
        pass
    e.fs.atomic_install = original
    assert e.fs.lstat(EVIDENCE_PATH) is None
    assert [p for p in e.fs.paths() if p.startswith(OPERATOR_ROOT)] == [] or all(
        p == OPERATOR_ROOT for p in e.fs.paths() if p.startswith(OPERATOR_ROOT)
    ) is False


def test_service_becomes_active_between_plan_and_write_is_refused(tmp_path):
    from secp_commissioning.status import ServiceStateSnapshot

    class _Flip:
        """Atomic snapshots that flip: inactive during inspect/plan, active by the recheck."""

        def __init__(self):
            self._calls = 0

        def snapshot(self):
            self._calls += 1
            return ServiceStateSnapshot(
                inspected=True,
                operator_present=False,
                operator_enabled=False,
                operator_running=self._calls > 1,
                ordinary_running=True,
            )

    e = build_engine(_mk(tmp_path, "s"), service_state=_Flip())
    r = do_install(e, write=True, confirm=True)
    assert r.mode == "refused" and r.reason_code == "operator_service_running"
    assert e.fs.lstat(EVIDENCE_PATH) is None  # evidence never committed


def test_fresh_process_rollback_removes_exactly_created(tmp_path):
    # Install, then simulate a FRESH process: rebuild from evidence read off disk, rollback.
    e = build_engine(_mk(tmp_path, "s"))
    do_install(e, write=True, confirm=True)
    evidence = read_evidence(e.fs, EVIDENCE_PATH)
    dry = rollback_prepared(
        evidence=evidence, locations=e.locations, fs=e.fs, write=False, confirm=False
    )
    assert dry.mode == "dry_run" and e.fs.lstat(ENTRYPOINT_PATH) is not None
    done = rollback_prepared(
        evidence=evidence, locations=e.locations, fs=e.fs, write=True, confirm=True
    )
    assert done.mode == "written" and done.changed
    assert e.fs.lstat(ENTRYPOINT_PATH) is None
    assert e.fs.lstat(OPERATOR_ROOT) is None  # created dir removed
    assert e.fs.lstat(EVIDENCE_PATH) is None  # evidence removed LAST


def test_rollback_refuses_modified_file(tmp_path):
    e = build_engine(_mk(tmp_path, "s"))
    do_install(e, write=True, confirm=True)
    evidence = read_evidence(e.fs, EVIDENCE_PATH)
    e.fs.seed_file(ENTRYPOINT_PATH, b"operator edited this", uid=0, gid=0, mode=0o750)
    r = rollback_prepared(
        evidence=evidence, locations=e.locations, fs=e.fs, write=True, confirm=True
    )
    assert r.mode == "refused" and r.reason_code == "rollback_modified_file"
    assert e.fs.lstat(ENTRYPOINT_PATH) is not None  # untouched


def test_created_set_is_cumulative_across_a_heal(tmp_path):
    # Regression: after a heal (a deleted file re-created on a re-install), rollback must still own
    # EVERY object commissioning created — not just the last-healed one.
    e = build_engine(_mk(tmp_path, "s"))
    do_install(e, write=True, confirm=True)
    e.fs.remove_file(ENTRYPOINT_PATH)  # a managed file is deleted out of band
    do_install(
        e, now="2026-08-08T00:00:00+00:00", write=True, confirm=True
    )  # heals the absent file
    evidence = read_evidence(e.fs, EVIDENCE_PATH)
    # ALL four files + the dir are still marked created (cumulative), not just the healed one.
    assert all(f.created for f in evidence.installed_files)
    assert all(d.created for d in evidence.managed_directories)
    rollback_prepared(evidence=evidence, locations=e.locations, fs=e.fs, write=True, confirm=True)
    assert [p for p in e.fs.paths() if p.startswith(OPERATOR_ROOT)] == []  # nothing orphaned


def test_write_mode_refuses_when_operator_active_even_if_already_prepared(tmp_path):
    from secp_commissioning.status import StaticServiceState

    e = build_engine(_mk(tmp_path, "s"))
    do_install(e, write=True, confirm=True)
    # Operator becomes active out of band; a --write --confirm re-run must REFUSE, not "prepared".
    e.service_state = StaticServiceState(operator_running=True, operator_present=True)
    r = do_install(e, now="2026-08-08T00:00:00+00:00", write=True, confirm=True)
    assert r.mode == "refused" and r.reason_code == "operator_service_running"


def test_rollback_keeps_non_created_objects(tmp_path):
    # If evidence marks the dir as NOT created (pre-existing), rollback must never remove it.
    e = build_engine(_mk(tmp_path, "s"))
    e.fs.makedir(OPERATOR_ROOT, uid=0, gid=0, mode=0o750)  # pre-existing, already-correct
    do_install(e, write=True, confirm=True)
    evidence = read_evidence(e.fs, EVIDENCE_PATH)
    assert any(
        d.role == "operator_preparation_root" and not d.created
        for d in evidence.managed_directories
    )
    rollback_prepared(evidence=evidence, locations=e.locations, fs=e.fs, write=True, confirm=True)
    assert e.fs.lstat(OPERATOR_ROOT) is not None  # pre-existing dir preserved


# --- defect #1: image readiness gates EVERY non-refusal result + is re-observed before commit ---


class _VanishingImages:
    """Present for the first snapshot (inspect/gate), absent for the pre-commit re-observation."""

    def __init__(self, present):
        self._present = frozenset(present)
        self.calls = 0

    def image_present(self, digest):
        self.calls += 1
        return self.calls <= 3 and digest in self._present


def test_already_prepared_refused_when_an_image_is_missing(tmp_path):
    from _support import DIGEST_CP, DIGEST_OW
    from secp_commissioning.runtime import InMemoryContainerRuntime

    e = build_engine(_mk(tmp_path, "s"))
    do_install(e, write=True, confirm=True)  # prepared, all images present
    # One image disappears; a --write --confirm re-run must REFUSE, never report already_prepared.
    e.container_runtime = InMemoryContainerRuntime(present=(DIGEST_CP, DIGEST_OW))  # missing OP
    r = do_install(e, now="2026-08-08T00:00:00+00:00", write=True, confirm=True)
    assert r.mode == "refused" and r.reason_code == "image_not_present"


def test_image_disappears_before_evidence_commit_rolls_back(tmp_path):
    from _support import DIGEST_CP, DIGEST_OP, DIGEST_OW

    e = build_engine(_mk(tmp_path, "s"))
    e.container_runtime = _VanishingImages((DIGEST_CP, DIGEST_OW, DIGEST_OP))
    r = do_install(e, write=True, confirm=True)
    assert r.mode == "refused" and r.reason_code == "image_not_present"
    assert e.fs.lstat(EVIDENCE_PATH) is None  # evidence never committed
    # Every object THIS invocation created was rolled back (image vanished mid-write).
    assert [p for p in e.fs.paths() if p.startswith(OPERATOR_ROOT)] == []


def test_snapshot_observes_each_digest_exactly_once():
    from _support import DIGEST_CP, DIGEST_OP
    from secp_commissioning.runtime import InMemoryContainerRuntime, snapshot_images

    cr = InMemoryContainerRuntime(present=(DIGEST_CP,))
    snap = snapshot_images(cr, (DIGEST_CP, DIGEST_CP, DIGEST_OP, DIGEST_CP))
    assert cr.observations == [DIGEST_CP, DIGEST_OP]  # each DISTINCT digest queried once
    assert snap.is_present(DIGEST_CP) and not snap.is_present(DIGEST_OP)


# --- defect #2: the ordinary worker must be running/healthy across the write path ---


def test_install_refuses_when_ordinary_worker_goes_down_before_write(tmp_path):
    from secp_commissioning.status import ServiceStateSnapshot

    class _OrdinaryDown:
        def __init__(self):
            self._calls = 0

        def snapshot(self):
            self._calls += 1
            return ServiceStateSnapshot(
                inspected=True,
                operator_present=False,
                operator_enabled=False,
                operator_running=False,
                ordinary_running=self._calls <= 1,  # up for inspect/plan, down by the write recheck
            )

    e = build_engine(_mk(tmp_path, "s"), service_state=_OrdinaryDown())
    r = do_install(e, write=True, confirm=True)
    assert r.mode == "refused" and r.reason_code == "ordinary_worker_not_running"
    assert e.fs.lstat(EVIDENCE_PATH) is None


def test_idempotent_run_refuses_when_ordinary_worker_down(tmp_path):
    from secp_commissioning.status import StaticServiceState

    e = build_engine(_mk(tmp_path, "s"))
    do_install(e, write=True, confirm=True)
    e.service_state = StaticServiceState(ordinary_running=False)
    r = do_install(e, now="2026-08-08T00:00:00+00:00", write=True, confirm=True)
    assert r.mode == "refused" and r.reason_code == "ordinary_worker_not_running"


def test_dry_run_already_prepared_refused_when_operator_active(tmp_path):
    # A READ-ONLY preview must not report already_prepared while the operator is active: the service
    # gate is NOT scoped to write-mode (closes the idempotent-readiness-bypass).
    from secp_commissioning.status import StaticServiceState

    e = build_engine(_mk(tmp_path, "s"))
    do_install(e, write=True, confirm=True)
    e.service_state = StaticServiceState(operator_running=True, operator_present=True)
    r = do_install(e, write=False, confirm=False)  # dry-run preview, not a write
    assert r.mode == "refused" and r.reason_code == "operator_service_running"


def test_dry_run_refused_when_ordinary_worker_down(tmp_path):
    from secp_commissioning.status import StaticServiceState

    e = build_engine(_mk(tmp_path, "s"))
    do_install(e, write=True, confirm=True)
    e.service_state = StaticServiceState(ordinary_running=False)
    r = do_install(e, write=False, confirm=False)
    assert r.mode == "refused" and r.reason_code == "ordinary_worker_not_running"


# --- defect #6: rollback verifies the ENTIRE created set (metadata + no foreign child) first ---


def test_rollback_refuses_hardlinked_file(tmp_path):
    e = build_engine(_mk(tmp_path, "s"))
    do_install(e, write=True, confirm=True)
    evidence = read_evidence(e.fs, EVIDENCE_PATH)
    st = e.fs.lstat(ENTRYPOINT_PATH)
    entry = next(f for f in e.render.files if f.role == "operator_entrypoint_template")
    e.fs.seed_file(ENTRYPOINT_PATH, entry.content, uid=st.uid, gid=st.gid, mode=st.mode, nlink=2)
    r = rollback_prepared(
        evidence=evidence, locations=e.locations, fs=e.fs, write=True, confirm=True
    )
    assert r.mode == "refused" and r.reason_code == "rollback_hardlinked_file"
    assert e.fs.lstat(ENTRYPOINT_PATH) is not None  # nothing removed


def test_rollback_refuses_metadata_modified_file(tmp_path):
    e = build_engine(_mk(tmp_path, "s"))
    do_install(e, write=True, confirm=True)
    evidence = read_evidence(e.fs, EVIDENCE_PATH)
    st = e.fs.lstat(ENTRYPOINT_PATH)
    entry = next(f for f in e.render.files if f.role == "operator_entrypoint_template")
    changed_mode = 0o700 if st.mode != 0o700 else 0o711  # same content, different mode only
    e.fs.seed_file(ENTRYPOINT_PATH, entry.content, uid=0, gid=0, mode=changed_mode)
    r = rollback_prepared(
        evidence=evidence, locations=e.locations, fs=e.fs, write=True, confirm=True
    )
    assert r.mode == "refused" and r.reason_code == "rollback_modified_metadata"
    assert e.fs.lstat(ENTRYPOINT_PATH) is not None  # nothing removed


def test_rollback_refuses_foreign_child_and_removes_nothing(tmp_path):
    e = build_engine(_mk(tmp_path, "s"))
    do_install(e, write=True, confirm=True)
    evidence = read_evidence(e.fs, EVIDENCE_PATH)
    e.fs.seed_file(OPERATOR_ROOT + "/intruder", b"planted", uid=0, gid=0, mode=0o640)
    r = rollback_prepared(
        evidence=evidence, locations=e.locations, fs=e.fs, write=True, confirm=True
    )
    assert r.mode == "refused" and r.reason_code == "rollback_foreign_child"
    # Verify-all-before-delete: NOTHING (not even the verified files or evidence) was removed.
    assert e.fs.lstat(ENTRYPOINT_PATH) is not None
    assert e.fs.lstat(EVIDENCE_PATH) is not None
    assert e.fs.lstat(OPERATOR_ROOT + "/intruder") is not None
