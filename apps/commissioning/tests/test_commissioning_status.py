"""Status — independent re-verification, service honesty, topology safety (defect #6, #9)."""

from __future__ import annotations

import json

from _support import ENTRYPOINT_PATH, EVIDENCE_PATH, OPERATOR_ROOT, build_engine, do_install
from secp_commissioning.runtime import InMemoryContainerRuntime
from secp_commissioning.status import StaticServiceState, commissioning_status


def _mk(tmp_path, name):
    d = tmp_path / name
    d.mkdir(parents=True, exist_ok=True)
    return str(d)


def _status(e, service_state=None, container_runtime=None):
    return commissioning_status(
        locations=e.locations,
        fs=e.fs,
        container_runtime=container_runtime or e.container_runtime,
        service_state=service_state or e.service_state,
    )


def test_absent_before_install(tmp_path):
    e = build_engine(_mk(tmp_path, "s"))
    assert _status(e).state == "absent"


def test_prepared_after_install(tmp_path):
    e = build_engine(_mk(tmp_path, "s"))
    do_install(e, write=True, confirm=True)
    r = _status(e)
    assert r.state == "prepared" and r.evidence_digest is not None


def test_drifted_when_file_tampered(tmp_path):
    e = build_engine(_mk(tmp_path, "s"))
    do_install(e, write=True, confirm=True)
    e.fs.seed_file(ENTRYPOINT_PATH, b"tampered", uid=0, gid=0, mode=0o750)
    assert _status(e).state == "drifted"


def test_drifted_when_directory_mode_changes(tmp_path):
    e = build_engine(_mk(tmp_path, "s"))
    do_install(e, write=True, confirm=True)
    e.fs.seed_dir(OPERATOR_ROOT, uid=10001, gid=10001, mode=0o777)
    r = _status(e)
    assert r.state == "drifted" and "directory_ownership_mode_drift" in r.findings


def test_drifted_when_file_world_writable_does_not_raise(tmp_path):
    # Regression: a permission-drifted (world-writable) installed file is classified 'drifted' via
    # lstat — fs.sha256 must not raise (backend contract parity), so status returns a proper state.
    e = build_engine(_mk(tmp_path, "s"))
    do_install(e, write=True, confirm=True)
    e.fs.seed_file(ENTRYPOINT_PATH, e.render.files[0].content, uid=0, gid=0, mode=0o646)
    r = _status(e)
    assert r.state == "drifted" and "file_ownership_mode_drift" in r.findings


def test_drifted_when_file_hardlinked(tmp_path):
    from secp_commissioning.reader import read_evidence

    e = build_engine(_mk(tmp_path, "s"))
    do_install(e, write=True, confirm=True)
    read_evidence(e.fs, EVIDENCE_PATH)  # confirms it is loadable
    # Re-seed the same content/owner/mode but hardlinked (nlink=2).
    st = e.fs.lstat(ENTRYPOINT_PATH)
    e.fs.seed_file(
        ENTRYPOINT_PATH, e.render.files[2].content, uid=st.uid, gid=st.gid, mode=st.mode, nlink=2
    )
    r = _status(e)
    assert r.state == "drifted" and "file_hardlinked" in r.findings


def test_drifted_when_image_missing(tmp_path):
    e = build_engine(_mk(tmp_path, "s"))
    do_install(e, write=True, confirm=True)
    assert _status(e, container_runtime=InMemoryContainerRuntime(present=())).state == "drifted"


def test_invalid_when_operator_running(tmp_path):
    e = build_engine(_mk(tmp_path, "s"))
    do_install(e, write=True, confirm=True)
    r = _status(e, service_state=StaticServiceState(operator_running=True))
    assert r.state == "invalid" and "operator_service_running" in r.findings


def test_invalid_when_service_not_inspected(tmp_path):
    e = build_engine(_mk(tmp_path, "s"))
    do_install(e, write=True, confirm=True)
    r = _status(e, service_state=StaticServiceState(was_inspected=False))
    assert r.state == "invalid" and "service_state_not_inspected" in r.findings


def test_invalid_when_ordinary_worker_down(tmp_path):
    e = build_engine(_mk(tmp_path, "s"))
    do_install(e, write=True, confirm=True)
    r = _status(e, service_state=StaticServiceState(ordinary_running=False))
    assert r.state == "invalid" and "ordinary_worker_not_running" in r.findings


def test_invalid_when_evidence_tool_version_stale(tmp_path):
    # A prepared record built by a DIFFERENT tool version can no longer report 'prepared'.
    e = build_engine(_mk(tmp_path, "s"))
    do_install(e, write=True, confirm=True)
    data = json.loads(e.fs.safe_read(EVIDENCE_PATH, max_bytes=200000, expected_uid=0).decode())
    data["tool_version"] = "0.0.1"
    e.fs.seed_file(EVIDENCE_PATH, json.dumps(data).encode(), uid=0, gid=0, mode=0o640)
    assert _status(e).state == "invalid"


def test_never_infers_from_config_presence(tmp_path):
    e = build_engine(_mk(tmp_path, "s"))
    assert _status(e).state == "absent"  # descriptor/plan exist but nothing installed


def test_invalid_when_evidence_seal_flipped_on_disk(tmp_path):
    e = build_engine(_mk(tmp_path, "s"))
    do_install(e, write=True, confirm=True)
    data = json.loads(e.fs.safe_read(EVIDENCE_PATH, max_bytes=200000, expected_uid=0).decode())
    data["workflows_submitted"] = True
    e.fs.seed_file(EVIDENCE_PATH, json.dumps(data).encode(), uid=0, gid=0, mode=0o640)
    assert _status(e).state == "invalid"


def test_evidence_repr_is_redacted(tmp_path):
    from secp_commissioning.reader import read_evidence

    e = build_engine(_mk(tmp_path, "s"))
    do_install(e, write=True, confirm=True)
    text = repr(read_evidence(e.fs, EVIDENCE_PATH))
    assert "entrypoint.py" not in text and "secp_worker" not in text
    assert "status=prepared" in text
