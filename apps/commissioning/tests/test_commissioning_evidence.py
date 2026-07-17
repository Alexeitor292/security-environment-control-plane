"""Strict, topology-safe evidence schema (SECP-PR5C, defect #5, #9)."""

from __future__ import annotations

import json
import tempfile

import pytest
from _support import EVIDENCE_PATH, OPERATOR_ROOT, build_engine, do_install
from secp_commissioning.evidence import CommissioningError, evidence_from_dict


def _valid_evidence_dict() -> dict:
    e = build_engine(tempfile.mkdtemp())
    do_install(e, write=True, confirm=True)
    return json.loads(e.fs.safe_read(EVIDENCE_PATH, max_bytes=200000, expected_uid=0).decode())


def test_valid_evidence_roundtrips():
    data = _valid_evidence_dict()
    ev = evidence_from_dict(data)
    assert ev.activation_status == "prepared"


def test_extra_field_refused():
    data = {**_valid_evidence_dict(), "surprise": 1}
    with pytest.raises(CommissioningError):
        evidence_from_dict(data)


def test_secret_shaped_extra_field_refused():
    data = {**_valid_evidence_dict(), "vault_token": "x"}
    with pytest.raises(CommissioningError):
        evidence_from_dict(data)


def test_int_as_bool_seal_refused():
    data = _valid_evidence_dict()
    data["workflows_submitted"] = 0  # int, not a JSON bool
    with pytest.raises(CommissioningError):
        evidence_from_dict(data)


def test_string_as_bool_refused():
    data = _valid_evidence_dict()
    data["operator_service_running"] = "false"
    with pytest.raises(CommissioningError):
        evidence_from_dict(data)


def test_flipped_seal_refused():
    data = _valid_evidence_dict()
    data["workflows_submitted"] = True
    with pytest.raises(CommissioningError):
        evidence_from_dict(data)


def test_wrong_contract_version_refused():
    data = _valid_evidence_dict()
    data["contract_version"] = "secp.commissioning.descriptor/v2"
    with pytest.raises(CommissioningError):
        evidence_from_dict(data)


def test_unknown_role_refused():
    data = _valid_evidence_dict()
    data["installed_files"][0]["role"] = "not_a_role"
    with pytest.raises(CommissioningError):
        evidence_from_dict(data)


def test_duplicate_role_refused():
    data = _valid_evidence_dict()
    data["installed_files"].append(dict(data["installed_files"][0]))
    with pytest.raises(CommissioningError):
        evidence_from_dict(data)


def test_bad_digest_refused():
    data = _valid_evidence_dict()
    data["plan_digest"] = "not-a-digest"
    with pytest.raises(CommissioningError):
        evidence_from_dict(data)


def test_evidence_contains_no_raw_path_or_topology():
    data = _valid_evidence_dict()
    text = json.dumps(data)
    assert OPERATOR_ROOT not in text
    assert "registry.example" not in text
    assert "lab-01" not in text and "staging" not in text


def test_unknown_field_name_never_leaks_into_reason_code():
    data = _valid_evidence_dict()
    topo = "/srv/site-berlin/vm-42"
    data[topo] = True  # tampered extra field whose NAME is a topology string
    with pytest.raises(CommissioningError) as exc:
        evidence_from_dict(data)
    assert topo not in exc.value.reason_code
    assert exc.value.reason_code.startswith("evidence_unknown_field")


@pytest.mark.parametrize(
    "field,bad",
    [
        ("tool_version", "/opt/secp/operator/entrypoint.py"),
        ("operator_task_queue", "https://vault.internal:8200/v1/secret"),
        ("source_sha", "/etc/secp/x"),
        ("deployment_id", "site-berlin-vm-42"),
        ("recorded_at", "/srv/data"),
    ],
)
def test_scalar_fields_reject_smuggled_paths_or_urls(field, bad):
    data = _valid_evidence_dict()
    data[field] = bad
    with pytest.raises(CommissioningError):
        evidence_from_dict(data)


def test_evidence_records_created_flags():
    data = _valid_evidence_dict()
    # On a fresh install everything was created by this install.
    assert all(f["created"] is True for f in data["installed_files"])
    assert all(d["created"] is True for d in data["managed_directories"])


# --- defect #5: a PREPARED record must bind EXACTLY the reviewed role set + exact mode/version ---


def test_prepared_incomplete_role_set_refused():
    data = _valid_evidence_dict()
    data["installed_files"].pop()  # drop one required file role
    with pytest.raises(CommissioningError):
        evidence_from_dict(data)


def test_prepared_wrong_file_mode_refused():
    data = _valid_evidence_dict()
    data["installed_files"][0]["mode"] = 0o777  # not the role's exact mode
    with pytest.raises(CommissioningError):
        evidence_from_dict(data)


def test_prepared_wrong_directory_owner_refused():
    data = _valid_evidence_dict()
    data["managed_directories"][0]["owner_uid"] = 10001  # not root
    with pytest.raises(CommissioningError):
        evidence_from_dict(data)


def test_stale_tool_version_refused():
    data = _valid_evidence_dict()
    data["tool_version"] = "0.0.1"  # valid semver shape, but not the current tool version
    with pytest.raises(CommissioningError):
        evidence_from_dict(data)


def test_stale_entrypoint_template_digest_refused():
    data = _valid_evidence_dict()
    data["entrypoint_template_digest"] = "sha256:" + "0" * 64  # valid shape, wrong template
    with pytest.raises(CommissioningError):
        evidence_from_dict(data)


def test_non_distinct_queues_refused():
    data = _valid_evidence_dict()
    data["operator_task_queue"] = data["ordinary_task_queue"]
    with pytest.raises(CommissioningError):
        evidence_from_dict(data)


def test_naive_timestamp_refused():
    data = _valid_evidence_dict()
    data["recorded_at"] = "2026-07-17T00:00:00"  # matches shape but has no timezone
    with pytest.raises(CommissioningError):
        evidence_from_dict(data)


def test_impossible_timestamp_refused():
    data = _valid_evidence_dict()
    data["recorded_at"] = "2026-13-40T99:99:99+00:00"  # shape-plausible, not a real instant
    with pytest.raises(CommissioningError):
        evidence_from_dict(data)
