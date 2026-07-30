"""Root-owned enrollment-signer enablement marker READER (SECP-PR5H-B2, 2b-3b C1).

The marker file is a NECESSARY but not sufficient signal — it must also exactly match the
authoritative runtime binding (see ``test_enrollment_signer_binding``). This module proves the
reader itself: a valid marker loads; an absent / non-canonical / malformed / schema-wrong marker
seals; and on POSIX the genuine root-owned filesystem-posture gate rejects a non-root / absent file.
The gate is skipped off POSIX, so the content tests inject a passing ``_fs_safe``.
"""

from __future__ import annotations

import os
import types

import pytest
from secp_api import enrollment_signer_marker as marker_mod
from secp_api.enrollment_signer_client import (
    SealedEnrollmentOfferSignerClient,
    UnixSocketEnrollmentOfferSignerClient,
    build_enrollment_offer_signer,
)
from secp_api.enrollment_signer_marker import EnrollmentSignerMarker, load_valid_marker
from secp_commissioning.canonical import canonical_json

_D = "sha256:" + "a" * 64


@pytest.fixture
def allow_fs(monkeypatch):
    """Simulate the installer's root-owned marker by making the POSIX filesystem gate pass."""
    monkeypatch.setattr(marker_mod, "_fs_safe", lambda path: True)


def _marker_obj(**over) -> dict:
    obj = {
        "schema": "secp.enrollment-signer-enablement/v1",
        "installation_id": "controller-abc12345",
        "release_digest": _D,
        "active_identity_row_id": "row-1",
        "activation_token": "row-1|t",
        "controller_key_id": _D,
        "uds_contract_identity": "/run/secp/enrollment-signer.sock",
        "api_uid": 10001,
        "api_gid": 10001,
        "signer_role_name": "secp_enrollment_signer",
        "locator_ca_digest": _D,
        "management_identity_digest": _D,
        "bootstrap_evidence_digest": _D,
        "recorded_at": "2026-07-28T00:00:00Z",
    }
    obj.update(over)
    return obj


def _write(tmp_path, obj_or_bytes) -> str:
    p = tmp_path / "enrollment-signer.enabled"
    p.write_bytes(
        obj_or_bytes if isinstance(obj_or_bytes, bytes) else canonical_json(obj_or_bytes).encode()
    )
    return str(p)


def test_valid_marker_loads(allow_fs, tmp_path):
    marker = load_valid_marker(path=_write(tmp_path, _marker_obj()))
    assert isinstance(marker, EnrollmentSignerMarker)
    assert marker.signer_role_name == "secp_enrollment_signer" and marker.api_uid == 10001
    assert not hasattr(marker, "broker_unit_identity")  # never a decorative unvalidated field


@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema":"secp.enrollment-signer-enablement/v1"}',  # missing fields
        b"not json",
        b"",
    ],
)
def test_bad_marker_bytes_seal(allow_fs, tmp_path, raw):
    assert load_valid_marker(path=_write(tmp_path, raw)) is None


def test_non_canonical_marker_seals(allow_fs, tmp_path):
    import json

    assert (
        load_valid_marker(path=_write(tmp_path, json.dumps(_marker_obj(), indent=2).encode()))
        is None
    )


def test_wrong_schema_seals(allow_fs, tmp_path):
    assert load_valid_marker(path=_write(tmp_path, _marker_obj(schema="other/v9"))) is None


def test_extra_or_removed_field_seals(allow_fs, tmp_path):
    assert load_valid_marker(path=_write(tmp_path, _marker_obj(extra=1))) is None
    assert load_valid_marker(path=_write(tmp_path, _marker_obj(broker_unit_identity=_D))) is None


def test_absent_marker_seals(allow_fs, tmp_path):
    assert load_valid_marker(path=str(tmp_path / "absent")) is None


@pytest.mark.skipif(
    os.name != "posix" or getattr(os, "geteuid", lambda: 1)() == 0,
    reason="the root-owned filesystem-posture gate needs POSIX + a non-root test process",
)
def test_fs_gate_rejects_a_non_root_or_absent_marker(tmp_path):
    assert load_valid_marker(path=_write(tmp_path, _marker_obj())) is None
    assert load_valid_marker(path=str(tmp_path / "absent")) is None


def test_non_production_env_flag_still_enables():
    on = build_enrollment_offer_signer(
        types.SimpleNamespace(is_production=False, enrollment_signer_enabled=True)
    )
    off = build_enrollment_offer_signer(
        types.SimpleNamespace(is_production=False, enrollment_signer_enabled=False)
    )
    assert isinstance(on, UnixSocketEnrollmentOfferSignerClient)
    assert isinstance(off, SealedEnrollmentOfferSignerClient)
