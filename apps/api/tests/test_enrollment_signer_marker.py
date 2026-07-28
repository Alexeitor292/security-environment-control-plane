"""Root-owned enrollment-signer enablement marker + the sole-prod-authority seam (2b-3b).

Proves the marker file is the SOLE positive production authority for the API signer client — an
environment variable can NOT enable it in production, and an absent / non-canonical / malformed /
schema-wrong marker seals. Off production the env flag still enables (test/dev compatibility).

The POSIX filesystem-posture gate (`_fs_safe`) requires a ROOT-owned marker, which a test tmp file
can never be; the content + seam tests therefore inject a passing `_fs_safe` (simulating the
root-owned marker the installer writes), and a dedicated POSIX-only test proves a real non-root /
absent file is rejected by the genuine gate.
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
from secp_api.enrollment_signer_marker import (
    EnrollmentSignerMarker,
    load_valid_marker,
    marker_binding_matches,
)
from secp_commissioning.canonical import canonical_json

_D = "sha256:" + "a" * 64


@pytest.fixture
def allow_fs(monkeypatch):
    """Simulate the installer's root-owned marker by making the POSIX filesystem-posture gate pass,
    so the content + seam logic is exercised (a test file can never be uid 0)."""
    monkeypatch.setattr(marker_mod, "_fs_safe", lambda path: True)


def _marker_obj(**over) -> dict:
    obj = {
        "schema": "secp.enrollment-signer-enablement/v1",
        "installation_id": "controller-abc12345",
        "release_digest": _D,
        "active_identity_row_id": "row-1",
        "activation_token": "row-1|t",
        "controller_key_id": _D,
        "broker_unit_identity": _D,
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


def _settings(*, production: bool, env_enabled: bool):
    return types.SimpleNamespace(is_production=production, enrollment_signer_enabled=env_enabled)


def test_valid_marker_loads(allow_fs, tmp_path):
    marker = load_valid_marker(path=_write(tmp_path, _marker_obj()))
    assert isinstance(marker, EnrollmentSignerMarker)
    assert marker.signer_role_name == "secp_enrollment_signer" and marker.api_uid == 10001


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

    raw = json.dumps(_marker_obj(), indent=2).encode()
    assert load_valid_marker(path=_write(tmp_path, raw)) is None


def test_wrong_schema_seals(allow_fs, tmp_path):
    assert load_valid_marker(path=_write(tmp_path, _marker_obj(schema="other/v9"))) is None


def test_extra_field_seals(allow_fs, tmp_path):
    assert load_valid_marker(path=_write(tmp_path, _marker_obj(extra=1))) is None


def test_absent_marker_seals(allow_fs, tmp_path):
    assert load_valid_marker(path=str(tmp_path / "absent")) is None


@pytest.mark.skipif(
    os.name != "posix" or getattr(os, "geteuid", lambda: 1)() == 0,
    reason="the root-owned filesystem-posture gate needs POSIX + a non-root test process",
)
def test_fs_gate_rejects_a_non_root_or_absent_marker(tmp_path):
    # the genuine gate (no injected pass): a test file is owned by the non-root runner → rejected.
    assert load_valid_marker(path=_write(tmp_path, _marker_obj())) is None
    assert load_valid_marker(path=str(tmp_path / "absent")) is None


# --- the sole-prod-authority seam -------------------------------------------------------------


def test_env_cannot_enable_the_signer_in_production(allow_fs, tmp_path):
    # production + env explicitly enabled + NO marker → still SEALED (marker is the sole authority)
    client = build_enrollment_offer_signer(
        _settings(production=True, env_enabled=True), marker_path=str(tmp_path / "absent")
    )
    assert isinstance(client, SealedEnrollmentOfferSignerClient)


def test_valid_marker_enables_in_production(allow_fs, tmp_path):
    client = build_enrollment_offer_signer(
        _settings(production=True, env_enabled=False), marker_path=_write(tmp_path, _marker_obj())
    )
    assert isinstance(client, UnixSocketEnrollmentOfferSignerClient)


def test_malformed_marker_seals_in_production(allow_fs, tmp_path):
    client = build_enrollment_offer_signer(
        _settings(production=True, env_enabled=True),
        marker_path=_write(tmp_path, _marker_obj(schema="other/v9")),
    )
    assert isinstance(client, SealedEnrollmentOfferSignerClient)


def test_non_production_env_flag_still_enables(tmp_path):
    on = build_enrollment_offer_signer(_settings(production=False, env_enabled=True))
    off = build_enrollment_offer_signer(_settings(production=False, env_enabled=False))
    assert isinstance(on, UnixSocketEnrollmentOfferSignerClient)
    assert isinstance(off, SealedEnrollmentOfferSignerClient)


def test_marker_binding_mismatch_is_detectable(allow_fs, tmp_path):
    marker = load_valid_marker(path=_write(tmp_path, _marker_obj()))
    assert marker is not None
    assert marker_binding_matches(marker, expected={"installation_id": "controller-abc12345"})
    assert not marker_binding_matches(marker, expected={"installation_id": "controller-other000"})
    assert not marker_binding_matches(marker, expected={"active_identity_row_id": "row-2"})
