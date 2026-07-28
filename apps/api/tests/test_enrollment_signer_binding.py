"""Authoritative enrollment-signer runtime binding + the sole-prod-authority seam (SECP-PR5H-B2 C1).

The production signer client enables ONLY when the root-owned marker's COMPLETE binding exactly
matches the authoritative :class:`EnrollmentSignerRuntimeBinding` built from the verified single
ACTIVE identity + the process euid/egid + the fixed role/UDS contracts + the independently-read CA
bundle.
Proves: a valid marker + matching binding enables; every missing / ambiguous / unverified / stale /
mismatched fact seals; and the environment flag can never bypass a mismatch in production.
"""

from __future__ import annotations

import hashlib
import types

import pytest
from secp_api import enrollment_signer_binding as bmod
from secp_api.controller_identity_dev import build_test_verified_controller_identity
from secp_api.controller_identity_models import ControllerEnrollmentIdentity
from secp_api.db import get_sessionmaker
from secp_api.enrollment_signer_binding import (
    EnrollmentSignerRuntimeBinding,
    build_runtime_binding,
    marker_matches_binding,
)
from secp_api.enrollment_signer_client import (
    SealedEnrollmentOfferSignerClient,
    UnixSocketEnrollmentOfferSignerClient,
    build_enrollment_offer_signer,
)
from secp_api.enrollment_signer_marker import load_valid_marker
from secp_api.services.controller_identity import activate_controller_identity
from secp_commissioning.canonical import canonical_json
from sqlalchemy import select

_UID, _GID = 10001, 10001


@pytest.fixture
def ca(tmp_path):
    p = tmp_path / "ca-bundle.pem"
    p.write_bytes(b"-----BEGIN CERTIFICATE-----\nMII...\n-----END CERTIFICATE-----\n")
    digest = "sha256:" + hashlib.sha256(p.read_bytes()).hexdigest()
    return str(p), digest


@pytest.fixture
def active(engine):
    with get_sessionmaker()() as s:
        activate_controller_identity(s, build_test_verified_controller_identity())
        s.commit()
    with get_sessionmaker()() as s:
        return (
            s.execute(
                select(ControllerEnrollmentIdentity).where(
                    ControllerEnrollmentIdentity.status == "active"
                )
            )
            .scalars()
            .one()
        )


def _binding(monkeypatch, ca_path):
    monkeypatch.setattr(bmod, "_process_ids", lambda: (_UID, _GID))
    with get_sessionmaker()() as s:
        return build_runtime_binding(s, ca_bundle_path=ca_path)


def _marker(binding: EnrollmentSignerRuntimeBinding, **over) -> dict:
    obj = {"schema": "secp.enrollment-signer-enablement/v1"}
    obj.update({f: getattr(binding, f) for f in bmod._BOUND_FIELDS})
    obj["recorded_at"] = "2026-07-28T00:00:00Z"
    obj.update(over)
    return obj


def test_binding_is_built_from_the_verified_active_identity(active, ca, monkeypatch):
    binding = _binding(monkeypatch, ca[0])
    assert binding is not None
    assert binding.active_identity_row_id == str(active.id)
    assert binding.api_uid == _UID and binding.signer_role_name == "secp_enrollment_signer"
    assert binding.locator_ca_digest == ca[1]
    assert marker_matches_binding(_marker_dc(binding), binding)


def _marker_dc(binding, **over):
    """A validated marker object (via the reader) that matches the binding."""
    obj = _marker(binding, **over)
    return _LoadedMarker(obj)


class _LoadedMarker:
    def __init__(self, obj):
        for k, v in obj.items():
            setattr(self, "schema_id" if k == "schema" else k, v)


def test_exact_marker_and_matching_binding_enables(active, ca, monkeypatch, tmp_path):
    binding = _binding(monkeypatch, ca[0])
    monkeypatch.setattr("secp_api.enrollment_signer_marker._fs_safe", lambda path: True)
    mp = tmp_path / "m.enabled"
    mp.write_bytes(canonical_json(_marker(binding)).encode())
    settings = types.SimpleNamespace(is_production=True, enrollment_signer_enabled=False)
    client = build_enrollment_offer_signer(settings, runtime_binding=binding, marker_path=str(mp))
    assert isinstance(client, UnixSocketEnrollmentOfferSignerClient)
    # the loaded marker matches the authoritative binding
    assert marker_matches_binding(load_valid_marker(path=str(mp)), binding)


def test_no_active_identity_seals(engine, ca, monkeypatch):
    # engine fixture => empty DB, no active identity
    assert _binding(monkeypatch, ca[0]) is None


def test_unreadable_ca_bundle_seals(active, monkeypatch, tmp_path):
    assert _binding(monkeypatch, str(tmp_path / "absent-ca.pem")) is None


@pytest.mark.parametrize(
    "field,bad",
    [
        ("installation_id", "controller-other00"),
        ("release_digest", "sha256:" + "9" * 64),
        ("active_identity_row_id", "row-wrong"),
        ("activation_token", "wrong|t"),
        ("controller_key_id", "sha256:" + "9" * 64),
        ("management_identity_digest", "sha256:" + "9" * 64),
        ("bootstrap_evidence_digest", "sha256:" + "9" * 64),
        ("api_uid", 4242),
        ("api_gid", 4242),
        ("signer_role_name", "postgres"),
        ("uds_contract_identity", "/tmp/evil.sock"),
        ("locator_ca_digest", "sha256:" + "9" * 64),
    ],
)
def test_any_binding_field_mismatch_seals(active, ca, monkeypatch, field, bad):
    binding = _binding(monkeypatch, ca[0])
    assert not marker_matches_binding(_marker_dc(binding, **{field: bad}), binding)


def test_env_flag_cannot_bypass_a_binding_mismatch_in_production(active, ca, monkeypatch, tmp_path):
    binding = _binding(monkeypatch, ca[0])
    monkeypatch.setattr("secp_api.enrollment_signer_marker._fs_safe", lambda path: True)
    mp = tmp_path / "m.enabled"
    # a STALE marker (wrong active row id) with the env flag explicitly ON -> still sealed
    mp.write_bytes(canonical_json(_marker(binding, active_identity_row_id="stale-row")).encode())
    settings = types.SimpleNamespace(is_production=True, enrollment_signer_enabled=True)
    client = build_enrollment_offer_signer(settings, runtime_binding=binding, marker_path=str(mp))
    assert isinstance(client, SealedEnrollmentOfferSignerClient)


def test_absent_marker_with_valid_binding_seals(active, ca, monkeypatch, tmp_path):
    binding = _binding(monkeypatch, ca[0])
    settings = types.SimpleNamespace(is_production=True, enrollment_signer_enabled=True)
    client = build_enrollment_offer_signer(
        settings, runtime_binding=binding, marker_path=str(tmp_path / "absent")
    )
    assert isinstance(client, SealedEnrollmentOfferSignerClient)
