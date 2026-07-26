"""Deployment-scoped controller enrollment identity — verified sourcing + rotation (PR5H-B1 F3/R1).

Exercises the durable single-active mechanism, rotation history, and fail-closed sourcing on a
per-test engine. The ``session`` fixture is a clean control-plane schema (no dev seed), so these
prove the primitives directly. Activation accepts ONLY a typed ``VerifiedControllerIdentity`` proof
(built here via the explicit TEST/DEV factory).
"""

from __future__ import annotations

import dataclasses

import pytest
from secp_api.controller_identity_models import (
    CONTROLLER_IDENTITY_ACTIVE,
    CONTROLLER_IDENTITY_SUPERSEDED,
    ControllerEnrollmentIdentity,
)
from secp_api.errors import WorkerEnrollmentError
from secp_api.models import _utcnow
from secp_api.services import controller_identity as ci
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError


def _proof(**over: str) -> ci.VerifiedControllerIdentity:
    return ci.build_test_verified_controller_identity(**over)


A = _proof()
B = _proof(controller_installation_id="controller-b0001", controller_trust_anchor_hex="22" * 32)


def _count(session, status: str) -> int:
    return len(
        session.execute(
            select(ControllerEnrollmentIdentity).where(
                ControllerEnrollmentIdentity.status == status
            )
        )
        .scalars()
        .all()
    )


def test_activation_accepts_only_a_typed_verified_proof() -> None:
    import inspect

    params = inspect.signature(ci.activate_controller_identity).parameters
    assert "verified" not in params  # no caller-controlled boolean seam
    assert "controller_key_id" not in params  # no raw identity fields
    assert list(params)[1] == "proof"  # (session, proof)


def test_sourcing_refuses_when_no_active_identity(session):
    with pytest.raises(WorkerEnrollmentError) as ei:
        ci.load_active_controller_identity(session)
    assert ei.value.code == "enrollment_controller_identity_unavailable"


def test_activate_then_source_returns_the_active_identity(session):
    ci.activate_controller_identity(session, A)
    session.commit()
    identity = ci.load_active_controller_identity(session)
    assert identity.controller_origin == A.controller_origin
    assert identity.controller_key_id == A.controller_key_id
    assert _count(session, CONTROLLER_IDENTITY_ACTIVE) == 1


def test_rotation_supersedes_prior_and_keeps_exactly_one_active(session):
    ci.activate_controller_identity(session, A)
    session.commit()
    ci.activate_controller_identity(session, B)
    session.commit()
    assert _count(session, CONTROLLER_IDENTITY_ACTIVE) == 1
    assert (
        _count(session, CONTROLLER_IDENTITY_SUPERSEDED) == 1
    )  # history preserved, not overwritten
    assert ci.load_active_controller_identity(session).controller_key_id == B.controller_key_id


def test_activate_refuses_inconsistent_key_and_anchor(session):
    from secp_api.worker_enrollment_contract import sha256_digest_of_hex

    bad = dataclasses.replace(A, controller_key_id=sha256_digest_of_hex("33" * 32))
    with pytest.raises(WorkerEnrollmentError) as ei:
        ci.activate_controller_identity(session, bad)
    assert ei.value.code == "enrollment_trust_anchor_invalid"


def test_activate_refuses_when_enrollment_key_not_separated(session):
    # the dedicated enrollment key id must differ from the management/evidence/release digests
    bad = dataclasses.replace(A, management_identity_digest=A.controller_key_id)
    with pytest.raises(WorkerEnrollmentError) as ei:
        ci.activate_controller_identity(session, bad)
    assert ei.value.code == "enrollment_identity_invalid"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("controller_origin", "http://not-https"),
        ("release_digest", "not-a-digest"),
        ("management_identity_digest", "not-a-digest"),
        ("bootstrap_evidence_digest", "sha256:zz"),
        ("controller_installation_id", "X"),
        ("enrollment_key_proof_id", "short"),
    ],
)
def test_malformed_proof_refuses_before_superseding_the_active_identity(session, field, value):
    ci.activate_controller_identity(session, A)
    session.commit()
    bad = dataclasses.replace(A, **{field: value})
    with pytest.raises(WorkerEnrollmentError):
        ci.activate_controller_identity(session, bad)
    session.rollback()
    # the previous identity is still active — a failed rotation never supersedes it
    assert _count(session, CONTROLLER_IDENTITY_ACTIVE) == 1
    assert ci.load_active_controller_identity(session).controller_key_id == A.controller_key_id


def test_active_implies_verified_at_the_database_level(session):
    now = _utcnow()
    row = ControllerEnrollmentIdentity(
        status=CONTROLLER_IDENTITY_ACTIVE,
        active_marker=True,
        controller_installation_id=A.controller_installation_id,
        controller_key_id=A.controller_key_id,
        controller_trust_anchor_hex=A.controller_trust_anchor_hex,
        controller_origin=A.controller_origin,
        release_digest=A.release_digest,
        management_identity_digest=A.management_identity_digest,
        bootstrap_evidence_digest=A.bootstrap_evidence_digest,
        enrollment_key_proof_id=A.enrollment_key_proof_id,
        verified=False,  # an unverified row can never be ACTIVE (ck_cei_active_verified)
        verified_at=None,
        activated_at=now,
    )
    session.add(row)
    with pytest.raises(IntegrityError):
        session.flush()


def test_sourcing_revalidates_persisted_bindings(session):
    ci.activate_controller_identity(session, A)
    session.commit()
    # corrupt the persisted management-identity digest (shape) — sourcing must refuse it
    session.execute(
        ControllerEnrollmentIdentity.__table__.update()
        .where(ControllerEnrollmentIdentity.status == CONTROLLER_IDENTITY_ACTIVE)
        .values(management_identity_digest="sha256:" + "a" * 63 + "z")
    )
    session.commit()
    with pytest.raises(WorkerEnrollmentError) as ei:
        ci.load_active_controller_identity(session)
    assert ei.value.code == "enrollment_controller_identity_unavailable"


def test_two_active_rows_violate_the_single_active_unique(session):
    now = _utcnow()
    for _ in range(2):
        session.add(
            ControllerEnrollmentIdentity(
                status=CONTROLLER_IDENTITY_ACTIVE,
                active_marker=True,
                controller_installation_id=A.controller_installation_id,
                controller_key_id=A.controller_key_id,
                controller_trust_anchor_hex=A.controller_trust_anchor_hex,
                controller_origin=A.controller_origin,
                release_digest=A.release_digest,
                management_identity_digest=A.management_identity_digest,
                bootstrap_evidence_digest=A.bootstrap_evidence_digest,
                enrollment_key_proof_id=A.enrollment_key_proof_id,
                verified=True,
                verified_at=now,
                activated_at=now,
            )
        )
    with pytest.raises(IntegrityError):
        session.flush()
