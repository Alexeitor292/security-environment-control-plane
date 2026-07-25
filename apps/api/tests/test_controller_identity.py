"""Deployment-scoped controller enrollment identity — sourcing + rotation (SECP-PR5H-B1, F3).

Exercises the durable single-active mechanism, rotation history, and fail-closed sourcing on a
per-test engine. The ``session`` fixture is a clean control-plane schema (no dev seed), so these
prove the primitives directly.
"""

from __future__ import annotations

import pytest
from secp_api.controller_identity_models import (
    CONTROLLER_IDENTITY_ACTIVE,
    CONTROLLER_IDENTITY_SUPERSEDED,
    ControllerEnrollmentIdentity,
)
from secp_api.errors import WorkerEnrollmentError
from secp_api.models import _utcnow
from secp_api.services import controller_identity as ci
from secp_api.worker_enrollment_contract import sha256_digest_of_hex
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

A = dict(
    controller_installation_id="controller-a0001",
    controller_key_id=sha256_digest_of_hex("11" * 32),
    controller_trust_anchor_hex="11" * 32,
    controller_origin="https://ctrl-a.example.test",
    release_digest="sha256:" + "a" * 64,
)
B = dict(
    controller_installation_id="controller-b0001",
    controller_key_id=sha256_digest_of_hex("22" * 32),
    controller_trust_anchor_hex="22" * 32,
    controller_origin="https://ctrl-b.example.test",
    release_digest="sha256:" + "c" * 64,
)


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


def test_sourcing_refuses_when_no_active_identity(session):
    with pytest.raises(WorkerEnrollmentError) as ei:
        ci.load_active_controller_identity(session)
    assert ei.value.code == "enrollment_controller_identity_unavailable"


def test_activate_then_source_returns_the_active_identity(session):
    ci.activate_controller_identity(session, **A)
    session.commit()
    identity = ci.load_active_controller_identity(session)
    assert identity.controller_origin == A["controller_origin"]
    assert identity.controller_key_id == A["controller_key_id"]
    assert _count(session, CONTROLLER_IDENTITY_ACTIVE) == 1


def test_rotation_supersedes_prior_and_keeps_exactly_one_active(session):
    ci.activate_controller_identity(session, **A)
    session.commit()
    ci.activate_controller_identity(session, **B)
    session.commit()
    assert _count(session, CONTROLLER_IDENTITY_ACTIVE) == 1
    assert (
        _count(session, CONTROLLER_IDENTITY_SUPERSEDED) == 1
    )  # history preserved, not overwritten
    identity = ci.load_active_controller_identity(session)
    assert identity.controller_key_id == B["controller_key_id"]  # new invitations use only B


def test_activate_refuses_inconsistent_key_and_anchor(session):
    bad = dict(A, controller_key_id=sha256_digest_of_hex("33" * 32))  # key != sha256(anchor)
    with pytest.raises(WorkerEnrollmentError) as ei:
        ci.activate_controller_identity(session, **bad)
    assert ei.value.code == "enrollment_trust_anchor_invalid"


def test_sourcing_refuses_an_unverified_active_identity(session):
    ci.activate_controller_identity(session, **A, verified=False)
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
                verified=True,
                verified_at=now,
                activated_at=now,
                **A,
            )
        )
    with pytest.raises(IntegrityError):
        session.flush()
