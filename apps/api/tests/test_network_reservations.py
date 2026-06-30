"""Slice 4 + proof #8, #9 — network reservations: deterministic, collision-free,
release, cross-org denial."""

from __future__ import annotations

import pytest
from secp_api.enums import ReservationStatus
from secp_api.errors import AuthorizationError, DomainError, ValidationFailedError
from secp_api.models import NetworkReservation
from sqlalchemy.exc import IntegrityError


def _target(session, actor, *, prefix=24, block="10.50.0.0/16"):
    from secp_api.services import targets

    return targets.register_target(
        session,
        actor,
        display_name="Lab",
        plugin_name="proxmox",
        config={"base_url": "https://proxmox.example.test:8006"},
        secret_ref="env:SECP_PROVIDER_SECRET__T",
        address_spaces=[{"cidr_block": block, "subnet_prefix": prefix}],
    )


def test_deterministic_allocation(session, principal):
    from secp_api.services import reservations

    target = _target(session, principal)
    cidrs = [
        reservations.reserve_network(
            session, principal, target_id=target.id, team_ref=f"team{i}"
        ).cidr
        for i in range(3)
    ]
    session.commit()
    assert cidrs == ["10.50.0.0/24", "10.50.1.0/24", "10.50.2.0/24"]


def test_reservations_do_not_overlap(session, principal):
    from secp_api.services import reservations

    target = _target(session, principal)
    nets = [
        reservations.reserve_network(session, principal, target_id=target.id, team_ref=f"t{i}").cidr
        for i in range(5)
    ]
    session.commit()
    assert len(set(nets)) == 5  # all distinct


def test_duplicate_cidr_is_rejected_at_db(session, principal):
    """Proof #8 — the unique constraint prevents a colliding reservation."""
    target = _target(session, principal)
    session.add(
        NetworkReservation(
            organization_id=principal.organization_id,
            execution_target_id=target.id,
            team_ref="a",
            cidr="10.50.0.0/24",
            status=ReservationStatus.reserved,
        )
    )
    session.flush()
    session.add(
        NetworkReservation(
            organization_id=principal.organization_id,
            execution_target_id=target.id,
            team_ref="b",
            cidr="10.50.0.0/24",  # same CIDR on same target
            status=ReservationStatus.reserved,
        )
    )
    with pytest.raises(IntegrityError):
        session.flush()


def test_release_and_rereserve(session, principal):
    from secp_api.services import reservations

    target = _target(session, principal)
    r1 = reservations.reserve_network(session, principal, target_id=target.id, team_ref="t1")
    session.commit()
    reservations.release_reservation(session, principal, r1.id)
    session.commit()
    assert r1.status == ReservationStatus.released
    # Next reservation can reuse the freed CIDR (lowest free block).
    r2 = reservations.reserve_network(session, principal, target_id=target.id, team_ref="t2")
    session.commit()
    assert r2.cidr == "10.50.0.0/24"
    assert r2.status == ReservationStatus.reserved


def test_no_address_space_refused(session, principal):
    from secp_api.services import reservations, targets

    target = targets.register_target(
        session,
        principal,
        display_name="No-space",
        plugin_name="proxmox",
        config={"base_url": "https://proxmox.example.test:8006"},
        secret_ref="env:SECP_PROVIDER_SECRET__T2",
        address_spaces=[],
    )
    with pytest.raises(ValidationFailedError):
        reservations.reserve_network(session, principal, target_id=target.id, team_ref="t")


def test_validate_requested_network(session, principal):
    from secp_api.services import reservations

    target = _target(session, principal)
    assert reservations.validate_requested_network(session, principal, target.id, "10.50.3.0/24")
    assert not reservations.validate_requested_network(
        session, principal, target.id, "192.168.99.0/24"
    )


def test_cross_org_reservation_denied(session, principal, other_org_principal):
    from secp_api.services import reservations

    target = _target(session, principal)
    with pytest.raises(AuthorizationError):
        reservations.reserve_network(
            session, other_org_principal, target_id=target.id, team_ref="t"
        )


def test_exhausted_space_raises(session, principal):
    from secp_api.services import reservations

    # /30 block with /30 subnets => exactly one subnet available.
    target = _target(session, principal, prefix=30, block="10.99.0.0/30")
    reservations.reserve_network(session, principal, target_id=target.id, team_ref="a")
    session.commit()
    with pytest.raises(DomainError):
        reservations.reserve_network(session, principal, target_id=target.id, team_ref="b")
