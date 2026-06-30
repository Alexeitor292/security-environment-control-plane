"""Network reservation + address-space services (ADR-009).

Provider-neutral. Reserves non-overlapping CIDRs per execution target before any
future real provisioning. No real network is created in SECP-002A.
"""

from __future__ import annotations

import ipaddress
import uuid
from collections.abc import Iterator

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from secp_api import audit
from secp_api.auth import Principal
from secp_api.enums import AuditAction, Permission, ReservationStatus
from secp_api.errors import DomainError, NotFoundError, ValidationFailedError
from secp_api.models import AddressSpacePolicy, NetworkReservation
from secp_api.services.targets import get_target

MAX_ALLOCATION_ATTEMPTS = 3


def _reserved_networks(
    session: Session, target_id: uuid.UUID
) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    rows = (
        session.execute(
            select(NetworkReservation.cidr).where(
                NetworkReservation.execution_target_id == target_id,
                NetworkReservation.status == ReservationStatus.reserved,
            )
        )
        .scalars()
        .all()
    )
    return [ipaddress.ip_network(c) for c in rows]


def _approved_spaces(session: Session, target_id: uuid.UUID) -> list[AddressSpacePolicy]:
    return list(
        session.execute(
            select(AddressSpacePolicy)
            .where(AddressSpacePolicy.execution_target_id == target_id)
            .order_by(AddressSpacePolicy.cidr_block)
        )
        .scalars()
        .all()
    )


def _lock_allocations_for_target(session: Session, target_id: uuid.UUID) -> None:
    """Serialize allocation decisions for one execution target.

    Updating the target's address-space rows is a portable write lock: PostgreSQL
    takes row locks, while SQLite serializes writers for the database. The update
    is a no-op on data values but still protects the read/choose/insert sequence.
    """

    session.execute(
        update(AddressSpacePolicy)
        .where(AddressSpacePolicy.execution_target_id == target_id)
        .values(subnet_prefix=AddressSpacePolicy.subnet_prefix)
    )
    session.flush()


def _validate_requested_prefix(spaces: list[AddressSpacePolicy], prefix: int | None) -> int | None:
    if prefix is None:
        return None
    try:
        requested = int(prefix)
    except Exception as exc:
        raise ValidationFailedError("reservation prefix must be an integer") from exc
    allowed = {space.subnet_prefix for space in spaces}
    if requested not in allowed:
        raise ValidationFailedError(
            "reservation prefix must match an approved address-space subnet prefix",
            errors=[f"requested /{requested}; allowed prefixes: {sorted(allowed)}"],
        )
    return requested


def _candidate_subnets(
    spaces: list[AddressSpacePolicy], prefix: int | None
) -> Iterator[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    for space in spaces:
        if prefix is not None and prefix != space.subnet_prefix:
            continue
        block = ipaddress.ip_network(space.cidr_block, strict=True)
        yield from block.subnets(new_prefix=space.subnet_prefix)


def _persist_reservation(
    session: Session,
    actor: Principal,
    *,
    target_id: uuid.UUID,
    exercise_id: uuid.UUID | None,
    team_ref: str,
    cidr: str,
) -> NetworkReservation:
    existing = session.execute(
        select(NetworkReservation).where(
            NetworkReservation.execution_target_id == target_id,
            NetworkReservation.cidr == cidr,
        )
    ).scalar_one_or_none()
    if existing is not None:
        existing.status = ReservationStatus.reserved
        existing.team_ref = team_ref
        existing.exercise_id = exercise_id
        reservation = existing
    else:
        reservation = NetworkReservation(
            organization_id=actor.organization_id,
            execution_target_id=target_id,
            exercise_id=exercise_id,
            team_ref=team_ref,
            cidr=cidr,
            status=ReservationStatus.reserved,
        )
        session.add(reservation)
    session.flush()
    return reservation


def reserve_network(
    session: Session,
    actor: Principal,
    *,
    target_id: uuid.UUID,
    team_ref: str,
    exercise_id: uuid.UUID | None = None,
    prefix: int | None = None,
) -> NetworkReservation:
    """Deterministically reserve the next free, non-overlapping CIDR for a team."""
    actor.require(Permission.target_manage)
    target = get_target(session, actor, target_id)  # org-scoped

    for _attempt in range(MAX_ALLOCATION_ATTEMPTS):
        spaces = _approved_spaces(session, target_id)
        if not spaces:
            raise ValidationFailedError(
                f"execution target '{target.display_name}' has no approved address space"
            )
        requested_prefix = _validate_requested_prefix(spaces, prefix)
        _lock_allocations_for_target(session, target_id)
        reserved = _reserved_networks(session, target_id)

        for subnet in _candidate_subnets(spaces, requested_prefix):
            if any(subnet.overlaps(network) for network in reserved):
                continue
            cidr = str(subnet)
            try:
                with session.begin_nested():
                    reservation = _persist_reservation(
                        session,
                        actor,
                        target_id=target_id,
                        exercise_id=exercise_id,
                        team_ref=team_ref,
                        cidr=cidr,
                    )
            except IntegrityError:
                session.expire_all()
                break
            audit.record(
                session,
                action=AuditAction.reservation_created,
                resource_type="network_reservation",
                resource_id=reservation.id,
                organization_id=actor.organization_id,
                actor=str(actor.user_id),
                data={"cidr": cidr, "team_ref": team_ref},
            )
            return reservation

    raise DomainError("no free CIDR available in the approved address spaces")


def validate_requested_network(
    session: Session, actor: Principal, target_id: uuid.UUID, cidr: str
) -> bool:
    """True if ``cidr`` falls within an approved address space for the target."""
    get_target(session, actor, target_id)
    requested = ipaddress.ip_network(cidr, strict=True)
    for space in _approved_spaces(session, target_id):
        block = ipaddress.ip_network(space.cidr_block, strict=True)
        if requested.version != block.version:
            continue
        if requested.subnet_of(block) and requested.prefixlen == space.subnet_prefix:  # type: ignore[arg-type]
            return True
    return False


def release_reservation(
    session: Session, actor: Principal, reservation_id: uuid.UUID
) -> NetworkReservation:
    actor.require(Permission.target_manage)
    reservation = session.get(NetworkReservation, reservation_id)
    if reservation is None:
        raise NotFoundError(f"reservation {reservation_id} not found")
    actor.require_org(reservation.organization_id)
    reservation.status = ReservationStatus.released
    audit.record(
        session,
        action=AuditAction.reservation_released,
        resource_type="network_reservation",
        resource_id=reservation.id,
        organization_id=actor.organization_id,
        actor=str(actor.user_id),
        data={"cidr": reservation.cidr},
    )
    return reservation


def list_reservations(
    session: Session, actor: Principal, target_id: uuid.UUID
) -> list[NetworkReservation]:
    get_target(session, actor, target_id)
    return list(
        session.execute(
            select(NetworkReservation)
            .where(NetworkReservation.execution_target_id == target_id)
            .order_by(NetworkReservation.cidr)
        )
        .scalars()
        .all()
    )
