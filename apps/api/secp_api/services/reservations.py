"""Network reservation + address-space services (ADR-009).

Provider-neutral. Reserves non-overlapping CIDRs per execution target before any
future real provisioning. No real network is created in SECP-002A.
"""

from __future__ import annotations

import ipaddress
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from secp_api import audit
from secp_api.auth import Principal
from secp_api.enums import AuditAction, Permission, ReservationStatus
from secp_api.errors import DomainError, NotFoundError, ValidationFailedError
from secp_api.models import AddressSpacePolicy, NetworkReservation
from secp_api.services.targets import get_target


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

    spaces = _approved_spaces(session, target_id)
    if not spaces:
        raise ValidationFailedError(
            f"execution target '{target.display_name}' has no approved address space"
        )
    reserved = _reserved_networks(session, target_id)

    for space in spaces:
        block = ipaddress.ip_network(space.cidr_block, strict=False)
        prefix_len = prefix or space.subnet_prefix
        if prefix_len < block.prefixlen:
            continue
        for subnet in block.subnets(new_prefix=prefix_len):
            if any(subnet.overlaps(n) for n in reserved):
                continue
            cidr = str(subnet)
            existing = session.execute(
                select(NetworkReservation).where(
                    NetworkReservation.execution_target_id == target_id,
                    NetworkReservation.cidr == cidr,
                )
            ).scalar_one_or_none()
            if existing is not None:
                # Reuse a previously-released row (unique on target+cidr).
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
            session.flush()  # unique (target, cidr) constraint backstops concurrency
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
    requested = ipaddress.ip_network(cidr, strict=False)
    for space in _approved_spaces(session, target_id):
        block = ipaddress.ip_network(space.cidr_block, strict=False)
        if requested.version != block.version:
            continue
        if requested.subnet_of(block):  # type: ignore[arg-type]
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
