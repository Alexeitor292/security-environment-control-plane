"""Deployment-scoped controller enrollment identity (SECP-PR5H-B1, F3).

The authoritative, persisted, independently-verified controller identity the enrollment API binds
into every invitation. It is **deployment-scoped** — one identity per control-plane deployment, NOT
per organization; the actor's ``organization_id`` remains the invitation/enrollment tenancy and
authorization boundary.

Identity ROTATION appends history rather than overwriting: at most ONE row is ``active`` at a time
(enforced by the ``active_marker`` UNIQUE — ``True`` on the single active row, ``NULL`` on every
``superseded`` / ``revoked`` row; NULLs are distinct in a UNIQUE on both SQLite and PostgreSQL, so
this is a portable, fail-closed single-active mechanism that keeps the ORM ``create_all`` and the
Alembic migration schemas byte-identical for the parity guard). SUPERSEDED and REVOKED rows are
preserved so an invitation issued under a prior identity stays verifiable after rotation; new
invitations use only the current ACTIVE identity.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, String, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from secp_api.models import Base, UpdatedTimestampMixin, _uuid

#: The closed, ordered identity lifecycle states.
CONTROLLER_IDENTITY_ACTIVE = "active"
CONTROLLER_IDENTITY_SUPERSEDED = "superseded"
CONTROLLER_IDENTITY_REVOKED = "revoked"
CONTROLLER_IDENTITY_STATES = (
    CONTROLLER_IDENTITY_ACTIVE,
    CONTROLLER_IDENTITY_SUPERSEDED,
    CONTROLLER_IDENTITY_REVOKED,
)


def _digest(column: str) -> str:
    return f"(length({column}) = 71 AND {column} LIKE 'sha256:%')"


class ControllerEnrollmentIdentity(Base, UpdatedTimestampMixin):
    """One row in the deployment's controller-identity history; at most one is ``active``."""

    __tablename__ = "controller_enrollment_identity"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    #: ``True`` on the single ACTIVE row, ``NULL`` otherwise. UNIQUE => at most one active globally.
    active_marker: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    controller_installation_id: Mapped[str] = mapped_column(String(120), nullable=False)
    controller_key_id: Mapped[str] = mapped_column(String(80), nullable=False)
    controller_trust_anchor_hex: Mapped[str] = mapped_column(String(64), nullable=False)
    controller_origin: Mapped[str] = mapped_column(String(269), nullable=False)
    release_digest: Mapped[str] = mapped_column(String(80), nullable=False)
    #: immutable source bindings proven at activation (never paths/keys/credentials/raw evidence):
    #: the root-controlled management-plane identity digest, the attested bootstrap-evidence digest,
    #: and a bounded public proof id for the DEDICATED enrollment key (distinct from the
    #: management-evidence and release-signing keys).
    management_identity_digest: Mapped[str] = mapped_column(String(80), nullable=False)
    bootstrap_evidence_digest: Mapped[str] = mapped_column(String(80), nullable=False)
    enrollment_key_proof_id: Mapped[str] = mapped_column(String(120), nullable=False)
    verified: Mapped[bool] = mapped_column(Boolean, nullable=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    activated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    superseded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint("active_marker", name="uq_controller_enrollment_identity_active"),
        CheckConstraint(
            "status IN ('active', 'superseded', 'revoked')", name="ck_cei_status_closed"
        ),
        CheckConstraint(
            "(status = 'active' AND active_marker = true)"
            " OR (status <> 'active' AND active_marker IS NULL)",
            name="ck_cei_active_marker_pairing",
        ),
        CheckConstraint(_digest("controller_key_id"), name="ck_cei_key_digest"),
        CheckConstraint(_digest("release_digest"), name="ck_cei_release_digest"),
        CheckConstraint(_digest("management_identity_digest"), name="ck_cei_mgmt_digest"),
        CheckConstraint(_digest("bootstrap_evidence_digest"), name="ck_cei_evidence_digest"),
        CheckConstraint(
            "length(enrollment_key_proof_id) >= 8 AND length(enrollment_key_proof_id) <= 120",
            name="ck_cei_enrollment_key_proof",
        ),
        # ACTIVE implies verified at the DB level: an unverified row can never be active.
        CheckConstraint("status <> 'active' OR verified = true", name="ck_cei_active_verified"),
        CheckConstraint("length(controller_trust_anchor_hex) = 64", name="ck_cei_anchor_hex"),
        CheckConstraint(
            "(controller_origin LIKE 'https://%' AND length(controller_origin) <= 269)",
            name="ck_cei_origin_https",
        ),
        CheckConstraint(
            "length(controller_installation_id) >= 8 AND length(controller_installation_id) <= 64",
            name="ck_cei_install_bounded",
        ),
        CheckConstraint(
            "(verified = false AND verified_at IS NULL)"
            " OR (verified = true AND verified_at IS NOT NULL)",
            name="ck_cei_verified_pairing",
        ),
        CheckConstraint(
            "(status = 'superseded' AND superseded_at IS NOT NULL)"
            " OR (status <> 'superseded' AND superseded_at IS NULL)",
            name="ck_cei_superseded_pairing",
        ),
        CheckConstraint(
            "(status = 'revoked' AND revoked_at IS NOT NULL)"
            " OR (status <> 'revoked' AND revoked_at IS NULL)",
            name="ck_cei_revoked_pairing",
        ),
    )


__all__ = [
    "CONTROLLER_IDENTITY_ACTIVE",
    "CONTROLLER_IDENTITY_REVOKED",
    "CONTROLLER_IDENTITY_STATES",
    "CONTROLLER_IDENTITY_SUPERSEDED",
    "ControllerEnrollmentIdentity",
]
