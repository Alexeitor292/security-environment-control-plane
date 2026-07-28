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

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from secp_api.models import Base, UpdatedTimestampMixin, _utcnow, _uuid

#: The one closed activation-operation schema/version the durable receipt binds to.
CONTROLLER_IDENTITY_ACTIVATION_SCHEMA = "secp.controller-identity-activation/v1"
#: Bounded upper limit for the stored canonical receipt bytes.
CONTROLLER_ACTIVATION_RECEIPT_MAX_BYTES = 8192

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


class ControllerIdentityActivationReceipt(Base):
    """The durable, append-only, WRITE-ONCE receipt of one controller-identity activation OPERATION
    (SECP-PR5H-B2, 2b-3b C3). Keyed by ``operation_id`` (UNIQUE), it stores the EXACT canonical
    public receipt bytes the winning first execution returned, so an exact replay returns them
    verbatim even after process/API restart or an identity rotation (and rotation back) — an
    operation's replay proves it COMMITTED, not that its identity is currently active. The complete
    operation binding (schema, candidate, predecessor row+token or fresh-install absence,
    installation, release, generation, handoff timestamp) is bound into ``operation_digest``, so the
    SAME ``operation_id`` with ANY changed field conflicts, and a NEW ``operation_id`` cannot claim
    replay. The trusted API path only INSERTs and SELECTs this table — no update/delete path."""

    __tablename__ = "controller_identity_activation_receipt"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    operation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    operation_schema: Mapped[str] = mapped_column(String(64), nullable=False)
    #: sha256 over the complete canonical operation envelope (domain-separated); the binding key
    operation_digest: Mapped[str] = mapped_column(String(80), nullable=False)
    candidate_digest: Mapped[str] = mapped_column(String(80), nullable=False)
    #: the expected predecessor active row + its activation token (both NULL for a fresh install)
    expected_predecessor_row_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("controller_enrollment_identity.id"), nullable=True
    )
    expected_predecessor_activation_token: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )
    controller_installation_id: Mapped[str] = mapped_column(String(64), nullable=False)
    release_digest: Mapped[str] = mapped_column(String(80), nullable=False)
    generation: Mapped[int] = mapped_column(Integer, nullable=False)
    #: the caller's canonical UTC first-execution timestamp from the handoff (preserved exactly)
    handoff_created_at: Mapped[str] = mapped_column(String(40), nullable=False)
    resulting_row_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("controller_enrollment_identity.id"), nullable=False
    )
    resulting_activation_token: Mapped[str] = mapped_column(String(128), nullable=False)
    resulting_public_state_digest: Mapped[str] = mapped_column(String(80), nullable=False)
    #: the EXACT canonical bounded public receipt bytes returned verbatim on an exact replay
    receipt_json: Mapped[str] = mapped_column(Text, nullable=False)
    #: sha256 over ``receipt_json``; re-verified on read so a tampered receipt refuses state-corrupt
    receipt_digest: Mapped[str] = mapped_column(String(80), nullable=False)
    #: when the winning activation + receipt committed (distinct from ``handoff_created_at``)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )

    __table_args__ = (
        UniqueConstraint("operation_id", name="uq_controller_identity_activation_receipt"),
        CheckConstraint(_digest("operation_digest"), name="ck_ciar_operation_digest"),
        CheckConstraint(_digest("candidate_digest"), name="ck_ciar_candidate_digest"),
        CheckConstraint(_digest("release_digest"), name="ck_ciar_release_digest"),
        CheckConstraint(
            _digest("resulting_public_state_digest"), name="ck_ciar_public_state_digest"
        ),
        CheckConstraint(_digest("receipt_digest"), name="ck_ciar_receipt_digest"),
        CheckConstraint("generation >= 0", name="ck_ciar_generation_nonnegative"),
        CheckConstraint(
            f"length(receipt_json) <= {CONTROLLER_ACTIVATION_RECEIPT_MAX_BYTES}",
            name="ck_ciar_receipt_bounded",
        ),
        CheckConstraint(
            f"operation_schema = '{CONTROLLER_IDENTITY_ACTIVATION_SCHEMA}'",
            name="ck_ciar_schema_closed",
        ),
        # predecessor row id + token are BOTH null (fresh install) or BOTH present (rotation)
        CheckConstraint(
            "(expected_predecessor_row_id IS NULL"
            " AND expected_predecessor_activation_token IS NULL)"
            " OR (expected_predecessor_row_id IS NOT NULL"
            " AND expected_predecessor_activation_token IS NOT NULL)",
            name="ck_ciar_predecessor_pairing",
        ),
        CheckConstraint(
            "length(controller_installation_id) >= 8 AND length(controller_installation_id) <= 64",
            name="ck_ciar_install_bounded",
        ),
        CheckConstraint(
            "length(operation_id) >= 1 AND length(resulting_activation_token) >= 1",
            name="ck_ciar_tokens_bounded",
        ),
    )


__all__ = [
    "CONTROLLER_ACTIVATION_RECEIPT_MAX_BYTES",
    "CONTROLLER_IDENTITY_ACTIVATION_SCHEMA",
    "CONTROLLER_IDENTITY_ACTIVE",
    "CONTROLLER_IDENTITY_REVOKED",
    "CONTROLLER_IDENTITY_STATES",
    "CONTROLLER_IDENTITY_SUPERSEDED",
    "ControllerEnrollmentIdentity",
    "ControllerIdentityActivationReceipt",
]
