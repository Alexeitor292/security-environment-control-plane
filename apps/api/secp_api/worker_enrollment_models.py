"""Durable worker-enrollment persistence (SECP-PR5H-A, ADR-027).

The control-plane store behind the PR5G *pure* enrollment transition contract. It is
**secret-free**: no key material, access token, credential, host path, private endpoint or raw
handoff byte is ever stored, and failure text is a bounded closed code — never free-form prose.

Four tables, all provider-neutral:

* :class:`WorkerEnrollmentInvitation` — the invitation fields the transition state deliberately
  DROPS (``invitation_id``, ``controller_origin``, ``controller_trust_anchor_hex``, ``created_at``),
  plus the tenancy binding. Its ``UNIQUE(invitation_id)`` is the **single-use nonce key**, held
  INDEPENDENTLY of the state primary key because ``enrollment_id == invitation.digest()`` collapses
  only *identical* invitations — the same nonce with a different expiry would otherwise yield a
  different enrollment id and escape single-use.
* :class:`WorkerEnrollmentState` — the head row: all 17 contract fields in declaration order, plus a
  derived ``state_digest`` used in the compare-and-swap predicate.
* :class:`WorkerEnrollmentRevision` — append-only history, ``UNIQUE(enrollment_id, revision)``.
* :class:`WorkerEnrollmentStepReceipt` — at-least-once dedup keyed
  ``UNIQUE(enrollment_id, step, input_digest)``, so a legitimate network retry after advancement
  resolves to the recorded revision instead of a spurious ``enrollment_wrong_state``.

Two deliberate, load-bearing schema decisions:

1. ``expires_at`` / ``updated_at`` are persisted as **TEXT, verbatim**. The contract's canonical
   form embeds those raw strings, and ``...Z`` vs ``...+00:00`` digest DIFFERENTLY, so a
   ``timestamptz``
   round-trip would silently break every ``state_digest``. Do NOT "fix" these into real timestamps.
   The shadow ``expires_at_ts`` column exists ONLY to make the recovery sweep indexable, and
   ``observed_at`` records real wall-clock progress because ``refuse()`` / ``require_recovery()``
   legally leave ``updated_at`` stale.
2. The database NEVER expires a row on its own. Expiry is evaluated only inside the pure transition
   from a caller-supplied ``now``; a trigger or scheduled UPDATE would mutate the row outside the
   digest chain and invalidate the CAS.

Tenancy: ``organization_id`` is the ONLY authorization boundary. ``deployment_site_label`` is an
opaque, grammar-validated grouping label inside one organization (ADR-027) — never a tenant,
address, region, endpoint or provider value.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from secp_api.models import Base, TimestampMixin, _utcnow, _uuid

# The opaque deployment-site grammar lives in the PURE contract module (one definition, no drift):
# letters, digits, dot, underscore, hyphen — deliberately excluding ``/``, ``:``, ``@``, whitespace
# and anything URL/host/path/provider shaped.  Re-exported here for the schema layer's convenience.
from secp_api.worker_enrollment_contract import (
    DEPLOYMENT_SITE_LABEL_PATTERN,
    is_deployment_site_label,
)

# --- closed vocabularies + grammars (mirrors the pure contract; see ADR-027) ------------------

#: The eight closed enrollment states. ``worker_bound`` is the CODE spelling (ADR-026 prose says
#: ``worker_identity_bound``; a constraint written from the prose would reject every real row).
WORKER_ENROLLMENT_STATES: tuple[str, ...] = (
    "invited",
    "worker_bound",
    "offer_transported",
    "result_transported",
    "verified",
    "healthy",
    "refused",
    "recovery_required",
)

#: The step names the at-least-once dedup ledger accepts.
WORKER_ENROLLMENT_STEPS: tuple[str, ...] = (
    "bind_worker_identity",
    "record_controller_offer",
    "record_worker_result",
    "mark_verified",
    "mark_healthy",
)

# DB-level CHECKs are deliberately PORTABLE (shape/length/prefix only): the ORM builds the schema
# on SQLite in unit tests via ``create_all`` while PostgreSQL runs the real migration, and a regex
# (`~`)
# constraint exists only on PostgreSQL — it would diverge the two schemas and fail SQLite outright.
# The EXACT grammar is enforced in the application layer (``is_deployment_site_label`` + the pure
# contract), so these constraints are a portable second line of defence, never the only one.


def _digest(column: str) -> str:
    return f"(length({column}) = 71 AND {column} LIKE 'sha256:%')"


def _digest_or_empty(column: str) -> str:
    return f"({column} = '' OR {_digest(column)})"


def _bounded(column: str, low: int, high: int) -> str:
    return f"(length({column}) >= {low} AND length({column}) <= {high})"


def _bounded_or_empty(column: str, low: int, high: int) -> str:
    return f"({column} = '' OR {_bounded(column, low, high)})"


def _site_check(column: str) -> CheckConstraint:
    return CheckConstraint(_bounded(column, 1, 120), name=f"ck_{column}_bounded")


class WorkerEnrollmentInvitation(Base, TimestampMixin):
    """A short-lived, non-secret invitation plus the durable single-use nonce key.

    ``UNIQUE(invitation_id)`` is what makes single-use survive a process restart; consumption is one
    atomic conditional UPDATE (``WHERE invitation_id = :nonce AND consumed IS false``)."""

    __tablename__ = "worker_enrollment_invitation"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    deployment_site_label: Mapped[str] = mapped_column(String(120), nullable=False)
    #: the single-use nonce identity (sha256 digest) — UNIQUE independently of enrollment_id
    invitation_id: Mapped[str] = mapped_column(String(80), nullable=False)
    #: invitation.digest(); becomes the enrollment head-row primary key when opened
    enrollment_id: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    controller_installation_id: Mapped[str] = mapped_column(String(120), nullable=False)
    controller_key_id: Mapped[str] = mapped_column(String(80), nullable=False)
    controller_trust_anchor_hex: Mapped[str] = mapped_column(String(64), nullable=False)
    controller_origin: Mapped[str] = mapped_column(String(269), nullable=False)
    release_digest: Mapped[str] = mapped_column(String(80), nullable=False)
    transaction_id: Mapped[str] = mapped_column(String(512), nullable=False)
    #: canonical timestamps persisted VERBATIM (never round-tripped through timestamptz)
    invitation_created_at: Mapped[str] = mapped_column(String(40), nullable=False)
    expires_at: Mapped[str] = mapped_column(String(40), nullable=False)
    #: shadow copy used ONLY for indexable expiry sweeps
    expires_at_ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint("invitation_id", name="uq_worker_enrollment_invitation_nonce"),
        CheckConstraint(_digest("invitation_id"), name="ck_wei_invitation_id_digest"),
        CheckConstraint(_digest("enrollment_id"), name="ck_wei_enrollment_id_digest"),
        CheckConstraint(_digest("controller_key_id"), name="ck_wei_controller_key_digest"),
        CheckConstraint(_digest("release_digest"), name="ck_wei_release_digest"),
        CheckConstraint(
            _bounded("controller_installation_id", 8, 64), name="ck_wei_controller_install"
        ),
        CheckConstraint("length(controller_trust_anchor_hex) = 64", name="ck_wei_anchor_hex"),
        CheckConstraint(
            "(controller_origin LIKE 'https://%' AND length(controller_origin) <= 269)",
            name="ck_wei_origin_https",
        ),
        _site_check("deployment_site_label"),
        CheckConstraint(
            "(consumed = false AND consumed_at IS NULL)"
            " OR (consumed = true AND consumed_at IS NOT NULL)",
            name="ck_wei_consumed_pairing",
        ),
        CheckConstraint(
            "(revoked = false AND revoked_at IS NULL)"
            " OR (revoked = true AND revoked_at IS NOT NULL)",
            name="ck_wei_revoked_pairing",
        ),
        Index("ix_wei_org_site", "organization_id", "deployment_site_label"),
    )


class WorkerEnrollmentState(Base):
    """The durable head row: all 17 contract fields verbatim + the derived CAS digest."""

    __tablename__ = "worker_enrollment_state"

    enrollment_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    deployment_site_label: Mapped[str] = mapped_column(String(120), nullable=False)

    # --- the 17 EnrollmentState fields, in contract declaration order ---
    contract_version: Mapped[str] = mapped_column(String(80), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    predecessor_digest: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    controller_installation_id: Mapped[str] = mapped_column(String(120), nullable=False)
    controller_key_id: Mapped[str] = mapped_column(String(80), nullable=False)
    worker_installation_id: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    worker_key_id: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    release_digest: Mapped[str] = mapped_column(String(80), nullable=False)
    transaction_id: Mapped[str] = mapped_column(String(512), nullable=False)
    offer_digest: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    result_digest: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    expires_at: Mapped[str] = mapped_column(String(40), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(40), nullable=False)
    refusal_reason: Mapped[str] = mapped_column(String(80), nullable=False, default="")

    # --- derived / non-canonical operational columns (never part of canonical()) ---
    state_digest: Mapped[str] = mapped_column(String(80), nullable=False)
    #: real wall-clock progress; refuse()/require_recovery() legally leave updated_at stale
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow
    )
    #: shadow copy of expires_at used ONLY for the indexable recovery sweep
    expires_at_ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        CheckConstraint(
            "state IN ('" + "','".join(WORKER_ENROLLMENT_STATES) + "')", name="ck_wes_state_closed"
        ),
        CheckConstraint("revision >= 0", name="ck_wes_revision_nonnegative"),
        CheckConstraint("sequence >= 0", name="ck_wes_sequence_nonnegative"),
        CheckConstraint(_digest("enrollment_id"), name="ck_wes_enrollment_id_digest"),
        CheckConstraint(_digest("state_digest"), name="ck_wes_state_digest"),
        CheckConstraint(_digest_or_empty("predecessor_digest"), name="ck_wes_predecessor"),
        CheckConstraint(_digest("controller_key_id"), name="ck_wes_controller_key"),
        CheckConstraint(_digest_or_empty("worker_key_id"), name="ck_wes_worker_key"),
        CheckConstraint(_digest("release_digest"), name="ck_wes_release_digest"),
        CheckConstraint(_digest_or_empty("offer_digest"), name="ck_wes_offer_digest"),
        CheckConstraint(_digest_or_empty("result_digest"), name="ck_wes_result_digest"),
        CheckConstraint(
            _bounded("controller_installation_id", 8, 64), name="ck_wes_controller_install"
        ),
        CheckConstraint(
            _bounded_or_empty("worker_installation_id", 8, 64), name="ck_wes_worker_install"
        ),
        CheckConstraint("length(refusal_reason) <= 64", name="ck_wes_reason_code"),
        # only a terminal/refused row may carry a reason code
        CheckConstraint(
            "refusal_reason = '' OR state IN ('refused','recovery_required')",
            name="ck_wes_reason_only_when_terminal",
        ),
        _site_check("deployment_site_label"),
        Index("ix_wes_sweep", "state", "expires_at_ts"),
        Index("ix_wes_org_site", "organization_id", "deployment_site_label"),
    )


class WorkerEnrollmentRevision(Base):
    """Append-only revision history; one row per committed transition."""

    __tablename__ = "worker_enrollment_revision"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    enrollment_id: Mapped[str] = mapped_column(
        String(80), ForeignKey("worker_enrollment_state.enrollment_id"), nullable=False, index=True
    )
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    state_digest: Mapped[str] = mapped_column(String(80), nullable=False)
    predecessor_digest: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )

    __table_args__ = (
        UniqueConstraint("enrollment_id", "revision", name="uq_worker_enrollment_revision"),
        CheckConstraint("revision >= 0", name="ck_wer_revision_nonnegative"),
        CheckConstraint(
            "state IN ('" + "','".join(WORKER_ENROLLMENT_STATES) + "')", name="ck_wer_state_closed"
        ),
        CheckConstraint(_digest("state_digest"), name="ck_wer_state_digest"),
        CheckConstraint(_digest_or_empty("predecessor_digest"), name="ck_wer_predecessor"),
    )


class WorkerEnrollmentStepReceipt(Base):
    """At-least-once dedup: a repeated step with the same input resolves to its recorded
    revision."""

    __tablename__ = "worker_enrollment_step_receipt"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    enrollment_id: Mapped[str] = mapped_column(
        String(80), ForeignKey("worker_enrollment_state.enrollment_id"), nullable=False, index=True
    )
    step: Mapped[str] = mapped_column(String(40), nullable=False)
    #: the digest of the exact verified input (never the raw handoff bytes)
    input_digest: Mapped[str] = mapped_column(String(80), nullable=False)
    resulting_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    resulting_state_digest: Mapped[str] = mapped_column(String(80), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )

    __table_args__ = (
        UniqueConstraint(
            "enrollment_id", "step", "input_digest", name="uq_worker_enrollment_step_receipt"
        ),
        CheckConstraint(
            "step IN ('" + "','".join(WORKER_ENROLLMENT_STEPS) + "')", name="ck_wesr_step_closed"
        ),
        CheckConstraint("resulting_revision >= 0", name="ck_wesr_revision_nonnegative"),
        CheckConstraint(_digest("input_digest"), name="ck_wesr_input_digest"),
        CheckConstraint(_digest("resulting_state_digest"), name="ck_wesr_result_digest"),
    )


__all__ = [
    "DEPLOYMENT_SITE_LABEL_PATTERN",
    "WORKER_ENROLLMENT_STATES",
    "WORKER_ENROLLMENT_STEPS",
    "WorkerEnrollmentInvitation",
    "WorkerEnrollmentRevision",
    "WorkerEnrollmentState",
    "WorkerEnrollmentStepReceipt",
    "is_deployment_site_label",
]
