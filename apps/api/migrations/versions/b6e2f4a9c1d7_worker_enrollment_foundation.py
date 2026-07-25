"""Durable worker-enrollment foundation (SECP-PR5H-A).

Creates the four provider-neutral enrollment tables behind the PR5G pure transition contract:
the invitation + single-use nonce ledger, the durable head row, the append-only revision history,
and the at-least-once step-receipt dedup ledger.

The schema is intentionally inert in PR5H-A: nothing writes to it until the repository/CAS service
lands. ``downgrade`` drops the four tables in dependency order, so the head returns cleanly to
``d8f1a2b3c4e5`` and the PR5F rollback path is unaffected.

CHECK constraints are deliberately PORTABLE (shape/length/prefix, not PostgreSQL regex) so the
migration schema and the ORM's SQLite ``create_all`` schema stay identical; the exact grammar is
enforced in the application layer.

Revision ID: b6e2f4a9c1d7
Revises: d8f1a2b3c4e5
Create Date: 2026-07-22
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b6e2f4a9c1d7"
down_revision: str | None = "d8f1a2b3c4e5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_STATES = (
    "invited",
    "worker_bound",
    "offer_transported",
    "result_transported",
    "verified",
    "healthy",
    "refused",
    "recovery_required",
)
_STEPS = (
    "bind_worker_identity",
    "record_controller_offer",
    "record_worker_result",
    "mark_verified",
    "mark_healthy",
)


def _in(column: str, values: Sequence[str]) -> str:
    return f"{column} IN (" + ", ".join(f"'{v}'" for v in values) + ")"


def _digest(column: str) -> str:
    return f"(length({column}) = 71 AND {column} LIKE 'sha256:%')"


def _digest_or_empty(column: str) -> str:
    return f"({column} = '' OR {_digest(column)})"


def _bounded(column: str, low: int, high: int) -> str:
    return f"(length({column}) >= {low} AND length({column}) <= {high})"


def _bounded_or_empty(column: str, low: int, high: int) -> str:
    return f"({column} = '' OR {_bounded(column, low, high)})"


def upgrade() -> None:
    op.create_table(
        "worker_enrollment_invitation",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Uuid(),
            sa.ForeignKey("organization.id"),
            nullable=False,
            index=True,
        ),
        sa.Column("deployment_site_label", sa.String(length=120), nullable=False),
        sa.Column("invitation_id", sa.String(length=80), nullable=False),
        sa.Column("enrollment_id", sa.String(length=80), nullable=False, index=True),
        sa.Column("controller_installation_id", sa.String(length=120), nullable=False),
        sa.Column("controller_key_id", sa.String(length=80), nullable=False),
        sa.Column("controller_trust_anchor_hex", sa.String(length=64), nullable=False),
        sa.Column("controller_origin", sa.String(length=269), nullable=False),
        sa.Column("release_digest", sa.String(length=80), nullable=False),
        sa.Column("transaction_id", sa.String(length=512), nullable=False),
        sa.Column("invitation_created_at", sa.String(length=40), nullable=False),
        sa.Column("expires_at", sa.String(length=40), nullable=False),
        sa.Column("expires_at_ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed", sa.Boolean(), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked", sa.Boolean(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("invitation_id", name="uq_worker_enrollment_invitation_nonce"),
        sa.CheckConstraint(_digest("invitation_id"), name="ck_wei_invitation_id_digest"),
        sa.CheckConstraint(_digest("enrollment_id"), name="ck_wei_enrollment_id_digest"),
        sa.CheckConstraint(_digest("controller_key_id"), name="ck_wei_controller_key_digest"),
        sa.CheckConstraint(_digest("release_digest"), name="ck_wei_release_digest"),
        sa.CheckConstraint(
            _bounded("controller_installation_id", 8, 64), name="ck_wei_controller_install"
        ),
        sa.CheckConstraint("length(controller_trust_anchor_hex) = 64", name="ck_wei_anchor_hex"),
        sa.CheckConstraint(
            "(controller_origin LIKE 'https://%' AND length(controller_origin) <= 269)",
            name="ck_wei_origin_https",
        ),
        sa.CheckConstraint(
            _bounded("deployment_site_label", 1, 120), name="ck_deployment_site_label_bounded"
        ),
        sa.CheckConstraint(
            "(consumed = false AND consumed_at IS NULL)"
            " OR (consumed = true AND consumed_at IS NOT NULL)",
            name="ck_wei_consumed_pairing",
        ),
        sa.CheckConstraint(
            "(revoked = false AND revoked_at IS NULL)"
            " OR (revoked = true AND revoked_at IS NOT NULL)",
            name="ck_wei_revoked_pairing",
        ),
    )
    op.create_index(
        "ix_wei_org_site",
        "worker_enrollment_invitation",
        ["organization_id", "deployment_site_label"],
    )

    op.create_table(
        "worker_enrollment_state",
        sa.Column("enrollment_id", sa.String(length=80), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Uuid(),
            sa.ForeignKey("organization.id"),
            nullable=False,
            index=True,
        ),
        sa.Column("deployment_site_label", sa.String(length=120), nullable=False),
        sa.Column("contract_version", sa.String(length=80), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("predecessor_digest", sa.String(length=80), nullable=False),
        sa.Column("controller_installation_id", sa.String(length=120), nullable=False),
        sa.Column("controller_key_id", sa.String(length=80), nullable=False),
        sa.Column("worker_installation_id", sa.String(length=120), nullable=False),
        sa.Column("worker_key_id", sa.String(length=80), nullable=False),
        sa.Column("release_digest", sa.String(length=80), nullable=False),
        sa.Column("transaction_id", sa.String(length=512), nullable=False),
        sa.Column("offer_digest", sa.String(length=80), nullable=False),
        sa.Column("result_digest", sa.String(length=80), nullable=False),
        sa.Column("expires_at", sa.String(length=40), nullable=False),
        sa.Column("updated_at", sa.String(length=40), nullable=False),
        sa.Column("refusal_reason", sa.String(length=80), nullable=False),
        sa.Column("state_digest", sa.String(length=80), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at_ts", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(_in("state", _STATES), name="ck_wes_state_closed"),
        sa.CheckConstraint("revision >= 0", name="ck_wes_revision_nonnegative"),
        sa.CheckConstraint("sequence >= 0", name="ck_wes_sequence_nonnegative"),
        sa.CheckConstraint(_digest("enrollment_id"), name="ck_wes_enrollment_id_digest"),
        sa.CheckConstraint(_digest("state_digest"), name="ck_wes_state_digest"),
        sa.CheckConstraint(_digest_or_empty("predecessor_digest"), name="ck_wes_predecessor"),
        sa.CheckConstraint(_digest("controller_key_id"), name="ck_wes_controller_key"),
        sa.CheckConstraint(_digest_or_empty("worker_key_id"), name="ck_wes_worker_key"),
        sa.CheckConstraint(_digest("release_digest"), name="ck_wes_release_digest"),
        sa.CheckConstraint(_digest_or_empty("offer_digest"), name="ck_wes_offer_digest"),
        sa.CheckConstraint(_digest_or_empty("result_digest"), name="ck_wes_result_digest"),
        sa.CheckConstraint(
            _bounded("controller_installation_id", 8, 64), name="ck_wes_controller_install"
        ),
        sa.CheckConstraint(
            _bounded_or_empty("worker_installation_id", 8, 64), name="ck_wes_worker_install"
        ),
        sa.CheckConstraint("length(refusal_reason) <= 64", name="ck_wes_reason_code"),
        sa.CheckConstraint(
            "refusal_reason = '' OR state IN ('refused','recovery_required')",
            name="ck_wes_reason_only_when_terminal",
        ),
        sa.CheckConstraint(
            _bounded("deployment_site_label", 1, 120), name="ck_deployment_site_label_bounded"
        ),
    )
    op.create_index("ix_wes_sweep", "worker_enrollment_state", ["state", "expires_at_ts"])
    op.create_index(
        "ix_wes_org_site", "worker_enrollment_state", ["organization_id", "deployment_site_label"]
    )

    op.create_table(
        "worker_enrollment_revision",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "enrollment_id",
            sa.String(length=80),
            sa.ForeignKey("worker_enrollment_state.enrollment_id"),
            nullable=False,
            index=True,
        ),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("state_digest", sa.String(length=80), nullable=False),
        sa.Column("predecessor_digest", sa.String(length=80), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("enrollment_id", "revision", name="uq_worker_enrollment_revision"),
        sa.CheckConstraint("revision >= 0", name="ck_wer_revision_nonnegative"),
        sa.CheckConstraint(_in("state", _STATES), name="ck_wer_state_closed"),
        sa.CheckConstraint(_digest("state_digest"), name="ck_wer_state_digest"),
        sa.CheckConstraint(_digest_or_empty("predecessor_digest"), name="ck_wer_predecessor"),
    )

    op.create_table(
        "worker_enrollment_step_receipt",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "enrollment_id",
            sa.String(length=80),
            sa.ForeignKey("worker_enrollment_state.enrollment_id"),
            nullable=False,
            index=True,
        ),
        sa.Column("step", sa.String(length=40), nullable=False),
        sa.Column("input_digest", sa.String(length=80), nullable=False),
        sa.Column("resulting_revision", sa.Integer(), nullable=False),
        sa.Column("resulting_state_digest", sa.String(length=80), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "enrollment_id", "step", "input_digest", name="uq_worker_enrollment_step_receipt"
        ),
        sa.CheckConstraint(_in("step", _STEPS), name="ck_wesr_step_closed"),
        sa.CheckConstraint("resulting_revision >= 0", name="ck_wesr_revision_nonnegative"),
        sa.CheckConstraint(_digest("input_digest"), name="ck_wesr_input_digest"),
        sa.CheckConstraint(_digest("resulting_state_digest"), name="ck_wesr_result_digest"),
    )


def downgrade() -> None:
    # dependency order: receipts + revisions reference the head row.
    op.drop_table("worker_enrollment_step_receipt")
    op.drop_table("worker_enrollment_revision")
    op.drop_index("ix_wes_org_site", table_name="worker_enrollment_state")
    op.drop_index("ix_wes_sweep", table_name="worker_enrollment_state")
    op.drop_table("worker_enrollment_state")
    op.drop_index("ix_wei_org_site", table_name="worker_enrollment_invitation")
    op.drop_table("worker_enrollment_invitation")
