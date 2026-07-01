"""target onboarding and preflight evidence (SECP-002B-1B-0)

Adds:
  - ``target_onboarding`` — provider-neutral onboarding record binding an execution
    target to an onboarding mode, isolation model, immutable declared boundary, and a
    human approval (ADR-014).
  - ``target_preflight`` — immutable, redacted, structured onboarding preflight evidence.

Enum-backed columns are stored as strings (the app enforces the enum via ``EnumType``).

Revision ID: f6b3d2a1c8e0
Revises: e5a2f1b8c9d0
Create Date: 2026-07-01
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f6b3d2a1c8e0"
down_revision: str | None = "e5a2f1b8c9d0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "target_onboarding",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("execution_target_id", sa.Uuid(), nullable=False),
        sa.Column("onboarding_mode", sa.String(length=40), nullable=False),
        sa.Column("isolation_model", sa.String(length=40), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("declared_boundary", sa.JSON(), nullable=False),
        sa.Column("boundary_hash", sa.String(length=80), nullable=False),
        sa.Column("approved_target_config_hash", sa.String(length=80), nullable=True),
        sa.Column("approved_scope_policy_hash", sa.String(length=80), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("decided_by", sa.Uuid(), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decision_reason", sa.Text(), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["execution_target_id"], ["execution_target.id"]),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("target_onboarding", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_target_onboarding_boundary_hash"), ["boundary_hash"], unique=False
        )
        batch_op.create_index(
            batch_op.f("ix_target_onboarding_execution_target_id"),
            ["execution_target_id"],
            unique=False,
        )
        batch_op.create_index(
            batch_op.f("ix_target_onboarding_organization_id"),
            ["organization_id"],
            unique=False,
        )

    op.create_table(
        "target_preflight",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("onboarding_id", sa.Uuid(), nullable=False),
        sa.Column("collector", sa.String(length=60), nullable=False),
        sa.Column("passed", sa.Boolean(), nullable=False),
        sa.Column("checks", sa.JSON(), nullable=False),
        sa.Column("evidence_hash", sa.String(length=80), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["onboarding_id"], ["target_onboarding.id"]),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("target_preflight", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_target_preflight_evidence_hash"), ["evidence_hash"], unique=False
        )
        batch_op.create_index(
            batch_op.f("ix_target_preflight_onboarding_id"), ["onboarding_id"], unique=False
        )
        batch_op.create_index(
            batch_op.f("ix_target_preflight_organization_id"), ["organization_id"], unique=False
        )


def downgrade() -> None:
    with op.batch_alter_table("target_preflight", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_target_preflight_organization_id"))
        batch_op.drop_index(batch_op.f("ix_target_preflight_onboarding_id"))
        batch_op.drop_index(batch_op.f("ix_target_preflight_evidence_hash"))
    op.drop_table("target_preflight")

    with op.batch_alter_table("target_onboarding", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_target_onboarding_organization_id"))
        batch_op.drop_index(batch_op.f("ix_target_onboarding_execution_target_id"))
        batch_op.drop_index(batch_op.f("ix_target_onboarding_boundary_hash"))
    op.drop_table("target_onboarding")
