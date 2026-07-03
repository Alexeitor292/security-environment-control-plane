"""declarative disposable staging lab workflow (SECP-002B-1B-9)

Revision ID: a7f3c9e21b40
Revises: f2a6c1d8e9b0
Create Date: 2026-07-03
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a7f3c9e21b40"
down_revision: str | None = "f2a6c1d8e9b0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "staging_lab",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("execution_target_id", sa.Uuid(), nullable=False),
        sa.Column("display_name", sa.String(length=200), nullable=False),
        sa.Column("ownership_label", sa.String(length=120), nullable=False),
        sa.Column("purpose", sa.String(length=60), nullable=False),
        sa.Column("profile", sa.String(length=60), nullable=False),
        sa.Column("network_intent", sa.String(length=60), nullable=False),
        sa.Column("resource_class", sa.String(length=40), nullable=False),
        sa.Column("rollback_policy", sa.String(length=60), nullable=False),
        sa.Column("bootstrap_artifact_profile_id", sa.String(length=120), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("plan_version", sa.Integer(), nullable=False),
        sa.Column("plan_hash", sa.String(length=80), nullable=False),
        sa.Column("desired_state", sa.JSON(), nullable=True),
        sa.Column("idempotency_key", sa.String(length=80), nullable=False),
        sa.Column("simulated_observed_state", sa.JSON(), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("approved_by", sa.Uuid(), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("approved_plan_hash", sa.String(length=80), nullable=False),
        sa.Column("approved_plan_version", sa.Integer(), nullable=False),
        sa.Column("decision_reason", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["execution_target_id"], ["execution_target.id"]),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("idempotency_key", name="uq_staging_lab_idempotency_key"),
    )
    with op.batch_alter_table("staging_lab", schema=None) as b:
        b.create_index(b.f("ix_staging_lab_execution_target_id"), ["execution_target_id"])
        b.create_index(b.f("ix_staging_lab_organization_id"), ["organization_id"])
        b.create_index(b.f("ix_staging_lab_ownership_label"), ["ownership_label"])
        b.create_index(b.f("ix_staging_lab_plan_hash"), ["plan_hash"])


def downgrade() -> None:
    with op.batch_alter_table("staging_lab", schema=None) as b:
        b.drop_index(b.f("ix_staging_lab_plan_hash"))
        b.drop_index(b.f("ix_staging_lab_ownership_label"))
        b.drop_index(b.f("ix_staging_lab_organization_id"))
        b.drop_index(b.f("ix_staging_lab_execution_target_id"))
    op.drop_table("staging_lab")
