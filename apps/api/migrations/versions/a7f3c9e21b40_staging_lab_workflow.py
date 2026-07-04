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
        sa.Column("bootstrap_artifact_profile", sa.String(length=60), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
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

    op.create_table(
        "staging_lab_work_item",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("staging_lab_id", sa.Uuid(), nullable=False),
        sa.Column("operation_kind", sa.String(length=40), nullable=False),
        sa.Column("plan_hash", sa.String(length=80), nullable=False),
        sa.Column("plan_version", sa.Integer(), nullable=False),
        sa.Column("idempotency_key", sa.String(length=80), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("failure_reason", sa.String(length=200), nullable=False),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.ForeignKeyConstraint(["staging_lab_id"], ["staging_lab.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("idempotency_key", name="uq_staging_work_idempotency_key"),
    )
    with op.batch_alter_table("staging_lab_work_item", schema=None) as b:
        b.create_index(b.f("ix_staging_lab_work_item_organization_id"), ["organization_id"])
        b.create_index(b.f("ix_staging_lab_work_item_staging_lab_id"), ["staging_lab_id"])
        b.create_index(b.f("ix_staging_lab_work_item_plan_hash"), ["plan_hash"])
        b.create_index(
            "uq_staging_work_active",
            ["staging_lab_id", "operation_kind"],
            unique=True,
            sqlite_where=sa.text("status in ('queued','claimed')"),
            postgresql_where=sa.text("status in ('queued','claimed')"),
        )

    op.create_table(
        "staging_substrate_eligibility",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("execution_target_id", sa.Uuid(), nullable=False),
        sa.Column("plugin_type", sa.String(length=40), nullable=False),
        sa.Column("allowed_profile", sa.String(length=60), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("issued_by", sa.Uuid(), nullable=True),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_by", sa.Uuid(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["execution_target_id"], ["execution_target.id"]),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("staging_substrate_eligibility", schema=None) as b:
        b.create_index(
            b.f("ix_staging_substrate_eligibility_organization_id"), ["organization_id"]
        )
        b.create_index(
            b.f("ix_staging_substrate_eligibility_execution_target_id"),
            ["execution_target_id"],
        )
        b.create_index(
            "uq_staging_substrate_active",
            ["execution_target_id"],
            unique=True,
            sqlite_where=sa.text("status = 'active'"),
            postgresql_where=sa.text("status = 'active'"),
        )


def downgrade() -> None:
    with op.batch_alter_table("staging_substrate_eligibility", schema=None) as b:
        b.drop_index("uq_staging_substrate_active")
        b.drop_index(b.f("ix_staging_substrate_eligibility_execution_target_id"))
        b.drop_index(b.f("ix_staging_substrate_eligibility_organization_id"))
    op.drop_table("staging_substrate_eligibility")
    with op.batch_alter_table("staging_lab_work_item", schema=None) as b:
        b.drop_index("uq_staging_work_active")
        b.drop_index(b.f("ix_staging_lab_work_item_plan_hash"))
        b.drop_index(b.f("ix_staging_lab_work_item_staging_lab_id"))
        b.drop_index(b.f("ix_staging_lab_work_item_organization_id"))
    op.drop_table("staging_lab_work_item")
    with op.batch_alter_table("staging_lab", schema=None) as b:
        b.drop_index(b.f("ix_staging_lab_plan_hash"))
        b.drop_index(b.f("ix_staging_lab_ownership_label"))
        b.drop_index(b.f("ix_staging_lab_organization_id"))
        b.drop_index(b.f("ix_staging_lab_execution_target_id"))
    op.drop_table("staging_lab")
