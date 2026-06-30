"""correction pass outbox and discovery integrity

Revision ID: d4c2e7f9a8b1
Revises: 29900a63b28f
Create Date: 2026-06-30 16:10:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "d4c2e7f9a8b1"
down_revision: str | None = "29900a63b28f"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "workflow_dispatch_outbox",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("workflow_run_id", sa.Uuid(), nullable=False),
        sa.Column("workflow", sa.String(length=120), nullable=False),
        sa.Column("workflow_id", sa.String(length=255), nullable=False),
        sa.Column("task_queue", sa.String(length=255), nullable=False),
        sa.Column("args", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.ForeignKeyConstraint(["workflow_run_id"], ["workflow_run.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("workflow_id"),
        sa.UniqueConstraint("workflow_run_id"),
    )
    with op.batch_alter_table("workflow_dispatch_outbox", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_workflow_dispatch_outbox_organization_id"),
            ["organization_id"],
            unique=False,
        )
        batch_op.create_index(
            batch_op.f("ix_workflow_dispatch_outbox_workflow_run_id"),
            ["workflow_run_id"],
            unique=False,
        )

    with op.batch_alter_table("workflow_run", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_workflow_run_snapshot_id"), ["snapshot_id"])
        batch_op.create_foreign_key(
            "fk_workflow_run_snapshot",
            "provider_inventory_snapshot",
            ["snapshot_id"],
            ["id"],
        )

    with op.batch_alter_table("provider_inventory_snapshot", schema=None) as batch_op:
        batch_op.drop_column("workflow_run_id")


def downgrade() -> None:
    with op.batch_alter_table("provider_inventory_snapshot", schema=None) as batch_op:
        batch_op.add_column(sa.Column("workflow_run_id", sa.Uuid(), nullable=True))

    with op.batch_alter_table("workflow_run", schema=None) as batch_op:
        batch_op.drop_constraint("fk_workflow_run_snapshot", type_="foreignkey")
        batch_op.drop_index(batch_op.f("ix_workflow_run_snapshot_id"))

    with op.batch_alter_table("workflow_dispatch_outbox", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_workflow_dispatch_outbox_workflow_run_id"))
        batch_op.drop_index(batch_op.f("ix_workflow_dispatch_outbox_organization_id"))
    op.drop_table("workflow_dispatch_outbox")
