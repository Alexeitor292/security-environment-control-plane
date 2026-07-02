"""read-only target evidence records (SECP-002B-1B-1)

Revision ID: c9d7e4f2a6b1
Revises: b8e5f1c9d3a2
Create Date: 2026-07-02
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c9d7e4f2a6b1"
down_revision: str | None = "b8e5f1c9d3a2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "target_evidence_record",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("onboarding_id", sa.Uuid(), nullable=False),
        sa.Column("execution_target_id", sa.Uuid(), nullable=False),
        sa.Column("evidence_source", sa.String(length=80), nullable=False),
        sa.Column("verification_level", sa.String(length=40), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("evidence_payload", sa.JSON(), nullable=False),
        sa.Column("findings", sa.JSON(), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence_hash", sa.String(length=80), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["execution_target_id"], ["execution_target.id"]),
        sa.ForeignKeyConstraint(["onboarding_id"], ["target_onboarding.id"]),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_target_evidence_record_evidence_hash",
        "target_evidence_record",
        ["evidence_hash"],
    )
    op.create_index(
        "ix_target_evidence_record_execution_target_id",
        "target_evidence_record",
        ["execution_target_id"],
    )
    op.create_index(
        "ix_target_evidence_record_onboarding_id",
        "target_evidence_record",
        ["onboarding_id"],
    )
    op.create_index(
        "ix_target_evidence_record_organization_id",
        "target_evidence_record",
        ["organization_id"],
    )
    with op.batch_alter_table("target_preflight", schema=None) as b:
        b.add_column(sa.Column("target_evidence_id", sa.Uuid(), nullable=True))
        b.add_column(sa.Column("target_evidence_hash", sa.String(length=80), nullable=True))
        b.create_foreign_key(
            "fk_target_preflight_target_evidence_id",
            "target_evidence_record",
            ["target_evidence_id"],
            ["id"],
        )
    op.create_index(
        "ix_target_preflight_target_evidence_id",
        "target_preflight",
        ["target_evidence_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_target_preflight_target_evidence_id", table_name="target_preflight")
    with op.batch_alter_table("target_preflight", schema=None) as b:
        b.drop_constraint("fk_target_preflight_target_evidence_id", type_="foreignkey")
        b.drop_column("target_evidence_hash")
        b.drop_column("target_evidence_id")
    op.drop_index("ix_target_evidence_record_organization_id", table_name="target_evidence_record")
    op.drop_index("ix_target_evidence_record_onboarding_id", table_name="target_evidence_record")
    op.drop_index(
        "ix_target_evidence_record_execution_target_id", table_name="target_evidence_record"
    )
    op.drop_index("ix_target_evidence_record_evidence_hash", table_name="target_evidence_record")
    op.drop_table("target_evidence_record")
