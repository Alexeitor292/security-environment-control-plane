"""live-read authorization contract (SECP-002B-1B-6)

Revision ID: f2a6c1d8e9b0
Revises: c9d7e4f2a6b1
Create Date: 2026-07-02
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f2a6c1d8e9b0"
down_revision: str | None = "c9d7e4f2a6b1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "live_read_authorization",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("execution_target_id", sa.Uuid(), nullable=False),
        sa.Column("onboarding_id", sa.Uuid(), nullable=False),
        sa.Column("connection_hash", sa.String(length=80), nullable=False),
        sa.Column("boundary_hash", sa.String(length=80), nullable=False),
        sa.Column("authorization_version", sa.Integer(), nullable=False),
        sa.Column("authorization_expiry", sa.DateTime(timezone=True), nullable=False),
        sa.Column("collector_contract_version", sa.String(length=120), nullable=False),
        sa.Column("endpoint_allowlist_version", sa.String(length=120), nullable=False),
        sa.Column("evidence_source", sa.String(length=80), nullable=False),
        sa.Column("verification_level", sa.String(length=40), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("approved_by", sa.Uuid(), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.Uuid(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason_code", sa.String(length=80), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["execution_target_id"], ["execution_target.id"]),
        sa.ForeignKeyConstraint(["onboarding_id"], ["target_onboarding.id"]),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "execution_target_id",
            "onboarding_id",
            "authorization_version",
            name="uq_live_read_authorization_target_onboarding_version",
        ),
    )
    with op.batch_alter_table("live_read_authorization", schema=None) as b:
        b.create_index(b.f("ix_live_read_authorization_boundary_hash"), ["boundary_hash"])
        b.create_index(b.f("ix_live_read_authorization_connection_hash"), ["connection_hash"])
        b.create_index(
            b.f("ix_live_read_authorization_execution_target_id"),
            ["execution_target_id"],
        )
        b.create_index(b.f("ix_live_read_authorization_onboarding_id"), ["onboarding_id"])
        b.create_index(b.f("ix_live_read_authorization_organization_id"), ["organization_id"])


def downgrade() -> None:
    with op.batch_alter_table("live_read_authorization", schema=None) as b:
        b.drop_index(b.f("ix_live_read_authorization_organization_id"))
        b.drop_index(b.f("ix_live_read_authorization_onboarding_id"))
        b.drop_index(b.f("ix_live_read_authorization_execution_target_id"))
        b.drop_index(b.f("ix_live_read_authorization_connection_hash"))
        b.drop_index(b.f("ix_live_read_authorization_boundary_hash"))
    op.drop_table("live_read_authorization")
