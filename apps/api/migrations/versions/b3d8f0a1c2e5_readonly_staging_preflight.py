"""app-owned read-only staging preflight (SECP-B2-0)

Revision ID: b3d8f0a1c2e5
Revises: a7f3c9e21b40
Create Date: 2026-07-04
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b3d8f0a1c2e5"
down_revision: str | None = "a7f3c9e21b40"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "readonly_staging_preflight",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("execution_target_id", sa.Uuid(), nullable=False),
        sa.Column("onboarding_id", sa.Uuid(), nullable=False),
        sa.Column("live_read_authorization_id", sa.Uuid(), nullable=False),
        sa.Column("authorization_version", sa.Integer(), nullable=False),
        sa.Column("collector_contract_version", sa.String(length=120), nullable=False),
        sa.Column("endpoint_allowlist_version", sa.String(length=120), nullable=False),
        sa.Column("operation_fingerprint", sa.String(length=80), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("outcome_code", sa.String(length=40), nullable=True),
        sa.Column("readiness_facts", sa.JSON(), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["execution_target_id"], ["execution_target.id"]),
        sa.ForeignKeyConstraint(["live_read_authorization_id"], ["live_read_authorization.id"]),
        sa.ForeignKeyConstraint(["onboarding_id"], ["target_onboarding.id"]),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("operation_fingerprint", name="uq_readonly_preflight_fingerprint"),
        sa.UniqueConstraint(
            "execution_target_id",
            "onboarding_id",
            "live_read_authorization_id",
            "authorization_version",
            name="uq_readonly_preflight_scope",
        ),
    )
    with op.batch_alter_table("readonly_staging_preflight", schema=None) as b:
        b.create_index(
            b.f("ix_readonly_staging_preflight_organization_id"), ["organization_id"]
        )
        b.create_index(
            b.f("ix_readonly_staging_preflight_execution_target_id"), ["execution_target_id"]
        )
        b.create_index(b.f("ix_readonly_staging_preflight_onboarding_id"), ["onboarding_id"])
        b.create_index(
            b.f("ix_readonly_staging_preflight_live_read_authorization_id"),
            ["live_read_authorization_id"],
        )
        b.create_index(
            "uq_readonly_preflight_active",
            ["execution_target_id", "onboarding_id", "live_read_authorization_id"],
            unique=True,
            sqlite_where=sa.text("status in ('queued','claimed','running')"),
            postgresql_where=sa.text("status in ('queued','claimed','running')"),
        )


def downgrade() -> None:
    with op.batch_alter_table("readonly_staging_preflight", schema=None) as b:
        b.drop_index("uq_readonly_preflight_active")
        b.drop_index(b.f("ix_readonly_staging_preflight_live_read_authorization_id"))
        b.drop_index(b.f("ix_readonly_staging_preflight_onboarding_id"))
        b.drop_index(b.f("ix_readonly_staging_preflight_execution_target_id"))
        b.drop_index(b.f("ix_readonly_staging_preflight_organization_id"))
    op.drop_table("readonly_staging_preflight")
