"""durable resolution-lease foundation (SECP-B2-3)

Revision ID: c4e9a1f7d2b3
Revises: b3d8f0a1c2e5
Create Date: 2026-07-04
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c4e9a1f7d2b3"
down_revision: str | None = "b3d8f0a1c2e5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "resolution_lease",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("live_read_authorization_id", sa.Uuid(), nullable=False),
        sa.Column("authorization_version", sa.Integer(), nullable=False),
        sa.Column("operation_fingerprint", sa.String(length=80), nullable=False),
        sa.Column("lease_id", sa.Uuid(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("worker_identity_id", sa.String(length=120), nullable=False),
        sa.Column("reason_code", sa.String(length=60), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["live_read_authorization_id"], ["live_read_authorization.id"]),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.PrimaryKeyConstraint("id"),
        # Global operation uniqueness boundary — NO worker identity.
        sa.UniqueConstraint(
            "live_read_authorization_id",
            "authorization_version",
            "operation_fingerprint",
            name="uq_resolution_lease_operation",
        ),
    )
    with op.batch_alter_table("resolution_lease", schema=None) as b:
        b.create_index(b.f("ix_resolution_lease_organization_id"), ["organization_id"])
        b.create_index(
            b.f("ix_resolution_lease_live_read_authorization_id"),
            ["live_read_authorization_id"],
        )


def downgrade() -> None:
    with op.batch_alter_table("resolution_lease", schema=None) as b:
        b.drop_index(b.f("ix_resolution_lease_live_read_authorization_id"))
        b.drop_index(b.f("ix_resolution_lease_organization_id"))
    op.drop_table("resolution_lease")
