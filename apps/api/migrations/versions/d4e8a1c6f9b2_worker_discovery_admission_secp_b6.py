"""worker discovery admission + SSH endpoint binding hash (SECP-B6 MB-1/MB-2)

Revision ID: d4e8a1c6f9b2
Revises: c9e1a4f7b2d5
Create Date: 2026-07-07
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d4e8a1c6f9b2"
down_revision: str | None = "c9e1a4f7b2d5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # MB-2: immutable, secret-free SSH endpoint-binding digest on the live-read authorization.
    op.add_column(
        "live_read_authorization",
        sa.Column("endpoint_binding_hash", sa.String(length=80), nullable=True),
    )

    # MB-1: durable, one-time, control-plane-verified worker discovery admission.
    op.create_table(
        "worker_discovery_admission",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("worker_registration_id", sa.Uuid(), nullable=False),
        sa.Column("identity_version", sa.Integer(), nullable=False),
        sa.Column("discovery_job_id", sa.Uuid(), nullable=False),
        sa.Column("enrollment_id", sa.Uuid(), nullable=False),
        sa.Column("execution_target_id", sa.Uuid(), nullable=False),
        sa.Column("onboarding_id", sa.Uuid(), nullable=False),
        sa.Column("live_read_authorization_id", sa.Uuid(), nullable=False),
        sa.Column("authorization_version", sa.Integer(), nullable=False),
        sa.Column("endpoint_binding_hash", sa.String(length=80), nullable=False),
        sa.Column("purpose", sa.String(length=60), nullable=False),
        sa.Column("nonce", sa.String(length=96), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("admitted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.ForeignKeyConstraint(
            ["worker_registration_id"], ["worker_identity_registration.id"]
        ),
        sa.ForeignKeyConstraint(["discovery_job_id"], ["discovery_job.id"]),
        sa.ForeignKeyConstraint(["enrollment_id"], ["target_discovery_enrollment.id"]),
        sa.ForeignKeyConstraint(["execution_target_id"], ["execution_target.id"]),
        sa.ForeignKeyConstraint(["onboarding_id"], ["target_onboarding.id"]),
        sa.ForeignKeyConstraint(
            ["live_read_authorization_id"], ["live_read_authorization.id"]
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("nonce", name="uq_worker_discovery_admission_nonce"),
    )
    op.create_index(
        "ix_worker_discovery_admission_organization_id",
        "worker_discovery_admission",
        ["organization_id"],
    )
    op.create_index(
        "ix_worker_discovery_admission_worker_registration_id",
        "worker_discovery_admission",
        ["worker_registration_id"],
    )
    op.create_index(
        "ix_worker_discovery_admission_discovery_job_id",
        "worker_discovery_admission",
        ["discovery_job_id"],
    )
    op.create_index(
        "ix_worker_discovery_admission_enrollment_id",
        "worker_discovery_admission",
        ["enrollment_id"],
    )
    op.create_index(
        "ix_worker_discovery_admission_nonce", "worker_discovery_admission", ["nonce"]
    )


def downgrade() -> None:
    op.drop_index(
        "ix_worker_discovery_admission_nonce", table_name="worker_discovery_admission"
    )
    op.drop_index(
        "ix_worker_discovery_admission_enrollment_id", table_name="worker_discovery_admission"
    )
    op.drop_index(
        "ix_worker_discovery_admission_discovery_job_id",
        table_name="worker_discovery_admission",
    )
    op.drop_index(
        "ix_worker_discovery_admission_worker_registration_id",
        table_name="worker_discovery_admission",
    )
    op.drop_index(
        "ix_worker_discovery_admission_organization_id",
        table_name="worker_discovery_admission",
    )
    op.drop_table("worker_discovery_admission")
    op.drop_column("live_read_authorization", "endpoint_binding_hash")
