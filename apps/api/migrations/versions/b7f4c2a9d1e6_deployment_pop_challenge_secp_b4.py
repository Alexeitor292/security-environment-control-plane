"""durable remote-PoP challenge store (SECP-B4 corrective)

Revision ID: b7f4c2a9d1e6
Revises: e03ec7dce4ad
Create Date: 2026-07-05
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b7f4c2a9d1e6"
down_revision: str | None = "e03ec7dce4ad"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "staging_deployment_pop_challenge",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("nonce", sa.String(length=96), nullable=False),
        sa.Column("deployment_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("operation_fingerprint", sa.String(length=90), nullable=False),
        sa.Column("worker_registration_id", sa.Uuid(), nullable=True),
        sa.Column("worker_identity_version", sa.Integer(), nullable=False),
        sa.Column("plan_hash", sa.String(length=80), nullable=False),
        sa.Column("consumed", sa.Boolean(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("nonce", name="uq_staging_deploy_pop_nonce"),
    )
    op.create_index(
        "ix_staging_deployment_pop_challenge_nonce",
        "staging_deployment_pop_challenge",
        ["nonce"],
    )
    op.create_index(
        "ix_staging_deployment_pop_challenge_deployment_id",
        "staging_deployment_pop_challenge",
        ["deployment_id"],
    )
    op.create_index(
        "ix_staging_deployment_pop_challenge_organization_id",
        "staging_deployment_pop_challenge",
        ["organization_id"],
    )
    # Persist the exact observed provider locator + per-resource ownership marker on each resource
    # record, so rollback/teardown fresh-reads the actual object (never a generic generated label).
    with op.batch_alter_table("staging_deployment_resource") as batch:
        batch.add_column(sa.Column("observed_locator", sa.JSON(), nullable=True))
        batch.add_column(sa.Column("ownership_marker", sa.String(length=200), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("staging_deployment_resource") as batch:
        batch.drop_column("ownership_marker")
        batch.drop_column("observed_locator")
    op.drop_index(
        "ix_staging_deployment_pop_challenge_organization_id",
        table_name="staging_deployment_pop_challenge",
    )
    op.drop_index(
        "ix_staging_deployment_pop_challenge_deployment_id",
        table_name="staging_deployment_pop_challenge",
    )
    op.drop_index(
        "ix_staging_deployment_pop_challenge_nonce",
        table_name="staging_deployment_pop_challenge",
    )
    op.drop_table("staging_deployment_pop_challenge")
