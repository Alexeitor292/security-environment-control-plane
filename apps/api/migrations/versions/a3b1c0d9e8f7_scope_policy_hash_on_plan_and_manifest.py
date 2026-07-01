"""Bind provisioning scope-policy hash to plan and manifest (SECP-002B-0).

Adds ``target_scope_policy_hash`` (nullable String(80)) to:
  - ``deployment_plan``: captured at plan-generation time; plan approval then covers
    the exact scope policy in effect, not just the target config hash.
  - ``provisioning_manifest``: copied from the plan at manifest-generation time;
    the manifest is fully self-describing with respect to its scope binding.

Nullable so that pre-migration rows are preserved; the application layer fails
closed when the column is NULL (refuses manifest generation and worker execution).

Revision ID: a3b1c0d9e8f7
Revises: 7f15807ffed4
Create Date: 2026-06-30
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a3b1c0d9e8f7"
down_revision: str | None = "7f15807ffed4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "deployment_plan",
        sa.Column("target_scope_policy_hash", sa.String(length=80), nullable=True),
    )
    op.add_column(
        "provisioning_manifest",
        sa.Column("target_scope_policy_hash", sa.String(length=80), nullable=True),
    )


def downgrade() -> None:
    with op.batch_alter_table("provisioning_manifest", schema=None) as batch_op:
        batch_op.drop_column("target_scope_policy_hash")
    with op.batch_alter_table("deployment_plan", schema=None) as batch_op:
        batch_op.drop_column("target_scope_policy_hash")
