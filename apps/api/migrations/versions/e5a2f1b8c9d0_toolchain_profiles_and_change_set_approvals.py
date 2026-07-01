"""toolchain profiles, change-set approvals, and toolchain bindings (SECP-002B-1A)

Adds:
  - ``toolchain_profile`` — immutable, secret-free, provider-neutral toolchain
    provenance bound to an execution target (ADR-013).
  - ``provisioning_change_set_approval`` — durable human approval of an exact,
    redacted dry-run change-set hash for apply/destroy on the real OpenTofu path.
  - ``toolchain_profile_id`` + ``toolchain_profile_hash`` (nullable) on
    ``deployment_plan`` and ``provisioning_manifest``. Nullable so the Simulator and
    fake-runner (B0) paths are unaffected; the real-lab activation gate fails closed
    when either is NULL.

Enum-backed columns are stored as strings (the app enforces the enum via ``EnumType``).

Revision ID: e5a2f1b8c9d0
Revises: a3b1c0d9e8f7
Create Date: 2026-06-30
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "e5a2f1b8c9d0"
down_revision: str | None = "a3b1c0d9e8f7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "toolchain_profile",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("execution_target_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("runner_kind", sa.String(length=60), nullable=False),
        sa.Column("activation_class", sa.String(length=60), nullable=False),
        sa.Column("renderer_version", sa.String(length=60), nullable=False),
        sa.Column("content", sa.JSON(), nullable=False),
        sa.Column("content_hash", sa.String(length=80), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["execution_target_id"], ["execution_target.id"]),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("execution_target_id", "version"),
    )
    with op.batch_alter_table("toolchain_profile", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_toolchain_profile_content_hash"), ["content_hash"], unique=False
        )
        batch_op.create_index(
            batch_op.f("ix_toolchain_profile_execution_target_id"),
            ["execution_target_id"],
            unique=False,
        )
        batch_op.create_index(
            batch_op.f("ix_toolchain_profile_organization_id"),
            ["organization_id"],
            unique=False,
        )

    op.create_table(
        "provisioning_change_set_approval",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("manifest_id", sa.Uuid(), nullable=False),
        sa.Column("toolchain_profile_id", sa.Uuid(), nullable=False),
        sa.Column("authorizes_kind", sa.String(length=40), nullable=False),
        sa.Column("change_set_hash", sa.String(length=80), nullable=False),
        sa.Column("rendered_workspace_hash", sa.String(length=80), nullable=False),
        sa.Column("manifest_content_hash", sa.String(length=80), nullable=False),
        sa.Column("toolchain_profile_hash", sa.String(length=80), nullable=False),
        sa.Column("target_scope_policy_hash", sa.String(length=80), nullable=False),
        sa.Column("reservations_hash", sa.String(length=80), nullable=False),
        sa.Column("renderer_version", sa.String(length=60), nullable=False),
        sa.Column("module_bundle_hash", sa.String(length=80), nullable=False),
        sa.Column("summary", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("decided_by", sa.Uuid(), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decision_reason", sa.Text(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["manifest_id"], ["provisioning_manifest.id"]),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.ForeignKeyConstraint(["toolchain_profile_id"], ["toolchain_profile.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("manifest_id", "authorizes_kind", "change_set_hash"),
    )
    with op.batch_alter_table("provisioning_change_set_approval", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_provisioning_change_set_approval_change_set_hash"),
            ["change_set_hash"],
            unique=False,
        )
        batch_op.create_index(
            batch_op.f("ix_provisioning_change_set_approval_manifest_id"),
            ["manifest_id"],
            unique=False,
        )
        batch_op.create_index(
            batch_op.f("ix_provisioning_change_set_approval_organization_id"),
            ["organization_id"],
            unique=False,
        )
        batch_op.create_index(
            batch_op.f("ix_provisioning_change_set_approval_toolchain_profile_id"),
            ["toolchain_profile_id"],
            unique=False,
        )

    # Nullable pins on existing tables. No DB-level FK is added here (mirrors the
    # a3b1c0d9e8f7 pattern): the columns are nullable and the app enforces integrity,
    # so the ALTER is a plain add-column that is portable across SQLite and PostgreSQL.
    op.add_column("deployment_plan", sa.Column("toolchain_profile_id", sa.Uuid(), nullable=True))
    op.add_column(
        "deployment_plan",
        sa.Column("toolchain_profile_hash", sa.String(length=80), nullable=True),
    )
    op.add_column(
        "provisioning_manifest", sa.Column("toolchain_profile_id", sa.Uuid(), nullable=True)
    )
    op.add_column(
        "provisioning_manifest",
        sa.Column("toolchain_profile_hash", sa.String(length=80), nullable=True),
    )


def downgrade() -> None:
    with op.batch_alter_table("provisioning_manifest", schema=None) as batch_op:
        batch_op.drop_column("toolchain_profile_hash")
        batch_op.drop_column("toolchain_profile_id")
    with op.batch_alter_table("deployment_plan", schema=None) as batch_op:
        batch_op.drop_column("toolchain_profile_hash")
        batch_op.drop_column("toolchain_profile_id")

    with op.batch_alter_table("provisioning_change_set_approval", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_provisioning_change_set_approval_toolchain_profile_id"))
        batch_op.drop_index(batch_op.f("ix_provisioning_change_set_approval_organization_id"))
        batch_op.drop_index(batch_op.f("ix_provisioning_change_set_approval_manifest_id"))
        batch_op.drop_index(batch_op.f("ix_provisioning_change_set_approval_change_set_hash"))
    op.drop_table("provisioning_change_set_approval")

    with op.batch_alter_table("toolchain_profile", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_toolchain_profile_organization_id"))
        batch_op.drop_index(batch_op.f("ix_toolchain_profile_execution_target_id"))
        batch_op.drop_index(batch_op.f("ix_toolchain_profile_content_hash"))
    op.drop_table("toolchain_profile")
