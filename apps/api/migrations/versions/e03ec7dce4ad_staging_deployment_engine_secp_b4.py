"""staging deployment engine (SECP-B4)

Revision ID: e03ec7dce4ad
Revises: f3b8d1c6a4e9
Create Date: 2026-07-05
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "e03ec7dce4ad"
down_revision: str | None = "f3b8d1c6a4e9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_INFLIGHT = sa.text("status IN ('queued','claimed','running')")


def upgrade() -> None:
    op.create_table(
        "staging_deployment",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("execution_target_id", sa.Uuid(), nullable=False),
        sa.Column("onboarding_id", sa.Uuid(), nullable=False),
        sa.Column("display_name", sa.String(length=200), nullable=False),
        sa.Column("ownership_label", sa.String(length=120), nullable=False),
        sa.Column("resource_profile", sa.String(length=60), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("decision_code", sa.String(length=40), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("plan_version", sa.Integer(), nullable=False),
        sa.Column("plan_hash", sa.String(length=80), nullable=False),
        sa.Column("approved_plan_hash", sa.String(length=80), nullable=False),
        sa.Column("approved_by", sa.Uuid(), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failure_code", sa.String(length=60), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["execution_target_id"], ["execution_target.id"]),
        sa.ForeignKeyConstraint(["onboarding_id"], ["target_onboarding.id"]),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("staging_deployment", schema=None) as b:
        for col in (
            "execution_target_id",
            "onboarding_id",
            "organization_id",
            "ownership_label",
            "plan_hash",
        ):
            b.create_index(b.f(f"ix_staging_deployment_{col}"), [col])

    op.create_table(
        "staging_deployment_plan",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("deployment_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("plan_version", sa.Integer(), nullable=False),
        sa.Column("plan_hash", sa.String(length=80), nullable=False),
        sa.Column("ownership_tag", sa.String(length=120), nullable=False),
        sa.Column("capacity_assessment_hash", sa.String(length=80), nullable=False),
        sa.Column("artifact_manifest_id", sa.String(length=120), nullable=False),
        sa.Column("plan_document", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["deployment_id"], ["staging_deployment.id"]),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("deployment_id", "plan_hash", name="uq_staging_deploy_plan_hash"),
    )
    with op.batch_alter_table("staging_deployment_plan", schema=None) as b:
        for col in ("deployment_id", "organization_id", "plan_hash"):
            b.create_index(b.f(f"ix_staging_deployment_plan_{col}"), [col])

    op.create_table(
        "staging_deployment_approval",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("deployment_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("approved_plan_hash", sa.String(length=80), nullable=False),
        sa.Column("plan_version", sa.Integer(), nullable=False),
        sa.Column("onboarding_id", sa.Uuid(), nullable=False),
        sa.Column("ownership_tag", sa.String(length=120), nullable=False),
        sa.Column("capacity_assessment_hash", sa.String(length=80), nullable=False),
        sa.Column("artifact_manifest_id", sa.String(length=120), nullable=False),
        sa.Column("worker_identity_version", sa.Integer(), nullable=False),
        sa.Column("approved_by", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["deployment_id"], ["staging_deployment.id"]),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "deployment_id", "approved_plan_hash", name="uq_staging_deploy_approval"
        ),
    )
    with op.batch_alter_table("staging_deployment_approval", schema=None) as b:
        for col in ("deployment_id", "organization_id"):
            b.create_index(b.f(f"ix_staging_deployment_approval_{col}"), [col])

    op.create_table(
        "staging_deployment_operation",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("deployment_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("operation_kind", sa.String(length=40), nullable=False),
        sa.Column("operation_fingerprint", sa.String(length=90), nullable=False),
        sa.Column("plan_hash", sa.String(length=80), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("phase", sa.String(length=60), nullable=True),
        sa.Column("failure_code", sa.String(length=60), nullable=True),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["deployment_id"], ["staging_deployment.id"]),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("operation_fingerprint", name="uq_staging_deploy_op_fingerprint"),
    )
    with op.batch_alter_table("staging_deployment_operation", schema=None) as b:
        for col in ("deployment_id", "organization_id"):
            b.create_index(b.f(f"ix_staging_deployment_operation_{col}"), [col])
        b.create_index(
            "uq_staging_deploy_op_inflight",
            ["deployment_id"],
            unique=True,
            sqlite_where=_INFLIGHT,
            postgresql_where=_INFLIGHT,
        )

    op.create_table(
        "staging_deployment_resource",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("deployment_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("resource_kind", sa.String(length=40), nullable=False),
        sa.Column("ownership_tag", sa.String(length=120), nullable=False),
        sa.Column("resource_ref", sa.String(length=120), nullable=False),
        sa.Column("inverse_op", sa.String(length=40), nullable=False),
        sa.Column("state", sa.String(length=40), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["deployment_id"], ["staging_deployment.id"]),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "deployment_id", "resource_kind", "resource_ref", name="uq_staging_deploy_resource"
        ),
    )
    with op.batch_alter_table("staging_deployment_resource", schema=None) as b:
        for col in ("deployment_id", "organization_id", "ownership_tag"):
            b.create_index(b.f(f"ix_staging_deployment_resource_{col}"), [col])

    op.create_table(
        "staging_deployment_verification",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("deployment_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("operation_id", sa.Uuid(), nullable=False),
        sa.Column("check_code", sa.String(length=60), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["deployment_id"], ["staging_deployment.id"]),
        sa.ForeignKeyConstraint(["operation_id"], ["staging_deployment_operation.id"]),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("staging_deployment_verification", schema=None) as b:
        for col in ("deployment_id", "operation_id", "organization_id"):
            b.create_index(b.f(f"ix_staging_deployment_verification_{col}"), [col])


def downgrade() -> None:
    for table in (
        "staging_deployment_verification",
        "staging_deployment_resource",
        "staging_deployment_operation",
        "staging_deployment_approval",
        "staging_deployment_plan",
        "staging_deployment",
    ):
        op.drop_table(table)
