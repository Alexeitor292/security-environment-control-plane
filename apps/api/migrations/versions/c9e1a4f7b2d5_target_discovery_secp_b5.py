"""worker-owned read-only target discovery (SECP-B5)

Revision ID: c9e1a4f7b2d5
Revises: b7f4c2a9d1e6
Create Date: 2026-07-06
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c9e1a4f7b2d5"
down_revision: str | None = "b7f4c2a9d1e6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_INFLIGHT = sa.text("status IN ('queued','claimed','running')")


def upgrade() -> None:
    op.create_table(
        "target_discovery_enrollment",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("execution_target_id", sa.Uuid(), nullable=False),
        sa.Column("onboarding_id", sa.Uuid(), nullable=False),
        sa.Column("display_name", sa.String(length=200), nullable=False),
        sa.Column("ownership_label", sa.String(length=120), nullable=False),
        sa.Column("resource_profile", sa.String(length=60), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("decision_code", sa.String(length=40), nullable=False),
        sa.Column("enrollment_version", sa.Integer(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("active_plan_hash", sa.String(length=80), nullable=False),
        sa.Column("approved_plan_hash", sa.String(length=80), nullable=False),
        sa.Column("approved_by", sa.Uuid(), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failure_code", sa.String(length=60), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.ForeignKeyConstraint(["execution_target_id"], ["execution_target.id"]),
        sa.ForeignKeyConstraint(["onboarding_id"], ["target_onboarding.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_target_discovery_enrollment_organization_id",
        "target_discovery_enrollment",
        ["organization_id"],
    )
    op.create_index(
        "ix_target_discovery_enrollment_execution_target_id",
        "target_discovery_enrollment",
        ["execution_target_id"],
    )
    op.create_index(
        "ix_target_discovery_enrollment_onboarding_id",
        "target_discovery_enrollment",
        ["onboarding_id"],
    )
    op.create_index(
        "ix_target_discovery_enrollment_ownership_label",
        "target_discovery_enrollment",
        ["ownership_label"],
    )
    op.create_index(
        "ix_target_discovery_enrollment_active_plan_hash",
        "target_discovery_enrollment",
        ["active_plan_hash"],
    )

    op.create_table(
        "discovery_job",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("enrollment_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("operation_fingerprint", sa.String(length=90), nullable=False),
        sa.Column("enrollment_version", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("phase", sa.String(length=60), nullable=True),
        sa.Column("failure_code", sa.String(length=60), nullable=True),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["enrollment_id"], ["target_discovery_enrollment.id"]),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("operation_fingerprint", name="uq_discovery_job_fingerprint"),
    )
    op.create_index("ix_discovery_job_enrollment_id", "discovery_job", ["enrollment_id"])
    op.create_index("ix_discovery_job_organization_id", "discovery_job", ["organization_id"])
    op.create_index(
        "uq_discovery_job_inflight",
        "discovery_job",
        ["enrollment_id"],
        unique=True,
        sqlite_where=_INFLIGHT,
        postgresql_where=_INFLIGHT,
    )

    op.create_table(
        "discovery_snapshot",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("enrollment_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.Column("enrollment_version", sa.Integer(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("evidence_hash", sa.String(length=80), nullable=False),
        sa.Column("capacity_snapshot_hash", sa.String(length=80), nullable=False),
        sa.Column("eligibility", sa.String(length=20), nullable=False),
        sa.Column("reason_code", sa.String(length=60), nullable=True),
        sa.Column("worker_identity_version", sa.Integer(), nullable=False),
        sa.Column("bundle_available", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["enrollment_id"], ["target_discovery_enrollment.id"]),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.ForeignKeyConstraint(["job_id"], ["discovery_job.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_discovery_snapshot_enrollment_id", "discovery_snapshot", ["enrollment_id"])
    op.create_index(
        "ix_discovery_snapshot_organization_id", "discovery_snapshot", ["organization_id"]
    )
    op.create_index("ix_discovery_snapshot_job_id", "discovery_snapshot", ["job_id"])
    op.create_index("ix_discovery_snapshot_evidence_hash", "discovery_snapshot", ["evidence_hash"])

    op.create_table(
        "discovery_candidate_plan",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("enrollment_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("snapshot_id", sa.Uuid(), nullable=False),
        sa.Column("plan_version", sa.Integer(), nullable=False),
        sa.Column("plan_hash", sa.String(length=80), nullable=False),
        sa.Column("plan_document", sa.JSON(), nullable=False),
        sa.Column("node", sa.String(length=64), nullable=False),
        sa.Column("storage", sa.String(length=64), nullable=False),
        sa.Column("ownership_tag", sa.String(length=120), nullable=False),
        sa.Column("capacity_snapshot_hash", sa.String(length=80), nullable=False),
        sa.Column("evidence_hash", sa.String(length=80), nullable=False),
        sa.Column("worker_identity_version", sa.Integer(), nullable=False),
        sa.Column("enrollment_version", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["enrollment_id"], ["target_discovery_enrollment.id"]),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.ForeignKeyConstraint(["snapshot_id"], ["discovery_snapshot.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("enrollment_id", "plan_hash", name="uq_discovery_candidate_plan_hash"),
    )
    op.create_index(
        "ix_discovery_candidate_plan_enrollment_id", "discovery_candidate_plan", ["enrollment_id"]
    )
    op.create_index(
        "ix_discovery_candidate_plan_organization_id",
        "discovery_candidate_plan",
        ["organization_id"],
    )
    op.create_index(
        "ix_discovery_candidate_plan_snapshot_id", "discovery_candidate_plan", ["snapshot_id"]
    )
    op.create_index(
        "ix_discovery_candidate_plan_plan_hash", "discovery_candidate_plan", ["plan_hash"]
    )

    op.create_table(
        "discovery_candidate_plan_approval",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("enrollment_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("plan_hash", sa.String(length=80), nullable=False),
        sa.Column("plan_version", sa.Integer(), nullable=False),
        sa.Column("snapshot_id", sa.Uuid(), nullable=False),
        sa.Column("ownership_tag", sa.String(length=120), nullable=False),
        sa.Column("capacity_snapshot_hash", sa.String(length=80), nullable=False),
        sa.Column("evidence_hash", sa.String(length=80), nullable=False),
        sa.Column("worker_identity_version", sa.Integer(), nullable=False),
        sa.Column("enrollment_version", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approved_by", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["enrollment_id"], ["target_discovery_enrollment.id"]),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "enrollment_id", "plan_hash", name="uq_discovery_candidate_plan_approval"
        ),
    )
    op.create_index(
        "ix_discovery_candidate_plan_approval_enrollment_id",
        "discovery_candidate_plan_approval",
        ["enrollment_id"],
    )
    op.create_index(
        "ix_discovery_candidate_plan_approval_organization_id",
        "discovery_candidate_plan_approval",
        ["organization_id"],
    )


def downgrade() -> None:
    op.drop_table("discovery_candidate_plan_approval")
    op.drop_table("discovery_candidate_plan")
    op.drop_table("discovery_snapshot")
    op.drop_index("uq_discovery_job_inflight", table_name="discovery_job")
    op.drop_table("discovery_job")
    op.drop_table("target_discovery_enrollment")
