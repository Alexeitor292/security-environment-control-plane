"""onboarding deployment bindings + evidence provenance + single-active index (SECP-002B-1B-0)

Binds the target onboarding + approved preflight evidence into ``deployment_plan`` and
``provisioning_manifest``; adds the trusted-provenance + evidence-package fields to
``target_preflight``; pins the approved preflight package on ``target_onboarding``; and adds
a portable partial unique index enforcing at most one active onboarding per target.

Revision ID: a7c4e9d2b1f3
Revises: f6b3d2a1c8e0
Create Date: 2026-07-01
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a7c4e9d2b1f3"
down_revision: str | None = "f6b3d2a1c8e0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_BIND_COLUMNS = (
    ("target_onboarding_id", sa.Uuid(), True),
    ("onboarding_boundary_hash", sa.String(length=80), True),
    ("approved_preflight_id", sa.Uuid(), True),
    ("approved_preflight_evidence_hash", sa.String(length=80), True),
    ("onboarding_verification_level", sa.String(length=40), True),
)


def upgrade() -> None:
    for table in ("deployment_plan", "provisioning_manifest"):
        for name, coltype, nullable in _BIND_COLUMNS:
            op.add_column(table, sa.Column(name, coltype, nullable=nullable))

    op.add_column(
        "target_onboarding", sa.Column("approved_preflight_id", sa.Uuid(), nullable=True)
    )
    op.add_column(
        "target_onboarding",
        sa.Column("approved_preflight_evidence_hash", sa.String(length=80), nullable=True),
    )
    op.add_column(
        "target_onboarding",
        sa.Column("approved_boundary_hash", sa.String(length=80), nullable=True),
    )
    op.add_column(
        "target_onboarding",
        sa.Column("approved_verification_level", sa.String(length=40), nullable=True),
    )

    op.add_column(
        "target_preflight",
        sa.Column(
            "verification_level",
            sa.String(length=40),
            nullable=False,
            server_default="simulated",
        ),
    )
    op.add_column(
        "target_preflight",
        sa.Column(
            "collector_kind",
            sa.String(length=60),
            nullable=False,
            server_default="fake_declared_boundary",
        ),
    )
    op.add_column(
        "target_preflight",
        sa.Column("collector_identity", sa.String(length=120), nullable=False, server_default=""),
    )
    op.add_column(
        "target_preflight",
        sa.Column("evidence_version", sa.Integer(), nullable=False, server_default="1"),
    )
    for name in ("target_config_hash", "scope_policy_hash", "boundary_hash"):
        op.add_column(
            "target_preflight",
            sa.Column(name, sa.String(length=80), nullable=False, server_default=""),
        )
    op.add_column("target_preflight", sa.Column("toolchain_profile_id", sa.Uuid(), nullable=True))
    op.add_column(
        "target_preflight",
        sa.Column("toolchain_profile_hash", sa.String(length=80), nullable=True),
    )

    # Portable partial unique index: at most one active onboarding per target.
    op.create_index(
        "uq_target_onboarding_active",
        "target_onboarding",
        ["execution_target_id"],
        unique=True,
        sqlite_where=sa.text("status = 'active'"),
        postgresql_where=sa.text("status = 'active'"),
    )


def downgrade() -> None:
    op.drop_index("uq_target_onboarding_active", table_name="target_onboarding")
    with op.batch_alter_table("target_preflight", schema=None) as b:
        for name in (
            "toolchain_profile_hash",
            "toolchain_profile_id",
            "boundary_hash",
            "scope_policy_hash",
            "target_config_hash",
            "evidence_version",
            "collector_identity",
            "collector_kind",
            "verification_level",
        ):
            b.drop_column(name)
    with op.batch_alter_table("target_onboarding", schema=None) as b:
        for name in (
            "approved_verification_level",
            "approved_boundary_hash",
            "approved_preflight_evidence_hash",
            "approved_preflight_id",
        ):
            b.drop_column(name)
    for table in ("provisioning_manifest", "deployment_plan"):
        with op.batch_alter_table(table, schema=None) as b:
            for name, _t, _n in reversed(_BIND_COLUMNS):
                b.drop_column(name)
