"""durable resolver-activation authorization + evidence (SECP-B2-4.1)

Revision ID: d1f4a8b6c3e2
Revises: c4e9a1f7d2b3
Create Date: 2026-07-04
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d1f4a8b6c3e2"
down_revision: str | None = "c4e9a1f7d2b3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "resolver_activation_authorization",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("execution_target_id", sa.Uuid(), nullable=False),
        sa.Column("onboarding_id", sa.Uuid(), nullable=False),
        sa.Column("live_read_authorization_id", sa.Uuid(), nullable=False),
        sa.Column("live_read_authorization_version", sa.Integer(), nullable=False),
        sa.Column("preflight_id", sa.Uuid(), nullable=False),
        sa.Column("operation_fingerprint", sa.String(length=80), nullable=False),
        sa.Column("resolver_adapter_contract_version", sa.String(length=120), nullable=False),
        sa.Column("purpose", sa.String(length=60), nullable=False),
        sa.Column("authorization_expiry", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence_fingerprint", sa.String(length=80), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("authorization_version", sa.Integer(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("approved_by", sa.Uuid(), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.Uuid(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason_code", sa.String(length=80), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["execution_target_id"], ["execution_target.id"]),
        sa.ForeignKeyConstraint(["live_read_authorization_id"], ["live_read_authorization.id"]),
        sa.ForeignKeyConstraint(["onboarding_id"], ["target_onboarding.id"]),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.ForeignKeyConstraint(["preflight_id"], ["readonly_staging_preflight.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "execution_target_id",
            "onboarding_id",
            "authorization_version",
            name="uq_resolver_activation_target_onboarding_version",
        ),
    )
    with op.batch_alter_table("resolver_activation_authorization", schema=None) as b:
        b.create_index(b.f("ix_resolver_activation_authorization_organization_id"), ["organization_id"])
        b.create_index(
            b.f("ix_resolver_activation_authorization_execution_target_id"), ["execution_target_id"]
        )
        b.create_index(b.f("ix_resolver_activation_authorization_onboarding_id"), ["onboarding_id"])
        b.create_index(
            b.f("ix_resolver_activation_authorization_live_read_authorization_id"),
            ["live_read_authorization_id"],
        )
        b.create_index(b.f("ix_resolver_activation_authorization_preflight_id"), ["preflight_id"])
        b.create_index(
            "uq_resolver_activation_active_operation",
            ["preflight_id"],
            unique=True,
            sqlite_where=sa.text("status in ('draft','approved')"),
            postgresql_where=sa.text("status in ('draft','approved')"),
        )

    op.create_table(
        "resolver_activation_evidence",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("authorization_id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.String(length=60), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("proof_id", sa.String(length=120), nullable=False),
        sa.Column("issuer", sa.String(length=120), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["authorization_id"], ["resolver_activation_authorization.id"]
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "authorization_id", "kind", name="uq_resolver_activation_evidence_kind"
        ),
    )
    with op.batch_alter_table("resolver_activation_evidence", schema=None) as b:
        b.create_index(
            b.f("ix_resolver_activation_evidence_authorization_id"), ["authorization_id"]
        )


def downgrade() -> None:
    with op.batch_alter_table("resolver_activation_evidence", schema=None) as b:
        b.drop_index(b.f("ix_resolver_activation_evidence_authorization_id"))
    op.drop_table("resolver_activation_evidence")
    with op.batch_alter_table("resolver_activation_authorization", schema=None) as b:
        b.drop_index("uq_resolver_activation_active_operation")
        b.drop_index(b.f("ix_resolver_activation_authorization_preflight_id"))
        b.drop_index(b.f("ix_resolver_activation_authorization_live_read_authorization_id"))
        b.drop_index(b.f("ix_resolver_activation_authorization_onboarding_id"))
        b.drop_index(b.f("ix_resolver_activation_authorization_execution_target_id"))
        b.drop_index(b.f("ix_resolver_activation_authorization_organization_id"))
    op.drop_table("resolver_activation_authorization")
