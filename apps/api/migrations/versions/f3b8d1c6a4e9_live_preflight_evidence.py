"""durable immutable live-preflight evidence (SECP-B2-4.5)

Revision ID: f3b8d1c6a4e9
Revises: e7a2c9b4f1d8
Create Date: 2026-07-05
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f3b8d1c6a4e9"
down_revision: str | None = "e7a2c9b4f1d8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "live_preflight_evidence",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("preflight_id", sa.Uuid(), nullable=False),
        sa.Column("execution_target_id", sa.Uuid(), nullable=False),
        sa.Column("onboarding_id", sa.Uuid(), nullable=False),
        sa.Column("live_read_authorization_id", sa.Uuid(), nullable=False),
        sa.Column("live_read_authorization_version", sa.Integer(), nullable=False),
        sa.Column("resolver_activation_authorization_id", sa.Uuid(), nullable=False),
        sa.Column("resolver_activation_authorization_version", sa.Integer(), nullable=False),
        sa.Column("worker_identity_registration_id", sa.Uuid(), nullable=False),
        sa.Column("worker_identity_version", sa.Integer(), nullable=False),
        sa.Column("resolution_lease_id", sa.Uuid(), nullable=False),
        sa.Column("operation_fingerprint", sa.String(length=80), nullable=False),
        sa.Column("collector_contract_version", sa.String(length=120), nullable=False),
        sa.Column("endpoint_allowlist_version", sa.String(length=120), nullable=False),
        sa.Column("resolver_contract_version", sa.String(length=120), nullable=False),
        sa.Column("evidence_schema_version", sa.String(length=120), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence_hash", sa.String(length=80), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.ForeignKeyConstraint(["preflight_id"], ["readonly_staging_preflight.id"]),
        sa.ForeignKeyConstraint(["execution_target_id"], ["execution_target.id"]),
        sa.ForeignKeyConstraint(["onboarding_id"], ["target_onboarding.id"]),
        sa.ForeignKeyConstraint(["live_read_authorization_id"], ["live_read_authorization.id"]),
        sa.ForeignKeyConstraint(
            ["resolver_activation_authorization_id"], ["resolver_activation_authorization.id"]
        ),
        sa.ForeignKeyConstraint(
            ["worker_identity_registration_id"], ["worker_identity_registration.id"]
        ),
        sa.ForeignKeyConstraint(["resolution_lease_id"], ["resolution_lease.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "preflight_id", "operation_fingerprint", name="uq_live_preflight_evidence_operation"
        ),
    )
    with op.batch_alter_table("live_preflight_evidence", schema=None) as b:
        for col in (
            "organization_id",
            "preflight_id",
            "execution_target_id",
            "onboarding_id",
            "live_read_authorization_id",
            "resolver_activation_authorization_id",
            "worker_identity_registration_id",
            "resolution_lease_id",
            "evidence_hash",
        ):
            b.create_index(b.f(f"ix_live_preflight_evidence_{col}"), [col])

    _install_immutability_trigger()


# --- Durable immutability (SECP-B2-4.5) --------------------------------------------------------
# A completed live-preflight evidence record is FULLY immutable: no update and no delete, on the
# raw/Core path too (the portable ORM guard covers SQLite + is defense in depth on PostgreSQL).


def _install_immutability_trigger() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(
        """
        CREATE OR REPLACE FUNCTION secp_live_preflight_evidence_immutable()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION
                'live_preflight_evidence records are immutable and cannot be updated or deleted';
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER secp_live_preflight_evidence_immutable
        BEFORE UPDATE OR DELETE ON live_preflight_evidence
        FOR EACH ROW EXECUTE FUNCTION secp_live_preflight_evidence_immutable();
        """
    )


def _drop_immutability_trigger() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(
        "DROP TRIGGER IF EXISTS secp_live_preflight_evidence_immutable ON live_preflight_evidence"
    )
    op.execute("DROP FUNCTION IF EXISTS secp_live_preflight_evidence_immutable")


def downgrade() -> None:
    _drop_immutability_trigger()
    with op.batch_alter_table("live_preflight_evidence", schema=None) as b:
        for col in (
            "evidence_hash",
            "resolution_lease_id",
            "worker_identity_registration_id",
            "resolver_activation_authorization_id",
            "live_read_authorization_id",
            "onboarding_id",
            "execution_target_id",
            "preflight_id",
            "organization_id",
        ):
            b.drop_index(b.f(f"ix_live_preflight_evidence_{col}"))
    op.drop_table("live_preflight_evidence")
