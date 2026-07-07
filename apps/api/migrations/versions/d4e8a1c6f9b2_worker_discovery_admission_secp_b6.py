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


# SECP-B6 MB-1 item-2: minting a durable, one-time worker discovery admission AND every status
# transition (challenged→admitted→consumed/refused/expired) is a CONTROL-PLANE authority. The worker
# shares the database, so an ORM ``before_flush`` guard alone is insufficient — a worker DB role
# bypassing the ORM could forge an ``admitted`` record. This installs a PostgreSQL BEFORE-ROW
# trigger denying INSERT/UPDATE/DELETE on ``worker_discovery_admission`` to any role that is not a
# member of the ``secp_control_plane`` role (a superuser is treated by ``pg_has_role`` as a member
# of every role, so the migration runner + control-plane role pass; a worker role is denied). The
# trigger fires BEFORE foreign-key validation, so the check is authoritative regardless of grants.
_ADMISSION_ROLE_GUARD_SQL = """
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'secp_control_plane') THEN
        CREATE ROLE secp_control_plane NOLOGIN;
    END IF;
END
$$;

CREATE OR REPLACE FUNCTION secp_worker_discovery_admission_guard()
RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
    IF NOT pg_has_role(current_user, 'secp_control_plane', 'MEMBER') THEN
        RAISE EXCEPTION
            'worker_discovery_admission is control-plane authority; role % may not %',
            current_user, TG_OP
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF (TG_OP = 'DELETE') THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END
$fn$;

DROP TRIGGER IF EXISTS trg_worker_discovery_admission_guard ON worker_discovery_admission;
CREATE TRIGGER trg_worker_discovery_admission_guard
    BEFORE INSERT OR UPDATE OR DELETE ON worker_discovery_admission
    FOR EACH ROW EXECUTE FUNCTION secp_worker_discovery_admission_guard();

-- ENABLE ALWAYS so the guard fires even under ``session_replication_role = replica`` — a role that
-- could set replica mode must not be able to bypass the control-plane authority check.
ALTER TABLE worker_discovery_admission
    ENABLE ALWAYS TRIGGER trg_worker_discovery_admission_guard;
"""

_ADMISSION_ROLE_GUARD_DROP_SQL = """
DROP TRIGGER IF EXISTS trg_worker_discovery_admission_guard ON worker_discovery_admission;
DROP FUNCTION IF EXISTS secp_worker_discovery_admission_guard();
"""


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

    # MB-1 item-2: PostgreSQL-only control-plane authority trigger (see module docstring above).
    # SQLite (hermetic default suite) skips it — its tests exercise the ORM guard instead.
    if op.get_bind().dialect.name == "postgresql":
        op.execute(_ADMISSION_ROLE_GUARD_SQL)


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(_ADMISSION_ROLE_GUARD_DROP_SQL)
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
