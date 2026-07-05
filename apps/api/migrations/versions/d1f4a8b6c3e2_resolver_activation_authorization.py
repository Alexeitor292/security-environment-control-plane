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

    _install_immutability_triggers()


# --- Durable immutability (SECP-B2-4.1) --------------------------------------------------------
# PostgreSQL-only DB-level guard so even raw SQL / Core ``update()`` (which bypasses the ORM
# ``before_flush`` guard) cannot mutate a bound/approved/terminal authorization or manage evidence
# after the authorization leaves draft. The portable ORM-level guard in ``secp_api.immutability``
# covers SQLite and is defense in depth on PostgreSQL. Only the closed lifecycle transitions
# (draft -> approved, draft/approved -> revoked, draft/approved -> expired) and the set-once
# approval/revocation/evidence-fingerprint facts they carry are permitted.


def _install_immutability_triggers() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(
        """
        CREATE OR REPLACE FUNCTION secp_resolver_activation_authorization_immutable()
        RETURNS trigger AS $$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION
                    'resolver_activation_authorization records are immutable and cannot be deleted';
            END IF;
            -- Binding facts are immutable after creation.
            IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
               OR NEW.execution_target_id IS DISTINCT FROM OLD.execution_target_id
               OR NEW.onboarding_id IS DISTINCT FROM OLD.onboarding_id
               OR NEW.live_read_authorization_id IS DISTINCT FROM OLD.live_read_authorization_id
               OR NEW.live_read_authorization_version
                   IS DISTINCT FROM OLD.live_read_authorization_version
               OR NEW.preflight_id IS DISTINCT FROM OLD.preflight_id
               OR NEW.operation_fingerprint IS DISTINCT FROM OLD.operation_fingerprint
               OR NEW.resolver_adapter_contract_version
                   IS DISTINCT FROM OLD.resolver_adapter_contract_version
               OR NEW.purpose IS DISTINCT FROM OLD.purpose
               OR NEW.authorization_expiry IS DISTINCT FROM OLD.authorization_expiry
               OR NEW.authorization_version IS DISTINCT FROM OLD.authorization_version
               OR NEW.created_by IS DISTINCT FROM OLD.created_by
               OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
                RAISE EXCEPTION
                    'resolver_activation_authorization binding facts are immutable after creation';
            END IF;
            -- Terminal states are final: no further mutation once revoked/expired.
            IF OLD.status IN ('revoked', 'expired') THEN
                RAISE EXCEPTION
                    'resolver_activation_authorization is immutable in a terminal state';
            END IF;
            -- Only the closed lifecycle transitions are allowed.
            IF NEW.status IS DISTINCT FROM OLD.status
               AND NOT (
                   (OLD.status = 'draft' AND NEW.status IN ('approved', 'revoked', 'expired'))
                   OR (OLD.status = 'approved' AND NEW.status IN ('revoked', 'expired'))
               ) THEN
                RAISE EXCEPTION
                    'resolver_activation_authorization status transition is not allowed (immutable)';
            END IF;
            -- Approval + revocation facts and the evidence fingerprint are set-once.
            IF OLD.evidence_fingerprint <> ''
               AND NEW.evidence_fingerprint IS DISTINCT FROM OLD.evidence_fingerprint THEN
                RAISE EXCEPTION
                    'resolver_activation_authorization evidence fingerprint is immutable (set-once)';
            END IF;
            IF OLD.approved_by IS NOT NULL AND NEW.approved_by IS DISTINCT FROM OLD.approved_by THEN
                RAISE EXCEPTION
                    'resolver_activation_authorization approved_by is immutable (set-once)';
            END IF;
            IF OLD.approved_at IS NOT NULL AND NEW.approved_at IS DISTINCT FROM OLD.approved_at THEN
                RAISE EXCEPTION
                    'resolver_activation_authorization approved_at is immutable (set-once)';
            END IF;
            IF OLD.revoked_by IS NOT NULL AND NEW.revoked_by IS DISTINCT FROM OLD.revoked_by THEN
                RAISE EXCEPTION
                    'resolver_activation_authorization revoked_by is immutable (set-once)';
            END IF;
            IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
                RAISE EXCEPTION
                    'resolver_activation_authorization revoked_at is immutable (set-once)';
            END IF;
            IF OLD.revocation_reason_code <> ''
               AND NEW.revocation_reason_code IS DISTINCT FROM OLD.revocation_reason_code THEN
                RAISE EXCEPTION
                    'resolver_activation_authorization revocation reason is immutable (set-once)';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER secp_resolver_activation_authorization_immutable
        BEFORE UPDATE OR DELETE ON resolver_activation_authorization
        FOR EACH ROW EXECUTE FUNCTION secp_resolver_activation_authorization_immutable();
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION secp_resolver_activation_evidence_draft_only()
        RETURNS trigger AS $$
        DECLARE
            parent_status text;
            target_id uuid;
        BEGIN
            IF TG_OP = 'DELETE' THEN
                target_id := OLD.authorization_id;
            ELSE
                target_id := NEW.authorization_id;
            END IF;
            SELECT status INTO parent_status
                FROM resolver_activation_authorization WHERE id = target_id;
            IF parent_status IS DISTINCT FROM 'draft' THEN
                RAISE EXCEPTION
                    'resolver_activation_evidence is immutable once the authorization leaves draft';
            END IF;
            IF TG_OP = 'DELETE' THEN
                RETURN OLD;
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER secp_resolver_activation_evidence_draft_only
        BEFORE INSERT OR UPDATE OR DELETE ON resolver_activation_evidence
        FOR EACH ROW EXECUTE FUNCTION secp_resolver_activation_evidence_draft_only();
        """
    )


def _drop_immutability_triggers() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(
        "DROP TRIGGER IF EXISTS secp_resolver_activation_evidence_draft_only "
        "ON resolver_activation_evidence"
    )
    op.execute("DROP FUNCTION IF EXISTS secp_resolver_activation_evidence_draft_only")
    op.execute(
        "DROP TRIGGER IF EXISTS secp_resolver_activation_authorization_immutable "
        "ON resolver_activation_authorization"
    )
    op.execute("DROP FUNCTION IF EXISTS secp_resolver_activation_authorization_immutable")


def downgrade() -> None:
    _drop_immutability_triggers()
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
