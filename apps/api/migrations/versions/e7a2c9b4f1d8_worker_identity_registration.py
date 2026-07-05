"""durable worker-identity registration + evidence (SECP-B2-4.3)

Revision ID: e7a2c9b4f1d8
Revises: d1f4a8b6c3e2
Create Date: 2026-07-05
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "e7a2c9b4f1d8"
down_revision: str | None = "d1f4a8b6c3e2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "worker_identity_registration",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("mechanism", sa.String(length=40), nullable=False),
        sa.Column("identity_label", sa.String(length=120), nullable=False),
        sa.Column("deployment_binding", sa.String(length=120), nullable=False),
        sa.Column("verification_anchor_fingerprint", sa.String(length=80), nullable=False),
        sa.Column("identity_version", sa.Integer(), nullable=False),
        sa.Column("expiry", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence_fingerprint", sa.String(length=80), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("approved_by", sa.Uuid(), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.Uuid(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason_code", sa.String(length=80), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id",
            "identity_label",
            "identity_version",
            name="uq_worker_identity_org_label_version",
        ),
    )
    with op.batch_alter_table("worker_identity_registration", schema=None) as b:
        b.create_index(
            b.f("ix_worker_identity_registration_organization_id"), ["organization_id"]
        )
        b.create_index(
            "uq_worker_identity_active",
            ["organization_id", "identity_label"],
            unique=True,
            sqlite_where=sa.text("status in ('draft','approved')"),
            postgresql_where=sa.text("status in ('draft','approved')"),
        )

    op.create_table(
        "worker_identity_evidence",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("registration_id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.String(length=60), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("proof_id", sa.String(length=120), nullable=False),
        sa.Column("issuer", sa.String(length=120), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["registration_id"], ["worker_identity_registration.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "registration_id", "kind", name="uq_worker_identity_evidence_kind"
        ),
    )
    with op.batch_alter_table("worker_identity_evidence", schema=None) as b:
        b.create_index(b.f("ix_worker_identity_evidence_registration_id"), ["registration_id"])

    _install_immutability_triggers()


# --- Durable immutability (SECP-B2-4.3) --------------------------------------------------------
# PostgreSQL-only DB-level guard so even raw SQL / Core ``update()`` (which bypasses the ORM
# ``before_flush`` guard) cannot mutate a bound/approved/terminal registration or manage evidence
# after the registration leaves draft. The portable ORM-level guard in ``secp_api.immutability``
# covers SQLite and is defense in depth on PostgreSQL. Only the closed lifecycle transitions
# (draft -> approved, draft/approved -> revoked, draft/approved -> expired) and the set-once
# approval/revocation/evidence-fingerprint facts they carry are permitted.


def _install_immutability_triggers() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(
        """
        CREATE OR REPLACE FUNCTION secp_worker_identity_registration_immutable()
        RETURNS trigger AS $$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION
                    'worker_identity_registration records are immutable and cannot be deleted';
            END IF;
            -- Binding facts are immutable after creation.
            IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
               OR NEW.mechanism IS DISTINCT FROM OLD.mechanism
               OR NEW.identity_label IS DISTINCT FROM OLD.identity_label
               OR NEW.deployment_binding IS DISTINCT FROM OLD.deployment_binding
               OR NEW.verification_anchor_fingerprint
                   IS DISTINCT FROM OLD.verification_anchor_fingerprint
               OR NEW.identity_version IS DISTINCT FROM OLD.identity_version
               OR NEW.expiry IS DISTINCT FROM OLD.expiry
               OR NEW.created_by IS DISTINCT FROM OLD.created_by
               OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
                RAISE EXCEPTION
                    'worker_identity_registration binding facts are immutable after creation';
            END IF;
            -- Terminal states are final: no further mutation once revoked/expired.
            IF OLD.status IN ('revoked', 'expired') THEN
                RAISE EXCEPTION
                    'worker_identity_registration is immutable in a terminal state';
            END IF;
            -- Only the closed lifecycle transitions are allowed.
            IF NEW.status IS DISTINCT FROM OLD.status
               AND NOT (
                   (OLD.status = 'draft' AND NEW.status IN ('approved', 'revoked', 'expired'))
                   OR (OLD.status = 'approved' AND NEW.status IN ('revoked', 'expired'))
               ) THEN
                RAISE EXCEPTION
                    'worker_identity_registration status transition is not allowed (immutable)';
            END IF;
            -- Approval + revocation facts and the evidence fingerprint are set-once.
            IF OLD.evidence_fingerprint <> ''
               AND NEW.evidence_fingerprint IS DISTINCT FROM OLD.evidence_fingerprint THEN
                RAISE EXCEPTION
                    'worker_identity_registration evidence fingerprint is immutable (set-once)';
            END IF;
            IF OLD.approved_by IS NOT NULL AND NEW.approved_by IS DISTINCT FROM OLD.approved_by THEN
                RAISE EXCEPTION
                    'worker_identity_registration approved_by is immutable (set-once)';
            END IF;
            IF OLD.approved_at IS NOT NULL AND NEW.approved_at IS DISTINCT FROM OLD.approved_at THEN
                RAISE EXCEPTION
                    'worker_identity_registration approved_at is immutable (set-once)';
            END IF;
            IF OLD.revoked_by IS NOT NULL AND NEW.revoked_by IS DISTINCT FROM OLD.revoked_by THEN
                RAISE EXCEPTION
                    'worker_identity_registration revoked_by is immutable (set-once)';
            END IF;
            IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
                RAISE EXCEPTION
                    'worker_identity_registration revoked_at is immutable (set-once)';
            END IF;
            IF OLD.revocation_reason_code <> ''
               AND NEW.revocation_reason_code IS DISTINCT FROM OLD.revocation_reason_code THEN
                RAISE EXCEPTION
                    'worker_identity_registration revocation reason is immutable (set-once)';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER secp_worker_identity_registration_immutable
        BEFORE UPDATE OR DELETE ON worker_identity_registration
        FOR EACH ROW EXECUTE FUNCTION secp_worker_identity_registration_immutable();
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION secp_worker_identity_evidence_draft_only()
        RETURNS trigger AS $$
        DECLARE
            parent_status text;
            target_id uuid;
        BEGIN
            IF TG_OP = 'DELETE' THEN
                target_id := OLD.registration_id;
            ELSE
                target_id := NEW.registration_id;
            END IF;
            SELECT status INTO parent_status
                FROM worker_identity_registration WHERE id = target_id;
            IF parent_status IS DISTINCT FROM 'draft' THEN
                RAISE EXCEPTION
                    'worker_identity_evidence is immutable once the registration leaves draft';
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
        CREATE TRIGGER secp_worker_identity_evidence_draft_only
        BEFORE INSERT OR UPDATE OR DELETE ON worker_identity_evidence
        FOR EACH ROW EXECUTE FUNCTION secp_worker_identity_evidence_draft_only();
        """
    )


def _drop_immutability_triggers() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(
        "DROP TRIGGER IF EXISTS secp_worker_identity_evidence_draft_only "
        "ON worker_identity_evidence"
    )
    op.execute("DROP FUNCTION IF EXISTS secp_worker_identity_evidence_draft_only")
    op.execute(
        "DROP TRIGGER IF EXISTS secp_worker_identity_registration_immutable "
        "ON worker_identity_registration"
    )
    op.execute("DROP FUNCTION IF EXISTS secp_worker_identity_registration_immutable")


def downgrade() -> None:
    _drop_immutability_triggers()
    with op.batch_alter_table("worker_identity_evidence", schema=None) as b:
        b.drop_index(b.f("ix_worker_identity_evidence_registration_id"))
    op.drop_table("worker_identity_evidence")
    with op.batch_alter_table("worker_identity_registration", schema=None) as b:
        b.drop_index("uq_worker_identity_active")
        b.drop_index(b.f("ix_worker_identity_registration_organization_id"))
    op.drop_table("worker_identity_registration")
