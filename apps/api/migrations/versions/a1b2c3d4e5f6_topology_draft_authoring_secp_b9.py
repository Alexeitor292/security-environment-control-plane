"""durable topology draft authoring (SECP-B9)

Revision ID: a1b2c3d4e5f6
Revises: f7a3d1e9b4c2
Create Date: 2026-07-11
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a1b2c3d4e5f6"
down_revision: str | None = "f7a3d1e9b4c2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "topology_authoring_document",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("source_environment_version_id", sa.Uuid(), nullable=True),
        sa.Column("exercise_id", sa.Uuid(), nullable=True),
        sa.Column("display_name", sa.String(length=200), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("current_revision_id", sa.Uuid(), nullable=True),
        sa.Column("validated_revision_id", sa.Uuid(), nullable=True),
        sa.Column("submitted_revision_id", sa.Uuid(), nullable=True),
        sa.Column("approved_revision_id", sa.Uuid(), nullable=True),
        sa.Column("revision_count", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("updated_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.ForeignKeyConstraint(
            ["source_environment_version_id"], ["environment_version.id"]
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "id", name="uq_topology_doc_org_id"),
    )
    op.create_index(
        "ix_topology_authoring_document_organization_id",
        "topology_authoring_document",
        ["organization_id"],
    )
    op.create_index(
        "ix_topology_authoring_document_source_environment_version_id",
        "topology_authoring_document",
        ["source_environment_version_id"],
    )
    op.create_index(
        "ix_topology_authoring_document_exercise_id",
        "topology_authoring_document",
        ["exercise_id"],
    )

    op.create_table(
        "topology_revision",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("document_id", sa.Uuid(), nullable=False),
        sa.Column("revision_number", sa.Integer(), nullable=False),
        sa.Column("parent_revision_id", sa.Uuid(), nullable=True),
        sa.Column("schema_version", sa.String(length=64), nullable=False),
        sa.Column("document_content", sa.JSON(), nullable=False),
        sa.Column("content_hash", sa.String(length=80), nullable=False),
        sa.Column("source_environment_version_id", sa.Uuid(), nullable=True),
        sa.Column("change_note", sa.String(length=500), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("decided_by", sa.Uuid(), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decision_reason", sa.String(length=500), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.ForeignKeyConstraint(
            ["document_id"], ["topology_authoring_document.id"]
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "document_id", "revision_number", name="uq_topology_revision_number"
        ),
    )
    op.create_index(
        "ix_topology_revision_organization_id", "topology_revision", ["organization_id"]
    )
    op.create_index(
        "ix_topology_revision_document_id", "topology_revision", ["document_id"]
    )
    op.create_index(
        "ix_topology_revision_content_hash", "topology_revision", ["content_hash"]
    )

    op.create_table(
        "topology_validation_result",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("document_id", sa.Uuid(), nullable=False),
        sa.Column("revision_id", sa.Uuid(), nullable=False),
        sa.Column("content_hash", sa.String(length=80), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("error_count", sa.Integer(), nullable=False),
        sa.Column("warning_count", sa.Integer(), nullable=False),
        sa.Column("findings", sa.JSON(), nullable=False),
        sa.Column("result_hash", sa.String(length=80), nullable=False),
        sa.Column("validated_by", sa.Uuid(), nullable=True),
        sa.Column("validated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.ForeignKeyConstraint(
            ["document_id"], ["topology_authoring_document.id"]
        ),
        sa.ForeignKeyConstraint(["revision_id"], ["topology_revision.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_topology_validation_result_organization_id",
        "topology_validation_result",
        ["organization_id"],
    )
    op.create_index(
        "ix_topology_validation_result_document_id",
        "topology_validation_result",
        ["document_id"],
    )
    op.create_index(
        "ix_topology_validation_result_revision_id",
        "topology_validation_result",
        ["revision_id"],
    )
    op.create_index(
        "ix_topology_validation_result_content_hash",
        "topology_validation_result",
        ["content_hash"],
    )

    _install_immutability_triggers()


def _install_immutability_triggers() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    # A revision's content, hash, and bindings are immutable; only its status
    # and set-once decision metadata may change.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION secp_topology_revision_immutable()
        RETURNS trigger AS $$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'topology_revision records are immutable and cannot be deleted';
            END IF;
            IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
               OR NEW.document_id IS DISTINCT FROM OLD.document_id
               OR NEW.revision_number IS DISTINCT FROM OLD.revision_number
               OR NEW.parent_revision_id IS DISTINCT FROM OLD.parent_revision_id
               OR NEW.schema_version IS DISTINCT FROM OLD.schema_version
               OR NEW.document_content::text IS DISTINCT FROM OLD.document_content::text
               OR NEW.content_hash IS DISTINCT FROM OLD.content_hash
               OR NEW.source_environment_version_id
                   IS DISTINCT FROM OLD.source_environment_version_id
               OR NEW.change_note IS DISTINCT FROM OLD.change_note
               OR NEW.created_by IS DISTINCT FROM OLD.created_by
               OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
                RAISE EXCEPTION 'topology_revision content is immutable after creation';
            END IF;
            IF OLD.decided_by IS NOT NULL AND NEW.decided_by IS DISTINCT FROM OLD.decided_by THEN
                RAISE EXCEPTION 'topology_revision decided_by is immutable (set-once)';
            END IF;
            IF OLD.decided_at IS NOT NULL AND NEW.decided_at IS DISTINCT FROM OLD.decided_at THEN
                RAISE EXCEPTION 'topology_revision decided_at is immutable (set-once)';
            END IF;
            IF OLD.decision_reason IS NOT NULL
               AND NEW.decision_reason IS DISTINCT FROM OLD.decision_reason THEN
                RAISE EXCEPTION 'topology_revision decision_reason is immutable (set-once)';
            END IF;
            -- Only the closed lifecycle transitions are allowed.
            IF NEW.status IS DISTINCT FROM OLD.status
               AND NOT (
                   (OLD.status = 'draft' AND NEW.status IN ('validated', 'superseded'))
                   OR (OLD.status = 'validated' AND NEW.status IN ('submitted', 'superseded'))
                   OR (OLD.status = 'submitted' AND NEW.status IN ('approved', 'rejected'))
               ) THEN
                RAISE EXCEPTION 'topology_revision status transition is not allowed (immutable)';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER secp_topology_revision_immutable
        BEFORE UPDATE OR DELETE ON topology_revision
        FOR EACH ROW EXECUTE FUNCTION secp_topology_revision_immutable();
        """
    )
    # A validation result is append-only: no update, no delete.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION secp_topology_validation_result_immutable()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'topology_validation_result records are append-only and immutable';
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER secp_topology_validation_result_immutable
        BEFORE UPDATE OR DELETE ON topology_validation_result
        FOR EACH ROW EXECUTE FUNCTION secp_topology_validation_result_immutable();
        """
    )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            "DROP TRIGGER IF EXISTS secp_topology_validation_result_immutable "
            "ON topology_validation_result"
        )
        op.execute(
            "DROP FUNCTION IF EXISTS secp_topology_validation_result_immutable()"
        )
        op.execute(
            "DROP TRIGGER IF EXISTS secp_topology_revision_immutable ON topology_revision"
        )
        op.execute("DROP FUNCTION IF EXISTS secp_topology_revision_immutable()")

    op.drop_table("topology_validation_result")
    op.drop_table("topology_revision")
    op.drop_table("topology_authoring_document")
