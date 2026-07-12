"""environment version publication persistence (SECP-B10 / ADR-016 PR B)

Adds the nullable, backward-compatible publication binding columns to
``environment_version`` (topology document/revision/validation provenance + hashes,
optional base version, contract version, and the server-derived publication
fingerprint), a named uniqueness constraint on ``(template_id, publication_fingerprint)``
(idempotency), and a portable coherent-publication check constraint (legacy rows have
every publication column NULL; published rows have all required columns non-null and
api_version = controlplane.security/v1alpha2). It also CREATE OR REPLACEs the PostgreSQL
``secp_block_version_mutation`` trigger function so raw SQL cannot alter any binding column;
the downgrade restores the prior function body BEFORE dropping the columns.

Existing v1alpha1 rows are untouched (all new columns default NULL).

Revision ID: b2c9e5a1f4d7
Revises: a1b2c3d4e5f6
Create Date: 2026-07-12
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b2c9e5a1f4d7"
down_revision: str | None = "a1b2c3d4e5f6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


# Portable coherent-publication check (SQLite + PostgreSQL). Mirrors
# secp_api.models._PUBLICATION_COHERENCE_CHECK exactly. Two legal states, keyed on api_version:
# legacy v1alpha1 with every publication column NULL; published v1alpha2 with all required
# columns non-null and publication_contract_version=secp.publication/v1. No unpublished v1alpha2
# state is legal.
_PUBLICATION_COHERENCE_CHECK = (
    "(api_version = 'controlplane.security/v1alpha1'"
    " AND source_topology_document_id IS NULL"
    " AND source_topology_revision_id IS NULL"
    " AND topology_content_hash IS NULL"
    " AND topology_validation_result_id IS NULL"
    " AND topology_validation_result_hash IS NULL"
    " AND base_environment_version_id IS NULL"
    " AND publication_contract_version IS NULL"
    " AND publication_fingerprint IS NULL)"
    " OR (api_version = 'controlplane.security/v1alpha2'"
    " AND source_topology_document_id IS NOT NULL"
    " AND source_topology_revision_id IS NOT NULL"
    " AND topology_content_hash IS NOT NULL"
    " AND topology_validation_result_id IS NOT NULL"
    " AND topology_validation_result_hash IS NOT NULL"
    " AND publication_contract_version = 'secp.publication/v1'"
    " AND publication_fingerprint IS NOT NULL)"
)

# Hardened PostgreSQL guard (SECP-B10 / ADR-016). Fires BEFORE INSERT OR UPDATE.
#   INSERT: enforce the same api_version-keyed coherence as the CHECK constraint AND that the
#     mirrored publication columns equal spec.spec.publicationProvenance exactly, spec.apiVersion
#     equals api_version, and publication_contract_version = secp.publication/v1. This makes a
#     caller-fabricated, mismatched, partial, or unpublished-v1alpha2 row impossible even via raw
#     SQL / direct ORM construction that bypasses the publication service.
#   UPDATE: identity + spec/hash + created_by + every publication binding column are immutable.
_NEW_VERSION_FUNCTION = """
CREATE OR REPLACE FUNCTION secp_block_version_mutation()
RETURNS trigger AS $$
DECLARE
    prov jsonb;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF (NEW.spec->>'apiVersion') IS DISTINCT FROM NEW.api_version THEN
            RAISE EXCEPTION 'environment_version spec.apiVersion must equal api_version';
        END IF;
        IF NEW.api_version = 'controlplane.security/v1alpha1' THEN
            IF NEW.source_topology_document_id IS NOT NULL
               OR NEW.source_topology_revision_id IS NOT NULL
               OR NEW.topology_content_hash IS NOT NULL
               OR NEW.topology_validation_result_id IS NOT NULL
               OR NEW.topology_validation_result_hash IS NOT NULL
               OR NEW.base_environment_version_id IS NOT NULL
               OR NEW.publication_contract_version IS NOT NULL
               OR NEW.publication_fingerprint IS NOT NULL THEN
                RAISE EXCEPTION 'environment_version v1alpha1 rows must carry no publication columns';
            END IF;
        ELSIF NEW.api_version = 'controlplane.security/v1alpha2' THEN
            IF NEW.source_topology_document_id IS NULL
               OR NEW.source_topology_revision_id IS NULL
               OR NEW.topology_content_hash IS NULL
               OR NEW.topology_validation_result_id IS NULL
               OR NEW.topology_validation_result_hash IS NULL
               OR NEW.publication_contract_version IS NULL
               OR NEW.publication_fingerprint IS NULL THEN
                RAISE EXCEPTION 'environment_version v1alpha2 rows require complete publication bindings';
            END IF;
            IF NEW.publication_contract_version IS DISTINCT FROM 'secp.publication/v1' THEN
                RAISE EXCEPTION 'environment_version publication_contract_version must be secp.publication/v1';
            END IF;
            IF NEW.publication_fingerprint NOT LIKE 'sha256:%' THEN
                RAISE EXCEPTION 'environment_version publication_fingerprint must be a sha256 digest';
            END IF;
            prov := (NEW.spec::jsonb) -> 'spec' -> 'publicationProvenance';
            IF prov IS NULL THEN
                RAISE EXCEPTION 'environment_version v1alpha2 spec is missing publicationProvenance';
            END IF;
            IF NEW.source_topology_document_id::text IS DISTINCT FROM (prov->>'topology_document_id')
               OR NEW.source_topology_revision_id::text IS DISTINCT FROM (prov->>'topology_revision_id')
               OR NEW.topology_content_hash IS DISTINCT FROM (prov->>'topology_content_hash')
               OR NEW.topology_validation_result_id::text IS DISTINCT FROM (prov->>'topology_validation_result_id')
               OR NEW.topology_validation_result_hash IS DISTINCT FROM (prov->>'topology_validation_result_hash')
               OR NEW.base_environment_version_id::text IS DISTINCT FROM (prov->>'base_environment_version_id')
               OR NEW.publication_contract_version IS DISTINCT FROM (prov->>'publication_contract_version') THEN
                RAISE EXCEPTION 'environment_version publication columns must mirror spec.publicationProvenance';
            END IF;
        ELSE
            RAISE EXCEPTION 'environment_version has unsupported api_version %', NEW.api_version;
        END IF;
        RETURN NEW;
    END IF;

    -- UPDATE: every protected binding is immutable after creation.
    IF NEW.spec::text IS DISTINCT FROM OLD.spec::text
       OR NEW.content_hash IS DISTINCT FROM OLD.content_hash
       OR NEW.version_number IS DISTINCT FROM OLD.version_number
       OR NEW.api_version IS DISTINCT FROM OLD.api_version
       OR NEW.created_by IS DISTINCT FROM OLD.created_by
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.template_id IS DISTINCT FROM OLD.template_id
       OR NEW.source_topology_document_id IS DISTINCT FROM OLD.source_topology_document_id
       OR NEW.source_topology_revision_id IS DISTINCT FROM OLD.source_topology_revision_id
       OR NEW.topology_content_hash IS DISTINCT FROM OLD.topology_content_hash
       OR NEW.topology_validation_result_id IS DISTINCT FROM OLD.topology_validation_result_id
       OR NEW.topology_validation_result_hash IS DISTINCT FROM OLD.topology_validation_result_hash
       OR NEW.base_environment_version_id IS DISTINCT FROM OLD.base_environment_version_id
       OR NEW.publication_contract_version IS DISTINCT FROM OLD.publication_contract_version
       OR NEW.publication_fingerprint IS DISTINCT FROM OLD.publication_fingerprint THEN
        RAISE EXCEPTION 'environment_version is immutable after creation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
"""

# The exact pre-PR-B trigger: the initial-migration (09a75fd21cf8) UPDATE-only function body plus
# a BEFORE UPDATE trigger. Restored on downgrade BEFORE the new columns are dropped so no trigger
# references a column that no longer exists.
_OLD_VERSION_FUNCTION = """
CREATE OR REPLACE FUNCTION secp_block_version_mutation()
RETURNS trigger AS $$
BEGIN
    IF NEW.spec::text IS DISTINCT FROM OLD.spec::text
       OR NEW.content_hash IS DISTINCT FROM OLD.content_hash
       OR NEW.version_number IS DISTINCT FROM OLD.version_number
       OR NEW.api_version IS DISTINCT FROM OLD.api_version THEN
        RAISE EXCEPTION 'environment_version is immutable after creation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
"""

# Fire on INSERT and UPDATE (hardened) vs. the original UPDATE-only trigger.
_TRIGGER_NAME = "secp_environment_version_immutable"
_NEW_TRIGGER = (
    f"CREATE TRIGGER {_TRIGGER_NAME} BEFORE INSERT OR UPDATE ON environment_version "
    "FOR EACH ROW EXECUTE FUNCTION secp_block_version_mutation();"
)
_OLD_TRIGGER = (
    f"CREATE TRIGGER {_TRIGGER_NAME} BEFORE UPDATE ON environment_version "
    "FOR EACH ROW EXECUTE FUNCTION secp_block_version_mutation();"
)
_DROP_TRIGGER = f"DROP TRIGGER IF EXISTS {_TRIGGER_NAME} ON environment_version;"


def upgrade() -> None:
    with op.batch_alter_table("environment_version", schema=None) as batch_op:
        batch_op.add_column(sa.Column("source_topology_document_id", sa.Uuid(), nullable=True))
        batch_op.add_column(sa.Column("source_topology_revision_id", sa.Uuid(), nullable=True))
        batch_op.add_column(sa.Column("topology_content_hash", sa.String(length=80), nullable=True))
        batch_op.add_column(sa.Column("topology_validation_result_id", sa.Uuid(), nullable=True))
        batch_op.add_column(
            sa.Column("topology_validation_result_hash", sa.String(length=80), nullable=True)
        )
        batch_op.add_column(sa.Column("base_environment_version_id", sa.Uuid(), nullable=True))
        batch_op.add_column(
            sa.Column("publication_contract_version", sa.String(length=64), nullable=True)
        )
        batch_op.add_column(sa.Column("publication_fingerprint", sa.String(length=80), nullable=True))
        batch_op.create_index(
            batch_op.f("ix_environment_version_source_topology_document_id"),
            ["source_topology_document_id"],
            unique=False,
        )
        batch_op.create_index(
            batch_op.f("ix_environment_version_source_topology_revision_id"),
            ["source_topology_revision_id"],
            unique=False,
        )
        batch_op.create_index(
            batch_op.f("ix_environment_version_topology_validation_result_id"),
            ["topology_validation_result_id"],
            unique=False,
        )
        batch_op.create_index(
            batch_op.f("ix_environment_version_base_environment_version_id"),
            ["base_environment_version_id"],
            unique=False,
        )
        batch_op.create_foreign_key(
            "fk_environment_version_source_topology_document",
            "topology_authoring_document",
            ["source_topology_document_id"],
            ["id"],
        )
        batch_op.create_foreign_key(
            "fk_environment_version_source_topology_revision",
            "topology_revision",
            ["source_topology_revision_id"],
            ["id"],
        )
        batch_op.create_foreign_key(
            "fk_environment_version_topology_validation_result",
            "topology_validation_result",
            ["topology_validation_result_id"],
            ["id"],
        )
        batch_op.create_foreign_key(
            "fk_environment_version_base_version",
            "environment_version",
            ["base_environment_version_id"],
            ["id"],
        )
        batch_op.create_unique_constraint(
            "uq_environment_version_publication_fingerprint",
            ["template_id", "publication_fingerprint"],
        )
        batch_op.create_check_constraint(
            "ck_environment_version_publication_coherent",
            _PUBLICATION_COHERENCE_CHECK,
        )
    if op.get_bind().dialect.name == "postgresql":
        op.execute(_NEW_VERSION_FUNCTION)
        # Re-arm the trigger to fire on INSERT too (was BEFORE UPDATE only).
        op.execute(_DROP_TRIGGER)
        op.execute(_NEW_TRIGGER)


def downgrade() -> None:
    # Restore the prior PostgreSQL function AND the original BEFORE UPDATE-only trigger FIRST, so no
    # trigger references (or fires INSERT coherence on) columns about to be dropped.
    if op.get_bind().dialect.name == "postgresql":
        op.execute(_OLD_VERSION_FUNCTION)
        op.execute(_DROP_TRIGGER)
        op.execute(_OLD_TRIGGER)
    with op.batch_alter_table("environment_version", schema=None) as batch_op:
        batch_op.drop_constraint("ck_environment_version_publication_coherent", type_="check")
        batch_op.drop_constraint(
            "uq_environment_version_publication_fingerprint", type_="unique"
        )
        batch_op.drop_constraint("fk_environment_version_base_version", type_="foreignkey")
        batch_op.drop_constraint(
            "fk_environment_version_topology_validation_result", type_="foreignkey"
        )
        batch_op.drop_constraint(
            "fk_environment_version_source_topology_revision", type_="foreignkey"
        )
        batch_op.drop_constraint(
            "fk_environment_version_source_topology_document", type_="foreignkey"
        )
        batch_op.drop_index(batch_op.f("ix_environment_version_base_environment_version_id"))
        batch_op.drop_index(batch_op.f("ix_environment_version_topology_validation_result_id"))
        batch_op.drop_index(batch_op.f("ix_environment_version_source_topology_revision_id"))
        batch_op.drop_index(batch_op.f("ix_environment_version_source_topology_document_id"))
        batch_op.drop_column("publication_fingerprint")
        batch_op.drop_column("publication_contract_version")
        batch_op.drop_column("base_environment_version_id")
        batch_op.drop_column("topology_validation_result_hash")
        batch_op.drop_column("topology_validation_result_id")
        batch_op.drop_column("topology_content_hash")
        batch_op.drop_column("source_topology_revision_id")
        batch_op.drop_column("source_topology_document_id")
