"""B8 production activation evidence and key-rotation invariants (SECP-PR5F).

Revision ID: d8f1a2b3c4e5
Revises: c4e2f9a1b7d3
Create Date: 2026-07-19
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d8f1a2b3c4e5"
down_revision: str | None = "c4e2f9a1b7d3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_BOUND = sa.text("status = 'bound'")
_ROLLBACK_INCOMPATIBLE_IDENTITY = sa.text(
    """
    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM worker_identity_registration
        WHERE mechanism = 'ed25519_signed_nonce'
    ) THEN 1 ELSE 0 END
    """
)
_DUPLICATE_BOUND_TARGET = sa.text(
    """
    SELECT CASE WHEN EXISTS (
        SELECT 1
        FROM proxmox_readonly_bootstrap_session
        WHERE status = 'bound'
        GROUP BY execution_target_id, onboarding_id
        HAVING COUNT(*) > 1
    ) THEN 1 ELSE 0 END
    """
)

# The controller image is switched only after Alembic has returned.  A read-only compatibility
# probe (or even the repeated query below) cannot close the interval between the migration commit
# and that image switch: the still-running PR5F API could otherwise insert an Ed25519 registration
# after the query and leave the old image unable to read the database.  PostgreSQL therefore keeps
# this database-enforced write fence throughout split activation and any downgraded interval.
# ``ADD CONSTRAINT`` takes
# the table lock needed to order itself against concurrent writers, ``NOT VALID`` immediately
# constrains new tuples, and an explicit validation proves existing rows.  The constraint remains
# enforced after the migration transaction commits and cannot be bypassed with
# ``session_replication_role``.  Alembic never releases it: only the fixed activation-finalization
# helper may do that after the signed worker result has been authenticated.
_ROLLBACK_FENCE_NAME = "ck_worker_identity_pr5f_ed25519_rollback_fence"
_LOCK_ROLLBACK_FENCE_TABLE_SQL = """
LOCK TABLE worker_identity_registration IN ACCESS EXCLUSIVE MODE
"""
_INSTALL_ROLLBACK_FENCE_SQL = f"""
ALTER TABLE worker_identity_registration
ADD CONSTRAINT {_ROLLBACK_FENCE_NAME}
CHECK (mechanism::text IS DISTINCT FROM 'ed25519_signed_nonce'::text) NOT VALID
"""
_VALIDATE_ROLLBACK_FENCE_SQL = f"""
ALTER TABLE worker_identity_registration
VALIDATE CONSTRAINT {_ROLLBACK_FENCE_NAME}
"""
_DROP_ROLLBACK_FENCE_SQL = f"""
ALTER TABLE worker_identity_registration
DROP CONSTRAINT IF EXISTS {_ROLLBACK_FENCE_NAME}
"""


# The production activation keeps the already-pinned ordinary-worker base image and layers the
# reviewed PR5F Python closure over it.  The unmodified base image predates the two PR5F columns
# below, so PostgreSQL must remain safe if a rollback temporarily returns to that writer and an
# INSERT/UPDATE omits them.  These triggers are a compatibility boundary, not an authority bypass:
# they derive only closed evidence from facts the existing worker already persists and make the
# public-material revision monotonic.  ENABLE ALWAYS prevents replica mode from silently bypassing
# the boundary.
_LEGACY_WRITE_COMPAT_SQL = """
CREATE OR REPLACE FUNCTION secp_worker_discovery_node_revision_guard()
RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.revision IS DISTINCT FROM 1 THEN
            RAISE EXCEPTION 'worker discovery node initial revision must be 1';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.ssh_public_key IS DISTINCT FROM OLD.ssh_public_key
       OR NEW.ssh_public_key_fingerprint IS DISTINCT FROM OLD.ssh_public_key_fingerprint
       OR NEW.admission_anchor_hex IS DISTINCT FROM OLD.admission_anchor_hex
       OR NEW.admission_anchor_fingerprint IS DISTINCT FROM OLD.admission_anchor_fingerprint THEN
        -- The old B8 image leaves revision unchanged; the PR5F source advances it itself.  Accept
        -- exactly those two representations and canonicalize both to the same next revision.
        IF NEW.revision IS DISTINCT FROM OLD.revision
           AND NEW.revision IS DISTINCT FROM OLD.revision + 1 THEN
            RAISE EXCEPTION 'worker discovery node key rotation revision is invalid';
        END IF;
        NEW.revision := OLD.revision + 1;
        -- A registration is pinned to the prior admission anchor and cannot survive rotation.
        NEW.worker_identity_registration_id := NULL;
    ELSIF NEW.revision IS DISTINCT FROM OLD.revision THEN
        RAISE EXCEPTION 'worker discovery node revision changed without key rotation';
    END IF;
    RETURN NEW;
END
$fn$;

DROP TRIGGER IF EXISTS trg_worker_discovery_node_revision_guard ON worker_discovery_node;
CREATE TRIGGER trg_worker_discovery_node_revision_guard
    BEFORE INSERT OR UPDATE ON worker_discovery_node
    FOR EACH ROW EXECUTE FUNCTION secp_worker_discovery_node_revision_guard();
ALTER TABLE worker_discovery_node
    ENABLE ALWAYS TRIGGER trg_worker_discovery_node_revision_guard;

CREATE OR REPLACE FUNCTION secp_discovery_snapshot_contact_compat()
RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
    -- Existing rows retain legacy_unrecorded.  On a new write from the pinned B8 worker, the
    -- server default is the reliable signal that the old model omitted contact_state entirely.
    IF NEW.contact_state = 'legacy_unrecorded' THEN
        NEW.contact_state := CASE
            WHEN NEW.reason_code = 'probe_source_sealed' THEN 'sealed'
            WHEN NEW.reason_code = 'enrollment_changed' THEN 'drift'
            WHEN NEW.reason_code = 'bootstrap_unavailable' THEN 'bundle_unavailable'
            WHEN NEW.reason_code = 'host_key_binding_unverified' THEN 'host_key_refused'
            ELSE 'unverifiable'
        END;
    END IF;
    RETURN NEW;
END
$fn$;

DROP TRIGGER IF EXISTS trg_discovery_snapshot_contact_compat ON discovery_snapshot;
CREATE TRIGGER trg_discovery_snapshot_contact_compat
    BEFORE INSERT ON discovery_snapshot
    FOR EACH ROW EXECUTE FUNCTION secp_discovery_snapshot_contact_compat();
ALTER TABLE discovery_snapshot
    ENABLE ALWAYS TRIGGER trg_discovery_snapshot_contact_compat;
"""

_LEGACY_WRITE_COMPAT_DROP_SQL = """
DROP TRIGGER IF EXISTS trg_discovery_snapshot_contact_compat ON discovery_snapshot;
DROP FUNCTION IF EXISTS secp_discovery_snapshot_contact_compat();
DROP TRIGGER IF EXISTS trg_worker_discovery_node_revision_guard ON worker_discovery_node;
DROP FUNCTION IF EXISTS secp_worker_discovery_node_revision_guard();
"""


def upgrade() -> None:
    bind = op.get_bind()
    # SQLite DDL is non-transactional. Detect the one deliberate legacy-data refusal before adding
    # either PR5F column so a rejected local/CI migration remains at an intact c4 schema and can be
    # retried after the duplicate state is resolved. The aggregate existence query is bounded and
    # never reads or reports a target/onboarding value. PostgreSQL performs the same early proof for
    # consistent fail-closed behavior; its unique index remains the authoritative concurrency gate.
    if bind.execute(_DUPLICATE_BOUND_TARGET).scalar_one() != 0:
        raise RuntimeError("PR5F upgrade refused: duplicate bound bootstrap state is present")

    # A stable evidence binding for the public worker node. Existing rows start at revision 1;
    # later idempotent publications leave it unchanged and key rotations increment it.
    op.add_column(
        "worker_discovery_node",
        sa.Column("revision", sa.Integer(), nullable=False, server_default="1"),
    )

    # Snapshots written before PR5F did not durably record whether target contact occurred. Do not
    # infer that fact from eligibility or bundle presence: mark it truthfully as legacy-unrecorded.
    op.add_column(
        "discovery_snapshot",
        sa.Column(
            "contact_state",
            sa.String(length=40),
            nullable=False,
            server_default="legacy_unrecorded",
        ),
    )

    if op.get_bind().dialect.name == "postgresql":
        op.execute(_LEGACY_WRITE_COMPAT_SQL)

    # Exactly one live key binding may exist for a target/onboarding pair. A database containing
    # duplicate legacy bindings fails this migration instead of silently selecting or deleting one.
    op.create_index(
        "uq_proxmox_bootstrap_bound_target",
        "proxmox_readonly_bootstrap_session",
        ["execution_target_id", "onboarding_id"],
        unique=True,
        sqlite_where=_BOUND,
        postgresql_where=_BOUND,
    )

    # Keep Ed25519 identity adoption closed while controller and worker activation are separated by
    # a signed, manually transported handoff.  Canonicalizing the named constraint under one table
    # lock also makes a downgrade/re-upgrade retry deterministic.  The fixed API finalization helper
    # releases this fence only after the worker result has been authenticated.
    if bind.dialect.name == "postgresql":
        op.execute(_LOCK_ROLLBACK_FENCE_TABLE_SQL)
        op.execute(_DROP_ROLLBACK_FENCE_SQL)
        op.execute(_INSTALL_ROLLBACK_FENCE_SQL)
        if bind.execute(_ROLLBACK_INCOMPATIBLE_IDENTITY).scalar_one() != 0:
            raise RuntimeError("PR5F upgrade refused: Ed25519 worker identity state is present")
        op.execute(_VALIDATE_ROLLBACK_FENCE_SQL)


def downgrade() -> None:
    # A pre-PR5F API cannot deserialize this new mechanism value. Never let an operator make the
    # schema/image rollback look safe after the browser adoption flow has persisted one.
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        # Repair/install the fence before even observing compatibility. NOT VALID still constrains
        # every new row, while letting the closed query below produce the deliberate refusal for
        # legacy rows. The table lock orders this operation against already-running writers.
        op.execute(_LOCK_ROLLBACK_FENCE_TABLE_SQL)
        op.execute(_DROP_ROLLBACK_FENCE_SQL)
        op.execute(_INSTALL_ROLLBACK_FENCE_SQL)
    if bind.execute(_ROLLBACK_INCOMPATIBLE_IDENTITY).scalar_one() != 0:
        raise RuntimeError("PR5F downgrade refused: Ed25519 worker identity state is present")
    if bind.dialect.name == "postgresql":
        # Validation proves the complete pre-existing table and closes the downgrade gate. Leave
        # the constraint installed in c4; ``upgrade`` removes it only after restoring all PR5F DDL.
        op.execute(_VALIDATE_ROLLBACK_FENCE_SQL)
        op.execute(_LEGACY_WRITE_COMPAT_DROP_SQL)
    op.drop_index(
        "uq_proxmox_bootstrap_bound_target",
        table_name="proxmox_readonly_bootstrap_session",
    )
    op.drop_column("discovery_snapshot", "contact_state")
    op.drop_column("worker_discovery_node", "revision")
