"""Deployment-scoped controller enrollment identity (SECP-PR5H-B1, F3).

Adds the authoritative, persisted, independently-verified controller-identity history table that the
supported enrollment API binds into every invitation. Linear successor of the PR5H-A enrollment
foundation: ``b6e2f4a9c1d7 -> c2f8e1a4b6d9`` becomes the new sole head. Identity history is
append-only with at most one ``active`` row (the ``active_marker`` UNIQUE); ``downgrade`` drops the
single table, returning cleanly to ``b6e2f4a9c1d7``.

CHECK constraints are deliberately PORTABLE (shape/length/prefix, not PostgreSQL regex) so the
migration schema and the ORM's SQLite ``create_all`` schema stay identical; the exact grammar and
the ``sha256(anchor)==key_id`` binding are enforced in the application layer.

Revision ID: c2f8e1a4b6d9
Revises: b6e2f4a9c1d7
Create Date: 2026-07-25
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c2f8e1a4b6d9"
down_revision: str | None = "b6e2f4a9c1d7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _digest(column: str) -> str:
    return f"(length({column}) = 71 AND {column} LIKE 'sha256:%')"


def upgrade() -> None:
    op.create_table(
        "controller_enrollment_identity",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("active_marker", sa.Boolean(), nullable=True),
        sa.Column("controller_installation_id", sa.String(length=120), nullable=False),
        sa.Column("controller_key_id", sa.String(length=80), nullable=False),
        sa.Column("controller_trust_anchor_hex", sa.String(length=64), nullable=False),
        sa.Column("controller_origin", sa.String(length=269), nullable=False),
        sa.Column("release_digest", sa.String(length=80), nullable=False),
        sa.Column("management_identity_digest", sa.String(length=80), nullable=False),
        sa.Column("bootstrap_evidence_digest", sa.String(length=80), nullable=False),
        sa.Column("enrollment_key_proof_id", sa.String(length=120), nullable=False),
        sa.Column("verified", sa.Boolean(), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("superseded_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        # column order matches the ORM: UpdatedTimestampMixin yields updated_at then created_at
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("active_marker", name="uq_controller_enrollment_identity_active"),
        sa.CheckConstraint(
            "status IN ('active', 'superseded', 'revoked')", name="ck_cei_status_closed"
        ),
        sa.CheckConstraint(
            "(status = 'active' AND active_marker = true)"
            " OR (status <> 'active' AND active_marker IS NULL)",
            name="ck_cei_active_marker_pairing",
        ),
        sa.CheckConstraint(_digest("controller_key_id"), name="ck_cei_key_digest"),
        sa.CheckConstraint(_digest("release_digest"), name="ck_cei_release_digest"),
        sa.CheckConstraint(_digest("management_identity_digest"), name="ck_cei_mgmt_digest"),
        sa.CheckConstraint(_digest("bootstrap_evidence_digest"), name="ck_cei_evidence_digest"),
        sa.CheckConstraint(
            "length(enrollment_key_proof_id) >= 8 AND length(enrollment_key_proof_id) <= 120",
            name="ck_cei_enrollment_key_proof",
        ),
        sa.CheckConstraint("status <> 'active' OR verified = true", name="ck_cei_active_verified"),
        sa.CheckConstraint("length(controller_trust_anchor_hex) = 64", name="ck_cei_anchor_hex"),
        sa.CheckConstraint(
            "(controller_origin LIKE 'https://%' AND length(controller_origin) <= 269)",
            name="ck_cei_origin_https",
        ),
        sa.CheckConstraint(
            "length(controller_installation_id) >= 8"
            " AND length(controller_installation_id) <= 64",
            name="ck_cei_install_bounded",
        ),
        sa.CheckConstraint(
            "(verified = false AND verified_at IS NULL)"
            " OR (verified = true AND verified_at IS NOT NULL)",
            name="ck_cei_verified_pairing",
        ),
        sa.CheckConstraint(
            "(status = 'superseded' AND superseded_at IS NOT NULL)"
            " OR (status <> 'superseded' AND superseded_at IS NULL)",
            name="ck_cei_superseded_pairing",
        ),
        sa.CheckConstraint(
            "(status = 'revoked' AND revoked_at IS NOT NULL)"
            " OR (status <> 'revoked' AND revoked_at IS NULL)",
            name="ck_cei_revoked_pairing",
        ),
    )


    # T3: make the append-only revision history a TRUE immutable snapshot — persist the exact
    # canonical state committed at each revision so a delayed idempotent retry returns the ORIGINAL
    # step result, never the current head. Nullable for a portable ADD COLUMN; the commit path
    # always populates it and rehydration refuses a NULL/mismatched snapshot as state_corrupt.
    op.add_column(
        "worker_enrollment_revision",
        sa.Column("state_snapshot", sa.Text(), nullable=True),
    )

    # Phase 3 (+ C1/C2): the immutable, content-addressed public signed controller offer minted at
    # the bind exchange, persisted write-once per enrollment so a lost-response retry returns the
    # EXACT original BindExchangeOut even after healthy/revoke/restart/key-rotation. Public material
    # only. The C2 winning-bind columns pin the exact winning request + resulting state + original
    # response so an exact retry can be proven (never re-signed) and a different worker / key / PoP
    # / initial request conflicts. They are nullable at the schema level (portable), but the trusted
    # persist path ALWAYS populates them and the repository refuses a NULL/mismatched row on read.
    op.create_table(
        "worker_enrollment_signed_offer",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "enrollment_id",
            sa.String(length=80),
            sa.ForeignKey("worker_enrollment_state.enrollment_id"),
            nullable=False,
        ),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("offer_revision", sa.Integer(), nullable=False),
        sa.Column("signer_key_id", sa.String(length=80), nullable=False),
        sa.Column("signed_offer", sa.Text(), nullable=False),
        sa.Column("response_digest", sa.String(length=80), nullable=False),
        # --- C2 exact winning-bind replay bindings ---
        sa.Column("bind_input_digest", sa.String(length=80), nullable=True),
        sa.Column("offer_claim_digest", sa.String(length=80), nullable=True),
        sa.Column("resulting_revision", sa.Integer(), nullable=True),
        sa.Column("resulting_state_digest", sa.String(length=80), nullable=True),
        sa.Column("worker_installation_id", sa.String(length=120), nullable=True),
        sa.Column("worker_key_id", sa.String(length=80), nullable=True),
        sa.Column("response_json", sa.Text(), nullable=True),
        sa.Column("response_json_digest", sa.String(length=80), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("enrollment_id", name="uq_worker_enrollment_signed_offer"),
        sa.CheckConstraint("offer_revision >= 0", name="ck_weso_revision_nonnegative"),
        sa.CheckConstraint(
            "(length(signer_key_id) = 71 AND signer_key_id LIKE 'sha256:%')",
            name="ck_weso_signer_key_id",
        ),
        sa.CheckConstraint(
            "(length(response_digest) = 71 AND response_digest LIKE 'sha256:%')",
            name="ck_weso_response_digest",
        ),
        sa.CheckConstraint("length(signed_offer) <= 8192", name="ck_weso_payload_bounded"),
        sa.CheckConstraint(
            "(bind_input_digest IS NULL OR (length(bind_input_digest) = 71 "
            "AND bind_input_digest LIKE 'sha256:%'))",
            name="ck_weso_bind_input_digest",
        ),
        sa.CheckConstraint(
            "(offer_claim_digest IS NULL OR (length(offer_claim_digest) = 71 "
            "AND offer_claim_digest LIKE 'sha256:%'))",
            name="ck_weso_offer_claim_digest",
        ),
        sa.CheckConstraint(
            "(resulting_state_digest IS NULL OR (length(resulting_state_digest) = 71 "
            "AND resulting_state_digest LIKE 'sha256:%'))",
            name="ck_weso_resulting_state_digest",
        ),
        sa.CheckConstraint(
            "(resulting_revision IS NULL OR resulting_revision >= 0)",
            name="ck_weso_resulting_revision",
        ),
        sa.CheckConstraint(
            "(worker_key_id IS NULL OR (length(worker_key_id) = 71 "
            "AND worker_key_id LIKE 'sha256:%'))",
            name="ck_weso_worker_key_id",
        ),
        sa.CheckConstraint(
            "(response_json_digest IS NULL OR (length(response_json_digest) = 71 "
            "AND response_json_digest LIKE 'sha256:%'))",
            name="ck_weso_response_json_digest",
        ),
        sa.CheckConstraint(
            "(response_json IS NULL OR length(response_json) <= 16384)",
            name="ck_weso_response_json_bounded",
        ),
    )


def downgrade() -> None:
    op.drop_table("worker_enrollment_signed_offer")
    with op.batch_alter_table("worker_enrollment_revision") as batch:
        batch.drop_column("state_snapshot")
    op.drop_table("controller_enrollment_identity")
