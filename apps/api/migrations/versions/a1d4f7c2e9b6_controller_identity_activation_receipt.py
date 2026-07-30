"""Durable controller-identity activation receipt (SECP-PR5H-B2, 2b-3b C3).

Adds ONE new append-only, WRITE-ONCE table keyed by ``operation_id`` (UNIQUE) that stores the exact
canonical public receipt of a controller-identity activation operation, so an exact replay returns the
byte-equivalent original receipt even after restart or an identity rotation — and a new/changed
operation cannot claim replay. No existing durable primitive can represent this (every existing
operation/receipt table is FK-bound to an enrollment / manifest+org / deployment+org aggregate this
activation lacks, and none is ``operation_id``-keyed with a byte-frozen payload), so a linear migration
is unavoidable. Linear successor of the sole head: ``c2f8e1a4b6d9 -> a1d4f7c2e9b6`` becomes the new
sole head; ``downgrade`` drops the single table, returning cleanly to ``c2f8e1a4b6d9``.

CHECK constraints are deliberately PORTABLE (shape/length/prefix) so the migration schema and the
ORM's SQLite ``create_all`` schema stay byte-identical for the parity guard; the exact operation-digest
binding + replay/conflict/corruption semantics are enforced in the application layer.

Revision ID: a1d4f7c2e9b6
Revises: c2f8e1a4b6d9
Create Date: 2026-07-28
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a1d4f7c2e9b6"
down_revision: str | None = "c2f8e1a4b6d9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SCHEMA = "secp.controller-identity-activation/v1"
_RECEIPT_MAX = 8192


def _digest(column: str) -> str:
    return f"(length({column}) = 71 AND {column} LIKE 'sha256:%')"


def upgrade() -> None:
    op.create_table(
        "controller_identity_activation_receipt",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("operation_id", sa.String(length=128), nullable=False),
        sa.Column("operation_schema", sa.String(length=64), nullable=False),
        sa.Column("operation_digest", sa.String(length=80), nullable=False),
        sa.Column("candidate_digest", sa.String(length=80), nullable=False),
        sa.Column(
            "expected_predecessor_row_id",
            sa.Uuid(),
            sa.ForeignKey("controller_enrollment_identity.id"),
            nullable=True,
        ),
        sa.Column("expected_predecessor_activation_token", sa.String(length=128), nullable=True),
        sa.Column("controller_installation_id", sa.String(length=64), nullable=False),
        sa.Column("release_digest", sa.String(length=80), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("handoff_created_at", sa.String(length=40), nullable=False),
        sa.Column(
            "resulting_row_id",
            sa.Uuid(),
            sa.ForeignKey("controller_enrollment_identity.id"),
            nullable=False,
        ),
        sa.Column("resulting_activation_token", sa.String(length=128), nullable=False),
        sa.Column("resulting_public_state_digest", sa.String(length=80), nullable=False),
        sa.Column("receipt_json", sa.Text(), nullable=False),
        sa.Column("receipt_digest", sa.String(length=80), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("operation_id", name="uq_controller_identity_activation_receipt"),
        sa.CheckConstraint(_digest("operation_digest"), name="ck_ciar_operation_digest"),
        sa.CheckConstraint(_digest("candidate_digest"), name="ck_ciar_candidate_digest"),
        sa.CheckConstraint(_digest("release_digest"), name="ck_ciar_release_digest"),
        sa.CheckConstraint(
            _digest("resulting_public_state_digest"), name="ck_ciar_public_state_digest"
        ),
        sa.CheckConstraint(_digest("receipt_digest"), name="ck_ciar_receipt_digest"),
        sa.CheckConstraint("generation >= 0", name="ck_ciar_generation_nonnegative"),
        sa.CheckConstraint(
            f"length(receipt_json) <= {_RECEIPT_MAX}", name="ck_ciar_receipt_bounded"
        ),
        sa.CheckConstraint(f"operation_schema = '{_SCHEMA}'", name="ck_ciar_schema_closed"),
        sa.CheckConstraint(
            "(expected_predecessor_row_id IS NULL"
            " AND expected_predecessor_activation_token IS NULL)"
            " OR (expected_predecessor_row_id IS NOT NULL"
            " AND expected_predecessor_activation_token IS NOT NULL)",
            name="ck_ciar_predecessor_pairing",
        ),
        sa.CheckConstraint(
            "length(controller_installation_id) >= 8"
            " AND length(controller_installation_id) <= 64",
            name="ck_ciar_install_bounded",
        ),
        sa.CheckConstraint(
            "length(operation_id) >= 1 AND length(resulting_activation_token) >= 1",
            name="ck_ciar_tokens_bounded",
        ),
    )


def downgrade() -> None:
    op.drop_table("controller_identity_activation_receipt")
