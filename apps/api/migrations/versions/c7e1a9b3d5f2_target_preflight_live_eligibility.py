"""Target-preflight live read-only eligibility bindings (SECP-002B-1B, B1B-PR3)

Adds the security-critical bindings that a controlled, worker-owned live read-only eligibility
preflight must record on the EXISTING ``target_preflight`` table (no parallel evidence table): an
opaque exact-once ``operation_fingerprint`` (idempotency), the closed ``eligibility_outcome`` code,
the ``eligibility_policy_version`` label, an explicit ``evidence_expires_at`` (conservative bounded
TTL / expiry-bound evidence), and the live-read-authorization + worker-identity binding ids/version.

Every column is NULLABLE and additive: an existing simulated preflight row leaves them NULL and is
unchanged. None of the columns carries a secret, endpoint, credential, raw observation, or free
text — only closed ids/versions/codes/labels/timestamps and an opaque digest. A partial UNIQUE index
constrains ``(onboarding_id, operation_fingerprint)`` for the NON-NULL (live-eligibility) rows only,
enforcing exact-once persistence per completed operation while leaving simulated rows unconstrained.

Downgrade drops the index and the columns (a truthful reverse of the additive upgrade). No data is
rewritten in either direction; simulated preflight rows are untouched.

Revision ID: c7e1a9b3d5f2
Revises: f2b8c1d4a9e7
Create Date: 2026-07-13
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c7e1a9b3d5f2"
down_revision: str | None = "f2b8c1d4a9e7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "target_preflight"
_INDEX_NAME = "uq_target_preflight_eligibility_operation"
_FP_NOT_NULL = sa.text("operation_fingerprint IS NOT NULL")

_COLUMNS = (
    sa.Column("operation_fingerprint", sa.String(length=80), nullable=True),
    sa.Column("eligibility_outcome", sa.String(length=40), nullable=True),
    sa.Column("eligibility_policy_version", sa.String(length=120), nullable=True),
    sa.Column("evidence_expires_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("live_read_authorization_id", sa.Uuid(), nullable=True),
    sa.Column("live_read_authorization_version", sa.Integer(), nullable=True),
    sa.Column("worker_identity_registration_id", sa.Uuid(), nullable=True),
)


def upgrade() -> None:
    for column in _COLUMNS:
        op.add_column(_TABLE, column.copy())
    op.create_index(
        "ix_target_preflight_operation_fingerprint",
        _TABLE,
        ["operation_fingerprint"],
        unique=False,
    )
    # Exact-once per completed live-eligibility operation; simulated rows (NULL fingerprint) are
    # never constrained by this partial-unique index.
    op.create_index(
        _INDEX_NAME,
        _TABLE,
        ["onboarding_id", "operation_fingerprint"],
        unique=True,
        sqlite_where=_FP_NOT_NULL,
        postgresql_where=_FP_NOT_NULL,
    )


def downgrade() -> None:
    op.drop_index(_INDEX_NAME, table_name=_TABLE)
    op.drop_index("ix_target_preflight_operation_fingerprint", table_name=_TABLE)
    for column in reversed(_COLUMNS):
        op.drop_column(_TABLE, column.name)
