"""OIDC subject uniqueness (ADR-017 / OIDC-A)

Adds a partial unique index on ``app_user.subject`` so a non-null OIDC subject is globally unique
for the single configured issuer model: the exact ``sub`` claim maps to exactly one pre-provisioned
user. Multiple NULL subjects (users not yet linked to an IdP identity) remain permitted; duplicate
non-null subjects are forbidden. Portable across SQLite + PostgreSQL via a dual sqlite_where /
postgresql_where partial index.

The upgrade FAILS CLOSED (without printing any subject value — only a count of colliding groups) if
the existing data already contains duplicate non-null subjects, so the constraint can never be added
over ambiguous identity data. Email is intentionally NOT made globally unique, and the existing
``(organization_id, email)`` constraint is untouched. No external identity table is introduced in
this slice; multi-issuer support will require an (issuer, subject) identity model in a future
version.

Revision ID: f2b8c1d4a9e7
Revises: b2c9e5a1f4d7
Create Date: 2026-07-13
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f2b8c1d4a9e7"
down_revision: str | None = "b2c9e5a1f4d7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_INDEX_NAME = "uq_app_user_subject"
_SUBJECT_NOT_NULL = sa.text("subject IS NOT NULL")


def _duplicate_nonnull_subject_groups(bind: sa.Connection) -> int:
    """Count subjects that appear more than once among non-null rows. Returns a NUMBER only —
    it never selects, returns, or logs any subject value, so a fail-closed upgrade cannot leak an
    identity even when data is inconsistent."""
    result = bind.execute(
        sa.text(
            "SELECT COUNT(*) FROM ("
            "  SELECT subject FROM app_user "
            "  WHERE subject IS NOT NULL "
            "  GROUP BY subject HAVING COUNT(*) > 1"
            ") AS dups"
        )
    ).scalar()
    return int(result or 0)


def upgrade() -> None:
    bind = op.get_bind()
    duplicates = _duplicate_nonnull_subject_groups(bind)
    if duplicates:
        raise RuntimeError(
            f"cannot add unique app_user.subject index: {duplicates} duplicate non-null "
            "subject group(s) exist; deduplicate the affected users before upgrading"
        )
    op.create_index(
        _INDEX_NAME,
        "app_user",
        ["subject"],
        unique=True,
        sqlite_where=_SUBJECT_NOT_NULL,
        postgresql_where=_SUBJECT_NOT_NULL,
    )


def downgrade() -> None:
    op.drop_index(_INDEX_NAME, table_name="app_user")
