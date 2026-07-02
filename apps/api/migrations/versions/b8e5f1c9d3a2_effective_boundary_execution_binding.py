"""effective execution boundary bindings on plan + manifest (SECP-002B-1B-0 correction pass)

Persists the canonical effective execution boundary (declared onboarding boundary ∩ target
scope policy) and its hash on ``deployment_plan`` and ``provisioning_manifest``. These are
immutable, hash-bound execution inputs: recomputed and required to agree at manifest
generation and the worker gate, and enforced against every provider action by the worker.

Revision ID: b8e5f1c9d3a2
Revises: a7c4e9d2b1f3
Create Date: 2026-07-01
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b8e5f1c9d3a2"
down_revision: str | None = "a7c4e9d2b1f3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_BOUNDARY_COLUMNS = (
    ("effective_boundary", sa.JSON(), True),
    ("effective_boundary_hash", sa.String(length=80), True),
)


def upgrade() -> None:
    for table in ("deployment_plan", "provisioning_manifest"):
        for name, coltype, nullable in _BOUNDARY_COLUMNS:
            op.add_column(table, sa.Column(name, coltype, nullable=nullable))


def downgrade() -> None:
    for table in ("provisioning_manifest", "deployment_plan"):
        with op.batch_alter_table(table, schema=None) as b:
            for name, _t, _n in reversed(_BOUNDARY_COLUMNS):
                b.drop_column(name)
