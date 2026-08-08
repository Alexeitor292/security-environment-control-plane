"""provider-execution credential reference on ExecutionTarget

The dedicated, opaque locator for the credential that PERFORMS Proxmox mutations. It exists so the
mutation credential can never be the read-only one: every other reference on this table serves a
different purpose, and before this column the only way to reach an apply credential was the generic
``secret_ref`` — the same column the legacy discovery and live-readonly paths resolve. A read-only
credential silently becoming the apply credential is the exact defect this closes.

NULLABLE, NO BACKFILL, NO SERVER DEFAULT — deliberately. Historical rows are honest: a target that
never had a dedicated mutation reference gets NULL, and NULL cannot execute. Copying ``secret_ref``
(or either of the other dedicated references) into this column would manufacture an authorization
nobody granted, which is the whole thing being prevented.

Revision ID: 7c2f4b8d1a6e
Revises: e3b7a9c25f41
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "7c2f4b8d1a6e"
down_revision: str | None = "e3b7a9c25f41"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "execution_target",
        sa.Column("provider_execution_secret_ref", sa.String(length=500), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("execution_target", "provider_execution_secret_ref")
