"""Durable selected-worker binding for a provisioning operation (ADR-030 condition 2).

Adds ONE nullable column, ``provisioning_operation.worker_installation_id``, so that "which worker
was selected to execute this operation" is a durable fact rather than an unanswerable question.

WHY A MIGRATION IS UNAVOIDABLE. ADR-030 condition 2 requires the executing worker's identity to
equal the one the operation names. No existing column can carry it: ``runner`` is a deterministic
runner OPERATION id (String(60)) and a worker identity stored there would be indistinguishable from
the value already written, and ``WorkerDiscoveryAdmission.worker_registration_id`` binds a worker
selected for a READ under its own single-use nonce and expiry — provisioning has its own authority
domain. Without this column the authority derivation refuses every execution with
``execution_worker_selection_not_durable``, which is correct and also means nothing can ever run.

NULLABLE, AND DELIBERATELY NOT BACKFILLED. Operations that predate this column have no selection
that anyone recorded, and inventing one would be fabricating an authorization record. NULL is the
honest value and it fails CLOSED: ``services.provisioning_worker_selection.assert_dispatchable``
refuses to let a NULL-bound operation become dispatchable, and the execution authority refuses a
NULL binding outright. So a historical row is not "open to any worker"; it is unexecutable.

WRITE-ONCE IS ENFORCED IN THE APPLICATION LAYER, NOT HERE. A portable CHECK cannot express
"NULL may become a value, a value may never change" — that is a transition constraint over two row
versions, and the repository's portable-schema rule (the parity guard compares this migration's
schema to the ORM's SQLite ``create_all``) forbids a backend-specific trigger in one and not the
other. ``secp_api.immutability`` guards the transition for both backends instead, which is the same
place every other write-once binding in this schema is enforced.

Linear successor of the sole head: ``a1d4f7c2e9b6 -> e3b7a9c25f41`` becomes the new sole head.
``downgrade`` drops the single column, returning cleanly to ``a1d4f7c2e9b6``; because the column is
nullable and never backfilled, the downgrade loses only bindings written after this migration —
and an operation whose binding is dropped becomes undispatchable rather than unbound-and-runnable.

Revision ID: e3b7a9c25f41
Revises: a1d4f7c2e9b6
Create Date: 2026-08-07
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "e3b7a9c25f41"
down_revision: str | None = "a1d4f7c2e9b6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "provisioning_operation"
_COLUMN = "worker_installation_id"

#: Matches the canonical worker installation identity representation already used by
#: ``worker_enrollment_state.worker_installation_id`` and
#: ``worker_enrollment_invitation.controller_installation_id`` — String(120), so the same value can
#: be compared across tables without truncation on either side.
_IDENTITY_LENGTH = 120


def upgrade() -> None:
    # ``batch_alter_table`` because SQLite cannot ALTER a column in place; on PostgreSQL this is a
    # plain ADD COLUMN. Both backends must end at the same schema for the parity guard.
    with op.batch_alter_table(_TABLE) as batch:
        batch.add_column(
            sa.Column(_COLUMN, sa.String(length=_IDENTITY_LENGTH), nullable=True),
        )


def downgrade() -> None:
    with op.batch_alter_table(_TABLE) as batch:
        batch.drop_column(_COLUMN)
