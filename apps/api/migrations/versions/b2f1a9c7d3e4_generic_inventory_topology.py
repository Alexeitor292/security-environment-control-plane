"""generic observed inventory and topology (ADR-008)

Renames the simulator-named projection tables to provider-neutral names and adds
generic provenance / provider-linkage columns. DATA-PRESERVING: tables are renamed
(not dropped), and new NOT NULL columns get safe server defaults so existing
simulator rows remain valid.

Revision ID: b2f1a9c7d3e4
Revises: 09a75fd21cf8
Create Date: 2026-06-30
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b2f1a9c7d3e4"
down_revision: str | None = "09a75fd21cf8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Rename tables (preserves rows, FKs, and indexes).
    op.rename_table("simulated_network", "environment_network")
    op.rename_table("simulated_node", "environment_node")
    op.rename_table("simulated_topology_edge", "environment_topology_edge")

    # 2. Add generic columns. SQLite + PostgreSQL both support ADD COLUMN with a
    #    server default for NOT NULL columns.
    op.add_column(
        "environment_network",
        sa.Column("status", sa.String(length=40), nullable=False, server_default="up"),
    )
    op.add_column(
        "environment_network",
        sa.Column("provider_resource_id", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "environment_network",
        sa.Column(
            "provider_resource_type",
            sa.String(length=60),
            nullable=False,
            server_default="network",
        ),
    )
    op.add_column(
        "environment_network",
        sa.Column("source", sa.String(length=60), nullable=False, server_default="simulator"),
    )
    op.add_column(
        "environment_network",
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "environment_network",
        sa.Column("attributes", sa.JSON(), nullable=True),
    )

    op.add_column(
        "environment_node",
        sa.Column("provider_resource_id", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "environment_node",
        sa.Column(
            "provider_resource_type",
            sa.String(length=60),
            nullable=False,
            server_default="node",
        ),
    )
    op.add_column(
        "environment_node",
        sa.Column("source", sa.String(length=60), nullable=False, server_default="simulator"),
    )
    op.add_column(
        "environment_node",
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.add_column(
        "environment_topology_edge",
        sa.Column("provider", sa.String(length=60), nullable=False, server_default="simulator"),
    )
    op.add_column(
        "environment_topology_edge",
        sa.Column("source", sa.String(length=60), nullable=False, server_default="simulator"),
    )
    op.add_column(
        "environment_topology_edge",
        sa.Column(
            "simulated", sa.Boolean(), nullable=False, server_default=sa.true()
        ),
    )


def downgrade() -> None:
    for col in ("simulated", "source", "provider"):
        op.drop_column("environment_topology_edge", col)
    for col in ("observed_at", "source", "provider_resource_type", "provider_resource_id"):
        op.drop_column("environment_node", col)
    for col in (
        "attributes",
        "observed_at",
        "source",
        "provider_resource_type",
        "provider_resource_id",
        "status",
    ):
        op.drop_column("environment_network", col)
    op.rename_table("environment_topology_edge", "simulated_topology_edge")
    op.rename_table("environment_node", "simulated_node")
    op.rename_table("environment_network", "simulated_network")
