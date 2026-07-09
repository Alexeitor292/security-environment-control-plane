"""worker-owned discovery bundle automation (SECP-B8)

Revision ID: f7a3d1e9b4c2
Revises: e5f2b9a3c7d1
Create Date: 2026-07-09
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f7a3d1e9b4c2"
down_revision: str | None = "e5f2b9a3c7d1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # SECP-B8: capture the Proxmox host's SSH PUBLIC key (from the bootstrap proof) so the worker
    # can synthesize a valid known_hosts entry (host-key pinning). Non-secret; never a private key.
    op.add_column(
        "proxmox_readonly_bootstrap_session",
        sa.Column("host_public_key", sa.Text(), nullable=True),
    )

    # SECP-B8: a worker node's self-published PUBLIC key material (SSH public key + Ed25519
    # admission anchor) so the UI auto-populates the wizard. PUBLIC only — no private key column.
    op.create_table(
        "worker_discovery_node",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("node_label", sa.String(length=120), nullable=False),
        sa.Column("ssh_public_key", sa.Text(), nullable=False),
        sa.Column("ssh_public_key_fingerprint", sa.String(length=120), nullable=False),
        sa.Column("admission_anchor_hex", sa.String(length=80), nullable=False),
        sa.Column("admission_anchor_fingerprint", sa.String(length=80), nullable=False),
        sa.Column("worker_identity_registration_id", sa.Uuid(), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "node_label", name="uq_worker_discovery_node_label"),
    )
    op.create_index(
        "ix_worker_discovery_node_organization_id",
        "worker_discovery_node",
        ["organization_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_worker_discovery_node_organization_id", table_name="worker_discovery_node")
    op.drop_table("worker_discovery_node")
    op.drop_column("proxmox_readonly_bootstrap_session", "host_public_key")
