"""proxmox read-only discovery bootstrap session (SECP-B7)

Revision ID: e5f2b9a3c7d1
Revises: d4e8a1c6f9b2
Create Date: 2026-07-07
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "e5f2b9a3c7d1"
down_revision: str | None = "d4e8a1c6f9b2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # SECP-B7: a secret-free bootstrap session that automates the read-only discovery access path.
    # It stores ONLY public material (worker SSH public key + fingerprint, host key fingerprint) and
    # the opaque endpoint-binding digest — never a private key, credential, or token. ``created_at``
    # and ``updated_at`` are populated by the ORM (UpdatedTimestampMixin) — the SECP-B7 fix that
    # keeps the ORM and this migration consistent (both NOT NULL, no server default).
    op.create_table(
        "proxmox_readonly_bootstrap_session",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("execution_target_id", sa.Uuid(), nullable=False),
        sa.Column("onboarding_id", sa.Uuid(), nullable=False),
        sa.Column("account", sa.String(length=40), nullable=False),
        sa.Column("pve_role", sa.String(length=60), nullable=False),
        sa.Column("worker_ssh_public_key", sa.Text(), nullable=False),
        sa.Column("worker_ssh_public_key_fingerprint", sa.String(length=120), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("ssh_port", sa.Integer(), nullable=False),
        sa.Column("host_key_fingerprint", sa.String(length=120), nullable=True),
        sa.Column("endpoint_binding_hash", sa.String(length=80), nullable=True),
        sa.Column("live_read_authorization_id", sa.Uuid(), nullable=True),
        sa.Column("authorization_version", sa.Integer(), nullable=True),
        sa.Column("proof_summary", sa.JSON(), nullable=True),
        sa.Column("failure_code", sa.String(length=60), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.ForeignKeyConstraint(["execution_target_id"], ["execution_target.id"]),
        sa.ForeignKeyConstraint(["onboarding_id"], ["target_onboarding.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_proxmox_readonly_bootstrap_session_organization_id",
        "proxmox_readonly_bootstrap_session",
        ["organization_id"],
    )
    op.create_index(
        "ix_proxmox_readonly_bootstrap_session_execution_target_id",
        "proxmox_readonly_bootstrap_session",
        ["execution_target_id"],
    )
    op.create_index(
        "ix_proxmox_readonly_bootstrap_session_onboarding_id",
        "proxmox_readonly_bootstrap_session",
        ["onboarding_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_proxmox_readonly_bootstrap_session_onboarding_id",
        table_name="proxmox_readonly_bootstrap_session",
    )
    op.drop_index(
        "ix_proxmox_readonly_bootstrap_session_execution_target_id",
        table_name="proxmox_readonly_bootstrap_session",
    )
    op.drop_index(
        "ix_proxmox_readonly_bootstrap_session_organization_id",
        table_name="proxmox_readonly_bootstrap_session",
    )
    op.drop_table("proxmox_readonly_bootstrap_session")
