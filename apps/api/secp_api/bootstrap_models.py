"""Durable ORM model for the SECP-B7 Proxmox read-only discovery bootstrap session.

The app-owned record that drives the wizard which replaces the manual SECP-B6 canary steps. It is
**secret-free**: it stores the operator-provided worker SSH **public** key (never a private key), a
public host-key fingerprint, the opaque ``sha256:`` endpoint-binding digest computed by backend code
(never the raw host/port), and closed status/label values. The API never stores an SSH private key,
a credential, or a token here. It lives in its own module (imported by ``secp_api.models``) to keep
the SECP-B7 diff focused; it registers on the shared ``Base`` like every other model.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from secp_api.enums import ProxmoxBootstrapStatus
from secp_api.models import Base, UpdatedTimestampMixin, _uuid
from secp_api.types import EnumType


class ProxmoxReadOnlyBootstrapSession(Base, UpdatedTimestampMixin):
    """A secret-free bootstrap session binding an active-onboarded Proxmox target to the read-only
    discovery access path the operator provisions on the host. Its only cryptographic outputs that
    touch the control plane are PUBLIC values (the worker SSH public key + its fingerprint, the host
    key fingerprint) and the opaque endpoint-binding digest. Mutable lifecycle via compare-and-swap;
    it grants nothing on its own — a separately-approved live-read authorization is still needed."""

    __tablename__ = "proxmox_readonly_bootstrap_session"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    execution_target_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("execution_target.id"), nullable=False, index=True
    )
    onboarding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("target_onboarding.id"), nullable=False, index=True
    )
    account: Mapped[str] = mapped_column(String(40), nullable=False)
    pve_role: Mapped[str] = mapped_column(String(60), nullable=False)
    # The operator-provided worker SSH PUBLIC key (normalized ``ssh-<type> <base64> [comment]``) and
    # its SHA256 fingerprint. NEVER a private key — the service rejects private-key material.
    worker_ssh_public_key: Mapped[str] = mapped_column(Text, nullable=False)
    worker_ssh_public_key_fingerprint: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[ProxmoxBootstrapStatus] = mapped_column(
        EnumType(ProxmoxBootstrapStatus, length=20),
        default=ProxmoxBootstrapStatus.pending,
        nullable=False,
    )
    revision: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    ssh_port: Mapped[int] = mapped_column(Integer, default=22, nullable=False)
    # Public host-key fingerprint + opaque endpoint-binding digest — set once proof is accepted.
    host_key_fingerprint: Mapped[str | None] = mapped_column(String(120), nullable=True)
    # SECP-B8: the Proxmox host's SSH PUBLIC key line ("ssh-ed25519 AAAA..."), captured from the
    # bootstrap proof. Non-secret; the worker writes it into known_hosts so host-key pinning is
    # authoritative (the host itself emitted it). NEVER a private key.
    host_public_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    endpoint_binding_hash: Mapped[str | None] = mapped_column(String(80), nullable=True)
    # Set when the session is bound to a separately-approved live-read authorization.
    live_read_authorization_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    authorization_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Bounded, secret-free proof facts the operator submitted (closed keys only).
    proof_summary: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    failure_code: Mapped[str | None] = mapped_column(String(60), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)

    def __repr__(self) -> str:
        return (
            "ProxmoxReadOnlyBootstrapSession("
            f"id={self.id!s}, status={getattr(self.status, 'value', self.status)!r})"
        )


class WorkerDiscoveryNode(Base, UpdatedTimestampMixin):
    """SECP-B8: a worker node's self-published PUBLIC key material.

    The worker generates + OWNS its SSH and Ed25519 admission keypairs; it publishes only the PUBLIC
    halves here so the UI can auto-populate the bootstrap wizard and the operator can register the
    worker identity. This record NEVER holds a private key — the API rejects private-key material on
    the publication path. It is a convenience/registry surface; it grants nothing on its own."""

    __tablename__ = "worker_discovery_node"
    __table_args__ = (
        UniqueConstraint("organization_id", "node_label", name="uq_worker_discovery_node_label"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    node_label: Mapped[str] = mapped_column(String(120), nullable=False)
    # PUBLIC key material only (a private key is rejected before this row is written).
    ssh_public_key: Mapped[str] = mapped_column(Text, nullable=False)
    ssh_public_key_fingerprint: Mapped[str] = mapped_column(String(120), nullable=False)
    admission_anchor_hex: Mapped[str] = mapped_column(String(80), nullable=False)
    admission_anchor_fingerprint: Mapped[str] = mapped_column(String(80), nullable=False)
    # Set once an operator has registered/approved the worker identity for this anchor.
    worker_identity_registration_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)

    def __repr__(self) -> str:
        return f"WorkerDiscoveryNode(id={self.id!s}, node_label={self.node_label!r})"
