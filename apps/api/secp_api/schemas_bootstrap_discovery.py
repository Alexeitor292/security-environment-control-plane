"""API schemas for the SECP-B7 Proxmox read-only discovery bootstrap flow.

Request models accept ONLY non-secret values (an SSH PUBLIC key, a port, a public host-key
fingerprint, a bounded proof block). Response models expose only closed IDs / fingerprints / the
opaque endpoint digest — never a private key, credential, raw host, or command.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class BootstrapSessionCreate(BaseModel):
    execution_target_id: uuid.UUID
    # The worker's SSH PUBLIC key (``ssh-<type> <base64> [comment]``). A private key is rejected.
    worker_ssh_public_key: str = Field(min_length=32, max_length=8192)
    ssh_port: int = Field(default=22, ge=1, le=65535)


class BootstrapCompleteRequest(BaseModel):
    # A public SSH host-key fingerprint (``SHA256:...``) read off the Proxmox host.
    host_key_fingerprint: str = Field(min_length=9, max_length=200)
    # Optional pasted SECPDISC-PROOF block (bounded; secret-free; private-key material rejected).
    proof_text: str | None = Field(default=None, max_length=8192)
    # SECP-B8: optional host PUBLIC key line ("ssh-ed25519 AAAA..."). Normally parsed from the
    # proof; accepted explicitly for API clients. A private key is rejected; must match the fp.
    host_public_key: str | None = Field(default=None, max_length=8192)


class BootstrapSessionOut(ORMModel):
    id: uuid.UUID
    execution_target_id: uuid.UUID
    onboarding_id: uuid.UUID
    account: str
    pve_role: str
    worker_ssh_public_key_fingerprint: str
    status: str
    ssh_port: int
    host_key_fingerprint: str | None = None
    endpoint_binding_hash: str | None = None
    live_read_authorization_id: uuid.UUID | None = None
    authorization_version: int | None = None
    failure_code: str | None = None
    expires_at: datetime
    created_at: datetime
    updated_at: datetime


class BootstrapScriptOut(BaseModel):
    session_id: uuid.UUID
    account: str
    pve_role: str
    worker_ssh_public_key_fingerprint: str
    # The idempotent Proxmox bootstrap script (secret-free; the only operator action is running it).
    script: str


class BindingDescriptorOut(BaseModel):
    """The worker's secret-free ``binding.json`` — exactly the non-secret fields the mounted bundle
    requires. Contains no host/port/key material."""

    organization_id: uuid.UUID
    execution_target_id: uuid.UUID
    onboarding_id: uuid.UUID
    enrollment_id: uuid.UUID
    authorization_id: uuid.UUID
    authorization_version: int
    endpoint_binding_hash: str


class BundleDescriptorOut(BaseModel):
    """SECP-B8: the SECRET-FREE superset the worker's bundle manager assembles the mounted bundle
    from — the ``binding.json`` fields PLUS the SSH endpoint facts, the public host-key fingerprint,
    and the host PUBLIC key line for ``known_hosts``. NEVER contains a private key or credential."""

    organization_id: uuid.UUID
    execution_target_id: uuid.UUID
    onboarding_id: uuid.UUID
    enrollment_id: uuid.UUID
    authorization_id: uuid.UUID
    authorization_version: int
    endpoint_binding_hash: str
    ssh_host: str
    ssh_port: int
    account: str
    host_key_fingerprint: str
    host_public_key: str


class DiscoveryReadinessOut(BaseModel):
    """SECP-B8: a precise, secret-free readiness diagnostic — which prerequisite is missing for an
    enrollment's live discovery path (so the worker never fails opaquely with sealed probes)."""

    enrollment_id: uuid.UUID
    execution_target_id: uuid.UUID
    onboarding_id: uuid.UUID
    bootstrap_session_id: uuid.UUID | None = None
    bootstrap_status: str | None = None
    ready: bool
    missing_prerequisites: list[str]
    checks: dict[str, bool]


class SubstrateEligibilityGrantOut(ORMModel):
    """SECP-B8: the result of granting a target staging-substrate eligibility (a target-admin action
    gated by ``staging_substrate:manage``). Non-secret; grants nothing beyond eligibility."""

    id: uuid.UUID
    organization_id: uuid.UUID
    execution_target_id: uuid.UUID
    status: str
