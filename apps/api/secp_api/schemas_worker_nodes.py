"""SECP-B8 API schemas for worker discovery node public-key publication.

Request models accept ONLY PUBLIC material (an SSH public key line + an Ed25519 anchor hex). A
private key is rejected in the service before anything is written. Response models expose only the
public key material + fingerprints — never a private key.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class WorkerNodeRegisterRequest(BaseModel):
    node_label: str = Field(min_length=1, max_length=120)
    # The worker's SSH PUBLIC key ("ssh-<type> <base64> [comment]"). A private key is rejected.
    ssh_public_key: str = Field(min_length=32, max_length=8192)
    # The worker's Ed25519 admission PUBLIC anchor (64 hex chars). Never a private key.
    admission_anchor_hex: str = Field(min_length=64, max_length=64)


class WorkerNodeOut(ORMModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    node_label: str
    ssh_public_key: str
    ssh_public_key_fingerprint: str
    admission_anchor_hex: str
    admission_anchor_fingerprint: str
    worker_identity_registration_id: uuid.UUID | None = None
    created_at: datetime
    updated_at: datetime
