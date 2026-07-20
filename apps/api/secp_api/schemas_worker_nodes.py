"""SECP-B8 API schemas for worker discovery node public-key publication.

Request models accept ONLY PUBLIC material (an SSH public key line + an Ed25519 anchor hex). A
private key is rejected in the service before anything is written. Response models expose only the
public key material + fingerprints — never a private key.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, model_validator


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class WorkerNodeRegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    node_label: str = Field(min_length=1, max_length=120)
    # The worker's SSH PUBLIC key ("ssh-<type> <base64> [comment]"). A private key is rejected.
    ssh_public_key: str = Field(min_length=32, max_length=8192)
    # The worker's Ed25519 admission PUBLIC anchor (64 hex chars). Never a private key.
    admission_anchor_hex: str = Field(min_length=64, max_length=64)


class WorkerNodeIdentityApprovalLinkRequest(BaseModel):
    """Explicit, secret-free operator review that creates/approves/links one node identity."""

    model_config = ConfigDict(extra="forbid")

    expected_node_revision: StrictInt = Field(ge=1)
    expected_ssh_public_key_fingerprint: str = Field(min_length=8, max_length=200)
    expected_admission_anchor_fingerprint: str = Field(min_length=71, max_length=71)
    deployment_binding: str = Field(min_length=1, max_length=120)
    proof_id: str = Field(min_length=1, max_length=120)
    issuer: str = Field(min_length=1, max_length=120)
    deployment_binding_review_confirmed: StrictBool
    verification_anchor_review_confirmed: StrictBool
    rotation_revocation_review_confirmed: StrictBool

    @model_validator(mode="before")
    @classmethod
    def require_literal_true_reviews(cls, value: object) -> object:
        """Reject false and coercible stand-ins such as JSON ``1`` or ``"true"``."""
        fields = (
            "deployment_binding_review_confirmed",
            "verification_anchor_review_confirmed",
            "rotation_revocation_review_confirmed",
        )
        if not isinstance(value, Mapping) or any(value.get(field) is not True for field in fields):
            raise ValueError("all worker identity reviews require literal JSON true")
        return value


class WorkerNodeOut(ORMModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    node_label: str
    ssh_public_key: str
    ssh_public_key_fingerprint: str
    admission_anchor_hex: str
    admission_anchor_fingerprint: str
    revision: int
    worker_identity_registration_id: uuid.UUID | None = None
    created_at: datetime
    updated_at: datetime
