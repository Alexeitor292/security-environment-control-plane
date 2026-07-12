"""Strict request schema for the EnvironmentVersion publication API (ADR-016 PR C).

The route passes these fields verbatim to the transactional publication service, which performs
the authoritative v1alpha2 validation and closed-code mapping. The schema is deliberately narrow:
no caller idempotency key, no caller publication fingerprint, no caller topology bytes, and no
caller provenance object outside ``definition`` (extra fields are forbidden). Malformed values
are never echoed — the app's request-validation redaction returns only a generic closed code.
"""

from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EnvironmentPublicationRequest(BaseModel):
    """Publish an approved topology revision + non-topology v1alpha2 definition into a new
    immutable EnvironmentVersion. ``definition`` stays a raw mapping because the publication
    service is the authoritative validator; the server owns hashing, provenance, and the
    idempotency fingerprint (none of which the caller may supply)."""

    model_config = ConfigDict(extra="forbid")

    template_id: uuid.UUID
    definition: dict[str, Any]
    topology_document_id: uuid.UUID
    topology_revision_id: uuid.UUID
    expected_topology_content_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    validation_result_id: uuid.UUID
    base_environment_version_id: uuid.UUID | None = None
