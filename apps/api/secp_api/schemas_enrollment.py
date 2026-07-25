"""API schemas for the supported worker-enrollment path (SECP-PR5H-B1).

The controller API surface over the durable PR5H-A enrollment foundation. Secret-free by
construction: the request carries only the controller's OWN public identity, a signed release
digest, an opaque deployment-site label and a bounded TTL; the response carries the **non-secret**
invitation the operator hands to the worker plus the bounded status projection — never a private
key, a raw handoff record, a host path, an endpoint beyond the controller's own HTTPS origin, or a
free-form message.

NOTE (skeleton seam, PR5H-B1): the controller identity fields are accepted as request input in this
first vertical slice. A subsequent B1 slice sources them from the controller's persisted bootstrap
identity and removes them from the request, so a caller can never bind an arbitrary controller
identity. Tracked in the PR5H-B1 map.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

# The controller's HTTPS origin the worker will connect OUTBOUND to (validated exactly by the pure
# contract's grammar; bounded here as defense in depth). Never an internal address or a path.
_ORIGIN_MAX = 269
_HEX64 = r"^[0-9a-f]{64}$"
_DIGEST = r"^sha256:[0-9a-f]{64}$"
_INSTALL = r"^[a-z0-9][a-z0-9-]{7,63}$"
_SITE = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$"


class CreateEnrollmentInvitation(BaseModel):
    """Create a single-use worker-enrollment invitation. The nonce, transaction id and timestamps
    are generated server-side; the enrollment id is derived from the invitation digest."""

    controller_installation_id: str = Field(pattern=_INSTALL)
    controller_key_id: str = Field(pattern=_DIGEST)
    controller_trust_anchor_hex: str = Field(pattern=_HEX64)
    controller_origin: str = Field(min_length=1, max_length=_ORIGIN_MAX)
    release_digest: str = Field(pattern=_DIGEST)
    deployment_site_label: str = Field(pattern=_SITE)
    ttl_seconds: int = Field(default=3600, ge=1, le=86400)


class EnrollmentInvitationOut(BaseModel):
    """The non-secret invitation an operator hands to a worker to begin enrollment."""

    enrollment_id: str
    invitation_id: str
    controller_installation_id: str
    controller_key_id: str
    controller_trust_anchor_hex: str
    controller_origin: str
    release_digest: str
    transaction_id: str
    deployment_site_label: str
    created_at: str
    expires_at: str
    state: str
    revision: int


class EnrollmentStatusOut(BaseModel):
    """The bounded, secret-free enrollment status projection (mirror of the durable public view)."""

    enrollment_id: str
    state: str
    revision: int
    controller_installation_id: str
    controller_key_fingerprint: str
    worker_installation_id: str
    worker_key_fingerprint: str
    release_fingerprint: str
    offer_fingerprint: str
    result_fingerprint: str
    expires_at: str
    updated_at: str
    refusal_reason: str
