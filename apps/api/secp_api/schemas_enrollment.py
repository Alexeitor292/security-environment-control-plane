"""API schemas for the supported worker-enrollment path (SECP-PR5H-B1).

The controller API surface over the durable PR5H-A enrollment foundation. Secret-free by
construction: the request carries only the controller's OWN public identity, a signed release
digest, an opaque deployment-site label and a bounded TTL; the response carries the **non-secret**
invitation the operator hands to the worker plus the bounded status projection — never a private
key, a raw handoff record, a host path, an endpoint beyond the controller's own HTTPS origin, or a
free-form message.

The controller identity (installation id, key id, trust anchor, origin, running release digest) is
NOT a caller input: the service sources it from the authoritative, persisted, independently verified
ACTIVE controller bootstrap identity (F3). ``extra="forbid"`` makes any caller-supplied identity
field a 422 rather than a silently ignored value.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

_SITE = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$"
# A high-entropy idempotency key the supported CLI/UI generates automatically (never typed by a
# human): a closed url-safe alphabet, 22-128 chars (>= 128 bits at 22). The RAW key is never logged
# or persisted — only its org-bound domain-separated digest becomes the durable single-use nonce.
_IDEMPOTENCY_KEY = r"^[A-Za-z0-9_-]{22,128}$"


class CreateEnrollmentInvitation(BaseModel):
    """Create a single-use worker-enrollment invitation. The controller identity, nonce, transaction
    id and timestamps are all server-owned; the enrollment id is derived from the invitation
    digest. Retry-safe: an exact retry with the same ``idempotency_key`` returns the original."""

    model_config = ConfigDict(extra="forbid")

    idempotency_key: str = Field(pattern=_IDEMPOTENCY_KEY)
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


class RevokeEnrollment(BaseModel):
    """Operator revocation. ``expected_revision`` is the revision the client last observed (from the
    status projection); a stale value on a live enrollment refuses a bounded conflict."""

    model_config = ConfigDict(extra="forbid")

    expected_revision: int = Field(ge=0)


_DIGEST = r"^sha256:[0-9a-f]{64}$"

# Progression requests carry ONLY the caller's last-observed ``expected_revision`` (a small integer
# from the status projection) — never internal CAS coordinates. The service loads the authoritative
# row and DERIVES ``state_digest`` / ``sequence`` / ``predecessor_digest`` from that exact state, so
# a customer, worker CLI or UI never has to compute, store or manage the durable CAS material.


class BindWorkerRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    worker_installation_id: str = Field(min_length=1, max_length=64)
    worker_key_id: str = Field(pattern=_DIGEST)
    transaction_id: str = Field(min_length=1, max_length=512)
    expected_revision: int = Field(ge=0)


class RecordHandoffRequest(BaseModel):
    """A bound handoff fact (controller-offer or worker-result). The API consumes ALREADY-BOUND
    facts — a digest + transaction + signer key id — never raw handoff bytes or a private key."""

    model_config = ConfigDict(extra="forbid")

    digest: str = Field(pattern=_DIGEST)
    transaction_id: str = Field(min_length=1, max_length=512)
    signer_key_id: str = Field(pattern=_DIGEST)
    expected_revision: int = Field(ge=0)


class VerifyReleaseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    release_digest: str = Field(pattern=_DIGEST)
    expected_revision: int = Field(ge=0)


class MarkHealthyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_revision: int = Field(ge=0)


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
