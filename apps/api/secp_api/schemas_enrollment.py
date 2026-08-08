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

**DECISION — the invitation response is ONE-SHOT, and there is deliberately no re-fetch route.**

:class:`EnrollmentInvitationOut` is returned exactly once, by the create call
(``POST /api/v1/enrollment/invitations``) — or by an exact ``idempotency_key`` retry of that same
create, which replays the ORIGINAL response.
No other endpoint returns it: the status projection, the org-scoped list, and every progression
response carry only :class:`EnrollmentStatusOut`. An operator who loses the invitation revokes and
re-creates; that is the supported remedy, not a recovery gap.

This is a security property, not an oversight. The invitation is **bearer-grade**:
``bind_worker_exchange`` verifies that the presenter owns the key it presents, NOT that it is the
intended recipient (``services/worker_enrollment.py``) — so the first valid binder wins. A re-fetch
route would let a compromised ``enrollment:manage`` credential silently steal an *in-flight*
enrollment: read the invitation, bind first, and the legitimate worker's later bind refuses as
``enrollment_already_bound`` with nothing to distinguish theft from a race. Without such a route the
same attacker must first REVOKE the enrollment — an ordinary, audited, operator-visible action that
the legitimate worker observes as a refusal it can attribute. Keeping the material one-shot
therefore converts a silent takeover into a loud one.

The UI already tells the operator the invitation is shown once; this docstring is the written
rationale that behaviour is meant to rest on. Adding a re-fetch endpoint would reverse a security
decision and must not be done as a convenience change.
"""

from __future__ import annotations

from typing import Literal

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


class MarkRecoveryRequired(BaseModel):
    """Operator-triggered recovery: mark an enrollment as needing operator remediation.

    The complement of the scheduled expiry sweep — the sweep reaches enrollments that ran out of
    time, this reaches one an operator has decided is stuck, without waiting for the TTL. Carries
    ONLY the last-observed ``expected_revision``; the reason code is server-owned (a bounded code,
    never caller free-text) and the durable CAS coordinates are derived server-side.
    """

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
    #: The opaque deployment-site grouping label, so an operator inventory can group workers without
    #: a second round trip. Outside the canonical contract by construction — it can never affect
    #: ``state_digest``, the CAS chain, or any durable invariant. Organization remains the ONLY
    #: authorization boundary; this label is never interpreted as a tenant, address or endpoint.
    deployment_site_label: str
    expires_at: str
    updated_at: str
    refusal_reason: str


class EnrollmentListOut(BaseModel):
    """One org-scoped page of the enrollment inventory.

    NO invitation material appears here — a list carries only the bounded status projection. The
    single-use invitation is returned exactly once, by the create call (see the one-shot decision in
    this module's docstring); it is never re-derivable from a list, a status read, or a cursor.

    ``next_cursor`` is an OPAQUE keyset continuation token over the ``(expires_at, enrollment_id)``
    order. It is null when this page was the last one. Clients must treat it as a blob: pass it back
    verbatim as ``after`` and never parse, construct, or persist its decoded form.
    """

    items: list[EnrollmentStatusOut]
    next_cursor: str | None = None


# --- SECP-PR5H-B1 Phase 3: the supported evidence-driven exchange -------------------------------
# The worker proves possession of its own key by SIGNING a bound claim; the controller mints an
# internally-signed offer via the root-gated broker and returns it. Requests carry ONLY public
# material (the worker's public key + detached attestation + the last-observed revision); the worker
# key id is DERIVED from the presented public key and is never accepted from the wire.

_HEX64 = r"^[0-9a-f]{64}$"
_HEX128 = r"^[0-9a-f]{128}$"
# a bounded worker installation label (the worker's claimed label, signature-bound into the PoP)
_INSTALL = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$"


class DetachedAttestationIn(BaseModel):
    """A detached Ed25519 attestation presented by the worker. PUBLIC material only."""

    model_config = ConfigDict(extra="forbid")

    algorithm: Literal["Ed25519"]
    key_id: str = Field(pattern=_DIGEST)
    public_key_hex: str = Field(pattern=_HEX64)
    signature: str = Field(pattern=_HEX128)


class DetachedAttestationOut(BaseModel):
    """A detached Ed25519 attestation returned to the worker (the controller offer signature)."""

    algorithm: str
    key_id: str
    public_key_hex: str
    signature: str


class SignedControllerOfferOut(BaseModel):
    """The internally-signed controller offer: the canonical claim + its detached attestation. The
    worker re-verifies it against the invitation-pinned controller key."""

    claim: dict[str, str]
    attestation: DetachedAttestationOut


class BindExchangeRequest(BaseModel):
    """The worker-initiated bind exchange (proof-of-possession). Carries ONLY the worker's presented
    public key, its claimed installation label, the detached PoP attestation, and the last-observed
    revision. ``worker_key_id`` is NEVER accepted — it is derived from ``worker_public_key_hex``."""

    model_config = ConfigDict(extra="forbid")

    worker_installation_id: str = Field(pattern=_INSTALL)
    worker_public_key_hex: str = Field(pattern=_HEX64)
    attestation: DetachedAttestationIn
    expected_revision: int = Field(ge=0)


class BindExchangeOut(BaseModel):
    """The bind-exchange response: the internally-signed controller offer + the bounded status."""

    signed_offer: SignedControllerOfferOut
    signed_ownership: SignedControllerOfferOut
    enrollment: EnrollmentStatusOut


class ResultExchangeRequest(BaseModel):
    """The worker-initiated result exchange. Carries the worker's presented public key, the bounded
    outcome token, the detached worker-result attestation, the bounded health-evidence structure the
    controller recomputes the digest from (CHECKED FACTS, never a caller boolean), and the
    last-observed revision. The controller rebuilds the signed claim from AUTHORITATIVE state (the
    result claim is never accepted from the wire); only an authenticated, fully-passing,
    successful-outcome result advances the enrollment to verified then healthy."""

    model_config = ConfigDict(extra="forbid")

    worker_public_key_hex: str = Field(pattern=_HEX64)
    outcome: str = Field(min_length=1, max_length=64)
    attestation: DetachedAttestationIn
    health_evidence: dict[str, bool]
    expected_revision: int = Field(ge=0)


class ResultExchangeOut(BaseModel):
    """The result-exchange response: the final bounded enrollment status (verified/healthy)."""

    enrollment: EnrollmentStatusOut
