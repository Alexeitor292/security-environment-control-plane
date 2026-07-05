"""Worker-only identity-verification seam for read-only-preflight resolution (SECP-B2-3 / B2-4.4).

This is the narrow seam a durable, independently-verified worker identity implements. The verifier
is given the AUTHORITATIVE preflight (never a caller-supplied organization) and returns a redacted,
safe :class:`VerifiedWorkerIdentity` from the durable ``WorkerIdentityRegistration``, or it fails
closed. The **shipped default denies**: it reads no process environment, host file, container
metadata, network identity endpoint, certificate, or external service, and it never authenticates
anything — so the worker fails closed at ``worker_identity_untrusted`` before the activation
capability, any durable lease, secret resolution, or collection.

A durable-backed verifier may be injected for tests / a future separately-reviewed activation, but
it is never selectable by production worker runtime code (the consumer default is the denying one).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from secp_api.enums import ResolutionLeaseReason

if TYPE_CHECKING:
    from secp_api.models import ReadonlyStagingPreflight
    from sqlalchemy.orm import Session


class WorkerIdentityUnavailable(Exception):
    """Raised when a worker identity cannot be independently verified. Fail closed.

    Redacted: carries only a closed reason code, never an identity value, host detail, or secret.
    """

    reason = ResolutionLeaseReason.worker_identity_untrusted


@dataclass(frozen=True)
class VerifiedWorkerIdentity:
    """The redacted, safe result of durable worker-identity verification (SECP-B2-4.4).

    Carries ONLY authoritative, non-secret facts from the durable ``WorkerIdentityRegistration``
    — never a certificate/PEM, public-key text, private material, CSR, endpoint, raw claim, or a
    secret reference. ``worker_identity_id`` is the opaque identity label (used as the lease worker
    id); ``deployment_binding_fingerprint`` is a ``sha256:`` hash of the opaque deployment binding.
    """

    worker_identity_id: str
    registration_id: uuid.UUID
    organization_id: uuid.UUID
    identity_version: int
    mechanism: str
    deployment_binding_fingerprint: str

    def __post_init__(self) -> None:
        if not (isinstance(self.worker_identity_id, str) and self.worker_identity_id.strip()):
            raise WorkerIdentityUnavailable("worker identity id is blank")

    def __repr__(self) -> str:
        return "VerifiedWorkerIdentity(<redacted>)"

    __str__ = __repr__


@runtime_checkable
class WorkerIdentityVerifier(Protocol):
    """Narrow worker-only seam. ``verify`` returns a :class:`VerifiedWorkerIdentity` or fails.

    It receives the AUTHORITATIVE preflight and MUST bind any durable-registration lookup to the
    preflight organization, never a caller-supplied organization.
    """

    def verify(
        self, session: Session, *, preflight: ReadonlyStagingPreflight, now: datetime
    ) -> VerifiedWorkerIdentity: ...


class DenyingWorkerIdentityVerifier:
    """The shipped default: DENIES every verification and fails closed.

    It performs no I/O of any kind — no environment read, no host-file access, no container data,
    no network identity endpoint, no certificate, no external service. There is no configuration,
    environment variable, or flag that makes it approve.
    """

    def verify(
        self, session: Session, *, preflight: ReadonlyStagingPreflight, now: datetime
    ) -> VerifiedWorkerIdentity:
        raise WorkerIdentityUnavailable(
            "no independently authenticated worker identity is configured"
        )
