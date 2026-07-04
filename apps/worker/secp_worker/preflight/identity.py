"""Worker-only identity-verification seam for read-only-preflight resolution (SECP-B2-3).

This is the narrow seam a FUTURE, independently authenticated worker identity would implement. The
**shipped default denies**: it reads no process environment, host file, container metadata, network
identity endpoint, certificate, or external service, and it never authenticates anything. It exists
so the worker fails closed at ``worker_identity_untrusted`` before any durable lease is acquired.

A test-only static verifier may be injected for lease-state tests, but it lives in the tests and is
never selectable by production worker runtime code (the consumer default is the denying verifier).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from secp_api.enums import ResolutionLeaseReason


class WorkerIdentityUnavailable(Exception):
    """Raised when a worker identity cannot be independently verified. Fail closed.

    Redacted: carries only a closed reason code, never an identity value, host detail, or secret.
    """

    reason = ResolutionLeaseReason.worker_identity_untrusted


@dataclass(frozen=True)
class WorkerIdentity:
    """A secret-free, independently-verified worker identity id, for audit/evidence only."""

    worker_identity_id: str

    def __post_init__(self) -> None:
        if not (isinstance(self.worker_identity_id, str) and self.worker_identity_id.strip()):
            raise WorkerIdentityUnavailable("worker identity id is blank")


@runtime_checkable
class WorkerIdentityVerifier(Protocol):
    """Narrow worker-only seam. ``verify`` returns a :class:`WorkerIdentity` or fails closed."""

    def verify(self) -> WorkerIdentity: ...


class DenyingWorkerIdentityVerifier:
    """The shipped default: DENIES every verification and fails closed.

    It performs no I/O of any kind — no environment read, no host-file access, no container
    metadata, no network identity endpoint, no certificate, no external service. There is no
    configuration, environment variable, or flag that makes it approve.
    """

    def verify(self) -> WorkerIdentity:
        raise WorkerIdentityUnavailable(
            "no independently authenticated worker identity is configured"
        )
