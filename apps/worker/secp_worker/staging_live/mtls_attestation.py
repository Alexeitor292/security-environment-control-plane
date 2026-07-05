"""Concrete mTLS workload-identity attestation source with proof-of-possession (SECP-B2-5-pre).

Unlike public-anchor fingerprint matching ALONE, this source proves possession of the deployment-
local private material by signing a FRESH, bounded, non-replayable challenge tied to the current
preflight operation and verifying that signature against the public anchor — at attest time — before
emitting the (still re-verifiable) :class:`WorkerIdentityClaim`. The private material is supplied
ONLY through an explicitly injected, deployment-local :class:`MtlsWorkloadMaterial`; there is no Git
value, environment-variable enable switch, database toggle, or worker default that selects or
configures it. It never logs or persists a PEM, certificate, key, CSR, signature, challenge, subject
DN, SAN, or raw provider error, and it contacts no CA or network. Normal worker modules must not
import this module.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable

from secp_api.models import ReadonlyStagingPreflight

from secp_worker.preflight.worker_identity_attestation import (
    WorkerIdentityAttestationUnavailable,
    WorkerIdentityClaim,
)


class MtlsMaterialUnavailable(Exception):
    """Raised by sealed/failing mTLS material. Closed reason only, no value leak."""

    def __init__(self, reason_code: str = "mtls_material_unavailable") -> None:
        super().__init__(f"mtls material unavailable: {reason_code}")
        self.reason_code = reason_code


@runtime_checkable
class MtlsWorkloadMaterial(Protocol):
    """Deployment-local mTLS material seam. An implementation is supplied ONLY out of band on the
    isolated worker; it never enters Git. It exposes the PUBLIC anchor and can sign + verify a
    challenge — never revealing the private key/PEM/CSR."""

    def public_anchor(self) -> str: ...
    def sign_challenge(self, challenge: bytes) -> bytes: ...
    def verify_signature(self, challenge: bytes, signature: bytes) -> bool: ...


class SealedMtlsWorkloadMaterial:
    """The shipped default: NO material. Signing/anchor refuse and verification fails — no I/O."""

    def public_anchor(self) -> str:
        raise MtlsMaterialUnavailable("no deployment-local mtls material is configured")

    def sign_challenge(self, challenge: bytes) -> bytes:
        raise MtlsMaterialUnavailable("no deployment-local mtls material is configured")

    def verify_signature(self, challenge: bytes, signature: bytes) -> bool:
        return False


@dataclass(frozen=True)
class MtlsIdentityDescriptor:
    """The claimed identity metadata (safe/opaque). The org/label/binding/version/mechanism are
    re-checked against the registration by the worker verifier; possession is proven here."""

    organization_id: uuid.UUID
    mechanism: str
    identity_label: str
    deployment_binding: str
    identity_version: int


def build_operation_challenge(preflight: ReadonlyStagingPreflight, now: datetime) -> bytes:
    """A fresh, bounded, NON-REPLAYABLE challenge tied to THIS preflight operation + a random nonce.

    Derived from the durable operation identity (preflight id + operation fingerprint) + the current
    time + a fresh cryptographic nonce, hashed to a fixed-length value. It carries no secret and is
    never persisted or logged.
    """
    nonce = secrets.token_bytes(32)
    material = (
        f"{preflight.id}|{preflight.operation_fingerprint}|{now.isoformat()}".encode() + nonce
    )
    return hashlib.sha256(material).digest()


class MtlsWorkloadIdentitySource:
    """A proof-of-possession mTLS attestation source. Constructed ONLY with explicitly injected
    deployment-local material — never selectable by a worker default."""

    def __init__(
        self, *, material: MtlsWorkloadMaterial, descriptor: MtlsIdentityDescriptor
    ) -> None:
        self._material = material
        self._descriptor = descriptor

    def attest(self, *, preflight: ReadonlyStagingPreflight, now: datetime) -> WorkerIdentityClaim:
        challenge = build_operation_challenge(preflight, now)
        try:
            signature = self._material.sign_challenge(challenge)
            anchor = self._material.public_anchor()
            proven = self._material.verify_signature(challenge, signature)
        except MtlsMaterialUnavailable as exc:
            # Fail closed with a CLOSED reason — never surface the underlying material error.
            raise WorkerIdentityAttestationUnavailable("mtls_material_unavailable") from exc
        if not proven:
            raise WorkerIdentityAttestationUnavailable("proof_of_possession_failed")
        d = self._descriptor
        return WorkerIdentityClaim(
            organization_id=d.organization_id,
            mechanism=d.mechanism,
            identity_label=d.identity_label,
            deployment_binding=d.deployment_binding,
            identity_version=d.identity_version,
            public_anchor=anchor,
        )
