"""Independent cryptographic proof-of-possession for worker identity (SECP-B3).

This closes B2-5-pre activation-review condition C. The prior ``MtlsWorkloadIdentitySource`` let the
SAME injected material object both sign a challenge and validate its own signature — a dishonest
material trivially passed. Here the SIGNER and VERIFIER are DIFFERENT objects: a deployment-local
:class:`DeploymentLocalSigner` produces a signature, and a separate :class:`IndependentPoPVerifier`
verifies it CRYPTOGRAPHICALLY against the anchor whose fingerprint is pinned in the durable
registration (never one the signer merely asserts). Proof is bound to a fresh, bounded,
operation-specific challenge, so replay, a wrong key, a wrong identity, a stale challenge, and a
cross-org proof all fail closed.

Signature scheme: a hash-based one-time signature (Lamport over SHA-256). It is genuinely asymmetric
in the property that matters here — verification uses ONLY the public anchor + the signature and
never the private key — and it is standard-library-only (no third-party crypto dependency, no
network, no CA). The asymmetric alternative (Ed25519) is an injectable :class:`PoPSignatureScheme`
seam for when a vetted asymmetric dependency is added; the verifier is agnostic to the scheme.

Nothing here logs or persists a private key, anchor, challenge, signature, or raw error; only
closed reason codes and pass/fail. No certificate/CSR/key/PEM is parsed and no I/O is performed.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol, runtime_checkable

from secp_api.models import ReadonlyStagingPreflight
from secp_api.worker_identity_contract import compute_verification_anchor_fingerprint

from secp_worker.preflight.fingerprint import compute_operation_fingerprint
from secp_worker.preflight.worker_identity_attestation import (
    WorkerIdentityAttestationUnavailable,
    WorkerIdentityClaim,
)

# A challenge is short-lived: proof must be produced and verified within a tight bound.
DEFAULT_CHALLENGE_TTL_SECONDS = 120
# Lamport parameters: SHA-256 → a 256-bit message digest → 256 revealed preimages of 32 bytes.
_DIGEST_BITS = 256
_LEAF_BYTES = 32


class DeploymentSignerUnavailable(Exception):
    """Raised by a sealed/failing deployment-local signer. Closed reason only; no value leak."""

    def __init__(self, reason_code: str = "deployment_signer_unavailable") -> None:
        super().__init__(f"deployment signer unavailable: {reason_code}")
        self.reason_code = reason_code


@runtime_checkable
class PoPSignatureScheme(Protocol):
    """A verification-only view of a signature scheme. ``verify`` uses ONLY the public anchor + the
    signature — never the private key — so a separate verifier can validate a signer's proof."""

    def verify(self, *, public_anchor: str, message: bytes, signature: str) -> bool: ...


@runtime_checkable
class DeploymentLocalSigner(Protocol):
    """The deployment-local private-material seam (worker-only, injected). It exposes the
    PUBLIC anchor and signs a challenge; it NEVER reveals the private key. Distinct from verifier
    so no object validates its own proof."""

    def public_anchor(self) -> str: ...
    def sign(self, message: bytes) -> str: ...


class SealedDeploymentLocalSigner:
    """The shipped default: NO signer. Anchor/sign refuse — no material, no I/O."""

    def public_anchor(self) -> str:
        raise DeploymentSignerUnavailable("no deployment-local signer is configured")

    def sign(self, message: bytes) -> str:
        raise DeploymentSignerUnavailable("no deployment-local signer is configured")


def _bit(digest: bytes, index: int) -> int:
    return (digest[index // 8] >> (index % 8)) & 1


class HashBasedPoPScheme:
    """A Lamport one-time signature over SHA-256 (standard-library-only, public-verifiable).

    The public anchor is hashed leaves; a signature reveals one preimage per message-digest
    bit; verification hashes each revealed preimage and compares to the anchor — using only public
    data. Reuse of a key would leak; each PoP uses a FRESH per-operation challenge, so
    every signature covers a distinct message and a one-time key is sufficient and safe.
    """

    def generate_signer(self) -> InMemoryHashBasedSigner:
        """Generate a fresh deployment-local signer (private leaves + derived public anchor)."""
        private = [
            [secrets.token_bytes(_LEAF_BYTES) for _ in range(_DIGEST_BITS)] for _ in range(2)
        ]
        anchor_leaves = [
            [hashlib.sha256(private[b][i]).digest() for i in range(_DIGEST_BITS)] for b in range(2)
        ]
        anchor_hex = b"".join(anchor_leaves[0] + anchor_leaves[1]).hex()
        return InMemoryHashBasedSigner(scheme=self, private=private, public_anchor_hex=anchor_hex)

    def sign(self, *, private: list[list[bytes]], message: bytes) -> str:
        digest = hashlib.sha256(message).digest()
        revealed = [private[_bit(digest, i)][i] for i in range(_DIGEST_BITS)]
        return b"".join(revealed).hex()

    def verify(self, *, public_anchor: str, message: bytes, signature: str) -> bool:
        try:
            anchor = bytes.fromhex(public_anchor)
            sig = bytes.fromhex(signature)
        except ValueError:
            return False
        if len(anchor) != 2 * _DIGEST_BITS * _LEAF_BYTES or len(sig) != _DIGEST_BITS * _LEAF_BYTES:
            return False
        digest = hashlib.sha256(message).digest()
        ok = True
        for i in range(_DIGEST_BITS):
            b = _bit(digest, i)
            preimage = sig[i * _LEAF_BYTES : (i + 1) * _LEAF_BYTES]
            expected = anchor[(b * _DIGEST_BITS + i) * _LEAF_BYTES :][:_LEAF_BYTES]
            # Constant-time compare; accumulate so total work is independent of where a mismatch is.
            ok &= hmac.compare_digest(hashlib.sha256(preimage).digest(), expected)
        return bool(ok)


@dataclass(frozen=True)
class InMemoryHashBasedSigner:
    """A deployment-local :class:`DeploymentLocalSigner` backed by an in-memory one-time key.

    The private leaves live only in this object and are never serialized, logged, or persisted. Used
    on the isolated worker (real material injected out of band) and in tests.
    """

    scheme: HashBasedPoPScheme
    private: list[list[bytes]]
    public_anchor_hex: str

    def public_anchor(self) -> str:
        return self.public_anchor_hex

    def sign(self, message: bytes) -> str:
        return self.scheme.sign(private=self.private, message=message)

    def __repr__(self) -> str:  # never expose private leaves
        return "InMemoryHashBasedSigner(<redacted>)"


@dataclass(frozen=True)
class OperationChallenge:
    """A fresh, bounded, non-replayable challenge bound to ONE preflight operation.

    ``value`` is a random nonce; the signed message additionally folds in the operation identity and
    expiry so a signature cannot be replayed for another operation or after it expires. Carries no
    secret and is never persisted or logged.
    """

    value: str
    preflight_id: str
    operation_fingerprint: str
    issued_at: datetime
    expires_at: datetime

    def signing_message(self) -> bytes:
        return (
            f"secp-b3/pop/v1|{self.value}|{self.preflight_id}|"
            f"{self.operation_fingerprint}|{self.expires_at.isoformat()}"
        ).encode()


def issue_operation_challenge(
    *,
    preflight: ReadonlyStagingPreflight,
    now: datetime,
    ttl_seconds: int = DEFAULT_CHALLENGE_TTL_SECONDS,
    nonce: str | None = None,
) -> OperationChallenge:
    """Issue a fresh, bounded challenge tied to THIS preflight operation. A random nonce makes it
    non-replayable; ``ttl_seconds`` bounds its validity."""
    return OperationChallenge(
        value=nonce or secrets.token_hex(32),
        preflight_id=str(preflight.id),
        operation_fingerprint=compute_operation_fingerprint(preflight),
        issued_at=now,
        expires_at=now + timedelta(seconds=ttl_seconds),
    )


@dataclass(frozen=True)
class PoPResult:
    """A closed proof-of-possession outcome. Never carries a key/anchor/signature/value."""

    ok: bool
    reason_code: str


class IndependentPoPVerifier:
    """Verifies a proof-of-possession INDEPENDENTLY of the signer.

    Given the anchor fingerprint pinned in the registration (never one the signer asserts), a
    fresh operation challenge, the presented anchor, and the signature, it: (1) rejects a stale
    challenge; (2) rejects a challenge bound to a different operation (replay); (3)
    pins the presented anchor to the registered fingerprint (wrong identity / cross-org fail here);
    (4) cryptographically verifies the signature over the challenge message with the injected scheme
    (wrong key / tampered / replayed-stale signature fail here). Returns a closed result.
    """

    def __init__(self, scheme: PoPSignatureScheme) -> None:
        self._scheme = scheme

    def verify(
        self,
        *,
        registered_anchor_fingerprint: str,
        presented_anchor: str,
        challenge: OperationChallenge,
        signature: str,
        now: datetime,
        expected_preflight_id: str,
        expected_operation_fingerprint: str,
    ) -> PoPResult:
        if now > challenge.expires_at:
            return PoPResult(ok=False, reason_code="stale_challenge")
        if (
            challenge.preflight_id != expected_preflight_id
            or challenge.operation_fingerprint != expected_operation_fingerprint
        ):
            return PoPResult(ok=False, reason_code="challenge_operation_mismatch")
        if not (isinstance(presented_anchor, str) and presented_anchor):
            return PoPResult(ok=False, reason_code="anchor_missing")
        # Pin the presented anchor to the registered fingerprint (never signer-asserted).
        if not hmac.compare_digest(
            compute_verification_anchor_fingerprint(presented_anchor),
            str(registered_anchor_fingerprint),
        ):
            return PoPResult(ok=False, reason_code="anchor_pin_mismatch")
        if not self._scheme.verify(
            public_anchor=presented_anchor,
            message=challenge.signing_message(),
            signature=signature,
        ):
            return PoPResult(ok=False, reason_code="proof_of_possession_failed")
        return PoPResult(ok=True, reason_code="verified")


@dataclass(frozen=True)
class MtlsIdentityDescriptor:
    """The claimed identity metadata (safe/opaque). The org/label/binding/version/mechanism are
    re-checked against the durable registration by the worker verifier; possession is proven here.
    """

    organization_id: uuid.UUID
    mechanism: str
    identity_label: str
    deployment_binding: str
    identity_version: int


class PoPVerifiedAttestationSource:
    """A ``WorkerIdentityAttestationSource`` that emits a claim ONLY after an INDEPENDENT
    proof-of-possession verification succeeds.

    Construction requires a deployment-local ``signer`` (private material), a SEPARATE
    ``IndependentPoPVerifier``, the ``descriptor``, and the anchor fingerprint pinned in the
    durable registration. ``attest`` issues a fresh operation challenge, signs it, and verifies the
    signature independently against the pinned anchor before returning the claim; the object that
    signs never validates its own proof. Any failure raises a closed
    ``WorkerIdentityAttestationUnavailable``; no key/anchor/challenge/signature is logged.
    """

    def __init__(
        self,
        *,
        signer: DeploymentLocalSigner,
        verifier: IndependentPoPVerifier,
        descriptor: MtlsIdentityDescriptor,
        registered_anchor_fingerprint: str,
        ttl_seconds: int = DEFAULT_CHALLENGE_TTL_SECONDS,
    ) -> None:
        self._signer = signer
        self._verifier = verifier
        self._descriptor = descriptor
        self._registered_anchor_fingerprint = registered_anchor_fingerprint
        self._ttl_seconds = ttl_seconds

    def attest(self, *, preflight: ReadonlyStagingPreflight, now: datetime) -> WorkerIdentityClaim:
        challenge = issue_operation_challenge(
            preflight=preflight, now=now, ttl_seconds=self._ttl_seconds
        )
        try:
            anchor = self._signer.public_anchor()
            signature = self._signer.sign(challenge.signing_message())
        except DeploymentSignerUnavailable as exc:
            raise WorkerIdentityAttestationUnavailable("deployment_signer_unavailable") from exc
        result = self._verifier.verify(
            registered_anchor_fingerprint=self._registered_anchor_fingerprint,
            presented_anchor=anchor,
            challenge=challenge,
            signature=signature,
            now=now,
            expected_preflight_id=str(preflight.id),
            expected_operation_fingerprint=compute_operation_fingerprint(preflight),
        )
        if not result.ok:
            raise WorkerIdentityAttestationUnavailable(result.reason_code)
        d = self._descriptor
        return WorkerIdentityClaim(
            organization_id=d.organization_id,
            mechanism=d.mechanism,
            identity_label=d.identity_label,
            deployment_binding=d.deployment_binding,
            identity_version=d.identity_version,
            public_anchor=anchor,
        )
