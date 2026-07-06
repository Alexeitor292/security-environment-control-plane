"""Independent cryptographic proof-of-possession for worker identity (SECP-B3).

This closes B2-5-pre activation-review condition C. The prior ``MtlsWorkloadIdentitySource`` let the
SAME injected material object both sign a challenge and validate its own signature — a dishonest
material trivially passed. Here the SIGNER and VERIFIER are DIFFERENT objects: a deployment-local
:class:`DeploymentLocalSigner` produces a signature, and a separate :class:`IndependentPoPVerifier`
verifies it CRYPTOGRAPHICALLY against the anchor whose fingerprint is pinned in the durable
registration (never one the signer merely asserts). Proof is bound to a fresh, bounded,
operation-specific challenge, so replay, a wrong key, a wrong identity, a stale challenge, and a
cross-org proof all fail closed.

SCOPE — LOCAL possession self-check ONLY, NOT a remote authentication primitive. The shipped scheme
is :class:`LocalHashBasedPoPScheme`, a Lamport-style hash-based signature (standard-library-only, no
third-party dependency, no network, no CA). It is a genuine ONE-TIME signature: it is sound for a
single signature per key, and this module uses it in-process only, where the worker verifies its own
deployment-local material before emitting a claim. It is emphatically NOT safe as a many-time remote
authentication mechanism: a fresh per-operation challenge does NOT make a one-time key safe to reuse
across operations — reused Lamport signatures leak private preimages and become forgeable. The
challenge is also prover-issued (in-process), not verifier-issued, so it cannot establish freshness
to a remote verifier. Accordingly :class:`LocalHashBasedPoPScheme` declares
``remote_authentication_eligible = False`` and :func:`assert_remote_authentication_eligible` refuses
it, so a future remote-authentication path cannot wire it by mistake.

The injectable asymmetric :class:`PoPSignatureScheme` seam is preserved for a future Ed25519-backed
implementation (a many-time primitive) that would declare itself remote-eligible and be paired
with a verifier-issued challenge; the verifier here is agnostic to the scheme. Adding that primitive
(and any dependency it needs) is out of scope for this module — remote mTLS authentication is NOT
solved here.

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
from typing import NoReturn, Protocol, runtime_checkable

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


class RemoteAuthenticationIneligible(Exception):
    """Raised when a scheme not approved for REMOTE authentication is used where remote-eligibility
    is required. Fail closed so the local hash-based possession check can never back remote auth."""

    def __init__(self, reason_code: str = "scheme_not_remote_authentication_eligible") -> None:
        super().__init__(f"remote authentication ineligible: {reason_code}")
        self.reason_code = reason_code


@runtime_checkable
class PoPSignatureScheme(Protocol):
    """A verification-only view of a signature scheme. ``verify`` uses ONLY the public anchor + the
    signature — never the private key — so a separate verifier can validate a signer's proof.

    ``remote_authentication_eligible`` is the gate a remote-authentication path MUST check
    (via :func:`assert_remote_authentication_eligible`): only a many-time asymmetric primitive
    paired with a verifier-issued challenge may declare ``True``. The local hash-based scheme is
    ``False``.
    """

    @property
    def remote_authentication_eligible(self) -> bool: ...

    def verify(self, *, public_anchor: str, message: bytes, signature: str) -> bool: ...


def assert_remote_authentication_eligible(scheme: PoPSignatureScheme) -> None:
    """Fail closed unless ``scheme`` declares itself eligible for REMOTE authentication. The local
    hash-based possession scheme declares ``False``, so this refuses it — a structural guard that
    prevents a future remote-auth path from wiring the in-process placeholder by mistake."""
    if not getattr(scheme, "remote_authentication_eligible", False):
        raise RemoteAuthenticationIneligible


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


class Ed25519PoPScheme:
    """A REAL, remote-eligible asymmetric proof-of-possession scheme (Ed25519 via ``cryptography``).

    Verification uses ONLY the registered public key (the anchor) and the signature — never the
    private key — and Ed25519 is a genuine MANY-TIME primitive, so it is sound for the deployed
    remote-authentication path (unlike the local hash placeholder). The public anchor is the raw
    32-byte Ed25519 public key encoded as hex; a signature is the raw 64-byte signature as hex.

    It declares ``remote_authentication_eligible = True`` (see
    :func:`assert_remote_authentication_eligible`); it is paired with a VERIFIER-issued challenge in
    the remote PoP protocol. No private key is logged, persisted, or exposed; verification never
    raises a raw crypto error (a malformed anchor/signature or a bad proof simply returns
    """

    remote_authentication_eligible: bool = True

    def generate_keypair(self) -> tuple[str, str]:
        """Generate a fresh (private-key-hex, public-anchor-hex) pair. The private hex is used ONLY
        a deployment-local signer/tests and is never persisted or logged."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        private = Ed25519PrivateKey.generate()
        raw_private = private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        raw_public = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return raw_private.hex(), raw_public.hex()

    def sign(self, *, private_key_hex: str, message: bytes) -> str:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
        return private.sign(message).hex()

    def verify(self, *, public_anchor: str, message: bytes, signature: str) -> bool:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        try:
            anchor = bytes.fromhex(public_anchor)
            sig = bytes.fromhex(signature)
        except ValueError:
            return False
        if len(anchor) != 32 or len(sig) != 64:
            return False
        try:
            Ed25519PublicKey.from_public_bytes(anchor).verify(sig, message)
        except (InvalidSignature, ValueError):
            return False
        return True


class LocalHashBasedPoPScheme:
    """A Lamport-style ONE-TIME hash signature over SHA-256 — a LOCAL, in-process possession check.

    Verification uses only public data (the public anchor + the signature), never the private key.
    Its security is one-time: a key is sound for a SINGLE signature. Signing two different messages
    with one key leaks private preimages and enables forgery, so this scheme is NOT safe as a
    many-time remote authentication mechanism; a fresh challenge does not change that.
    It is used here only in-process (the worker checking its own deployment-local material), and it
    declares ``remote_authentication_eligible = False`` so it can never back a remote-auth path.
    """

    # Structural marker: this local placeholder is NOT eligible for remote authentication.
    remote_authentication_eligible: bool = False

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


class SignerNotSerializable(TypeError):
    """Raised if the deployment-local signer is serialized or copied. The private one-time key must
    never leave the process — no pickle/copy/deepcopy/asdict path may reveal or rebuild it.
    """


class InMemoryHashBasedSigner:
    """A deployment-local :class:`DeploymentLocalSigner` backed by an in-memory one-time key.

    The private leaves live ONLY in this object and can never leave the process. It is deliberately
    NOT a dataclass (so ``dataclasses.asdict`` cannot walk it) and uses ``__slots__`` (no dict
    for ``vars()``); pickle, ``copy``, and ``deepcopy`` all refuse; ``repr`` is redacted; and it is
    immutable after construction. In-process signing (and local verification via the scheme's public
    anchor) are unaffected. Used on the isolated worker (real material injected out of band).
    """

    __slots__ = ("_scheme", "_private", "_public_anchor_hex")

    # Annotation-only (no values): declares the slot attribute types without shadowing the slots.
    _scheme: LocalHashBasedPoPScheme
    _private: list[list[bytes]]
    _public_anchor_hex: str

    def __init__(
        self,
        *,
        scheme: LocalHashBasedPoPScheme,
        private: list[list[bytes]],
        public_anchor_hex: str,
    ) -> None:
        object.__setattr__(self, "_scheme", scheme)
        object.__setattr__(self, "_private", private)
        object.__setattr__(self, "_public_anchor_hex", public_anchor_hex)

    def public_anchor(self) -> str:
        return self._public_anchor_hex

    def sign(self, message: bytes) -> str:
        return self._scheme.sign(private=self._private, message=message)

    def __repr__(self) -> str:  # never expose private leaves
        return "InMemoryHashBasedSigner(<redacted>)"

    def __setattr__(self, name: str, value: object) -> NoReturn:  # immutable after construction
        raise AttributeError("InMemoryHashBasedSigner is immutable")

    def __delattr__(self, name: str) -> NoReturn:
        raise AttributeError("InMemoryHashBasedSigner is immutable")

    # The private one-time key must never leave the process: refuse every serialization/copy path.
    def __reduce__(self) -> NoReturn:
        raise SignerNotSerializable("InMemoryHashBasedSigner is not serializable")

    def __reduce_ex__(self, protocol: object) -> NoReturn:
        raise SignerNotSerializable("InMemoryHashBasedSigner is not serializable")

    def __getstate__(self) -> NoReturn:
        raise SignerNotSerializable("InMemoryHashBasedSigner is not serializable")

    def __copy__(self) -> NoReturn:
        raise SignerNotSerializable("InMemoryHashBasedSigner cannot be copied")

    def __deepcopy__(self, memo: object) -> NoReturn:
        raise SignerNotSerializable("InMemoryHashBasedSigner cannot be copied")


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
    """A ``WorkerIdentityAttestationSource`` that emits a claim ONLY after an INDEPENDENT, LOCAL
    proof-of-possession self-check succeeds.

    Construction requires a deployment-local ``signer`` (private material), a SEPARATE
    ``IndependentPoPVerifier``, the ``descriptor``, and the anchor fingerprint pinned in the
    durable registration. ``attest`` issues a fresh operation challenge, signs it, and verifies the
    signature independently against the pinned anchor before returning the claim; the object that
    signs never validates its own proof. Any failure raises a closed
    ``WorkerIdentityAttestationUnavailable``; no key/anchor/challenge/signature is logged.

    This is an IN-PROCESS possession self-check (the worker confirming its own deployment-local
    material), NOT a remote authentication handshake; with this scheme the challenge
    is prover-issued and the one-time key is reused. Real remote authentication requires
    a remote-eligible asymmetric scheme (see :func:`assert_remote_authentication_eligible`) with a
    verifier-issued challenge; it is out of scope here.
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
