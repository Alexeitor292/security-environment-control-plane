"""Remote-safe Ed25519 proof-of-possession protocol for the deployed path (SECP-B4 §7).

Unlike the local in-process hash self-check, this is a real remote challenge-response: the VERIFIER
issues a fresh, bounded, single-use nonce bound to the operation, organization, worker registration,
worker identity version, and plan hash; the deployment-local signer signs it with its Ed25519
key; and the verifier checks the signature against the anchor whose fingerprint is pinned in the
durable registration (never one the signer asserts) using a REMOTE-ELIGIBLE asymmetric scheme.

Fail-closed on: a stale/expired challenge, a challenge bound to a different
/identity-version/plan (altered payload / cross-org), a wrong key (Ed25519 verification failure), a
wrong registration (anchor-pin mismatch), and a replayed or reused challenge (single-use nonce
No private key, anchor, challenge, or signature is logged or persisted in this module.
"""

from __future__ import annotations

import hmac
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol, runtime_checkable

from secp_api.worker_identity_contract import compute_verification_anchor_fingerprint

from secp_worker.staging_live.mtls_pop import (
    Ed25519PoPScheme,
    PoPSignatureScheme,
    assert_remote_authentication_eligible,
)

DEFAULT_REMOTE_CHALLENGE_TTL_SECONDS = 90


@dataclass(frozen=True)
class RemotePoPChallenge:
    """A verifier-issued, single-use challenge bound to the FULL operation context."""

    nonce: str
    deployment_id: str
    operation_fingerprint: str
    organization_id: str
    worker_registration_id: str
    worker_identity_version: int
    plan_hash: str
    issued_at: datetime
    expires_at: datetime

    def signing_message(self) -> bytes:
        return (
            f"secp-b4/remote-pop/v1|{self.nonce}|{self.deployment_id}|{self.operation_fingerprint}"
            f"|{self.organization_id}|{self.worker_registration_id}|{self.worker_identity_version}"
            f"|{self.plan_hash}|{self.expires_at.isoformat()}"
        ).encode()


@runtime_checkable
class ChallengeStore(Protocol):
    """Records issued nonces and enforces single use. A real durable store survives worker restarts;
    the in-memory default is sufficient for a single process and for tests."""

    def issue(self, nonce: str) -> None: ...

    def consume(self, nonce: str) -> bool:
        """Return True the FIRST time an issued nonce is consumed; False on unknown or reused."""
        ...


class InMemoryChallengeStore:
    """Single-use nonce store (in-memory). Marks each issued nonce and refuses a second consume."""

    def __init__(self) -> None:
        self._issued: set[str] = set()
        self._consumed: set[str] = set()

    def issue(self, nonce: str) -> None:
        self._issued.add(nonce)

    def consume(self, nonce: str) -> bool:
        if nonce not in self._issued or nonce in self._consumed:
            return False
        self._consumed.add(nonce)
        return True


@dataclass(frozen=True)
class RemotePoPResult:
    ok: bool
    reason_code: str


class RemotePoPVerifier:
    """Issues verifier-side challenges and verifies remote Ed25519 proofs. Constructed only with a
    REMOTE-ELIGIBLE scheme (the local hash scheme is refused) + a single-use challenge store."""

    def __init__(
        self,
        *,
        scheme: PoPSignatureScheme | None = None,
        store: ChallengeStore | None = None,
    ) -> None:
        self._scheme: PoPSignatureScheme = scheme or Ed25519PoPScheme()
        assert_remote_authentication_eligible(self._scheme)  # refuse a non-remote scheme
        self._store = store or InMemoryChallengeStore()

    def issue_challenge(
        self,
        *,
        deployment_id: uuid.UUID,
        operation_fingerprint: str,
        organization_id: uuid.UUID,
        worker_registration_id: uuid.UUID,
        worker_identity_version: int,
        plan_hash: str,
        now: datetime,
        ttl_seconds: int = DEFAULT_REMOTE_CHALLENGE_TTL_SECONDS,
    ) -> RemotePoPChallenge:
        challenge = RemotePoPChallenge(
            nonce=secrets.token_hex(32),
            deployment_id=str(deployment_id),
            operation_fingerprint=operation_fingerprint,
            organization_id=str(organization_id),
            worker_registration_id=str(worker_registration_id),
            worker_identity_version=worker_identity_version,
            plan_hash=plan_hash,
            issued_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
        )
        self._store.issue(challenge.nonce)
        return challenge

    def verify(
        self,
        *,
        challenge: RemotePoPChallenge,
        presented_anchor: str,
        registered_anchor_fingerprint: str,
        signature: str,
        now: datetime,
        expected_deployment_id: uuid.UUID,
        expected_operation_fingerprint: str,
        expected_organization_id: uuid.UUID,
        expected_worker_registration_id: uuid.UUID,
        expected_worker_identity_version: int,
        expected_plan_hash: str,
    ) -> RemotePoPResult:
        if now > challenge.expires_at:
            return RemotePoPResult(False, "stale_challenge")
        # Altered payload / cross-org / wrong registration or identity version / plan drift.
        if (
            challenge.deployment_id != str(expected_deployment_id)
            or challenge.operation_fingerprint != expected_operation_fingerprint
            or challenge.organization_id != str(expected_organization_id)
            or challenge.worker_registration_id != str(expected_worker_registration_id)
            or challenge.worker_identity_version != expected_worker_identity_version
            or challenge.plan_hash != expected_plan_hash
        ):
            return RemotePoPResult(False, "challenge_binding_mismatch")
        if not (isinstance(presented_anchor, str) and presented_anchor):
            return RemotePoPResult(False, "anchor_missing")
        # Pin the presented anchor to the AUTHORITATIVE registered fingerprint (never
        if not hmac.compare_digest(
            compute_verification_anchor_fingerprint(presented_anchor),
            str(registered_anchor_fingerprint),
        ):
            return RemotePoPResult(False, "anchor_pin_mismatch")
        # Single use: a replayed or reused challenge nonce fails closed here, BEFORE crypto.
        if not self._store.consume(challenge.nonce):
            return RemotePoPResult(False, "challenge_replayed")
        if not self._scheme.verify(
            public_anchor=presented_anchor,
            message=challenge.signing_message(),
            signature=signature,
        ):
            return RemotePoPResult(False, "remote_pop_failed")
        return RemotePoPResult(True, "verified")
