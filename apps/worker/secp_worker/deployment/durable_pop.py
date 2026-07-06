"""Durable, restart-safe remote-PoP wiring (SECP-B4 corrective, §7).

Provides a DB-backed single-use nonce store (survives a worker/verifier restart; consumption is an
atomic conditional UPDATE) and a real :class:`RemotePoPAuthority` that runs the full verifier-issued
challenge -> deployment-local Ed25519 sign -> verify cycle, bound to the exact deployment/operation/
org/registration/identity-version/plan-hash. The deployment-local signer is a sealed worker-only
seam
(its private key is mounted only on the isolated worker), so proof fails closed until it is
supplied.

No key, anchor, challenge, or signature is logged or persisted (the store persists only the nonce,
bindings, and a consumed flag). No I/O beyond the injected DB session.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from secp_api.models import StagingDeploymentPoPChallenge
from sqlalchemy import update
from sqlalchemy.orm import Session

from secp_worker.deployment.remote_pop import (
    DEFAULT_REMOTE_CHALLENGE_TTL_SECONDS,
    RemotePoPChallenge,
    RemotePoPVerifier,
)
from secp_worker.deployment.seams import RemotePoPOutcome
from secp_worker.staging_live.mtls_pop import (
    DeploymentLocalSigner,
    DeploymentSignerUnavailable,
    Ed25519PoPScheme,
)


def _as_uuid(value: object) -> uuid.UUID:
    return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))


class DurableChallengeStore:
    """A DB-backed single-use nonce store. ``issue`` persists the nonce + bindings; ``consume`` is
    an
    atomic conditional UPDATE (``consumed`` False -> True), so a replay is refused even after a
    restart (a fresh store instance still sees the committed row)."""

    def __init__(
        self,
        session: Session,
        *,
        deployment_id: uuid.UUID,
        organization_id: uuid.UUID,
        operation_fingerprint: str,
        worker_registration_id: uuid.UUID | None,
        worker_identity_version: int,
        plan_hash: str,
    ) -> None:
        self._session = session
        self._deployment_id = deployment_id
        self._organization_id = organization_id
        self._operation_fingerprint = operation_fingerprint
        self._worker_registration_id = worker_registration_id
        self._worker_identity_version = worker_identity_version
        self._plan_hash = plan_hash
        self._expires_at: datetime | None = None

    def bind_expiry(self, expires_at: datetime) -> None:
        self._expires_at = expires_at

    def issue(self, nonce: str) -> None:
        # Persist an expiry for durable cleanup; if not explicitly bound, use a safe default (the
        # verifier independently enforces the precise challenge expiry).
        expires_at = self._expires_at or (datetime.now(UTC) + timedelta(hours=1))
        self._session.add(
            StagingDeploymentPoPChallenge(
                nonce=nonce,
                deployment_id=self._deployment_id,
                organization_id=self._organization_id,
                operation_fingerprint=self._operation_fingerprint,
                worker_registration_id=self._worker_registration_id,
                worker_identity_version=self._worker_identity_version,
                plan_hash=self._plan_hash,
                consumed=False,
                expires_at=expires_at,
            )
        )
        self._session.flush()

    def consume(self, nonce: str) -> bool:
        """Atomically mark an issued, not-yet-consumed nonce consumed. True only on the FIRST
        consume; False for an unknown or already-consumed nonce (replay), including after a
        restart."""
        result = self._session.execute(
            update(StagingDeploymentPoPChallenge)
            .where(
                StagingDeploymentPoPChallenge.nonce == nonce,
                StagingDeploymentPoPChallenge.consumed.is_(False),
            )
            .values(consumed=True)
        )
        self._session.flush()
        return result.rowcount == 1  # type: ignore[attr-defined]


class LocalRemotePoPAuthority:
    """Runs the real remote-PoP cycle for one operation with a durable nonce store. The signer is a
    sealed worker-only seam; when it is unavailable, proof fails closed."""

    def __init__(
        self,
        *,
        signer: DeploymentLocalSigner,
        store: DurableChallengeStore,
        registered_anchor_fingerprint: str,
        now: datetime,
        ttl_seconds: int = DEFAULT_REMOTE_CHALLENGE_TTL_SECONDS,
    ) -> None:
        self._signer = signer
        self._store = store
        self._registered_anchor_fingerprint = registered_anchor_fingerprint
        self._now = now
        self._ttl = ttl_seconds
        self._verifier = RemotePoPVerifier(scheme=Ed25519PoPScheme(), store=store)

    def prove(
        self,
        *,
        deployment_id: object,
        operation_fingerprint: str,
        organization_id: object,
        worker_registration_id: object,
        worker_identity_version: int,
        plan_hash: str,
    ) -> RemotePoPOutcome:
        dep_id = _as_uuid(deployment_id)
        org_id = (
            organization_id
            if isinstance(organization_id, uuid.UUID)
            else uuid.UUID(str(organization_id))
        )
        reg_id = (
            worker_registration_id
            if isinstance(worker_registration_id, uuid.UUID)
            else uuid.UUID(str(worker_registration_id))
        )
        challenge: RemotePoPChallenge = self._issue(
            dep_id, operation_fingerprint, org_id, reg_id, worker_identity_version, plan_hash
        )
        try:
            signature = self._signer.sign(challenge.signing_message())
            anchor = self._signer.public_anchor()
        except DeploymentSignerUnavailable:
            return RemotePoPOutcome(False, "remote_pop_unavailable")
        result = self._verifier.verify(
            challenge=challenge,
            presented_anchor=anchor,
            registered_anchor_fingerprint=self._registered_anchor_fingerprint,
            signature=signature,
            now=self._now,
            expected_deployment_id=dep_id,
            expected_operation_fingerprint=operation_fingerprint,
            expected_organization_id=org_id,
            expected_worker_registration_id=reg_id,
            expected_worker_identity_version=worker_identity_version,
            expected_plan_hash=plan_hash,
        )
        return RemotePoPOutcome(result.ok, result.reason_code)

    def _issue(
        self,
        deployment_id: uuid.UUID,
        operation_fingerprint: str,
        organization_id: uuid.UUID,
        worker_registration_id: uuid.UUID,
        worker_identity_version: int,
        plan_hash: str,
    ) -> RemotePoPChallenge:
        from datetime import timedelta

        self._store.bind_expiry(self._now + timedelta(seconds=self._ttl))
        return self._verifier.issue_challenge(
            deployment_id=deployment_id,
            operation_fingerprint=operation_fingerprint,
            organization_id=organization_id,
            worker_registration_id=worker_registration_id,
            worker_identity_version=worker_identity_version,
            plan_hash=plan_hash,
            now=self._now,
            ttl_seconds=self._ttl,
        )
