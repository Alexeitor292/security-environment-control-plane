"""Worker-only sealed worker-identity attestation + verification seam (SECP-B2-4.3).

A future isolated staging worker must independently prove its identity before it can be trusted.
This module defines the *sealed foundation* for that proof:

* :class:`WorkerIdentityAttestationSource` — the narrow seam a FUTURE mechanism (mTLS workload
  identity) would implement to present a re-verifiable, secret-free :class:`WorkerIdentityClaim`.
* :class:`SealedWorkerIdentityAttestationSource` — the shipped default. It REFUSES and performs no
  I/O of any kind (no environment/file/network/certificate/key/CA access).
* :class:`RegisteredWorkerIdentityVerifier` — given an injected attestation source, it independently
  re-loads the durable :class:`WorkerIdentityRegistration`, recomputes the verification-anchor
  fingerprint from the claim's PUBLIC anchor, re-checks every binding + status + version + expiry +
  the evidence fingerprint, and returns an existing safe :class:`WorkerIdentity` ONLY on success.

This is **not** real mTLS: it parses no certificate, accesses no private key, performs no signing,
and contacts no CA/backend/network. It is **not** wired into shipped runtime — the consumer/runtime
default remains :class:`DenyingWorkerIdentityVerifier`, so no worker is trusted and no lease is
acquired because of this module. A claim is a carrier of claims to be re-checked, never proof.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import NoReturn, Protocol, runtime_checkable

from secp_api import audit
from secp_api.enums import AuditAction, WorkerIdentityStatus
from secp_api.models import WorkerIdentityEvidence, WorkerIdentityRegistration
from secp_api.worker_identity_contract import (
    WORKER_IDENTITY_CONTRACT_VERSION,
    compute_verification_anchor_fingerprint,
    compute_worker_identity_evidence_fingerprint,
    worker_identity_evidence_is_complete,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

from secp_worker.preflight.identity import WorkerIdentity

# ``WORKER_IDENTITY_CONTRACT_VERSION`` is the single pinned label defined in the shared app/worker
# contract module and imported above; it is re-used here (no separate worker copy can drift).


class WorkerIdentityAttestationUnavailable(Exception):
    """Raised by a sealed/failing attestation source. Fail closed. Carries only a closed reason."""

    def __init__(self, reason_code: str = "attestation_unavailable") -> None:
        super().__init__(f"worker identity attestation unavailable: {reason_code}")
        self.reason_code = reason_code


class WorkerIdentityVerificationRefused(Exception):
    """Fail-closed refusal carrying only a closed, secret-free reason code (no value leakage).

    ``registration_id`` / ``organization_id``, when present, are sourced ONLY from the AUTHORITATIVE
    durable registration that was loaded — never from the claim. They are ``None`` when no
    authoritative registration exists (e.g. an unknown/unapproved identity). The exception text
    carries only the closed reason code, never a claim value.
    """

    def __init__(
        self,
        reason_code: str,
        *,
        registration_id: uuid.UUID | None = None,
        organization_id: uuid.UUID | None = None,
    ) -> None:
        super().__init__(f"worker identity refused: {reason_code}")
        self.reason_code = reason_code
        self.registration_id = registration_id
        self.organization_id = organization_id


@dataclass(frozen=True)
class WorkerIdentityClaim:
    """A secret-free claim to be INDEPENDENTLY re-verified — never trusted as proof.

    ``public_anchor`` is the PUBLIC verification anchor the worker presents (e.g. a public-key
    value); the verifier hashes it and compares to the durable registration's stored fingerprint. It
    is never a private key, certificate, CSR, token, or secret.
    """

    organization_id: uuid.UUID
    mechanism: str
    identity_label: str
    deployment_binding: str
    identity_version: int
    public_anchor: str


@runtime_checkable
class WorkerIdentityAttestationSource(Protocol):
    """Narrow worker-only seam. ``attest`` returns a :class:`WorkerIdentityClaim` or fails."""

    def attest(self, *, now: datetime) -> WorkerIdentityClaim: ...


class SealedWorkerIdentityAttestationSource:
    """The shipped default: REFUSES every attestation and performs no I/O.

    It reads no environment, no host file, no container metadata, no network identity endpoint, no
    certificate, no key, and no CA. There is no configuration/flag that makes it attest. It exists
    a worker fails closed before any identity is produced.
    """

    def attest(self, *, now: datetime) -> WorkerIdentityClaim:
        raise WorkerIdentityAttestationUnavailable("no worker identity attestation is configured")


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


class RegisteredWorkerIdentityVerifier:
    """Verifies an injected attestation claim against the durable registry. NOT a runtime default.

    Construct with an attestation source (a fake in tests; a real mTLS source only in a future,
    separately-reviewed activation). ``verify`` fails closed on a sealed/failing source and on any
    missing/draft/revoked/expired/wrong-mechanism/label/deployment/anchor/version/evidence mismatch.
    Only on full success does it return a safe :class:`WorkerIdentity` (the opaque identity label).
    """

    def __init__(self, attestation_source: WorkerIdentityAttestationSource) -> None:
        self._source = attestation_source

    def verify(self, session: Session, *, now: datetime) -> WorkerIdentity:
        try:
            claim = self._source.attest(now=now)
        except WorkerIdentityAttestationUnavailable as exc:
            # No re-verifiable claim exists; fail closed. There is no durable record to attribute an
            # audit to, so none is recorded here.
            raise WorkerIdentityVerificationRefused(exc.reason_code) from exc
        try:
            return self._verify_claim(session, claim, now=now)
        except WorkerIdentityVerificationRefused as refused:
            _record_refusal(session, refused)
            raise

    def _verify_claim(
        self, session: Session, claim: WorkerIdentityClaim, *, now: datetime
    ) -> WorkerIdentity:
        row = session.execute(
            select(WorkerIdentityRegistration).where(
                WorkerIdentityRegistration.organization_id == claim.organization_id,
                WorkerIdentityRegistration.identity_label == claim.identity_label,
                WorkerIdentityRegistration.status == WorkerIdentityStatus.approved,
            )
        ).scalar_one_or_none()
        if row is None:
            # No authoritative registration exists to attribute an audit to.
            raise WorkerIdentityVerificationRefused("identity_not_approved")

        def _refuse(reason: str) -> NoReturn:
            # Attribute the refusal ONLY to the AUTHORITATIVE durable registration (its
            # server-generated id + org), never to any claim-supplied value.
            raise WorkerIdentityVerificationRefused(
                reason, registration_id=row.id, organization_id=row.organization_id
            )

        if row.status != WorkerIdentityStatus.approved:
            _refuse("identity_not_approved")
        if _as_utc(row.expiry) <= now:
            _refuse("identity_expired")
        if getattr(row.mechanism, "value", row.mechanism) != claim.mechanism:
            _refuse("wrong_mechanism")
        if row.identity_label != claim.identity_label:
            _refuse("identity_label_mismatch")
        if row.deployment_binding != claim.deployment_binding:
            _refuse("deployment_binding_mismatch")
        if row.identity_version != claim.identity_version:
            _refuse("identity_version_mismatch")
        if row.verification_anchor_fingerprint != compute_verification_anchor_fingerprint(
            claim.public_anchor
        ):
            _refuse("verification_anchor_mismatch")

        evidence = _evidence_rows(session, row.id)
        if not worker_identity_evidence_is_complete(evidence):
            _refuse("evidence_incomplete")
        if row.evidence_fingerprint != compute_worker_identity_evidence_fingerprint(evidence):
            _refuse("evidence_fingerprint_mismatch")

        # Success: return only the opaque, safe identity label (never the anchor/deployment secret).
        return WorkerIdentity(worker_identity_id=row.identity_label)


def _evidence_rows(session: Session, registration_id: uuid.UUID) -> list[WorkerIdentityEvidence]:
    return list(
        session.execute(
            select(WorkerIdentityEvidence)
            .where(WorkerIdentityEvidence.registration_id == registration_id)
            .order_by(WorkerIdentityEvidence.kind)
        )
        .scalars()
        .all()
    )


def _record_refusal(session: Session, refused: WorkerIdentityVerificationRefused) -> None:
    """Record a secret-free ``worker_identity.verification_refused`` audit.

    Persists ONLY the closed, verifier-generated reason code + the pinned contract version, and
    attributes the event to the AUTHORITATIVE durable registration (its server-generated id + org)
    when one was loaded. NO ``WorkerIdentityClaim`` field — organization, identity label, mechanism,
    deployment binding, identity version, public anchor, or any value derived from them — is ever
    written to the audit. When no authoritative registration exists, a context-free refusal (no org,
    no resource id) is recorded.
    """
    audit.record(
        session,
        action=AuditAction.worker_identity_verification_refused,
        resource_type="worker_identity_registration",
        resource_id=refused.registration_id,
        organization_id=refused.organization_id,
        actor="worker",
        outcome="refused",
        data={
            "reason_code": refused.reason_code,
            "worker_identity_contract_version": WORKER_IDENTITY_CONTRACT_VERSION,
        },
    )
