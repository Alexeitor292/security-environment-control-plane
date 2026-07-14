"""Worker-owned, READINESS-ONLY toolchain attestation (B1B-PR4 amendment §1).

A matching ``ToolchainProfile`` id/hash and a verifier-policy version are **NOT an attestation**.
This seam runs the existing, reviewed ``RealToolchainVerifier`` against an explicit,
deployment-local, immutable ``ToolchainFilesystemLayout`` and produces a durable, immutable, safe
attestation record — and then **STOPS**.

What it does NOT do (enforced by the readiness boundary tests):

* it executes **no binary** and runs **no subprocess**;
* it opens **no socket** and performs **no network I/O**;
* it loads **no provider plugin**;
* it renders **no workspace**;
* it constructs **no ``OpenTofuRunner``, process executor, or activation grant**;
* it infers nothing from ``PATH``, the cwd, ``HOME``, or any environment variable — the complete
  layout is supplied explicitly by the reviewed deployment-local composition;
* it performs **no import-time I/O** (``RealToolchainVerifier`` opens nothing until ``verify()``).

**RealToolchainVerifier remains unwired into execution.** ``OpenTofuRunner`` and
``run_real_provisioning`` still default to ``FakeToolchainVerifier``; this readiness-only path is
the sole construction site outside tests, and it runs no OpenTofu.

**Sealed by default.** The shipped composition carries **no** filesystem layout, so no shipped
runtime path can attest anything: the seam refuses at the seal before touching the disk.

The durable record stores ONLY: organization; worker identity id + version; toolchain profile id +
hash; the verifier policy version; the verified FACET NAMES; bounded reason codes; collection time;
an expiry; an evidence hash; and the operation fingerprint. It stores **no path, no filename, no
executable content, no provider content, no CLI content, and no raw expected/observed digest**.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from secp_api import audit
from secp_api.enums import (
    AuditAction,
    ReadinessReason,
    ToolchainAttestationOutcome,
    ToolchainProfileStatus,
    WorkerIdentityStatus,
)
from secp_api.readiness_contract import (
    MAX_EVIDENCE_REASONS,
    TOOLCHAIN_ATTESTATION_TTL,
    as_utc,
    readiness_evidence_hash,
    toolchain_attestation_fingerprint,
)
from secp_api.toolchain_profile import toolchain_profile_hash, validate_toolchain_profile
from sqlalchemy import select
from sqlalchemy.orm import Session

# The reviewed real verifier + its explicit, immutable filesystem layout (B1B-PR2). Importing them
# performs NO I/O.
from secp_worker.provisioning.toolchain_verify import (
    ATTESTATION_POLICY_VERSION,
    RealToolchainVerifier,
    ToolchainFilesystemLayout,
)

_R = ReadinessReason


class ToolchainAttestationRefused(Exception):
    """Internal control-flow signal carrying a closed, secret-free reason code."""

    def __init__(self, reason: ReadinessReason) -> None:
        super().__init__(f"toolchain attestation refused: {reason.value}")
        self.reason = reason


@dataclass(frozen=True)
class ToolchainAttestationResult:
    """Closed, secret-free outcome of one attestation attempt (safe for audit + the read model)."""

    outcome: str
    reason_code: str | None = None
    record_id: uuid.UUID | None = None
    evidence_hash: str | None = None
    reused: bool = False


def current_toolchain_attestation(
    session: Session, toolchain_profile_id: uuid.UUID, *, now: datetime
):
    """The current ``attested``, unexpired attestation for a profile, or ``None``.

    Currency requires: the outcome is ``attested``; the record is unexpired; the verifier policy
    version is current; and the recorded profile hash still equals the profile's own content hash.
    The FULL binding agreement (worker identity, org) is enforced by ``load_readiness_binding``.
    """
    from secp_api.models import ToolchainAttestationRecord, ToolchainProfile

    profile = session.get(ToolchainProfile, toolchain_profile_id)
    if profile is None:
        return None
    rows = (
        session.execute(
            select(ToolchainAttestationRecord)
            .where(
                ToolchainAttestationRecord.toolchain_profile_id == toolchain_profile_id,
                ToolchainAttestationRecord.outcome == ToolchainAttestationOutcome.attested,
            )
            .order_by(ToolchainAttestationRecord.collected_at.desc())
        )
        .scalars()
        .all()
    )
    for row in rows:
        if as_utc(row.expires_at) <= now:
            continue
        if row.verifier_policy_version != ATTESTATION_POLICY_VERSION:
            continue
        if row.toolchain_profile_hash != profile.content_hash:
            continue
        return row
    return None


def _sole_approved_worker_identity(session: Session, organization_id: uuid.UUID, now: datetime):
    from secp_api.models import WorkerIdentityRegistration

    rows = [
        r
        for r in session.execute(
            select(WorkerIdentityRegistration).where(
                WorkerIdentityRegistration.organization_id == organization_id,
                WorkerIdentityRegistration.status == WorkerIdentityStatus.approved,
            )
        )
        .scalars()
        .all()
        if r.expiry is not None and as_utc(r.expiry) > now
    ]
    return rows[0] if len(rows) == 1 else None


def run_toolchain_attestation(
    session: Session,
    *,
    toolchain_profile_id: uuid.UUID,
    layout: ToolchainFilesystemLayout | None = None,
    now: datetime | None = None,
) -> ToolchainAttestationResult:
    """Run the real, worker-local, filesystem-only toolchain attestation, then STOP.

    ``layout`` is supplied ONLY by the reviewed deployment-local composition. With no layout (the
    shipped default) the seam refuses at the seal and touches no disk.
    """
    from secp_api.models import ToolchainAttestationRecord, ToolchainProfile

    now = now or datetime.now(UTC)
    profile = session.get(ToolchainProfile, toolchain_profile_id)
    organization_id = None if profile is None else profile.organization_id

    def refuse(reason: ReadinessReason) -> ToolchainAttestationResult:
        audit.record(
            session,
            action=AuditAction.toolchain_attestation_refused,
            resource_type="toolchain_profile",
            resource_id=toolchain_profile_id,
            organization_id=organization_id,
            actor="worker",
            outcome="refused",
            data={
                "toolchain_profile_id": str(toolchain_profile_id),
                "reason_code": reason.value,
                "verifier_policy_version": ATTESTATION_POLICY_VERSION,
            },
        )
        return ToolchainAttestationResult(
            outcome=ToolchainAttestationOutcome.failed.value, reason_code=reason.value
        )

    try:
        # 0. SEAL — no reviewed deployment-local layout => nothing is read from disk, at all.
        if layout is None:
            raise ToolchainAttestationRefused(_R.toolchain_layout_unavailable)
        if not isinstance(layout, ToolchainFilesystemLayout):
            raise ToolchainAttestationRefused(_R.toolchain_layout_unavailable)

        # 1. AUTHORITATIVE RECORDS.
        if profile is None or profile.status != ToolchainProfileStatus.active:
            raise ToolchainAttestationRefused(_R.toolchain_profile_missing)
        try:
            validate_toolchain_profile(profile.content)
        except Exception:
            raise ToolchainAttestationRefused(_R.toolchain_profile_invalid) from None
        recomputed = toolchain_profile_hash(profile.content)
        if recomputed != profile.content_hash:
            raise ToolchainAttestationRefused(_R.toolchain_profile_drift)

        worker_identity = _sole_approved_worker_identity(session, profile.organization_id, now)
        if worker_identity is None:
            raise ToolchainAttestationRefused(_R.worker_identity_untrusted)

        fingerprint = toolchain_attestation_fingerprint(
            organization_id=str(profile.organization_id),
            execution_target_id=str(profile.execution_target_id),
            toolchain_profile_id=str(profile.id),
            toolchain_profile_hash=profile.content_hash,
            worker_identity_registration_id=str(worker_identity.id),
            worker_identity_version=worker_identity.identity_version,
            verifier_policy_version=ATTESTATION_POLICY_VERSION,
        )

        # 2. TERMINAL REPLAY — an exact retry within the TTL returns the durable ``attested`` record
        #    with no second filesystem read. A FAILED attempt never short-circuits a retry.
        existing = (
            session.query(ToolchainAttestationRecord)
            .filter(
                ToolchainAttestationRecord.toolchain_profile_id == profile.id,
                ToolchainAttestationRecord.operation_fingerprint == fingerprint,
                ToolchainAttestationRecord.outcome == ToolchainAttestationOutcome.attested,
            )
            .one_or_none()
        )
        if existing is not None and as_utc(existing.expires_at) > now:
            return ToolchainAttestationResult(
                outcome=ToolchainAttestationOutcome.attested.value,
                record_id=existing.id,
                evidence_hash=existing.evidence_hash,
                reused=True,
            )

        audit.record(
            session,
            action=AuditAction.toolchain_attestation_started,
            resource_type="toolchain_profile",
            resource_id=profile.id,
            organization_id=profile.organization_id,
            actor="worker",
            data={
                "toolchain_profile_id": str(profile.id),
                "operation_fingerprint": fingerprint,
                "verifier_policy_version": ATTESTATION_POLICY_VERSION,
            },
        )

        # 3. THE REAL ON-DISK VERIFICATION. It reads ONLY the explicit layout beneath its trusted
        #    root: no PATH, no cwd, no HOME, no environment, no binary execution, no subprocess, no
        #    socket, no provider load, no render.
        verifier = RealToolchainVerifier(layout)
        verification = verifier.verify(profile.content)

        verified = tuple(sorted(verification.verified))
        reasons = tuple(verification.reasons)[:MAX_EVIDENCE_REASONS]
        outcome = (
            ToolchainAttestationOutcome.attested
            if verification.ok
            else ToolchainAttestationOutcome.failed
        )

        # 4. SAFE, IMMUTABLE EVIDENCE — bounded facet NAMES + reason codes only.
        payload = {
            "kind": "toolchain_attestation",
            "toolchain_profile_id": str(profile.id),
            "toolchain_profile_hash": profile.content_hash,
            "verifier_policy_version": ATTESTATION_POLICY_VERSION,
            "outcome": outcome.value,
            "verified_facets": list(verified),
            "reason_codes": list(reasons),
            "worker_identity_registration_id": str(worker_identity.id),
            "worker_identity_version": worker_identity.identity_version,
            "operation_fingerprint": fingerprint,
        }
        row = ToolchainAttestationRecord(
            organization_id=profile.organization_id,
            execution_target_id=profile.execution_target_id,
            toolchain_profile_id=profile.id,
            toolchain_profile_hash=profile.content_hash,
            worker_identity_registration_id=worker_identity.id,
            worker_identity_version=worker_identity.identity_version,
            verifier_policy_version=ATTESTATION_POLICY_VERSION,
            outcome=outcome,
            verified_facets=list(verified),
            reason_codes=list(reasons),
            operation_fingerprint=fingerprint,
            collected_at=now,
            expires_at=now + TOOLCHAIN_ATTESTATION_TTL,
            evidence_hash=readiness_evidence_hash(payload),
        )
        session.add(row)
        session.flush()
        audit.record(
            session,
            action=AuditAction.toolchain_attestation_completed,
            resource_type="toolchain_attestation_record",
            resource_id=row.id,
            organization_id=row.organization_id,
            actor="worker",
            data={
                "toolchain_profile_id": str(profile.id),
                "toolchain_profile_hash": profile.content_hash,
                "outcome": outcome.value,
                "verified_facets": list(verified),
                "reason_codes": list(reasons),
                "verifier_policy_version": ATTESTATION_POLICY_VERSION,
                "operation_fingerprint": fingerprint,
                "evidence_hash": row.evidence_hash,
                "expires_at": row.expires_at.isoformat(),
            },
        )
        # 5. STOP. No OpenTofu runs; nothing is unsealed; nothing is dispatched.
        return ToolchainAttestationResult(
            outcome=outcome.value, record_id=row.id, evidence_hash=row.evidence_hash
        )
    except ToolchainAttestationRefused as exc:
        return refuse(exc.reason)
