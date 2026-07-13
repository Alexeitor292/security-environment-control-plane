"""API-side eligibility preflight surface: enqueue-only request + redacted read model.

This module is IMPORT-SAFE for the control-plane API: it never persists live evidence, never
contacts a target, and imports NO worker/plugin/transport/collector/recorder code. The controlled
live-evidence persistence path is worker-only (the worker eligibility recorder module) and is
structurally unreachable from here (the architecture-boundary lock forbids API-to-worker imports
outside the dispatch seam and name-forbids the eligibility symbols everywhere).

* :func:`request_eligibility_preflight` — permission-protected, org-scoped; records a requested
  audit and hands to the dispatcher, which durably enqueues on the worker path and REFUSES inline
  execution (no host contact, no transport, no secret, no persistence here).
* :func:`get_live_eligibility_evidence` — a safe, redacted projection with derived current validity
  (expiry + drift), exposing only closed codes / safe hashes / ids / times.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from secp_api import audit
from secp_api.auth import Principal
from secp_api.eligibility_policy import (
    ELIGIBILITY_POLICY_VERSION,
    LiveEligibilityEvidenceView,
    live_eligibility_evidence_is_valid,
)
from secp_api.enums import (
    AuditAction,
    LiveReadAuthorizationStatus,
    Permission,
    PreflightCheckStatus,
    WorkerIdentityStatus,
)
from secp_api.models import (
    ExecutionTarget,
    LiveReadAuthorization,
    TargetEvidenceRecord,
    TargetPreflight,
    WorkerIdentityRegistration,
)
from secp_api.target_evidence import findings_pass

# --- API request seam (enqueue-only; never contacts the target) ----------------------------------


def request_eligibility_preflight(
    session: Session, actor: Principal, onboarding_id: uuid.UUID
) -> None:
    """API-reachable request to run a controlled live read-only eligibility preflight.

    Permission-protected and org-scoped. It records a secret-free requested audit and hands to the
    dispatcher, which REFUSES inline execution (the API never contacts a host, builds a transport,
    resolves a secret, or persists evidence). There is no automatic preflight on onboarding
    approval — this must be requested explicitly.
    """
    from secp_api.dispatch import get_dispatcher
    from secp_api.services.onboarding import get_onboarding

    actor.require(Permission.onboarding_manage)
    ob = get_onboarding(session, actor, onboarding_id)
    audit.record(
        session,
        action=AuditAction.eligibility_preflight_requested,
        resource_type="target_onboarding",
        resource_id=ob.id,
        organization_id=ob.organization_id,
        actor=str(actor.user_id),
        data={"kind": "live_read_eligibility", "onboarding_id": str(ob.id)},
    )
    get_dispatcher().dispatch_real_eligibility_preflight(session, ob.id)


# --- Safe, redacted read model (org-scoped + permission-protected) -------------------------------


def _latest_live_eligibility_preflight(
    session: Session, onboarding_id: uuid.UUID
) -> TargetPreflight | None:
    return (
        session.execute(
            select(TargetPreflight)
            .where(
                TargetPreflight.onboarding_id == onboarding_id,
                TargetPreflight.eligibility_outcome.is_not(None),
            )
            .order_by(TargetPreflight.evidence_version.desc())
        )
        .scalars()
        .first()
    )


def get_live_eligibility_evidence(
    session: Session,
    actor: Principal,
    onboarding_id: uuid.UUID,
    *,
    now: datetime,
) -> dict | None:
    """Return a safe, redacted projection of the latest live-eligibility evidence, or ``None``.

    Exposes ONLY: evidence source, verification level, closed outcome, per-dimension outcomes +
    reason categories, safe hashes, collection + expiry times, current validity, the bound ids, and
    the policy version. It NEVER exposes an endpoint, hostname, command, raw observation, credential
    reference, mounted path, host key, certificate, provider response, or stack trace.
    """
    from secp_api.services.onboarding import get_onboarding

    actor.require(Permission.onboarding_manage)
    ob = get_onboarding(session, actor, onboarding_id)
    pf = _latest_live_eligibility_preflight(session, ob.id)
    if pf is None:
        return None
    record = (
        session.get(TargetEvidenceRecord, pf.target_evidence_id) if pf.target_evidence_id else None
    )
    target = session.get(ExecutionTarget, ob.execution_target_id)

    expires_at = pf.evidence_expires_at
    expired = expires_at is not None and _aware(expires_at) <= now
    # Drift is derived from the CURRENT authoritative records vs the bindings this evidence pinned:
    # boundary/config hashes, the eligibility policy version, and the bound live-read authorization
    # and worker-identity lifecycle/version. Any disagreement invalidates the stored evidence; a new
    # preflight (a new operation fingerprint) is required. The historical row is never mutated.
    boundary_or_config_drift = bool(
        ob.boundary_hash != pf.boundary_hash
        or (target is not None and target.config_hash != pf.target_config_hash)
    )
    policy_drift = pf.eligibility_policy_version != ELIGIBILITY_POLICY_VERSION
    auth = (
        session.get(LiveReadAuthorization, pf.live_read_authorization_id)
        if pf.live_read_authorization_id
        else None
    )
    auth_drift = auth is None or (
        auth.status != LiveReadAuthorizationStatus.approved
        or _aware(auth.authorization_expiry) <= now
        or auth.authorization_version != pf.live_read_authorization_version
    )
    wid = (
        session.get(WorkerIdentityRegistration, pf.worker_identity_registration_id)
        if pf.worker_identity_registration_id
        else None
    )
    worker_identity_drift = wid is None or (
        wid.status != WorkerIdentityStatus.approved or _aware(wid.expiry) <= now
    )
    drifted = bool(boundary_or_config_drift or policy_drift or auth_drift or worker_identity_drift)
    hash_matches = record is not None and record.evidence_hash == pf.target_evidence_hash
    findings_ok = bool(record is not None and findings_pass(record.findings))

    valid = live_eligibility_evidence_is_valid(
        LiveEligibilityEvidenceView(
            evidence_source=(record.evidence_source if record is not None else ""),
            verification_level=pf.verification_level,
            outcome=pf.eligibility_outcome or "",
            policy_version=pf.eligibility_policy_version or "",
            findings_pass=findings_ok,
            evidence_hash_matches=hash_matches,
            expired=expired,
            drifted=drifted,
        )
    )
    return {
        "onboarding_id": str(ob.id),
        "execution_target_id": str(ob.execution_target_id),
        "preflight_id": str(pf.id),
        "evidence_source": record.evidence_source if record is not None else None,
        "verification_level": pf.verification_level,
        "eligibility_outcome": pf.eligibility_outcome,
        "eligibility_policy_version": pf.eligibility_policy_version,
        "passed": pf.passed,
        "dimensions": [
            {"dimension": c.get("check"), "status": c.get("status")} for c in (pf.checks or [])
        ],
        "reason_categories": sorted(
            {
                c.get("status")
                for c in (pf.checks or [])
                if c.get("status")
                in {PreflightCheckStatus.failed.value, PreflightCheckStatus.warning.value}
            }
        ),
        "evidence_hash": pf.evidence_hash,
        "target_evidence_hash": pf.target_evidence_hash,
        "collected_at": _aware(record.collected_at).isoformat() if record is not None else None,
        "expires_at": _aware(expires_at).isoformat() if expires_at is not None else None,
        "expired": expired,
        "drifted": drifted,
        "valid": valid,
        "live_read_authorization_id": (
            str(pf.live_read_authorization_id) if pf.live_read_authorization_id else None
        ),
        "live_read_authorization_version": pf.live_read_authorization_version,
        "worker_identity_registration_id": (
            str(pf.worker_identity_registration_id) if pf.worker_identity_registration_id else None
        ),
    }


def _aware(value: datetime) -> datetime:
    from datetime import UTC

    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
