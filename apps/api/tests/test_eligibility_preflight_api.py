"""API surface for the controlled read-only eligibility preflight (SECP-002B-1B, B1B-PR3).

The API is enqueue-only + a redacted read model. It NEVER contacts a host, constructs a transport,
resolves a secret, or persists fabricated evidence. Inline execution is refused; the read model
exposes only closed, redacted fields.
"""

from __future__ import annotations

import pytest
from secp_api.safety import InlineExecutionForbidden
from secp_api.services import eligibility as elig
from secp_worker.onboarding.eligibility_preflight import run_real_eligibility_preflight

# Reuse the worker-test chain builder + a helper to run the full eligible path.
from tests._eligibility_fixtures import (  # type: ignore
    NOW,
    SECRET_REF,
    _build_chain,
    _full_composition,
)


def test_request_refuses_inline_execution(session, principal):
    """The inline dispatcher (dev/test default) refuses — the API never contacts the target."""
    chain = _build_chain(session)
    with pytest.raises(InlineExecutionForbidden):
        elig.request_eligibility_preflight(session, principal, chain.onboarding.id)


def test_request_records_a_requested_audit_before_refusing(session, principal):
    from secp_api.enums import AuditAction
    from secp_api.models import AuditEvent
    from sqlalchemy import select

    chain = _build_chain(session)
    with pytest.raises(InlineExecutionForbidden):
        elig.request_eligibility_preflight(session, principal, chain.onboarding.id)
    session.flush()
    actions = [
        e.action
        for e in session.execute(
            select(AuditEvent).where(AuditEvent.organization_id == chain.org_id)
        )
        .scalars()
        .all()
    ]
    assert AuditAction.eligibility_preflight_requested in actions


def test_read_model_absent_before_any_preflight(session, principal):
    chain = _build_chain(session)
    assert (
        elig.get_live_eligibility_evidence(session, principal, chain.onboarding.id, now=NOW) is None
    )


def test_read_model_exposes_only_redacted_fields(session, principal):
    chain = _build_chain(session)
    run_real_eligibility_preflight(
        session, request=chain.request(), composition=_full_composition(), now=NOW
    )
    view = elig.get_live_eligibility_evidence(session, principal, chain.onboarding.id, now=NOW)
    assert view is not None
    assert view["evidence_source"] == "live_readonly_proxmox"
    assert view["verification_level"] == "live_verified"
    assert view["eligibility_outcome"] == "eligible"
    assert view["passed"] is True
    assert view["valid"] is True
    assert view["expired"] is False
    assert view["drifted"] is False
    assert view["evidence_hash"].startswith("sha256:")
    assert view["live_read_authorization_id"] == str(chain.authorization.id)
    # No raw observation / endpoint / credential VALUE leaks in the projection (closed dimension
    # codes such as ``credential_read_capability`` are fine — we check for raw values only).
    blob = repr(view).lower()
    for leak in (
        "base_url",
        "example.test",
        "labnode",
        "labstore",
        "10.9.0.0",
        "transient-token",
        SECRET_REF.lower(),
    ):
        assert leak not in blob, f"read model leaked {leak!r}"


def test_read_model_is_permission_protected(session, principal, other_org_principal):
    chain = _build_chain(session, org_id=principal.organization_id)
    run_real_eligibility_preflight(
        session, request=chain.request(), composition=_full_composition(), now=NOW
    )
    from secp_api.errors import AuthorizationError, NotFoundError

    with pytest.raises((AuthorizationError, NotFoundError)):
        elig.get_live_eligibility_evidence(
            session, other_org_principal, chain.onboarding.id, now=NOW
        )


def test_read_model_reports_expiry(session, principal):
    from datetime import timedelta

    chain = _build_chain(session)
    run_real_eligibility_preflight(
        session, request=chain.request(), composition=_full_composition(), now=NOW
    )
    later = NOW + timedelta(days=1)  # past the 6h TTL
    view = elig.get_live_eligibility_evidence(session, principal, chain.onboarding.id, now=later)
    assert view["expired"] is True
    assert view["valid"] is False
