"""SECP-002B-1B-1 read-only target evidence contract. Simulated-only."""

from __future__ import annotations

import copy
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from secp_api.enums import EvidenceStatus, IsolationModel, OnboardingMode, VerificationLevel
from secp_api.errors import DomainError, ImmutableResourceError, ValidationFailedError
from secp_api.models import AuditEvent, TargetEvidenceRecord, TargetPreflight
from secp_api.onboarding import boundary_from_scope
from secp_api.services import onboarding as onb
from secp_api.target_evidence import (
    CHECK_CIDRS,
    CHECK_ISOLATION,
    CHECK_NETWORK_SEGMENTS,
    CHECK_NODES,
    CHECK_QUOTAS,
    CHECK_STORAGE,
    CHECK_VMID_RANGE,
    FINDING_FAIL,
    FINDING_UNVERIFIABLE,
    SIMULATED_EVIDENCE_SOURCE,
    compare_boundary_to_evidence,
    target_evidence_hash,
    validate_target_evidence_payload,
)
from sqlalchemy import select
from tests.conftest import VALID_ONBOARDING_BOUNDARY, build_provisioning_env  # type: ignore


@pytest.fixture
def client(engine):
    from secp_api.db import session_scope
    from secp_api.main import create_app
    from secp_api.seed import bootstrap_dev

    with session_scope() as s:
        bootstrap_dev(s)
    app = create_app()
    app.router.on_startup.clear()
    return TestClient(app)


def _status(findings: list[dict], check: str) -> str:
    return next(str(f["status"]) for f in findings if f["check"] == check)


def _new_onboarding(session, principal, target):
    return onb.create_onboarding(
        session,
        principal,
        target_id=target.id,
        onboarding_mode=OnboardingMode.existing_environment,
        isolation_model=IsolationModel.logical,
        declared_boundary=boundary_from_scope(target.scope_policy),
    )


def _payload(boundary: dict) -> dict:
    # Tests may call the worker collector directly; the architecture test only scans secp_api.
    from secp_worker.onboarding.target_evidence import SimulatedTargetEvidenceCollector

    return SimulatedTargetEvidenceCollector().collect(declared_boundary=copy.deepcopy(boundary))


def _hash_context(payload: dict, findings: list[dict]) -> dict:
    return {
        "organization_id": str(uuid.uuid4()),
        "onboarding_id": str(uuid.uuid4()),
        "execution_target_id": str(uuid.uuid4()),
        "evidence_source": SIMULATED_EVIDENCE_SOURCE,
        "verification_level": VerificationLevel.simulated.value,
        "status": EvidenceStatus.passed.value,
        "collected_at": datetime.now(UTC),
        "evidence_payload": payload,
        "findings": findings,
    }


def test_canonical_evidence_hashing_is_stable():
    payload = _payload(VALID_ONBOARDING_BOUNDARY)
    findings = compare_boundary_to_evidence(VALID_ONBOARDING_BOUNDARY, payload)
    base = _hash_context(payload, findings)
    same_payload = {
        "verification_level": payload["verification_level"],
        "observed": copy.deepcopy(payload["observed"]),
        "schema_version": payload["schema_version"],
        "evidence_source": payload["evidence_source"],
    }

    assert target_evidence_hash(**base) == target_evidence_hash(
        **{**base, "evidence_payload": same_payload, "findings": copy.deepcopy(findings)}
    )


@pytest.mark.parametrize(
    "field",
    [
        "execution_target_id",
        "onboarding_id",
        "collected_at",
        "status",
        "evidence_payload",
        "findings",
    ],
)
def test_evidence_hash_commits_to_full_record_context(field):
    payload = _payload(VALID_ONBOARDING_BOUNDARY)
    findings = compare_boundary_to_evidence(VALID_ONBOARDING_BOUNDARY, payload)
    base = _hash_context(payload, findings)
    changed = copy.deepcopy(base)
    if field in {"execution_target_id", "onboarding_id"}:
        changed[field] = str(uuid.uuid4())
    elif field == "collected_at":
        changed[field] = base["collected_at"] + timedelta(seconds=1)
    elif field == "status":
        changed[field] = EvidenceStatus.failed.value
    elif field == "evidence_payload":
        drifted_payload = copy.deepcopy(payload)
        drifted_payload["observed"]["nodes"] = drifted_payload["observed"]["nodes"][:-1]
        changed[field] = drifted_payload
    else:
        changed[field] = [
            {**findings[0], "status": FINDING_FAIL, "detail": "changed finding"},
            *findings[1:],
        ]

    assert target_evidence_hash(**base) != target_evidence_hash(**changed)


def test_evidence_hash_refuses_verification_level_drift():
    payload = _payload(VALID_ONBOARDING_BOUNDARY)
    findings = compare_boundary_to_evidence(VALID_ONBOARDING_BOUNDARY, payload)
    base = _hash_context(payload, findings)
    drifted_payload = copy.deepcopy(payload)
    drifted_payload["verification_level"] = VerificationLevel.live_verified.value

    with pytest.raises(ValidationFailedError, match="only simulated"):
        target_evidence_hash(
            **{
                **base,
                "verification_level": VerificationLevel.live_verified.value,
                "evidence_payload": drifted_payload,
            }
        )


def test_target_evidence_record_is_append_only(session, principal):
    build_provisioning_env(session, principal)
    record = session.execute(select(TargetEvidenceRecord)).scalars().first()
    assert record is not None

    record.findings = []
    with pytest.raises(ImmutableResourceError):
        session.flush()
    session.rollback()

    record = session.get(TargetEvidenceRecord, record.id)
    session.delete(record)
    with pytest.raises(ImmutableResourceError):
        session.flush()


def test_only_simulated_evidence_source_is_accepted():
    payload = _payload(VALID_ONBOARDING_BOUNDARY)
    validate_target_evidence_payload(payload)

    bad_source = copy.deepcopy(payload)
    bad_source["evidence_source"] = "unavailable"
    with pytest.raises(ValidationFailedError, match="only simulated"):
        validate_target_evidence_payload(bad_source)

    bad_level = copy.deepcopy(payload)
    bad_level["verification_level"] = VerificationLevel.live_verified.value
    with pytest.raises(ValidationFailedError, match="only simulated"):
        validate_target_evidence_payload(bad_level)


@pytest.mark.parametrize(
    ("check", "mutate"),
    [
        (CHECK_NODES, lambda observed: observed.__setitem__("nodes", [])),
        (CHECK_STORAGE, lambda observed: observed.__setitem__("storage", [])),
        (CHECK_NETWORK_SEGMENTS, lambda observed: observed.__setitem__("network_segments", [])),
        (CHECK_CIDRS, lambda observed: observed.__setitem__("cidr_reservations", [])),
        (
            CHECK_VMID_RANGE,
            lambda observed: observed.__setitem__(
                "vmid_range",
                {
                    "start": VALID_ONBOARDING_BOUNDARY["vmid_range"]["start"] + 1,
                    "end": VALID_ONBOARDING_BOUNDARY["vmid_range"]["end"],
                },
            ),
        ),
        (
            CHECK_QUOTAS,
            lambda observed: observed["quotas"].__setitem__(
                "max_vms", VALID_ONBOARDING_BOUNDARY["quotas"]["max_vms"] - 1
            ),
        ),
        (
            CHECK_ISOLATION,
            lambda observed: observed["isolation"].__setitem__("route_to_protected", True),
        ),
    ],
)
def test_boundary_comparison_mismatches_fail_closed(check, mutate):
    payload = _payload(VALID_ONBOARDING_BOUNDARY)
    mutate(payload["observed"])

    findings = compare_boundary_to_evidence(VALID_ONBOARDING_BOUNDARY, payload)

    assert _status(findings, check) == FINDING_FAIL


def test_missing_evidence_is_unverifiable_and_blocks_review(session, principal):
    env = build_provisioning_env(session, principal)
    ob = _new_onboarding(session, principal, env.target)
    pf = onb.record_simulated_preflight(session, principal, ob.id)
    session.execute(
        TargetPreflight.__table__.update()
        .where(TargetPreflight.__table__.c.id == pf.id)
        .values(target_evidence_id=None, target_evidence_hash=None)
    )
    session.commit()
    session.expire_all()

    findings = compare_boundary_to_evidence(VALID_ONBOARDING_BOUNDARY, None)
    assert {f["status"] for f in findings} == {FINDING_UNVERIFIABLE}
    with pytest.raises(DomainError, match="target evidence"):
        onb.submit_for_review(session, principal, ob.id)


def test_simulated_preflight_persists_bound_evidence_and_audits(session, principal):
    build_provisioning_env(session, principal)
    ob = session.execute(
        select(TargetPreflight).where(TargetPreflight.target_evidence_id.is_not(None))
    ).scalar_one()
    record = session.get(TargetEvidenceRecord, ob.target_evidence_id)

    assert record is not None
    assert record.evidence_source == SIMULATED_EVIDENCE_SOURCE
    assert record.verification_level == VerificationLevel.simulated.value
    assert record.status == EvidenceStatus.passed
    assert ob.target_evidence_hash == record.evidence_hash
    assert ob.evidence_hash == onb.recompute_evidence_hash(ob)

    actions = {event.action for event in session.query(AuditEvent).all()}
    assert "target_evidence.collected" in actions
    assert "target_evidence.compared" in actions


def test_secret_reference_absent_from_evidence_audit_and_api(
    session, principal, client: TestClient
):
    env = build_provisioning_env(session, principal)
    preflight = session.execute(select(TargetPreflight)).scalars().first()
    record = session.get(TargetEvidenceRecord, preflight.target_evidence_id)
    blob = str(
        {
            "payload": record.evidence_payload,
            "findings": record.findings,
            "audit": [event.data for event in session.query(AuditEvent).all()],
        }
    )
    assert env.target.secret_ref not in blob

    response = client.get(f"/api/v1/onboarding/{preflight.onboarding_id}/evidence")
    assert response.status_code == 200, response.text
    assert env.target.secret_ref not in response.text
    assert "evidence_payload" not in response.text


def test_existing_onboarding_lifecycle_still_reaches_active(session, principal):
    env = build_provisioning_env(session, principal)
    assert env.plan.target_onboarding_id is not None
