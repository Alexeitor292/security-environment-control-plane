"""SECP-002B-1B-6 — dormant live-read authorization contract tests.

Fake-only. These tests prove authorization loading/verification fails closed and never reaches
secret resolution, transport construction, collector invocation, evidence persistence, or network
activity. They do not invoke ``run_live_readonly_collection``.
"""

from __future__ import annotations

import inspect
import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from secp_api.enums import (
    AuditAction,
    IsolationModel,
    LiveReadAuthorizationStatus,
    OnboardingMode,
    OnboardingStatus,
    TargetStatus,
    VerificationLevel,
)
from secp_api.errors import DomainError, ImmutableResourceError
from secp_api.models import AuditEvent, ExecutionTarget, LiveReadAuthorization, TargetOnboarding
from secp_api.services import live_authorizations
from secp_plugin_proxmox import (
    LIVE_READ_COLLECTOR_CONTRACT_VERSION,
    LIVE_READ_EVIDENCE_SOURCE,
    PROXMOX_READONLY_POLICY_VERSION,
)
from secp_worker.onboarding.live_authorization import (
    LiveReadAuthorizationContract,
    LiveReadAuthorizationLoadRequest,
    LiveReadAuthorizationRefused,
    load_and_verify_live_read_authorization,
)

NOW = datetime(2026, 7, 2, tzinfo=UTC)
ORG_ID = uuid.uuid4()
TARGET_ID = uuid.uuid4()
ONBOARDING_ID = uuid.uuid4()
AUTHORIZATION_ID = uuid.uuid4()
OTHER_ID = uuid.uuid4()
SECRET_REF = "env:SECP_PROVIDER_SECRET__FAKE"
CONNECTION_HASH = "sha256:" + "11" * 32
BOUNDARY_HASH = "sha256:" + "22" * 32
OTHER_HASH = "sha256:" + "33" * 32
_DEFAULT = object()


def _target(**over) -> ExecutionTarget:
    fields = dict(
        id=TARGET_ID,
        organization_id=ORG_ID,
        display_name="placeholder target",
        plugin_name="proxmox",
        config={},
        config_hash="sha256:" + "44" * 32,
        secret_ref=SECRET_REF,
        status=TargetStatus.active,
        scope_policy={},
    )
    fields.update(over)
    return ExecutionTarget(**fields)


def _onboarding(**over) -> TargetOnboarding:
    fields = dict(
        id=ONBOARDING_ID,
        organization_id=ORG_ID,
        execution_target_id=TARGET_ID,
        onboarding_mode=OnboardingMode.existing_environment,
        isolation_model=IsolationModel.logical,
        status=OnboardingStatus.active,
        declared_boundary={},
        boundary_hash=BOUNDARY_HASH,
    )
    fields.update(over)
    return TargetOnboarding(**fields)


def _authorization(**over) -> LiveReadAuthorization:
    fields = dict(
        id=AUTHORIZATION_ID,
        organization_id=ORG_ID,
        execution_target_id=TARGET_ID,
        onboarding_id=ONBOARDING_ID,
        connection_hash=CONNECTION_HASH,
        boundary_hash=BOUNDARY_HASH,
        authorization_version=1,
        authorization_expiry=NOW + timedelta(days=1),
        collector_contract_version=LIVE_READ_COLLECTOR_CONTRACT_VERSION,
        endpoint_allowlist_version=PROXMOX_READONLY_POLICY_VERSION,
        evidence_source=LIVE_READ_EVIDENCE_SOURCE,
        verification_level=VerificationLevel.live_verified.value,
        status=LiveReadAuthorizationStatus.approved,
        approved_by=uuid.uuid4(),
        approved_at=NOW,
        revocation_reason_code="",
    )
    fields.update(over)
    return LiveReadAuthorization(**fields)


def _request(**over) -> LiveReadAuthorizationLoadRequest:
    fields = dict(
        organization_id=ORG_ID,
        execution_target_id=TARGET_ID,
        onboarding_id=ONBOARDING_ID,
        authorization_id=AUTHORIZATION_ID,
        authorization_version=1,
    )
    fields.update(over)
    return LiveReadAuthorizationLoadRequest(**fields)


def _contract(**over) -> LiveReadAuthorizationContract:
    fields = dict(
        evidence_source=LIVE_READ_EVIDENCE_SOURCE,
        verification_level=VerificationLevel.live_verified.value,
        collector_contract_version=LIVE_READ_COLLECTOR_CONTRACT_VERSION,
        endpoint_allowlist_version=PROXMOX_READONLY_POLICY_VERSION,
    )
    fields.update(over)
    return LiveReadAuthorizationContract(**fields)


class FakeRepository:
    def __init__(
        self,
        *,
        target=_DEFAULT,
        onboarding=_DEFAULT,
        authorization=_DEFAULT,
    ) -> None:
        self.target = _target() if target is _DEFAULT else target
        self.onboarding = _onboarding() if onboarding is _DEFAULT else onboarding
        self.authorization = _authorization() if authorization is _DEFAULT else authorization
        self.calls: list[tuple[str, uuid.UUID]] = []

    def get_execution_target(self, target_id: uuid.UUID):
        self.calls.append(("target", target_id))
        return self.target

    def get_target_onboarding(self, onboarding_id: uuid.UUID):
        self.calls.append(("onboarding", onboarding_id))
        return self.onboarding

    def get_live_read_authorization(self, authorization_id: uuid.UUID):
        self.calls.append(("authorization", authorization_id))
        return self.authorization


class FakeConnectionHashProvider:
    def __init__(self, value: str = CONNECTION_HASH) -> None:
        self.value = value
        self.calls: list[uuid.UUID] = []

    def current_connection_hash(self, execution_target: ExecutionTarget) -> str:
        self.calls.append(execution_target.id)
        return self.value


class FakeAuditSink:
    def __init__(self) -> None:
        self.refusals = []

    def record_validation_refused(self, refusal) -> None:
        self.refusals.append(refusal)


def _verify(repo: FakeRepository, *, request=None, hasher=None, contract=None, sink=None):
    return load_and_verify_live_read_authorization(
        request=_request() if request is None else request,
        repository=repo,
        connection_hash_provider=FakeConnectionHashProvider() if hasher is None else hasher,
        expected_contract=_contract() if contract is None else contract,
        audit_sink=FakeAuditSink() if sink is None else sink,
        now=NOW,
    )


@pytest.mark.parametrize(
    ("case", "repo", "load_request", "hasher", "contract", "reason", "hash_called"),
    [
        (
            "authorization_missing",
            FakeRepository(authorization=None),
            _request(),
            FakeConnectionHashProvider(),
            _contract(),
            "authorization_missing",
            False,
        ),
        (
            "authorization_draft",
            FakeRepository(authorization=_authorization(status=LiveReadAuthorizationStatus.draft)),
            _request(),
            FakeConnectionHashProvider(),
            _contract(),
            "authorization_draft",
            False,
        ),
        (
            "authorization_revoked",
            FakeRepository(
                authorization=_authorization(status=LiveReadAuthorizationStatus.revoked)
            ),
            _request(),
            FakeConnectionHashProvider(),
            _contract(),
            "authorization_revoked",
            False,
        ),
        (
            "authorization_expired",
            FakeRepository(authorization=_authorization(authorization_expiry=NOW)),
            _request(),
            FakeConnectionHashProvider(),
            _contract(),
            "authorization_expired",
            False,
        ),
        (
            "wrong_organization",
            FakeRepository(authorization=_authorization(organization_id=OTHER_ID)),
            _request(),
            FakeConnectionHashProvider(),
            _contract(),
            "wrong_organization",
            False,
        ),
        (
            "wrong_execution_target",
            FakeRepository(authorization=_authorization(execution_target_id=OTHER_ID)),
            _request(),
            FakeConnectionHashProvider(),
            _contract(),
            "wrong_execution_target",
            False,
        ),
        (
            "wrong_onboarding",
            FakeRepository(authorization=_authorization(onboarding_id=OTHER_ID)),
            _request(),
            FakeConnectionHashProvider(),
            _contract(),
            "wrong_onboarding",
            False,
        ),
        (
            "target_not_active",
            FakeRepository(target=_target(status=TargetStatus.disabled)),
            _request(),
            FakeConnectionHashProvider(),
            _contract(),
            "target_not_active",
            False,
        ),
        (
            "onboarding_not_active",
            FakeRepository(onboarding=_onboarding(status=OnboardingStatus.approved)),
            _request(),
            FakeConnectionHashProvider(),
            _contract(),
            "onboarding_not_active",
            False,
        ),
        (
            "connection_hash_drift",
            FakeRepository(),
            _request(),
            FakeConnectionHashProvider(OTHER_HASH),
            _contract(),
            "connection_hash_drift",
            True,
        ),
        (
            "boundary_hash_drift",
            FakeRepository(onboarding=_onboarding(boundary_hash=OTHER_HASH)),
            _request(),
            FakeConnectionHashProvider(),
            _contract(),
            "boundary_hash_drift",
            True,
        ),
        (
            "evidence_source_drift",
            FakeRepository(authorization=_authorization(evidence_source="other_source")),
            _request(),
            FakeConnectionHashProvider(),
            _contract(),
            "evidence_source_drift",
            True,
        ),
        (
            "verification_level_drift",
            FakeRepository(authorization=_authorization(verification_level="simulated")),
            _request(),
            FakeConnectionHashProvider(),
            _contract(),
            "verification_level_drift",
            True,
        ),
        (
            "collector_contract_version_drift",
            FakeRepository(authorization=_authorization(collector_contract_version="other/v1")),
            _request(),
            FakeConnectionHashProvider(),
            _contract(),
            "collector_contract_version_drift",
            True,
        ),
        (
            "endpoint_allowlist_version_drift",
            FakeRepository(authorization=_authorization(endpoint_allowlist_version="other/v1")),
            _request(),
            FakeConnectionHashProvider(),
            _contract(),
            "endpoint_allowlist_version_drift",
            True,
        ),
        (
            "authorization_version_drift",
            FakeRepository(),
            _request(authorization_version=2),
            FakeConnectionHashProvider(),
            _contract(),
            "authorization_version_drift",
            False,
        ),
    ],
    ids=lambda v: v if isinstance(v, str) else None,
)
def test_authorization_verifier_refuses_required_failures(
    case, repo, load_request, hasher, contract, reason, hash_called
):
    sink = FakeAuditSink()
    with pytest.raises(LiveReadAuthorizationRefused) as exc:
        _verify(repo, request=load_request, hasher=hasher, contract=contract, sink=sink)

    assert exc.value.reason_code == reason, case
    assert len(sink.refusals) == 1
    assert sink.refusals[0].reason_code == reason
    assert (hasher.calls != []) is hash_called
    assert SECRET_REF not in repr(exc.value)
    assert SECRET_REF not in repr(sink.refusals[0])


def test_authorization_verifier_builds_binding_only_after_all_checks_pass():
    hasher = FakeConnectionHashProvider()
    sink = FakeAuditSink()
    repo = FakeRepository()

    result = _verify(repo, hasher=hasher, sink=sink)

    assert result.execution_target is repo.target
    assert result.onboarding is repo.onboarding
    assert result.authorization is repo.authorization
    assert result.binding.execution_target_id == str(TARGET_ID)
    assert result.binding.onboarding_id == str(ONBOARDING_ID)
    assert result.binding.target_config_hash == CONNECTION_HASH
    assert result.binding.boundary_hash == BOUNDARY_HASH
    assert result.binding.credential_ref == SECRET_REF
    assert result.binding.authorization_expiry == "2026-07-03T00:00:00Z"
    assert hasher.calls == [TARGET_ID]
    assert sink.refusals == []
    assert SECRET_REF not in repr(result)
    assert SECRET_REF not in repr(result.binding)


def test_authorization_verifier_contract_has_no_live_execution_inputs():
    params = set(inspect.signature(load_and_verify_live_read_authorization).parameters)
    for forbidden in (
        "secret_resolver",
        "transport_factory",
        "collector",
        "session",
        "target_config",
        "declared_boundary",
        "secret_ref",
    ):
        assert forbidden not in params


def test_live_read_authorization_model_has_no_secret_or_live_payload_columns():
    columns = {column.name for column in LiveReadAuthorization.__table__.columns}
    for forbidden in (
        "endpoint_url",
        "host",
        "base_url",
        "config",
        "declared_boundary",
        "credential_ref",
        "secret_ref",
        "token",
        "secret",
        "credential_ref_hash",
        "observations",
        "evidence_payload",
    ):
        assert forbidden not in columns


def _db_target_and_onboarding(session, principal):
    target = ExecutionTarget(
        organization_id=principal.organization_id,
        display_name="placeholder target",
        plugin_name="proxmox",
        config={},
        config_hash="sha256:" + "55" * 32,
        secret_ref=SECRET_REF,
        status=TargetStatus.active,
        scope_policy={},
        created_by=principal.user_id,
    )
    session.add(target)
    session.flush()
    onboarding = TargetOnboarding(
        organization_id=principal.organization_id,
        execution_target_id=target.id,
        onboarding_mode=OnboardingMode.existing_environment,
        isolation_model=IsolationModel.logical,
        status=OnboardingStatus.active,
        declared_boundary={},
        boundary_hash=BOUNDARY_HASH,
        created_by=principal.user_id,
    )
    session.add(onboarding)
    session.flush()
    return target, onboarding


def test_authorization_lifecycle_audit_is_secret_free(session, principal):
    target, onboarding = _db_target_and_onboarding(session, principal)
    authorization = live_authorizations.create_live_read_authorization(
        session,
        principal,
        execution_target_id=target.id,
        onboarding_id=onboarding.id,
        connection_hash=CONNECTION_HASH,
        boundary_hash=BOUNDARY_HASH,
        authorization_version=1,
        authorization_expiry=NOW + timedelta(days=1),
        collector_contract_version=LIVE_READ_COLLECTOR_CONTRACT_VERSION,
        endpoint_allowlist_version=PROXMOX_READONLY_POLICY_VERSION,
        evidence_source=LIVE_READ_EVIDENCE_SOURCE,
        verification_level=VerificationLevel.live_verified.value,
    )
    live_authorizations.approve_live_read_authorization(session, principal, authorization.id)
    approved_by = authorization.approved_by
    approved_at = authorization.approved_at
    live_authorizations.revoke_live_read_authorization(
        session,
        principal,
        authorization.id,
        "operator_revoked",
    )
    live_authorizations.record_live_read_authorization_validation_refused(
        session,
        organization_id=principal.organization_id,
        authorization_id=authorization.id,
        execution_target_id=target.id,
        onboarding_id=onboarding.id,
        authorization_version=authorization.authorization_version,
        reason_code=SECRET_REF,
    )
    session.commit()

    assert authorization.status == LiveReadAuthorizationStatus.revoked
    assert authorization.approved_by == approved_by
    assert authorization.approved_at == approved_at.replace(tzinfo=None)
    events = session.query(AuditEvent).filter(AuditEvent.resource_id == str(authorization.id)).all()
    actions = {event.action for event in events}
    assert AuditAction.live_read_authorization_created.value in actions
    assert AuditAction.live_read_authorization_approved.value in actions
    assert AuditAction.live_read_authorization_revoked.value in actions
    assert AuditAction.live_read_authorization_validation_refused.value in actions
    blob = json.dumps([event.data for event in events], sort_keys=True)
    assert SECRET_REF not in blob
    assert "operator_revoked" in blob
    assert "unspecified" in blob


def test_authorization_immutability_preserves_approval_history(session, principal):
    target, onboarding = _db_target_and_onboarding(session, principal)
    authorization = live_authorizations.create_live_read_authorization(
        session,
        principal,
        execution_target_id=target.id,
        onboarding_id=onboarding.id,
        connection_hash=CONNECTION_HASH,
        boundary_hash=BOUNDARY_HASH,
        authorization_version=1,
        authorization_expiry=NOW + timedelta(days=1),
        collector_contract_version=LIVE_READ_COLLECTOR_CONTRACT_VERSION,
        endpoint_allowlist_version=PROXMOX_READONLY_POLICY_VERSION,
        evidence_source=LIVE_READ_EVIDENCE_SOURCE,
        verification_level=VerificationLevel.live_verified.value,
    )
    live_authorizations.approve_live_read_authorization(session, principal, authorization.id)
    session.commit()

    authorization.connection_hash = OTHER_HASH
    with pytest.raises(ImmutableResourceError):
        session.flush()
    session.rollback()

    authorization = session.get(LiveReadAuthorization, authorization.id)
    authorization.approved_by = uuid.uuid4()
    with pytest.raises(ImmutableResourceError):
        session.flush()


def test_authorization_service_refuses_invalid_lifecycle(session, principal):
    target, onboarding = _db_target_and_onboarding(session, principal)
    authorization = live_authorizations.create_live_read_authorization(
        session,
        principal,
        execution_target_id=target.id,
        onboarding_id=onboarding.id,
        connection_hash=CONNECTION_HASH,
        boundary_hash=BOUNDARY_HASH,
        authorization_version=1,
        authorization_expiry=NOW + timedelta(days=1),
        collector_contract_version=LIVE_READ_COLLECTOR_CONTRACT_VERSION,
        endpoint_allowlist_version=PROXMOX_READONLY_POLICY_VERSION,
        evidence_source=LIVE_READ_EVIDENCE_SOURCE,
        verification_level=VerificationLevel.live_verified.value,
    )

    with pytest.raises(DomainError):
        live_authorizations.revoke_live_read_authorization(
            session, principal, authorization.id, "not_approved"
        )


def test_authorization_request_and_contract_repr_are_secret_free():
    request = _request()
    contract = _contract()
    assert SECRET_REF not in repr(request)
    assert SECRET_REF not in repr(contract)
    assert "authorization_version=1" in repr(request)


def test_worker_authorization_module_has_no_network_or_persistence_tokens():
    import secp_worker.onboarding.live_authorization as la

    src = inspect.getsource(la)
    for forbidden in (
        "import httpx",
        "import requests",
        "import socket",
        "import subprocess",
        "SecretResolver",
        "HttpxReadOnlyTransport",
        "LiveReadOnlyProxmoxCollector(",
        "run_live_readonly_collection(",
        "TargetEvidenceRecord(",
        "session.add(",
        "session.commit(",
    ):
        assert forbidden not in src
