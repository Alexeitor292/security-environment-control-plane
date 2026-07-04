"""SECP-B2-4 — independent work-item re-verification + full-flow fail-closed-before-client tests.

The DbAuthoritativeReverifier derives the authoritative resolution facts SOLELY from the durable
work item (ReadonlyStagingPreflight) loaded by id, the re-verified records, and the pinned app
constants — it trusts no candidate purpose, fingerprint, expiry, version label, or reference.
These tests prove that, and that forged fingerprint / forged or unknown preflight id / identity
mismatch / unsupported purpose all fail closed BEFORE the injected fake client is ever used.
Nothing contacts a real backend, Proxmox, or any target.
"""

from __future__ import annotations

import dataclasses
import uuid
from datetime import UTC, datetime

import pytest
from secp_api.enums import (
    IsolationModel,
    OnboardingMode,
    OnboardingStatus,
    ReadonlyPreflightStatus,
    TargetStatus,
)
from secp_api.live_read_contract import (
    LIVE_READ_COLLECTOR_CONTRACT_VERSION,
    PROXMOX_READONLY_POLICY_VERSION,
)
from secp_api.models import ExecutionTarget, TargetOnboarding
from secp_api.services import readonly_preflight, staging_labs
from secp_worker.preflight.backends.openbao_resolver import OpenBaoWorkerSecretResolver
from secp_worker.preflight.fingerprint import compute_operation_fingerprint
from secp_worker.preflight.reverify import DbAuthoritativeReverifier
from secp_worker.preflight.secret_resolution import (
    ResolutionContract,
    ResolutionContractViolation,
    ResolutionPurpose,
    SecretMaterial,
    SecretResolutionUnavailable,
    TrustedCredentialReference,
)

VAULT_REF = "vault:secp/proxmox/target-1"


def _now() -> datetime:
    return datetime.now(UTC)


def _queued_preflight(session, principal, *, secret_ref: str = VAULT_REF):
    target = ExecutionTarget(
        organization_id=principal.organization_id,
        display_name="substrate",
        plugin_name="proxmox",
        config={"base_url": "placeholder", "verify_tls": True},
        config_hash="sha256:" + "ab" * 32,
        secret_ref=secret_ref,
        status=TargetStatus.active,
        scope_policy={},
        created_by=principal.user_id,
    )
    session.add(target)
    session.flush()
    session.add(
        TargetOnboarding(
            organization_id=principal.organization_id,
            execution_target_id=target.id,
            onboarding_mode=OnboardingMode.existing_environment,
            isolation_model=IsolationModel.logical,
            status=OnboardingStatus.active,
            declared_boundary={},
            boundary_hash="sha256:" + "cd" * 32,
            created_by=principal.user_id,
        )
    )
    session.flush()
    staging_labs.grant_substrate_eligibility(session, principal, execution_target_id=target.id)
    auth = readonly_preflight.create_preflight_authorization(
        session, principal, execution_target_id=target.id
    )
    readonly_preflight.approve_preflight_authorization(session, principal, auth.id)
    pf = readonly_preflight.queue_preflight(session, principal, live_read_authorization_id=auth.id)
    return target, auth, pf


def _seed_candidate(pf, *, ref: str = VAULT_REF, **over) -> ResolutionContract:
    """A candidate that faithfully names the work item (placeholder expiry). Used for tests that
    call the reverifier directly (it ignores expiry/fingerprint/reference) or where the reverifier
    is expected to REFUSE before the gate — so the expiry need not match the authoritative one."""
    base = dict(
        purpose=ResolutionPurpose.readonly_staging_preflight,
        organization_id=pf.organization_id,
        execution_target_id=pf.execution_target_id,
        onboarding_id=pf.onboarding_id,
        authorization_id=pf.live_read_authorization_id,
        authorization_version=pf.authorization_version,
        authorization_expiry="2999-01-01T00:00:00Z",
        preflight_id=pf.id,
        operation_fingerprint=compute_operation_fingerprint(pf),
        contract_version=LIVE_READ_COLLECTOR_CONTRACT_VERSION,
        endpoint_policy_version=PROXMOX_READONLY_POLICY_VERSION,
        credential_reference=TrustedCredentialReference(ref),
    )
    base.update(over)
    return ResolutionContract(**base)  # type: ignore[arg-type]


def _authoritative_contract(session, pf, *, ref: str = VAULT_REF) -> ResolutionContract:
    seed = _seed_candidate(pf, ref=ref)
    return DbAuthoritativeReverifier(session).reverify(seed, now=_now()).contract


def _matching_candidate(session, pf, *, ref: str = VAULT_REF, **over) -> ResolutionContract:
    """A candidate that matches the AUTHORITATIVE contract (incl. the real expiry) except for the
    single overridden field, so a gate refusal is attributable to exactly that field."""
    return dataclasses.replace(_authoritative_contract(session, pf, ref=ref), **over)


class _Req:
    def __init__(self, contract: ResolutionContract) -> None:
        self.contract = contract


class _SpyClient:
    def __init__(self) -> None:
        self.called = False
        self.reference_seen: str | None = None

    def read_secret(self, *, reference, now):
        self.called = True
        self.reference_seen = reference
        return "opaque-material"


# --- DbAuthoritativeReverifier derives authority from the work item ------------------------------


def test_reverify_derives_authority_from_the_work_item(session, principal):
    target, auth, pf = _queued_preflight(session, principal)
    # Candidate deliberately LIES about the fingerprint; the reverifier ignores it and recomputes.
    candidate = _seed_candidate(pf, operation_fingerprint="sha256:" + "ff" * 32)

    authority = DbAuthoritativeReverifier(session).reverify(candidate, now=_now())

    assert authority.contract.preflight_id == pf.id
    assert authority.contract.purpose == ResolutionPurpose.readonly_staging_preflight
    assert authority.contract.operation_fingerprint == compute_operation_fingerprint(pf)
    assert authority.contract.operation_fingerprint != candidate.operation_fingerprint
    assert authority.contract.execution_target_id == target.id
    assert authority.contract.authorization_id == auth.id
    assert authority.target_credential_reference == TrustedCredentialReference(VAULT_REF)
    assert authority.binding_credential_reference == TrustedCredentialReference(VAULT_REF)


def test_reverify_refuses_unknown_preflight_id(session, principal):
    _target, _auth, pf = _queued_preflight(session, principal)
    candidate = _seed_candidate(pf, preflight_id=uuid.uuid4())
    with pytest.raises(SecretResolutionUnavailable):
        DbAuthoritativeReverifier(session).reverify(candidate, now=_now())


def test_reverify_refuses_ineligible_terminal_preflight(session, principal):
    _target, _auth, pf = _queued_preflight(session, principal)
    pf.status = ReadonlyPreflightStatus.completed
    session.flush()
    candidate = _seed_candidate(pf)
    with pytest.raises(SecretResolutionUnavailable):
        DbAuthoritativeReverifier(session).reverify(candidate, now=_now())


@pytest.mark.parametrize(
    "override",
    [
        {"organization_id": uuid.uuid4()},
        {"execution_target_id": uuid.uuid4()},
        {"onboarding_id": uuid.uuid4()},
        {"authorization_id": uuid.uuid4()},
        {"authorization_version": 99},
    ],
)
def test_reverify_refuses_when_candidate_identity_mismatches_work_item(
    session, principal, override
):
    _target, _auth, pf = _queued_preflight(session, principal)
    candidate = _seed_candidate(pf, **override)
    with pytest.raises(SecretResolutionUnavailable):
        DbAuthoritativeReverifier(session).reverify(candidate, now=_now())


def test_reverify_fails_closed_when_authorization_is_revoked(session, principal):
    _target, auth, pf = _queued_preflight(session, principal)
    readonly_preflight.revoke_preflight_authorization(session, principal, auth.id, "operator")
    candidate = _seed_candidate(pf)
    with pytest.raises(SecretResolutionUnavailable):
        DbAuthoritativeReverifier(session).reverify(candidate, now=_now())


# --- Full flow through the adapter: everything fails closed BEFORE the client -------------------


def _resolver(session, client: _SpyClient) -> OpenBaoWorkerSecretResolver:
    return OpenBaoWorkerSecretResolver(
        reverifier=DbAuthoritativeReverifier(session), http_client=client
    )


def test_forged_operation_fingerprint_stops_before_client(session, principal):
    _target, _auth, pf = _queued_preflight(session, principal)
    candidate = _matching_candidate(session, pf, operation_fingerprint="sha256:" + "ff" * 32)
    client = _SpyClient()
    with pytest.raises(ResolutionContractViolation) as exc:
        _resolver(session, client).resolve(_Req(candidate), expectation=candidate, now=_now())
    assert exc.value.reason_code == "operation_fingerprint_mismatch"
    assert client.called is False


def test_forged_or_unknown_preflight_id_stops_before_client(session, principal):
    _target, _auth, pf = _queued_preflight(session, principal)
    candidate = _seed_candidate(pf, preflight_id=uuid.uuid4())
    client = _SpyClient()
    with pytest.raises(SecretResolutionUnavailable):
        _resolver(session, client).resolve(_Req(candidate), expectation=candidate, now=_now())
    assert client.called is False


def test_work_item_identity_mismatch_stops_before_client(session, principal):
    _target, _auth, pf = _queued_preflight(session, principal)
    candidate = _seed_candidate(pf, authorization_version=99)
    client = _SpyClient()
    with pytest.raises(SecretResolutionUnavailable):
        _resolver(session, client).resolve(_Req(candidate), expectation=candidate, now=_now())
    assert client.called is False


def test_unsupported_purpose_stops_before_client(session, principal):
    _target, _auth, pf = _queued_preflight(session, principal)
    candidate = _matching_candidate(session, pf)

    class _Fake(str):
        pass

    object.__setattr__(candidate, "purpose", _Fake("some_future_purpose"))
    client = _SpyClient()
    with pytest.raises(ResolutionContractViolation) as exc:
        _resolver(session, client).resolve(_Req(candidate), expectation=candidate, now=_now())
    assert exc.value.reason_code == "unsupported_purpose"
    assert client.called is False


def test_valid_db_backed_work_item_resolves_only_through_the_fake_client(session, principal):
    _target, _auth, pf = _queued_preflight(session, principal)
    candidate = _matching_candidate(session, pf)
    client = _SpyClient()
    material = _resolver(session, client).resolve(
        _Req(candidate), expectation=candidate, now=_now()
    )
    assert isinstance(material, SecretMaterial)
    assert client.called is True
    # The client is called with the AUTHORITATIVE vault reference (never the candidate's).
    assert client.reference_seen == VAULT_REF


def test_env_reference_target_refused_before_client(session, principal):
    # A target whose authoritative reference is a non-vault (env:) scheme is refused before client.
    env_ref = "env:SECP_PROVIDER_SECRET__PF"
    _target, _auth, pf = _queued_preflight(session, principal, secret_ref=env_ref)
    candidate = _matching_candidate(session, pf, ref=env_ref)
    client = _SpyClient()
    with pytest.raises(ResolutionContractViolation) as exc:
        _resolver(session, client).resolve(_Req(candidate), expectation=candidate, now=_now())
    assert exc.value.reason_code == "unsupported_reference_scheme"
    assert client.called is False
    # No reference/secret leaks through the raised error.
    assert env_ref not in str(exc.value)
