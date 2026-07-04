"""SECP-B2-4 — DbAuthoritativeReverifier re-loads + re-verifies authoritative records (fake-only).

Proves the independent authoritative re-verification is real: it goes back to the database and the
SECP-002B-1B-6 verifier at resolution time, returns the authoritative contract + references derived
from the records (not from the request), and fails closed when the authorization is revoked. No
secret backend, transport, or target is contacted.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from secp_api.enums import (
    IsolationModel,
    OnboardingMode,
    OnboardingStatus,
    TargetStatus,
)
from secp_api.live_read_contract import (
    LIVE_READ_COLLECTOR_CONTRACT_VERSION,
    PROXMOX_READONLY_POLICY_VERSION,
)
from secp_api.models import ExecutionTarget, TargetOnboarding
from secp_api.services import readonly_preflight, staging_labs
from secp_worker.preflight.reverify import DbAuthoritativeReverifier
from secp_worker.preflight.secret_resolution import (
    ResolutionContract,
    ResolutionPurpose,
    SecretResolutionUnavailable,
    TrustedCredentialReference,
)

OPAQUE_REF = "vault:secp/proxmox/target-1"


def _now() -> datetime:
    return datetime.now(UTC)


def _approved_authorization(session, principal):
    target = ExecutionTarget(
        organization_id=principal.organization_id,
        display_name="substrate",
        plugin_name="proxmox",
        config={"base_url": "placeholder", "verify_tls": True},
        config_hash="sha256:" + "ab" * 32,
        secret_ref=OPAQUE_REF,
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
    return target, auth


def _contract_for(target, auth) -> ResolutionContract:
    # Only IDs + purpose + operation_fingerprint are consulted by the reverifier; other fields are
    # re-derived from the authoritative records.
    return ResolutionContract(
        purpose=ResolutionPurpose.readonly_staging_preflight,
        organization_id=target.organization_id,
        execution_target_id=target.id,
        onboarding_id=auth.onboarding_id,
        authorization_id=auth.id,
        authorization_version=auth.authorization_version,
        authorization_expiry="2999-01-01T00:00:00Z",
        operation_fingerprint="sha256:" + "ab" * 32,
        contract_version=LIVE_READ_COLLECTOR_CONTRACT_VERSION,
        endpoint_policy_version=PROXMOX_READONLY_POLICY_VERSION,
        credential_reference=TrustedCredentialReference(OPAQUE_REF),
    )


def test_reverify_derives_authority_from_the_database(session, principal):
    target, auth = _approved_authorization(session, principal)
    contract = _contract_for(target, auth)

    authority = DbAuthoritativeReverifier(session).reverify(contract, now=_now())

    # The authoritative contract is derived from the records, not the request.
    assert authority.contract.execution_target_id == target.id
    assert authority.contract.onboarding_id == auth.onboarding_id
    assert authority.contract.authorization_id == auth.id
    assert authority.contract.authorization_version == auth.authorization_version
    assert authority.contract.contract_version == LIVE_READ_COLLECTOR_CONTRACT_VERSION
    assert authority.contract.endpoint_policy_version == PROXMOX_READONLY_POLICY_VERSION
    # The three references all resolve to the target's own opaque secret_ref.
    assert authority.contract.credential_reference == TrustedCredentialReference(OPAQUE_REF)
    assert authority.target_credential_reference == TrustedCredentialReference(OPAQUE_REF)
    assert authority.binding_credential_reference == TrustedCredentialReference(OPAQUE_REF)


def test_reverify_fails_closed_when_authorization_is_revoked(session, principal):
    target, auth = _approved_authorization(session, principal)
    contract = _contract_for(target, auth)
    readonly_preflight.revoke_preflight_authorization(session, principal, auth.id, "operator")

    with pytest.raises(SecretResolutionUnavailable):
        DbAuthoritativeReverifier(session).reverify(contract, now=_now())


def test_reverify_fails_closed_on_unknown_authorization(session, principal):
    target, auth = _approved_authorization(session, principal)
    contract = _contract_for(target, auth)
    # A request naming a non-existent authorization id must fail closed (never trusted).
    forged = ResolutionContract(
        purpose=contract.purpose,
        organization_id=contract.organization_id,
        execution_target_id=contract.execution_target_id,
        onboarding_id=contract.onboarding_id,
        authorization_id=uuid.uuid4(),
        authorization_version=contract.authorization_version,
        authorization_expiry=contract.authorization_expiry,
        operation_fingerprint=contract.operation_fingerprint,
        contract_version=contract.contract_version,
        endpoint_policy_version=contract.endpoint_policy_version,
        credential_reference=contract.credential_reference,
    )
    with pytest.raises(SecretResolutionUnavailable):
        DbAuthoritativeReverifier(session).reverify(forged, now=_now())
