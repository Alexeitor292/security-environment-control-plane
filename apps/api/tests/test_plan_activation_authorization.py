"""B1B-PR5A §7 — the SEPARATE plan-generation authorization lifecycle (ADR-022).

The plan-generation authorization is a second, explicit, dedicated-permission decision that binds
the APPROVED activation dossier and the current readiness world. Its sole representable purpose is
``plan_generation`` — apply/destroy are unrepresentable. Creating it needs an approved dossier AND
current remote-state + plan-secret readiness records to exist; approving it needs a DEDICATED
permission. Neither runs readiness, generates a plan, or executes anything.

These proofs cover what can be set up hermetically: the create-time preconditions (an approved
dossier and a current readiness world), the two independent permission gates, and the sole
representable purpose. The service raises the closed :class:`ReadinessError`; a permission failure
is folded to the ``forbidden`` code.
"""

from __future__ import annotations

import uuid

import pytest
from secp_api.auth import Principal
from secp_api.enums import (
    ActivationDossierEvidenceStatus,
    CredentialPurposeClass,
    Permission,
    PlanGenerationPurpose,
    ReadinessErrorCode,
)
from secp_api.errors import ReadinessError
from secp_api.plan_activation_contract import (
    PLAN_GENERATION_READINESS_POLICY_VERSION,
    REQUIRED_DOSSIER_EVIDENCE_KINDS,
)
from secp_api.services import targets
from secp_api.services.plan_activation import (
    approve_activation_dossier,
    approve_plan_generation_authorization,
    create_activation_dossier,
    create_plan_generation_authorization,
    get_plan_generation_readiness,
    record_dossier_evidence,
)
from tests._readiness_fixtures import build_readiness_env  # type: ignore[import-not-found]

PROVIDER_REF = "env:SECP_PROVIDER_SECRET__PROV"
STATE_REF = "env:SECP_PROVIDER_SECRET__STATE"


def _make_env(session, principal, tmp_path):
    """The full authoritative chain plus BOTH dedicated operation credential references."""
    env = build_readiness_env(session, principal, toolchain_root=str(tmp_path))
    for purpose, ref in (
        (CredentialPurposeClass.provider_plan_read, PROVIDER_REF),
        (CredentialPurposeClass.state_backend_plan, STATE_REF),
    ):
        targets.rotate_target_operation_credential(
            session, principal, env.target.id, purpose_class=purpose, secret_ref=ref
        )
    session.flush()
    return env


def _limited(principal, *perms: Permission) -> Principal:
    return Principal(
        user_id=uuid.uuid4(),
        organization_id=principal.organization_id,
        email="limited@local.test",
        permissions=frozenset(perms),
    )


def _approved_dossier(session, principal, manifest_id):
    dossier = create_activation_dossier(
        session,
        principal,
        manifest_id=manifest_id,
        recovery_owner_proof="proof-recovery",
        emergency_stop_owner_proof="proof-estop",
    )
    for kind in REQUIRED_DOSSIER_EVIDENCE_KINDS:
        record_dossier_evidence(
            session,
            principal,
            dossier.id,
            kind=kind,
            status=ActivationDossierEvidenceStatus.verified,
            proof_id="proof-abc",
            issuer="reviewer-1",
        )
    return approve_activation_dossier(session, principal, dossier.id)


def test_create_without_any_activation_dossier_is_refused(session, principal, tmp_path):
    env = _make_env(session, principal, tmp_path)
    with pytest.raises(ReadinessError) as exc:
        create_plan_generation_authorization(session, principal, manifest_id=env.manifest.id)
    assert exc.value.code == ReadinessErrorCode.invalid_state.value


def test_create_with_only_a_draft_dossier_is_refused(session, principal, tmp_path):
    env = _make_env(session, principal, tmp_path)
    # A DRAFT (un-approved) dossier does not authorize plan-generation creation.
    create_activation_dossier(
        session,
        principal,
        manifest_id=env.manifest.id,
        recovery_owner_proof="proof-recovery",
        emergency_stop_owner_proof="proof-estop",
    )
    with pytest.raises(ReadinessError) as exc:
        create_plan_generation_authorization(session, principal, manifest_id=env.manifest.id)
    assert exc.value.code == ReadinessErrorCode.invalid_state.value


def test_create_with_an_approved_dossier_but_no_readiness_world_is_refused(
    session, principal, tmp_path
):
    # An approved dossier is necessary but not sufficient: without a current remote-state +
    # plan-secret readiness world, the binding cannot be resolved.
    env = _make_env(session, principal, tmp_path)
    _approved_dossier(session, principal, env.manifest.id)
    with pytest.raises(ReadinessError) as exc:
        create_plan_generation_authorization(session, principal, manifest_id=env.manifest.id)
    assert exc.value.code == ReadinessErrorCode.binding_invalid.value


def test_create_requires_the_plan_generation_manage_permission(session, principal, tmp_path):
    env = _make_env(session, principal, tmp_path)
    no_manage = _limited(principal, Permission.plan_generation_approve)  # approve is NOT manage
    with pytest.raises(ReadinessError) as exc:
        create_plan_generation_authorization(session, no_manage, manifest_id=env.manifest.id)
    assert exc.value.code == ReadinessErrorCode.forbidden.value


def test_approve_requires_the_dedicated_plan_generation_approve_permission(session, principal):
    # The permission gate is evaluated before the row is loaded, so a manage-only holder is refused
    # even against an arbitrary id — approval is never inferable from manage.
    manage_only = _limited(principal, Permission.plan_generation_manage)
    with pytest.raises(ReadinessError) as exc:
        approve_plan_generation_authorization(session, manage_only, uuid.uuid4())
    assert exc.value.code == ReadinessErrorCode.forbidden.value


def test_plan_generation_purpose_is_exactly_plan_generation():
    # Apply/destroy/provider-mutation/state-mutation purposes are UNREPRESENTABLE — the sole member
    # is ``plan_generation``, so nothing else can ever be authorized.
    assert set(PlanGenerationPurpose) == {PlanGenerationPurpose.plan_generation}
    assert PlanGenerationPurpose.plan_generation.value == "plan_generation"


def test_readiness_read_model_requires_manage_and_reports_not_ready(session, principal, tmp_path):
    env = _make_env(session, principal, tmp_path)

    # The bounded read model is permission-protected; its refusal is folded to the closed,
    # redacted ``ReadinessError(forbidden)`` exactly like the lifecycle mutators.
    no_manage = _limited(principal)
    with pytest.raises(ReadinessError) as exc:
        get_plan_generation_readiness(session, no_manage, env.manifest.id)
    assert exc.value.code == ReadinessErrorCode.forbidden.value

    # With no dossier yet, the manifest is not ready and the read model resolves + executes nothing.
    status = get_plan_generation_readiness(session, principal, env.manifest.id)
    assert status["ready"] is False
    assert status["reasons"]  # a bounded, non-empty set of closed reason codes
    assert status["plan_generation_authorization_id"] is None
    # The read model pins the exact readiness-policy version it evaluated under.
    assert status["readiness_policy_version"] == PLAN_GENERATION_READINESS_POLICY_VERSION
