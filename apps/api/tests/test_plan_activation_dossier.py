"""B1B-PR5A §3 — the reviewed activation-dossier lifecycle (ADR-022).

The dossier is the durable, human-reviewed record binding ONE real-plan operation to its
authoritative upstream facts. It is created DRAFT with every fact derived server-side (never the
fail-closed placeholder hash), gathers the complete closed review-evidence set, and is approved
under a DEDICATED permission — creating or approving it executes nothing, contacts nothing, and
mints no grant.

The service raises the closed, redacted :class:`ReadinessError`; a permission failure is folded to
the ``forbidden`` code (never a raw ``AuthorizationError``), so every refusal is asserted on it.
"""

from __future__ import annotations

import uuid

import pytest
from secp_api.auth import Principal
from secp_api.credential_binding import active_credential_binding
from secp_api.enums import (
    ActivationDossierEvidenceKind,
    ActivationDossierEvidenceStatus,
    ActivationDossierStatus,
    CredentialPurposeClass,
    Permission,
    ReadinessErrorCode,
)
from secp_api.errors import ReadinessError
from secp_api.plan_activation_contract import REQUIRED_DOSSIER_EVIDENCE_KINDS
from secp_api.readiness_contract import is_placeholder_dossier
from secp_api.services import targets
from secp_api.services.plan_activation import (
    approve_activation_dossier,
    create_activation_dossier,
    record_dossier_evidence,
    revoke_activation_dossier,
)
from tests._readiness_fixtures import build_readiness_env  # type: ignore[import-not-found]

PROVIDER_REF = "env:SECP_PROVIDER_SECRET__PROV"
STATE_REF = "env:SECP_PROVIDER_SECRET__STATE"


def _make_env(session, principal, tmp_path, *, with_state: bool = True):
    """The full authoritative chain (worker identity + durable attestation) plus BOTH dedicated
    operation credential references, so the target has an active provider AND state binding."""
    env = build_readiness_env(session, principal, toolchain_root=str(tmp_path))
    targets.rotate_target_operation_credential(
        session,
        principal,
        env.target.id,
        purpose_class=CredentialPurposeClass.provider_plan_read,
        secret_ref=PROVIDER_REF,
    )
    if with_state:
        targets.rotate_target_operation_credential(
            session,
            principal,
            env.target.id,
            purpose_class=CredentialPurposeClass.state_backend_plan,
            secret_ref=STATE_REF,
        )
    session.flush()
    return env


def _limited(principal, *perms: Permission) -> Principal:
    """A same-org principal holding exactly ``perms`` (for permission-separation proofs)."""
    return Principal(
        user_id=uuid.uuid4(),
        organization_id=principal.organization_id,
        email="limited@local.test",
        permissions=frozenset(perms),
    )


def _new_dossier(session, principal, manifest_id):
    return create_activation_dossier(
        session,
        principal,
        manifest_id=manifest_id,
        recovery_owner_proof="proof-recovery",
        emergency_stop_owner_proof="proof-estop",
    )


def _record_full_evidence(session, actor, dossier_id) -> None:
    for kind in REQUIRED_DOSSIER_EVIDENCE_KINDS:
        record_dossier_evidence(
            session,
            actor,
            dossier_id,
            kind=kind,
            status=ActivationDossierEvidenceStatus.verified,
            proof_id="proof-abc",
            issuer="reviewer-1",
        )


def test_create_produces_a_draft_with_a_real_hash_and_both_bindings(session, principal, tmp_path):
    env = _make_env(session, principal, tmp_path)
    dossier = _new_dossier(session, principal, env.manifest.id)

    assert dossier.status == ActivationDossierStatus.draft
    # The dossier hash is server-derived and can NEVER equal the fail-closed placeholder sentinel.
    assert dossier.dossier_hash.startswith("sha256:")
    assert not is_placeholder_dossier(dossier.dossier_hash)
    assert dossier.evidence_fingerprint == ""  # no evidence bound yet

    # BOTH operation-specific opaque bindings are pinned to the target's current active bindings.
    provider = active_credential_binding(
        session, env.target.id, CredentialPurposeClass.provider_plan_read
    )
    state = active_credential_binding(
        session, env.target.id, CredentialPurposeClass.state_backend_plan
    )
    assert dossier.provider_credential_binding_id == provider.id
    assert dossier.provider_credential_binding_version == provider.binding_version
    assert dossier.state_credential_binding_id == state.id
    assert dossier.state_credential_binding_version == state.binding_version
    assert provider.id != state.id


def test_create_requires_both_operation_credential_bindings(session, principal, tmp_path):
    # A target with the provider reference set but NO state-backend reference has no state binding,
    # so a real dossier cannot exist.
    env = _make_env(session, principal, tmp_path, with_state=False)
    assert (
        active_credential_binding(session, env.target.id, CredentialPurposeClass.state_backend_plan)
        is None
    )
    with pytest.raises(ReadinessError) as exc:
        _new_dossier(session, principal, env.manifest.id)
    assert exc.value.code == ReadinessErrorCode.binding_invalid.value


def test_complete_evidence_then_approve_succeeds(session, principal, tmp_path):
    env = _make_env(session, principal, tmp_path)
    dossier = _new_dossier(session, principal, env.manifest.id)
    _record_full_evidence(session, principal, dossier.id)

    approved = approve_activation_dossier(session, principal, dossier.id)
    assert approved.status == ActivationDossierStatus.approved
    assert approved.approved_by == principal.user_id
    assert approved.approved_at is not None
    # Approval binds the complete evidence fingerprint (a sha256 over the closed metadata set).
    assert approved.evidence_fingerprint.startswith("sha256:")


def test_approve_with_incomplete_evidence_is_refused(session, principal, tmp_path):
    env = _make_env(session, principal, tmp_path)
    dossier = _new_dossier(session, principal, env.manifest.id)
    # Only ONE of the required kinds is verified — the dossier is not approvable.
    one_kind = next(iter(ActivationDossierEvidenceKind))
    record_dossier_evidence(
        session,
        principal,
        dossier.id,
        kind=one_kind,
        status=ActivationDossierEvidenceStatus.verified,
        proof_id="proof-abc",
        issuer="reviewer-1",
    )
    with pytest.raises(ReadinessError) as exc:
        approve_activation_dossier(session, principal, dossier.id)
    assert exc.value.code == ReadinessErrorCode.evidence_incomplete.value

    session.refresh(dossier)
    assert dossier.status == ActivationDossierStatus.draft  # unchanged


def test_pending_evidence_does_not_count_as_complete(session, principal, tmp_path):
    # Every kind is present, but one is only ``pending`` (not ``verified``) — still incomplete.
    env = _make_env(session, principal, tmp_path)
    dossier = _new_dossier(session, principal, env.manifest.id)
    kinds = list(REQUIRED_DOSSIER_EVIDENCE_KINDS)
    for kind in kinds[:-1]:
        record_dossier_evidence(
            session,
            principal,
            dossier.id,
            kind=kind,
            status=ActivationDossierEvidenceStatus.verified,
            proof_id="proof-abc",
            issuer="reviewer-1",
        )
    record_dossier_evidence(
        session,
        principal,
        dossier.id,
        kind=kinds[-1],
        status=ActivationDossierEvidenceStatus.pending,
        proof_id="proof-abc",
        issuer="reviewer-1",
    )
    with pytest.raises(ReadinessError) as exc:
        approve_activation_dossier(session, principal, dossier.id)
    assert exc.value.code == ReadinessErrorCode.evidence_incomplete.value


def test_create_without_the_manage_permission_is_refused(session, principal, tmp_path):
    env = _make_env(session, principal, tmp_path)
    no_manage = _limited(principal, Permission.activation_dossier_approve)  # approve is NOT manage
    with pytest.raises(ReadinessError) as exc:
        _new_dossier(session, no_manage, env.manifest.id)
    assert exc.value.code == ReadinessErrorCode.forbidden.value


def test_approve_requires_the_dedicated_approve_permission(session, principal, tmp_path):
    # A holder of ``activation_dossier:manage`` can create + fully evidence a dossier, but the
    # DEDICATED ``activation_dossier:approve`` permission is required to approve it. Approval is
    # never inferable from manage.
    env = _make_env(session, principal, tmp_path)
    manage_only = _limited(principal, Permission.activation_dossier_manage)
    dossier = _new_dossier(session, manage_only, env.manifest.id)
    _record_full_evidence(session, manage_only, dossier.id)

    with pytest.raises(ReadinessError) as exc:
        approve_activation_dossier(session, manage_only, dossier.id)
    assert exc.value.code == ReadinessErrorCode.forbidden.value
    session.refresh(dossier)
    assert dossier.status == ActivationDossierStatus.draft

    # The dedicated-permission holder (the admin) approves the very same dossier.
    approved = approve_activation_dossier(session, principal, dossier.id)
    assert approved.status == ActivationDossierStatus.approved


def test_evidence_cannot_be_recorded_once_the_dossier_is_not_draft(session, principal, tmp_path):
    env = _make_env(session, principal, tmp_path)
    dossier = _new_dossier(session, principal, env.manifest.id)
    _record_full_evidence(session, principal, dossier.id)
    approve_activation_dossier(session, principal, dossier.id)

    with pytest.raises(ReadinessError) as exc:
        record_dossier_evidence(
            session,
            principal,
            dossier.id,
            kind=next(iter(ActivationDossierEvidenceKind)),
            status=ActivationDossierEvidenceStatus.verified,
            proof_id="proof-late",
            issuer="reviewer-1",
        )
    assert exc.value.code == ReadinessErrorCode.invalid_state.value


def test_revoke_moves_an_approved_dossier_to_revoked(session, principal, tmp_path):
    env = _make_env(session, principal, tmp_path)
    dossier = _new_dossier(session, principal, env.manifest.id)
    _record_full_evidence(session, principal, dossier.id)
    approve_activation_dossier(session, principal, dossier.id)

    revoked = revoke_activation_dossier(session, principal, dossier.id, reason_code="operator")
    assert revoked.status == ActivationDossierStatus.revoked
    assert revoked.revoked_by == principal.user_id
    assert revoked.revoked_at is not None
    assert revoked.revocation_reason_code == "operator"

    # A revoked dossier is terminal: it can no longer be revoked again.
    with pytest.raises(ReadinessError) as exc:
        revoke_activation_dossier(session, principal, dossier.id)
    assert exc.value.code == ReadinessErrorCode.invalid_state.value


def test_revocation_reason_only_when_revoking_orm(session, principal, tmp_path):
    # Amendment §4 (ORM/SQLite mirror of the PG trigger): revocation_reason_code becomes non-empty
    # ONLY on the transition to revoked. Setting it during a non-revoke transition raises.
    from secp_api.errors import ImmutableResourceError

    env = _make_env(session, principal, tmp_path)
    dossier = _new_dossier(session, principal, env.manifest.id)
    session.flush()

    dossier.revocation_reason_code = "operator"
    dossier.status = ActivationDossierStatus.expired  # NOT revoked
    with pytest.raises(ImmutableResourceError, match="only when revoking"):
        session.flush()
    session.rollback()


def test_revocation_reason_accepted_on_revoke_orm(session, principal, tmp_path):
    env = _make_env(session, principal, tmp_path)
    dossier = _new_dossier(session, principal, env.manifest.id)
    session.flush()

    dossier.revocation_reason_code = "security_review"
    dossier.status = ActivationDossierStatus.revoked
    session.flush()  # allowed: set together with the revoke transition
    assert dossier.revocation_reason_code == "security_review"
