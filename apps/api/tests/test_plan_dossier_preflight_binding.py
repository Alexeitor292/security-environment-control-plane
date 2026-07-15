"""B1B-PR5A amendment §3 — the activation dossier binds the EXACT live eligibility preflight.

The dossier does not itself decide eligibility; it supplements ONE exact controlled-live
observation. On creation it pins that preflight's id + evidence hash and folds its full provenance
into the opaque dossier hash, so a NEW or changed live preflight (a different id/hash) invalidates
the dossier for current use: approval RE-VERIFIES the binding is still current, and the combined
readiness read model reports the drift. Approving the dossier decides nothing about eligibility and
makes nothing plan-ready — it only pins a preflight id/hash.

These proofs cover what can be set up hermetically with the shared readiness fixture (which builds a
current live-verified, eligible preflight). The service raises the closed, redacted
:class:`ReadinessError`; a stale/changed binding is folded to the ``binding_invalid`` code.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from secp_api.enums import (
    ActivationDossierEvidenceStatus,
    ActivationDossierStatus,
    CredentialPurposeClass,
    ReadinessErrorCode,
    ReadinessReason,
    WorkerIdentityMechanism,
    WorkerIdentityStatus,
)
from secp_api.errors import ReadinessError
from secp_api.models import WorkerIdentityRegistration, WorkflowRun
from secp_api.plan_activation_contract import REQUIRED_DOSSIER_EVIDENCE_KINDS
from secp_api.readiness_contract import is_placeholder_dossier
from secp_api.services import targets
from secp_api.services.eligibility import evaluate_live_eligibility
from secp_api.services.plan_activation import (
    active_plan_generation_authorization,
    approve_activation_dossier,
    create_activation_dossier,
    get_plan_generation_readiness,
    record_dossier_evidence,
    revoke_activation_dossier,
)
from sqlalchemy import func, select
from tests._readiness_fixtures import (  # type: ignore[import-not-found]
    NOW,
    VAULT_SECRET_REF,
    build_readiness_env,
    reauthorize_eligibility,
    single_node_scope,
    toolchain_fixture,
)

PROVIDER_REF = "env:SECP_PROVIDER_SECRET__PROV"
STATE_REF = "env:SECP_PROVIDER_SECRET__STATE"


def _rotate_dedicated_credentials(session, principal, target_id) -> None:
    """Set BOTH distinct dedicated operation credential references (the strict real-plan gate)."""
    for purpose, ref in (
        (CredentialPurposeClass.provider_plan_read, PROVIDER_REF),
        (CredentialPurposeClass.state_backend_plan, STATE_REF),
    ):
        targets.rotate_target_operation_credential(
            session, principal, target_id, purpose_class=purpose, secret_ref=ref
        )
    session.flush()


def _make_env(session, principal, tmp_path):
    """The full authoritative chain — including a current LIVE-VERIFIED, ELIGIBLE preflight — plus
    BOTH dedicated operation credential references, so a real dossier can bind."""
    env = build_readiness_env(session, principal, toolchain_root=str(tmp_path))
    _rotate_dedicated_credentials(session, principal, env.target.id)
    return env


def _chain_without_preflight(session, principal, tmp_path):
    """The complete pre-preflight authoritative chain (worker identity + durable attestation + both
    dedicated credentials) but with NO eligibility preflight ever run for the onboarding.

    It mirrors ``build_readiness_env`` up to — but excluding — the live-read authorization and the
    eligibility preflight, so fact resolution passes every earlier gate and reaches the live
    preflight binding, where there is no exact live observation to supplement.
    """
    from secp_worker.readiness.toolchain_attestation import run_toolchain_attestation
    from tests.conftest import build_lab_env  # type: ignore[import-not-found]

    layout, profile = toolchain_fixture(str(tmp_path))
    lab = build_lab_env(
        session,
        principal,
        toolchain=profile,
        scope=single_node_scope(),
        secret_ref=VAULT_SECRET_REF,
    )
    session.add(
        WorkerIdentityRegistration(
            organization_id=lab.target.organization_id,
            mechanism=WorkerIdentityMechanism.mtls_workload_identity,
            identity_label="readiness-worker",
            deployment_binding="readiness-deploy",
            verification_anchor_fingerprint="sha256:" + "b" * 64,
            identity_version=1,
            expiry=NOW + timedelta(days=1),
            status=WorkerIdentityStatus.approved,
        )
    )
    session.flush()
    result = run_toolchain_attestation(
        session, toolchain_profile_id=lab.toolchain.id, layout=layout, now=NOW
    )
    assert result.outcome == "attested", f"fixture attestation failed: {result}"
    _rotate_dedicated_credentials(session, principal, lab.target.id)
    return lab


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


def test_create_binds_the_exact_current_live_preflight(session, principal, tmp_path):
    env = _make_env(session, principal, tmp_path)
    live = evaluate_live_eligibility(session, env.onboarding, now=NOW)
    assert live is not None  # the fixture built a current live-verified, eligible preflight

    dossier = _new_dossier(session, principal, env.manifest.id)

    # The dossier PINS the exact current live preflight's id + evidence hash — it supplements one
    # exact observation, it does not itself decide eligibility.
    assert dossier.eligibility_preflight_id == env.eligibility_preflight.id
    assert dossier.eligibility_preflight_id == live.preflight.id
    assert dossier.eligibility_evidence_hash == live.preflight.evidence_hash
    # The dossier hash is server-derived (the preflight provenance is folded in) and can NEVER be
    # the fail-closed placeholder sentinel.
    assert dossier.dossier_hash.startswith("sha256:")
    assert not is_placeholder_dossier(dossier.dossier_hash)


def test_two_dossiers_same_preflight_bind_identical_binding(session, principal, tmp_path):
    env = _make_env(session, principal, tmp_path)
    first = _new_dossier(session, principal, env.manifest.id)
    # Only one active dossier may exist per manifest, so revoke the first before minting a second.
    revoke_activation_dossier(session, principal, first.id, reason_code="operator")
    second = _new_dossier(session, principal, env.manifest.id)

    # The live preflight never changed, so both dossiers pin the identical binding.
    assert first.eligibility_preflight_id == second.eligibility_preflight_id
    assert second.eligibility_preflight_id == env.eligibility_preflight.id
    assert first.eligibility_evidence_hash == second.eligibility_evidence_hash


def test_a_new_live_preflight_invalidates_the_dossier_binding(session, principal, tmp_path):
    env = _make_env(session, principal, tmp_path)
    dossier = _new_dossier(session, principal, env.manifest.id)
    bound_preflight_id = dossier.eligibility_preflight_id

    # Mint a NEWER live preflight for the SAME onboarding: a fresh live-read authorization version
    # re-runs the eligibility preflight, producing a new immutable evidence row (a higher-versioned,
    # now-current preflight with a distinct id + evidence hash).
    reauthorize_eligibility(session, env, version=2, now=NOW)
    assert env.eligibility_preflight.id != bound_preflight_id  # the current preflight changed

    # Approval RE-VERIFIES the binding is still current; the recomputed dossier hash now differs, so
    # the exact observation the dossier reviewed is no longer current.
    with pytest.raises(ReadinessError) as exc:
        approve_activation_dossier(session, principal, dossier.id)
    assert exc.value.code == ReadinessErrorCode.binding_invalid.value

    # The combined readiness read model reports the exact drift reason and is not ready.
    status = get_plan_generation_readiness(session, principal, env.manifest.id, now=NOW)
    assert status["ready"] is False
    assert ReadinessReason.activation_dossier_preflight_drift.value in status["reasons"]


def test_approval_alone_makes_no_eligibility_or_plan_ready(session, principal, tmp_path):
    env = _make_env(session, principal, tmp_path)
    dossier = _new_dossier(session, principal, env.manifest.id)
    _record_full_evidence(session, principal, dossier.id)

    runs_before = session.execute(select(func.count()).select_from(WorkflowRun)).scalar_one()
    approved = approve_activation_dossier(session, principal, dossier.id)

    assert approved.status == ActivationDossierStatus.approved
    # The dossier only PINS a preflight id/hash; it owns NO eligibility verdict of its own.
    assert approved.eligibility_preflight_id is not None
    assert approved.eligibility_evidence_hash is not None
    assert not hasattr(approved, "eligibility_outcome")

    # Approving the dossier mints NO plan-generation authorization and enqueues nothing.
    assert active_plan_generation_authorization(session, env.manifest.id) is None
    runs_after = session.execute(select(func.count()).select_from(WorkflowRun)).scalar_one()
    assert runs_after == runs_before

    # Dossier approval does not by itself make the manifest plan-ready: the SEPARATE plan-generation
    # authorization still does not exist.
    status = get_plan_generation_readiness(session, principal, env.manifest.id, now=NOW)
    assert status["ready"] is False
    assert status["plan_generation_authorization_id"] is None


def test_create_is_refused_when_there_is_no_live_preflight(session, principal, tmp_path):
    # A chain with every upstream fact resolved EXCEPT a live eligibility preflight for its
    # onboarding — so resolution reaches the preflight-binding gate with nothing to supplement.
    lab = _chain_without_preflight(session, principal, tmp_path)
    assert evaluate_live_eligibility(session, lab.onboarding, now=NOW) is None

    with pytest.raises(ReadinessError) as exc:
        _new_dossier(session, principal, lab.manifest.id)
    assert exc.value.code == ReadinessErrorCode.binding_invalid.value
