"""B1B-PR5B — durable execution lease (CAS + budget), attempt lifecycle, exactly-once result +
pending exact-hash approval, and the sealed-composition production refusal (ADR-022 §6/§8).

SQLite test FKs are off (conftest ``PRAGMA foreign_keys=OFF``), so the lease/result logic is
exercised against a hand-built :class:`ExecutionBinding` plus a real ``build_lab_env`` manifest +
toolchain profile (which the pending-approval wiring needs). The plan-only seal stays ``True``.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
import secp_api.models as _models
from secp_api.enums import ChangeSetApprovalStatus, PlanExecutionLeaseStatus
from secp_api.seed import bootstrap_dev
from secp_worker.plan_gen.lease import (
    ExecutionBinding,
    acquire_execution_lease,
    begin_attempt,
    fail_attempt,
    require_recovery,
)
from sqlalchemy import create_engine
from sqlalchemy.orm import Session as _Session
from tests.conftest import build_lab_env

NOW = datetime(2026, 7, 15, tzinfo=UTC)


@pytest.fixture
def session():
    """A plan-execution session on a plain in-memory SQLite engine with FK enforcement OFF.

    The lease/result binding facts are opaque ids (never real FKs at runtime — the worker re-derives
    every fact); this lets us exercise the CAS/budget/exactly-once logic against a hand-built
    :class:`ExecutionBinding` without reconstructing the entire ~15-record readiness chain.
    """
    engine = create_engine("sqlite://")
    _models.Base.metadata.create_all(engine)
    s = _Session(engine)
    try:
        yield s
    finally:
        s.rollback()
        s.close()


@pytest.fixture
def principal(session):
    p = bootstrap_dev(session)
    session.commit()
    return p


def _binding(env, **over) -> ExecutionBinding:
    h = lambda c: "sha256:" + c * 64  # noqa: E731
    base = dict(
        organization_id=env.target.organization_id,
        authorization_id=uuid.uuid4(),
        authorization_version=1,
        authorization_expiry=NOW + timedelta(hours=2),
        provisioning_manifest_id=env.manifest.id,
        provisioning_manifest_content_hash=env.manifest.content_hash,
        deployment_plan_id=env.plan.id,
        deployment_plan_content_hash=h("e"),
        environment_version_id=uuid.uuid4(),
        environment_version_content_hash=h("d"),
        execution_target_id=env.target.id,
        target_config_hash=h("f"),
        target_onboarding_id=uuid.uuid4(),
        onboarding_boundary_hash=h("1"),
        activation_dossier_id=uuid.uuid4(),
        activation_dossier_hash=h("a"),
        activation_dossier_revision=1,
        activation_dossier_expiry=NOW + timedelta(hours=3),
        eligibility_preflight_id=uuid.uuid4(),
        eligibility_evidence_hash=h("2"),
        toolchain_profile_id=env.toolchain.id,
        toolchain_profile_hash=env.toolchain.content_hash,
        toolchain_attestation_id=uuid.uuid4(),
        toolchain_attestation_hash=h("4"),
        toolchain_attestation_policy_version="secp-002b-1b/toolchain-attest/v1",
        worker_identity_registration_id=uuid.uuid4(),
        worker_identity_version=1,
        provider_credential_binding_id=uuid.uuid4(),
        provider_credential_binding_version=1,
        state_credential_binding_id=uuid.uuid4(),
        state_credential_binding_version=1,
        remote_state_readiness_id=uuid.uuid4(),
        remote_state_evidence_hash=h("9"),
        plan_secret_readiness_id=uuid.uuid4(),
        plan_secret_evidence_hash=h("0"),
        state_namespace_hash=h("b"),
        operation_fingerprint=h("c"),
    )
    base.update(over)
    return ExecutionBinding(**base)


# --- the CAS lease + budget ----------------------------------------------------------------------


def test_only_one_active_lease_per_operation_fingerprint(session, principal):
    env = build_lab_env(session, principal)
    binding = _binding(env)
    lease, reason = acquire_execution_lease(session, binding, lease_owner="w1", now=NOW)
    assert lease is not None and reason is None
    assert lease.status == PlanExecutionLeaseStatus.active
    # A second acquisition for the SAME operation fingerprint is refused (CAS contention).
    second, reason2 = acquire_execution_lease(session, binding, lease_owner="w2", now=NOW)
    assert second is None
    assert reason2 == "lease_contended"


def test_budget_is_shared_and_never_reset_across_leases(session, principal):
    env = build_lab_env(session, principal)
    binding = _binding(env)
    lease, _ = acquire_execution_lease(session, binding, lease_owner="w", now=NOW)
    # Exhaust the shared budget of 3 across this lease (each begin_attempt increments it).
    attempt = None
    for _ in range(3):
        attempt = begin_attempt(session, lease, binding, now=NOW)
    assert lease.attempts_used == 3
    fail_attempt(session, lease, attempt, reason_code="plan_failed", now=NOW)
    assert lease.status == PlanExecutionLeaseStatus.expired
    # A new lease acquisition for the same operation is refused: budget exhausted (not reset).
    lease2, reason = acquire_execution_lease(session, binding, lease_owner="w2", now=NOW)
    assert lease2 is None
    assert reason == "lease_budget_exhausted"


def test_recovery_required_is_terminal_and_records_a_bounded_reason(session, principal):
    env = build_lab_env(session, principal)
    binding = _binding(env)
    lease, _ = acquire_execution_lease(session, binding, lease_owner="w", now=NOW)
    attempt = begin_attempt(session, lease, binding, now=NOW)
    require_recovery(session, lease, attempt, reason_code="cleanup_residue", now=NOW)
    assert lease.status == PlanExecutionLeaseStatus.recovery_required
    assert lease.recovery_reason_code == "cleanup_residue"
    # Item 5: a terminally recovery-required lease is NON-RETRYABLE. A fresh acquisition for the
    # exact operation is refused (not silently re-leased) until a new authorization version mints a
    # distinct operation key — even though only 1 attempt was used, so budget is not the blocker.
    lease2, reason = acquire_execution_lease(session, binding, lease_owner="w2", now=NOW)
    assert lease2 is None
    assert reason == "lease_recovery_required"


def test_attempt_lifecycle_enum_is_the_exact_expanded_closed_set():
    """B1B-PR5B drift guard: the attempt lifecycle is EXACTLY this closed expanded set.

    PR5A had only ``requested``/``refused``; PR5B added the execution-phase markers. This is the
    authoritative assertion of the closed set (the PR5A refusal-path test no longer claims it).
    """
    from secp_api.enums import PlanGenerationAttemptStatus

    assert {s.value for s in PlanGenerationAttemptStatus} == {
        "requested",
        "running",
        "completed",
        "refused",
        "failed",
        "recovery_required",
    }


# --- the durable result + pending exact-hash approval --------------------------------------------


def _controlled_live_capability(
    binding, *, classification="controlled_live", lease=None, attempt=None
):
    from secp_api.plan_activation_contract import PLAN_ONLY_CAPABILITY_CONTRACT_VERSION
    from secp_worker.plan_gen.capability import PlanOnlyActivation, issue_plan_only_capability
    from secp_worker.plan_gen.controlled_live import (
        CONTROLLED_LIVE_PROVIDER_SOURCE,
        CONTROLLED_LIVE_RENDERER_VERSION,
        controlled_live_renderer_implementation_digest,
    )
    from secp_worker.plan_gen.process_boundary import (
        PLAN_ONLY_EXECUTOR_IMPLEMENTATION_ID,
        plan_only_executor_implementation_digest,
    )

    h = lambda c: "sha256:" + c * 64  # noqa: E731
    activation = PlanOnlyActivation(
        organization_id=binding.organization_id,
        plan_generation_authorization_id=binding.authorization_id,
        authorization_version=binding.authorization_version,
        authorization_expiry=binding.authorization_expiry,
        operation_fingerprint=binding.operation_fingerprint,
        plan_only_capability_contract_version=PLAN_ONLY_CAPABILITY_CONTRACT_VERSION,
        classification=classification,
        expires_at=NOW + timedelta(minutes=10),
        environment_version_id=binding.environment_version_id,
        environment_version_content_hash=binding.environment_version_content_hash,
        deployment_plan_id=binding.deployment_plan_id,
        deployment_plan_content_hash=binding.deployment_plan_content_hash,
        provisioning_manifest_id=binding.provisioning_manifest_id,
        provisioning_manifest_content_hash=binding.provisioning_manifest_content_hash,
        execution_target_id=binding.execution_target_id,
        target_config_hash=binding.target_config_hash,
        target_onboarding_id=binding.target_onboarding_id,
        onboarding_boundary_hash=binding.onboarding_boundary_hash,
        eligibility_preflight_id=binding.eligibility_preflight_id,
        eligibility_evidence_hash=binding.eligibility_evidence_hash,
        toolchain_profile_id=binding.toolchain_profile_id,
        toolchain_profile_hash=binding.toolchain_profile_hash,
        toolchain_attestation_id=binding.toolchain_attestation_id,
        toolchain_attestation_hash=binding.toolchain_attestation_hash,
        fresh_attestation_evidence_hash=h("5"),
        provider_source=CONTROLLED_LIVE_PROVIDER_SOURCE,
        provider_version="0.80.0",
        provider_lockfile_hash=h("6"),
        provider_mirror_identity=h("7"),
        module_bundle_hash=h("8"),
        renderer_version=CONTROLLED_LIVE_RENDERER_VERSION,
        activation_dossier_id=binding.activation_dossier_id,
        activation_dossier_hash=binding.activation_dossier_hash,
        activation_dossier_revision=binding.activation_dossier_revision,
        activation_dossier_expiry=binding.activation_dossier_expiry,
        provider_credential_binding_id=binding.provider_credential_binding_id,
        provider_credential_binding_version=binding.provider_credential_binding_version,
        state_credential_binding_id=binding.state_credential_binding_id,
        state_credential_binding_version=binding.state_credential_binding_version,
        remote_state_readiness_id=binding.remote_state_readiness_id,
        remote_state_evidence_hash=binding.remote_state_evidence_hash,
        plan_secret_readiness_id=binding.plan_secret_readiness_id,
        plan_secret_evidence_hash=binding.plan_secret_evidence_hash,
        worker_identity_registration_id=binding.worker_identity_registration_id,
        worker_identity_version=binding.worker_identity_version,
        # Item 10: the capability is bound to the EXACT running lease/attempt, so the result-time
        # provenance comparison (lease/attempt/number) agrees. A random id would be refused.
        execution_lease_id=lease.id if lease is not None else uuid.uuid4(),
        attempt_id=attempt.id if attempt is not None else uuid.uuid4(),
        attempt_number=lease.attempts_used if lease is not None else 1,
        process_implementation_id=PLAN_ONLY_EXECUTOR_IMPLEMENTATION_ID,
        process_implementation_digest=plan_only_executor_implementation_digest(),
        renderer_module_id=CONTROLLED_LIVE_RENDERER_VERSION,
        renderer_module_digest=controlled_live_renderer_implementation_digest(),
    )
    return issue_plan_only_capability(
        activation,
        now=NOW,
        expected_process_digest=plan_only_executor_implementation_digest(),
        expected_renderer_digest=controlled_live_renderer_implementation_digest(),
    )


def _plan_result(binding):
    from secp_worker.plan_gen.change_policy import PLAN_CHANGE_POLICY_VERSION
    from secp_worker.plan_gen.plan_runner import PlanOnlyPlanResult

    change_set = {
        "change_set_version": "secp-002b-1a/change-set/v2",
        # Item 10: the safe canonical provenance is folded INTO the change set before hashing; the
        # result-time check re-compares the operation fingerprint + change-policy version.
        "provenance": {
            "operation_fingerprint": binding.operation_fingerprint,
            "change_policy_version": PLAN_CHANGE_POLICY_VERSION,
        },
        "resources": [
            {
                "address": "proxmox_virtual_environment_container.a",
                "mode": "managed",
                "type": "proxmox_virtual_environment_container",
                "name": "a",
                "provider": "registry.terraform.io/bpg/proxmox",
                "actions": ["create"],
                "replace": False,
            }
        ],
        "summary": {"count": 1, "by_action": {"create": 1}},
    }
    return PlanOnlyPlanResult(
        change_set=change_set,
        change_set_hash="sha256:" + "cs" * 32,
        workspace_hash="sha256:" + "ws" * 32,
        created=1,
        resource_types=("proxmox_virtual_environment_container",),
    )


def _record(session, env, binding, *, classification="controlled_live"):
    from secp_worker.plan_gen.lease import acquire_execution_lease, begin_attempt
    from secp_worker.plan_gen.result import record_plan_generation_result

    lease, _ = acquire_execution_lease(session, binding, lease_owner="w", now=NOW)
    attempt = begin_attempt(session, lease, binding, now=NOW)
    capability = _controlled_live_capability(
        binding, classification=classification, lease=lease, attempt=attempt
    )
    return (
        record_plan_generation_result(
            session,
            binding=binding,
            capability=capability,
            plan_result=_plan_result(binding),
            lease=lease,
            attempt=attempt,
            manifest=env.manifest,
            toolchain_profile=env.toolchain,
            now=NOW,
        ),
        lease,
        attempt,
    )


def test_controlled_live_result_persists_and_creates_a_pending_apply_approval(session, principal):
    env = build_lab_env(session, principal)
    binding = _binding(env)
    result, lease, attempt = _record(session, env, binding)
    assert result.change_set_hash == "sha256:" + "cs" * 32
    assert result.change_summary == {
        "created": 1,
        "resource_types": ["proxmox_virtual_environment_container"],
    }
    # A pending, apply-authorizing, human-only approval exists for the EXACT hash — never approved.
    from secp_api.models import ProvisioningChangeSetApproval

    approval = session.get(ProvisioningChangeSetApproval, result.change_set_approval_id)
    assert approval is not None
    assert approval.status == ChangeSetApprovalStatus.pending  # NEVER auto-approved
    assert approval.change_set_hash == result.change_set_hash
    assert approval.authorizes_kind.value == "apply"
    # The lease is consumed + the attempt completed only AFTER the result was committed.
    assert lease.status == PlanExecutionLeaseStatus.consumed
    assert lease.result_id == result.id
    assert attempt.status.value == "completed"


def test_result_is_exactly_once_replay_returns_existing(session, principal):
    env = build_lab_env(session, principal)
    binding = _binding(env)
    r1, _, _ = _record(session, env, binding)
    from secp_worker.plan_gen.lease import existing_successful_result

    assert existing_successful_result(session, binding).id == r1.id
    # A replay short-circuit returns the existing result (a duplicate is refused via the unique).
    from secp_worker.plan_gen.result import record_plan_generation_result

    lease2, _ = acquire_execution_lease(session, binding, lease_owner="w2", now=NOW)
    attempt2 = begin_attempt(session, lease2, binding, now=NOW)
    r2 = record_plan_generation_result(
        session,
        binding=binding,
        capability=_controlled_live_capability(binding, lease=lease2, attempt=attempt2),
        plan_result=_plan_result(binding),
        lease=lease2,
        attempt=attempt2,
        manifest=env.manifest,
        toolchain_profile=env.toolchain,
        now=NOW,
    )
    assert r2.id == r1.id  # exactly-once


def test_test_only_capability_cannot_produce_a_controlled_live_result(session, principal):
    env = build_lab_env(session, principal)
    binding = _binding(env)
    from secp_worker.plan_gen.result import PlanResultRefused

    with pytest.raises(PlanResultRefused, match="test_only"):
        _record(session, env, binding, classification="test_only")


# --- the production orchestration still refuses with the plan-only seal FALSE (nothing executes) --


def test_run_plan_generation_still_refuses_in_production_with_seal_false(session, principal):
    """Even with ``_PLAN_ONLY_PROCESS_SEALED`` now False, the shipped default composition is
    disabled, so ordinary production refuses and creates NO lease, attempt, result, or change-set
    approval — before any executor construction or subprocess."""
    env = build_lab_env(session, principal)
    from secp_worker.plan_gen.orchestration import run_plan_generation

    result = run_plan_generation(session, manifest_id=env.manifest.id, now=NOW)
    assert result.outcome == "refused"
    from secp_api.models import ProvisioningChangeSetApproval
    from secp_api.plan_activation_models import (
        PlanGenerationExecutionLease,
        RealPlanGenerationAttempt,
        RealPlanGenerationResult,
    )

    assert session.query(PlanGenerationExecutionLease).count() == 0
    assert session.query(RealPlanGenerationResult).count() == 0
    # No RUNNING/COMPLETED attempt and no pending apply-approval were created.
    running = [
        a
        for a in session.query(RealPlanGenerationAttempt).all()
        if a.status.value not in ("refused",)
    ]
    assert running == []
    assert session.query(ProvisioningChangeSetApproval).count() == 0
    # The dedicated plan-only seal is now False; both generic B1-A subprocess seals remain True.
    from secp_worker.plan_gen import process_boundary as pb
    from secp_worker.provisioning import activation as act
    from secp_worker.provisioning import process_executor as pe

    assert pb._PLAN_ONLY_PROCESS_SEALED is False
    assert pe._B1A_SUBPROCESS_SEALED is True
    assert act._B1A_SUBPROCESS_SEALED is True
