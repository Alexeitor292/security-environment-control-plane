"""SECP-B4 §1 — durable deployment lifecycle + content-addressed plans + fail-closed drift.

Control-plane only; no worker/provider/SSH/OpenBao/transport code is imported and nothing real is
contacted. Proves the create -> plan -> submit -> approve -> deploy state machine, content-addressed
immutable plans, exact-plan approval binding, stale-approval refusal, and record immutability.
"""

from __future__ import annotations

import pytest
from secp_api.deployment_contract import deployment_operation_fingerprint
from secp_api.enums import (
    DeploymentOperationKind,
    IsolationModel,
    OnboardingMode,
    OnboardingStatus,
    StagingDeploymentStatus,
    TargetStatus,
)
from secp_api.errors import DomainError
from secp_api.immutability import ImmutableResourceError
from secp_api.models import (
    ExecutionTarget,
    StagingDeploymentApproval,
    StagingDeploymentOperation,
    StagingDeploymentPlan,
    TargetOnboarding,
)
from secp_api.services import staging_deployment as svc


def _target_with_active_onboarding(session, principal) -> ExecutionTarget:
    target = ExecutionTarget(
        organization_id=principal.organization_id,
        display_name="substrate",
        plugin_name="proxmox",
        config={"base_url": "placeholder", "verify_tls": True},
        config_hash="sha256:" + "ab" * 32,
        secret_ref="vault:secp/proxmox/target-1",
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
    return target


def _to_approved(session, principal):
    target = _target_with_active_onboarding(session, principal)
    dep = svc.create_deployment(session, principal, execution_target_id=target.id)
    svc.generate_plan(session, principal, dep.id)
    svc.submit_for_approval(session, principal, dep.id)
    svc.approve_deployment(session, principal, dep.id, expected_plan_hash=dep.plan_hash)
    return dep


def test_full_lifecycle_to_bootstrap_pending(session, principal):
    target = _target_with_active_onboarding(session, principal)
    dep = svc.create_deployment(session, principal, execution_target_id=target.id)
    assert dep.status == StagingDeploymentStatus.draft
    assert dep.ownership_label.startswith("secp-deploy-")

    svc.generate_plan(session, principal, dep.id)
    assert dep.status == StagingDeploymentStatus.planned
    assert dep.plan_hash.startswith("sha256:")
    plan = session.query(StagingDeploymentPlan).one()
    # The plan document lists only safe resource categories — never a secret/endpoint/host value.
    kinds = {r["kind"] for r in plan.plan_document["resources"]}
    assert (
        "isolated_bridge" in kinds and "control_plane_vm" in kinds and "nested_target_vm" in kinds
    )
    blob = str(plan.plan_document)
    for leak in ("password", "token", "http://", "https://", "BEGIN"):
        assert leak not in blob

    svc.submit_for_approval(session, principal, dep.id)
    assert dep.status == StagingDeploymentStatus.awaiting_approval

    svc.approve_deployment(session, principal, dep.id, expected_plan_hash=dep.plan_hash)
    assert dep.status == StagingDeploymentStatus.approved
    approval = session.query(StagingDeploymentApproval).one()
    assert approval.approved_plan_hash == dep.plan_hash
    assert approval.ownership_tag == plan.ownership_tag

    svc.submit_deployment(session, principal, dep.id)
    assert dep.status == StagingDeploymentStatus.bootstrap_pending
    op = session.query(StagingDeploymentOperation).one()
    assert op.operation_kind == DeploymentOperationKind.apply
    assert op.plan_hash == dep.approved_plan_hash


def test_plan_is_content_addressed_and_deterministic(session, principal):
    target = _target_with_active_onboarding(session, principal)
    dep = svc.create_deployment(session, principal, execution_target_id=target.id)
    svc.generate_plan(session, principal, dep.id)
    first_hash = dep.plan_hash
    # Re-planning the same draft/planned deployment yields a NEW version but the SAME content hash
    # would collide on the unique (deployment_id, plan_hash) — so it fails closed as a duplicate.
    with pytest.raises(DomainError):
        svc.generate_plan(session, principal, dep.id)
    assert dep.plan_hash == first_hash


def test_approval_requires_exact_plan_hash(session, principal):
    target = _target_with_active_onboarding(session, principal)
    dep = svc.create_deployment(session, principal, execution_target_id=target.id)
    svc.generate_plan(session, principal, dep.id)
    svc.submit_for_approval(session, principal, dep.id)
    with pytest.raises(DomainError):
        svc.approve_deployment(session, principal, dep.id, expected_plan_hash="sha256:" + "00" * 32)
    assert dep.status == StagingDeploymentStatus.awaiting_approval  # unchanged (fail closed)


def test_submit_requires_approved_state(session, principal):
    target = _target_with_active_onboarding(session, principal)
    dep = svc.create_deployment(session, principal, execution_target_id=target.id)
    with pytest.raises(DomainError):
        svc.submit_deployment(session, principal, dep.id)  # draft cannot deploy


def test_deploy_operation_is_idempotent(session, principal):
    dep = _to_approved(session, principal)
    svc.submit_deployment(session, principal, dep.id)
    # A duplicate enqueue for the same (deployment, kind, approved plan) resolves to the SAME row.
    fingerprint = deployment_operation_fingerprint(
        dep.id, DeploymentOperationKind.apply.value, dep.approved_plan_hash
    )
    op = svc._enqueue_operation(session, dep, principal, DeploymentOperationKind.apply)
    assert op.operation_fingerprint == fingerprint
    assert session.query(StagingDeploymentOperation).count() == 1


def test_plan_and_approval_records_are_immutable(session, principal):
    _to_approved(session, principal)
    plan = session.query(StagingDeploymentPlan).one()
    approval = session.query(StagingDeploymentApproval).one()
    plan.artifact_manifest_id = "tampered"
    with pytest.raises(ImmutableResourceError):
        session.flush()
    session.rollback()
    _to_approved(session, principal)
    approval = (
        session.query(StagingDeploymentApproval)
        .order_by(StagingDeploymentApproval.created_at.desc())
        .first()
    )
    approval.worker_identity_version = 999
    with pytest.raises(ImmutableResourceError):
        session.flush()
    session.rollback()


def test_deployment_service_imports_no_worker_or_provider_code():
    import ast
    from pathlib import Path

    src = Path("apps/api/secp_api/services/staging_deployment.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            assert not module.startswith("secp_worker"), f"API service imports {module}"
            for bad in ("httpx", "paramiko", "subprocess", "cryptography", "secp_plugin"):
                assert bad not in module, f"API service imports {module}"
