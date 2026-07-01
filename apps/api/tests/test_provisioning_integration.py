"""Proofs #12, #13, #14 — safe integration: gate, worker execution, audit records,
simulator unchanged, and idempotent retries."""

from __future__ import annotations

import uuid

import pytest
from secp_api.config import Settings
from secp_api.enums import AuditAction, ProvisioningOperationKind, ProvisioningStatus
from secp_api.errors import ProvisioningRefusedError
from secp_api.models import AuditEvent, ProvisioningManifest, ProvisioningOperation
from secp_api.services import manifests, provisioning
from secp_worker.provisioning import FakeOpenTofuRunner
from secp_worker.provisioning.execution import run_provisioning

GATE_ON = Settings(app_env="test", enable_fake_provisioning=True, workflow_dispatch_mode="inline")
GATE_OFF = Settings(app_env="test", enable_fake_provisioning=False, workflow_dispatch_mode="inline")


def _manifest_and_op(session, principal, provisioning_env):
    env = provisioning_env()
    manifest = manifests.generate_manifest(session, principal, env.plan.id)
    session.commit()
    op = provisioning.operation_for_manifest(session, manifest.id)
    return manifest, op


def _actions(session):
    return {e.action for e in session.query(AuditEvent).all()}


def test_target_bound_refused_when_gate_disabled(session, principal, provisioning_env):
    """Proof #13 — without the explicit gate the fake runner is refused (audited)."""
    _manifest, op = _manifest_and_op(session, principal, provisioning_env)
    runner = FakeOpenTofuRunner()
    with pytest.raises(ProvisioningRefusedError):
        run_provisioning(
            session, op.id, ProvisioningOperationKind.dry_run, runner, settings=GATE_OFF
        )
    refreshed = session.get(ProvisioningOperation, op.id)
    assert refreshed.status == ProvisioningStatus.failed
    assert AuditAction.provisioning_refused.value in _actions(session)


def test_full_fake_lifecycle_is_audited(session, principal, provisioning_env):
    """Proof #14 — dry-run, apply, destroy create auditable records; #8/#9 idempotent."""
    manifest, op = _manifest_and_op(session, principal, provisioning_env)
    runner = FakeOpenTofuRunner()

    run_provisioning(session, op.id, ProvisioningOperationKind.dry_run, runner, settings=GATE_ON)
    session.commit()
    assert session.get(ProvisioningOperation, op.id).status == ProvisioningStatus.dry_run_completed
    # 2 teams x (1 network + 3 nodes: attacker vm, web-server vm, wazuh-sensor container).
    assert op.result["summary"]["create"] == 8
    assert op.result["summary"]["by_type"] == {"network": 2, "vm": 4, "container": 2}

    run_provisioning(session, op.id, ProvisioningOperationKind.apply, runner, settings=GATE_ON)
    session.commit()
    assert session.get(ProvisioningOperation, op.id).status == ProvisioningStatus.applied

    # Idempotent retry of apply -> no-op, still applied.
    run_provisioning(session, op.id, ProvisioningOperationKind.apply, runner, settings=GATE_ON)
    session.commit()
    reapplied = session.get(ProvisioningOperation, op.id)
    assert reapplied.status == ProvisioningStatus.applied
    assert reapplied.result.get("idempotent_noop") is True

    run_provisioning(session, op.id, ProvisioningOperationKind.destroy, runner, settings=GATE_ON)
    session.commit()
    assert session.get(ProvisioningOperation, op.id).status == ProvisioningStatus.destroyed

    actions = _actions(session)
    for expected in (
        AuditAction.manifest_generated,
        AuditAction.manifest_validated,
        AuditAction.provisioning_dry_run_completed,
        AuditAction.provisioning_apply_started,
        AuditAction.provisioning_applied,
        AuditAction.provisioning_destroy_queued,
        AuditAction.provisioning_destroyed,
    ):
        assert expected.value in actions


def test_worker_refuses_unknown_operation(session, principal):
    """Worker never runs without a committed operation record."""
    runner = FakeOpenTofuRunner()
    with pytest.raises(ProvisioningRefusedError):
        run_provisioning(
            session, uuid.uuid4(), ProvisioningOperationKind.apply, runner, settings=GATE_ON
        )


def test_operation_result_has_no_secret(session, principal, provisioning_env):
    manifest, op = _manifest_and_op(session, principal, provisioning_env)
    runner = FakeOpenTofuRunner()
    run_provisioning(session, op.id, ProvisioningOperationKind.apply, runner, settings=GATE_ON)
    session.commit()
    blob = str(op.result).lower()
    for needle in ("secret", "token", "password", "credential"):
        assert needle not in blob


def test_simulator_deployment_creates_no_provisioning_records(session, principal, running_exercise):
    """Proof #12 — simulator lifecycle is unchanged; no manifests/operations."""
    running_exercise()
    session.commit()
    assert session.query(ProvisioningManifest).count() == 0
    assert session.query(ProvisioningOperation).count() == 0


def test_production_refuses_fake_provisioning_gate():
    """The fake-runner gate can never be enabled in production."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Settings(
            app_env="production",
            enable_fake_provisioning=True,
            auth_dev_mode=False,
            workflow_dispatch_mode="temporal",
        )
