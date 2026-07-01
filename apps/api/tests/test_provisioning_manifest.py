"""Proofs #1-6 — provisioning manifest: no secrets, immutable, and generation guards."""

from __future__ import annotations

import copy

import pytest
from secp_api.enums import PlanStatus, TargetStatus
from secp_api.errors import ImmutableResourceError, ValidationFailedError
from secp_api.models import ExecutionTarget, ProvisioningManifest
from secp_api.services import manifests


def test_manifest_generation_ok(session, principal, provisioning_env):
    env = provisioning_env()
    manifest = manifests.generate_manifest(session, principal, env.plan.id)
    session.commit()
    assert manifest.content_hash.startswith("sha256:")
    assert manifest.deployment_plan_id == env.plan.id
    assert manifest.execution_target_id == env.target.id
    assert manifest.target_config_hash == env.target.config_hash
    assert manifest.validated_at is not None
    # topology bounded by policy + reservations
    assert manifest.content["teams"] == 2
    assert len(manifest.content["reservations"]) == 2
    assert manifest.content["requested_totals"]["vms"] == 4  # 2 teams x (attacker+web)
    assert manifest.content["requested_totals"]["containers"] == 2  # wazuh sensor per team


def test_manifest_contains_no_secrets(session, principal, provisioning_env):
    """Proof #1 — no secret or secret_ref anywhere in the manifest."""
    env = provisioning_env()
    manifest = manifests.generate_manifest(session, principal, env.plan.id)
    session.commit()
    blob = str(manifest.content).lower()
    for needle in ("secret", "password", "token", "credential", "env:secp_provider", "private_key"):
        assert needle not in blob


def test_manifest_immutable_after_generation(session, principal, provisioning_env):
    """Proof #2 — manifest content/hash cannot change after generation."""
    env = provisioning_env()
    manifest = manifests.generate_manifest(session, principal, env.plan.id)
    session.commit()
    manifest.content = {**manifest.content, "tampered": True}
    with pytest.raises(ImmutableResourceError):
        session.flush()


def test_unapproved_plan_blocks_generation(session, principal, provisioning_env):
    """Proof #3 — an unapproved plan cannot create a manifest."""
    env = provisioning_env(approve=False)
    # Plan is 'awaiting_approval', not approved.
    assert env.plan.status == PlanStatus.awaiting_approval
    with pytest.raises(ValidationFailedError):
        manifests.generate_manifest(session, principal, env.plan.id)


def test_target_hash_drift_blocks_generation(session, principal, provisioning_env):
    """Proof #4 — target config-hash drift blocks generation."""
    env = provisioning_env()
    # Simulate drift: the plan's pinned hash no longer matches the target.
    plan = env.plan
    plan.target_config_hash = "sha256:stale-hash"
    session.commit()
    with pytest.raises(ValidationFailedError):
        manifests.generate_manifest(session, principal, plan.id)


def test_disabled_target_blocks_generation(session, principal, provisioning_env):
    """Proof #5 — a disabled target blocks generation."""
    env = provisioning_env()
    target = session.get(ExecutionTarget, env.target.id)
    target.status = TargetStatus.disabled
    session.commit()
    with pytest.raises(ValidationFailedError):
        manifests.generate_manifest(session, principal, env.plan.id)


def test_missing_reservations_block_generation(session, principal, provisioning_env):
    """Proof #6 — missing/released reservations block generation."""
    from secp_api.models import NetworkReservation
    from secp_api.services import reservations as res_service

    env = provisioning_env()
    # Release one team's reservation.
    reservation = (
        session.query(NetworkReservation)
        .filter(NetworkReservation.exercise_id == env.exercise.id)
        .first()
    )
    res_service.release_reservation(session, principal, reservation.id)
    session.commit()
    with pytest.raises(ValidationFailedError):
        manifests.generate_manifest(session, principal, env.plan.id)


def test_cross_org_reservation_blocks_generation(
    session, principal, other_org_principal, provisioning_env
):
    """Proof #6 (cont.) — a cross-org reservation is refused."""
    from secp_api.models import NetworkReservation

    env = provisioning_env()
    reservation = (
        session.query(NetworkReservation)
        .filter(NetworkReservation.exercise_id == env.exercise.id)
        .first()
    )
    # Tamper the reservation to another org (simulates cross-org contamination).
    reservation.organization_id = other_org_principal.organization_id
    session.commit()
    with pytest.raises(ValidationFailedError):
        manifests.generate_manifest(session, principal, env.plan.id)


def test_out_of_policy_template_blocks_generation(session, principal, provisioning_env):
    """A desired image outside allowed_templates is refused (blast radius)."""
    scope = copy.deepcopy(_narrow_templates_scope())
    env = provisioning_env(scope=scope)
    with pytest.raises(ValidationFailedError):
        manifests.generate_manifest(session, principal, env.plan.id)


def test_simulator_plan_has_no_manifest(session, principal, running_exercise):
    """A simulator (non-target-bound) plan cannot generate a manifest."""
    from secp_api.services import planning

    exercise = running_exercise()
    plan = planning.latest_plan(session, principal, exercise.id)
    with pytest.raises(ValidationFailedError):
        manifests.generate_manifest(session, principal, plan.id)


def test_no_manifest_persisted_on_refusal(session, principal, provisioning_env):
    env = provisioning_env(approve=False)
    with pytest.raises(ValidationFailedError):
        manifests.generate_manifest(session, principal, env.plan.id)
    assert session.query(ProvisioningManifest).count() == 0


def _narrow_templates_scope() -> dict:
    return {
        "allowed_nodes": ["pve-node-1"],
        "allowed_storage": ["local-lvm"],
        "allowed_bridges": ["vmbr0"],
        "allowed_templates": ["only-this-one"],  # excludes kali/ubuntu/wazuh
        "vmid_range": {"start": 9000, "end": 9100},
        "max_teams": 4,
        "max_vms": 20,
        "max_containers": 10,
        "max_total_vcpu": 64,
        "max_total_memory_mb": 131072,
        "max_total_disk_gb": 2048,
        "allowed_cidr_reservations": ["10.60.0.0/16"],
        "external_connectivity": {"policy": "deny"},
    }
