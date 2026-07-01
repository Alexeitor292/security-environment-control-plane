"""Proofs #1-6 — provisioning manifest: no secrets, immutable, and generation guards."""

from __future__ import annotations

import copy
import uuid

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
    from secp_api.models import DeploymentPlan

    env = provisioning_env()
    # Simulate out-of-band drift via direct DB update (ORM would now raise ImmutableResourceError).
    session.execute(
        DeploymentPlan.__table__.update()
        .where(DeploymentPlan.__table__.c.id == env.plan.id)
        .values(target_config_hash="sha256:stale-hash")
    )
    session.commit()
    session.expire_all()
    with pytest.raises(ValidationFailedError):
        manifests.generate_manifest(session, principal, env.plan.id)


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
        "node_sizing": {
            "only-this-one": {"vcpu": 1, "memory_mb": 512, "disk_gb": 5},
        },
    }


# ---------------------------------------------------------------------------
# Proofs #7 – resource / VM-ID enforcement
# ---------------------------------------------------------------------------


def _base_scope():
    """A tight scope that the VALID_DEFINITION topology easily fits within."""
    import copy

    from apps.api.tests.conftest import VALID_PROVISIONING_SCOPE  # type: ignore[import]

    return copy.deepcopy(VALID_PROVISIONING_SCOPE)


def _tight_scope(**overrides) -> dict:
    """Build a provisioning scope from the valid defaults with overrides applied."""
    import copy

    from tests.conftest import VALID_PROVISIONING_SCOPE  # accessed via pytest path

    scope = copy.deepcopy(VALID_PROVISIONING_SCOPE)
    scope.update(overrides)
    return scope


def test_manifest_nodes_have_vmid_and_sizing(session, principal, provisioning_env):
    """Every node in the manifest topology must have vmid, vcpu, memory_mb, disk_gb."""
    env = provisioning_env()
    manifest = manifests.generate_manifest(session, principal, env.plan.id)
    session.commit()

    for team in manifest.content["topology"]:
        for node in team["nodes"]:
            assert "vmid" in node, f"node {node['ref']} missing vmid"
            assert "vcpu" in node, f"node {node['ref']} missing vcpu"
            assert "memory_mb" in node, f"node {node['ref']} missing memory_mb"
            assert "disk_gb" in node, f"node {node['ref']} missing disk_gb"
            assert node["vcpu"] >= 1
            assert node["memory_mb"] >= 128
            assert node["disk_gb"] >= 1


def test_vmids_are_within_range_and_deterministic(session, principal, provisioning_env):
    """All assigned vmids must be within vmid_range and deterministic (no overlap)."""
    env = provisioning_env()
    manifest = manifests.generate_manifest(session, principal, env.plan.id)
    session.commit()

    vmid_range = manifest.content["scope_policy"]["vmid_range"]
    vmids = []
    for team in manifest.content["topology"]:
        for node in team["nodes"]:
            vmid = node["vmid"]
            assert vmid_range["start"] <= vmid <= vmid_range["end"], (
                f"vmid {vmid} is outside vmid_range [{vmid_range['start']}, {vmid_range['end']}]"
            )
            vmids.append(vmid)
    # No duplicate vmids.
    assert len(vmids) == len(set(vmids)), "duplicate vmids assigned"


def test_vcpu_cap_exceeded_blocks_generation(session, principal, provisioning_env):
    """Aggregate vCPU exceeding max_total_vcpu is refused at manifest generation."""
    # With 2 teams x 3 nodes: attacker(2)+web(1)+wazuh(1) = 4 vcpu per team = 8 total.
    # Set the cap below 8 to trigger the limit.
    from tests.conftest import VALID_PROVISIONING_SCOPE

    scope = copy.deepcopy(VALID_PROVISIONING_SCOPE)
    scope["max_total_vcpu"] = 3  # below 8
    env = provisioning_env(scope=scope)
    with pytest.raises(ValidationFailedError, match="blast-radius"):
        manifests.generate_manifest(session, principal, env.plan.id)


def test_memory_cap_exceeded_blocks_generation(session, principal, provisioning_env):
    """Aggregate memory_mb exceeding max_total_memory_mb is refused."""
    from tests.conftest import VALID_PROVISIONING_SCOPE

    # 2 teams × (4096 + 2048 + 1024) = 14336 MB total
    scope = copy.deepcopy(VALID_PROVISIONING_SCOPE)
    scope["max_total_memory_mb"] = 1000  # below 14336
    env = provisioning_env(scope=scope)
    with pytest.raises(ValidationFailedError, match="blast-radius"):
        manifests.generate_manifest(session, principal, env.plan.id)


def test_disk_cap_exceeded_blocks_generation(session, principal, provisioning_env):
    """Aggregate disk_gb exceeding max_total_disk_gb is refused."""
    from tests.conftest import VALID_PROVISIONING_SCOPE

    # 2 teams × (40 + 20 + 10) = 140 GB total
    scope = copy.deepcopy(VALID_PROVISIONING_SCOPE)
    scope["max_total_disk_gb"] = 10  # below 140
    env = provisioning_env(scope=scope)
    with pytest.raises(ValidationFailedError, match="blast-radius"):
        manifests.generate_manifest(session, principal, env.plan.id)


def test_vmid_range_exhausted_blocks_generation(session, principal, provisioning_env):
    """A vmid_range too narrow to assign one vmid per node is refused."""
    from tests.conftest import VALID_PROVISIONING_SCOPE

    # 2 teams × 3 nodes = 6 nodes need vmids 9000–9005; range 9000–9002 only fits 3.
    scope = copy.deepcopy(VALID_PROVISIONING_SCOPE)
    scope["vmid_range"] = {"start": 9000, "end": 9002}
    env = provisioning_env(scope=scope)
    with pytest.raises(ValidationFailedError, match="exhausted"):
        manifests.generate_manifest(session, principal, env.plan.id)


def test_missing_node_sizing_fails_closed(session, principal, provisioning_env):
    """If node_sizing is missing for any image, generation fails closed (no hidden default)."""
    from tests.conftest import VALID_PROVISIONING_SCOPE

    scope = copy.deepcopy(VALID_PROVISIONING_SCOPE)
    # Remove one image from node_sizing — this must fail.
    del scope["node_sizing"]["kali-linux"]
    env = provisioning_env(scope=scope)
    with pytest.raises(ValidationFailedError, match="node_sizing"):
        manifests.generate_manifest(session, principal, env.plan.id)


# ---------------------------------------------------------------------------
# Proofs #8 — provisioning scope-policy hash binding
# ---------------------------------------------------------------------------


def test_plan_carries_scope_policy_hash(session, principal, provisioning_env):
    """A target-bound plan must carry a non-null scope-policy hash at generation."""
    from secp_api.provisioning_scope import provisioning_scope_policy_hash

    env = provisioning_env()
    assert env.plan.target_scope_policy_hash is not None
    assert env.plan.target_scope_policy_hash.startswith("sha256:")
    expected = provisioning_scope_policy_hash(env.target.scope_policy)
    assert env.plan.target_scope_policy_hash == expected


def test_manifest_binds_scope_policy_hash(session, principal, provisioning_env):
    """A generated manifest must carry the scope-policy hash and agree with its plan."""
    from secp_api.provisioning_scope import provisioning_scope_policy_hash

    env = provisioning_env()
    manifest = manifests.generate_manifest(session, principal, env.plan.id)
    session.commit()

    # Plan and manifest must agree.
    assert manifest.target_scope_policy_hash == env.plan.target_scope_policy_hash
    # Hash must be in the manifest content (self-documenting).
    assert manifest.content.get("target_scope_policy_hash") == env.plan.target_scope_policy_hash
    # Hash must match the current target scope policy.
    expected = provisioning_scope_policy_hash(env.target.scope_policy)
    assert manifest.target_scope_policy_hash == expected


def test_scope_policy_drift_after_plan_approval_blocks_generation(
    session, principal, provisioning_env
):
    """Broadening scope_policy after plan approval must block manifest generation."""
    env = provisioning_env()  # plan approved with original policy
    original_hash = env.plan.target_scope_policy_hash

    # Broaden the scope policy on the target AFTER approval.
    drifted = copy.deepcopy(env.target.scope_policy)
    drifted["provisioning"]["max_vms"] = 9999  # broader than approved
    session.execute(
        ExecutionTarget.__table__.update()
        .where(ExecutionTarget.__table__.c.id == env.target.id)
        .values(scope_policy=drifted)
    )
    session.commit()
    session.expire_all()

    with pytest.raises(ValidationFailedError, match="scope-policy hash mismatch"):
        manifests.generate_manifest(session, principal, env.plan.id)
    # No manifest must have been persisted.
    assert session.query(ProvisioningManifest).count() == 0
    # The plan's stored hash must not have changed (it's on the plan, not the target).
    session.expire_all()
    refreshed_plan = session.get(type(env.plan), env.plan.id)
    assert refreshed_plan.target_scope_policy_hash == original_hash


def test_new_plan_under_new_policy_allows_generation(session, principal, provisioning_env):
    """A new plan generated under the updated policy allows manifest generation.

    Scenario: policy changes after approval → old plan refused, new exercise + plan
    under the updated policy succeeds.
    """
    from secp_api.services import catalog, exercises, planning, reservations
    from tests.conftest import VALID_DEFINITION

    env = provisioning_env()  # plan approved under policy A

    # Change the scope policy on the target to policy B.
    policy_b = copy.deepcopy(env.target.scope_policy)
    policy_b["provisioning"]["max_vms"] = 9999
    session.execute(
        ExecutionTarget.__table__.update()
        .where(ExecutionTarget.__table__.c.id == env.target.id)
        .values(scope_policy=policy_b)
    )
    session.commit()
    session.expire_all()

    # Old plan (policy A hash) is refused under policy B.
    with pytest.raises(ValidationFailedError, match="scope-policy hash mismatch"):
        manifests.generate_manifest(session, principal, env.plan.id)

    # The scope change also invalidates the policy-A onboarding approval (SECP-002B-1B-0);
    # re-onboard the target under policy B before generating a new plan.
    from secp_api.services import onboarding as onb
    from tests.conftest import onboard_and_activate

    old_ob = onb.active_onboarding_for_target(session, env.target.id)
    onb.retire_onboarding(session, principal, old_ob.id)
    session.commit()
    onboard_and_activate(session, principal, session.get(ExecutionTarget, env.target.id))
    session.commit()

    # Create a fresh exercise on the same target — it will capture policy B's hash.
    tmpl = catalog.create_template(
        session, principal, name="Prov2", slug=f"prov2-{uuid.uuid4().hex[:8]}"
    )
    ver = catalog.create_version(
        session, principal, template_id=tmpl.id, definition=VALID_DEFINITION
    )
    ex2 = exercises.create_exercise(
        session,
        principal,
        template_id=tmpl.id,
        version_id=ver.id,
        name="prov-new",
        execution_target_id=env.target.id,
    )
    exercises.validate_exercise(session, principal, ex2.id)
    new_plan = planning.generate_plan(session, principal, ex2.id)
    planning.submit_plan(session, principal, new_plan.id)
    planning.approve_plan(session, principal, new_plan.id, "approved under policy B")
    for team in ("team1", "team2"):
        reservations.reserve_network(
            session, principal, target_id=env.target.id, team_ref=team, exercise_id=ex2.id
        )
    session.commit()

    # New plan (policy B hash) succeeds under policy B.
    manifest = manifests.generate_manifest(session, principal, new_plan.id)
    session.commit()
    assert manifest is not None
    assert manifest.target_scope_policy_hash == new_plan.target_scope_policy_hash


def test_missing_scope_policy_hash_on_plan_blocks_generation(session, principal, provisioning_env):
    """A plan without a scope-policy hash (pre-migration row) must fail closed."""
    from secp_api.models import DeploymentPlan

    env = provisioning_env()
    # Use direct DB update to simulate a pre-migration NULL (bypasses ORM guard).
    session.execute(
        DeploymentPlan.__table__.update()
        .where(DeploymentPlan.__table__.c.id == env.plan.id)
        .values(target_scope_policy_hash=None)
    )
    session.commit()
    session.expire_all()

    with pytest.raises(ValidationFailedError, match="no scope-policy hash"):
        manifests.generate_manifest(session, principal, env.plan.id)
    assert session.query(ProvisioningManifest).count() == 0


# ---------------------------------------------------------------------------
# Proofs #9 — DeploymentPlan binding-field immutability (SECP-002B-0)
# ---------------------------------------------------------------------------


def test_plan_lifecycle_works_normally(session, principal, provisioning_env):
    """Proof #9a — generate, submit, approve transitions work with the ORM guard in place."""
    from secp_api.enums import PlanStatus
    from secp_api.services import planning

    env = provisioning_env(approve=False)
    assert env.plan.status == PlanStatus.awaiting_approval

    # Approve — must not raise (status/decided_by/decided_at are NOT protected).
    planning.approve_plan(session, principal, env.plan.id, "approved")
    session.commit()
    session.expire_all()
    plan = session.get(type(env.plan), env.plan.id)
    assert plan.status == PlanStatus.approved


def test_approved_plan_target_scope_policy_hash_immutable(session, principal, provisioning_env):
    """Proof #9b — target_scope_policy_hash raises ImmutableResourceError after creation."""
    env = provisioning_env()
    env.plan.target_scope_policy_hash = "sha256:tampered"
    with pytest.raises(ImmutableResourceError, match="DeploymentPlan binding"):
        session.flush()


def test_approved_plan_target_config_hash_immutable(session, principal, provisioning_env):
    """Proof #9c — target_config_hash raises ImmutableResourceError after creation."""
    env = provisioning_env()
    env.plan.target_config_hash = "sha256:tampered"
    with pytest.raises(ImmutableResourceError, match="DeploymentPlan binding"):
        session.flush()


def test_approved_plan_plan_field_immutable(session, principal, provisioning_env):
    """Proof #9d — 'plan' JSON field raises ImmutableResourceError after creation."""
    env = provisioning_env()
    env.plan.plan = {"tampered": True}
    with pytest.raises(ImmutableResourceError, match="DeploymentPlan binding"):
        session.flush()


def test_approved_plan_summary_immutable(session, principal, provisioning_env):
    """Proof #9e — 'summary' raises ImmutableResourceError after creation."""
    env = provisioning_env()
    env.plan.summary = {"tampered": True}
    with pytest.raises(ImmutableResourceError, match="DeploymentPlan binding"):
        session.flush()


def test_manifest_generation_detects_out_of_band_plan_hash_corruption(
    session, principal, provisioning_env
):
    """Proof #9f — direct-DB corruption of plan's scope hash is detected at generation.

    The ORM guard protects the ORM path; for defense in depth the manifest service
    also catches a mismatch between the (corrupted) plan hash and the live target.
    """
    from secp_api.models import DeploymentPlan

    env = provisioning_env()

    # Corrupt the plan's stored hash using a direct DB update (bypasses ORM guard).
    session.execute(
        DeploymentPlan.__table__.update()
        .where(DeploymentPlan.__table__.c.id == env.plan.id)
        .values(target_scope_policy_hash="sha256:corrupted-hash")
    )
    session.commit()
    session.expire_all()

    # Manifest generation must refuse: current target hash != corrupted plan hash.
    with pytest.raises(ValidationFailedError, match="scope-policy hash mismatch"):
        manifests.generate_manifest(session, principal, env.plan.id)
    assert session.query(ProvisioningManifest).count() == 0


def test_simulator_plan_lifecycle_unchanged(session, principal, running_exercise):
    """Proof #9g — non-target-bound (simulator) plan is unaffected by the new guard."""
    from secp_api.enums import PlanStatus
    from secp_api.services import planning

    exercise = running_exercise()
    plan = planning.latest_plan(session, principal, exercise.id)
    assert plan is not None
    # After start_exercise, the simulator plan transitions to applied.
    assert plan.status in (PlanStatus.approved, PlanStatus.applied)
    assert plan.execution_target_id is None
    assert plan.target_config_hash is None
    assert plan.target_scope_policy_hash is None
