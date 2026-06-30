"""SECP-002A — Execution-target pinning in deployment plans.

Nine acceptance tests:

1. Simulator exercise plan has null target-pinning fields.
2. Target-bound exercise plan stores the correct target ID and immutable config hash.
3. Plan summary contains the pinned target information.
4. Disabled targets cannot be used for new plan generation.
5. Cross-organization target binding / target-backed planning is denied.
6. Target config cannot be changed after a plan exists (immutability guard).
7. Proxmox-bound plans cannot deploy during SECP-002A.
8. No provider request, secret resolution, or Temporal provider workflow starts
   during that refusal (proved by asserting state unchanged + no workflow created).
9. The refusal creates an audit event.
"""

from __future__ import annotations

import pytest
from secp_api.enums import AuditAction
from secp_api.errors import AuthorizationError, DomainError, ImmutableResourceError
from secp_api.models import AuditEvent, Exercise, WorkflowRun
from secp_api.safety import InlineExecutionForbidden
from secp_api.services import exercises, planning
from secp_api.services.catalog import create_template, create_version
from secp_api.services.targets import register_target

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

_PROXMOX_CONFIG = {"base_url": "https://proxmox.lab.test:8006/api2/json", "verify_tls": True}


@pytest.fixture
def proxmox_target(session, principal):
    """An active Proxmox execution target owned by the principal's organization."""
    return register_target(
        session,
        principal,
        display_name="Lab Proxmox",
        plugin_name="proxmox",
        config=_PROXMOX_CONFIG,
        secret_ref="env:SECP_PROVIDER_SECRET__LAB",
    )


@pytest.fixture
def template_version(session, principal, valid_definition):
    """Template + version for re-use across tests."""
    t = create_template(session, principal, name="Pin Test", slug="pin-test")
    v = create_version(session, principal, template_id=t.id, definition=valid_definition)
    session.commit()
    return t, v


def _approved_target_exercise(session, principal, target, template, version, *, name="ptex"):
    """Drive a target-bound exercise through plan generation and approval."""
    ex = exercises.create_exercise(
        session,
        principal,
        template_id=template.id,
        version_id=version.id,
        name=name,
        execution_target_id=target.id,
    )
    exercises.validate_exercise(session, principal, ex.id)
    plan = planning.generate_plan(session, principal, ex.id)
    planning.submit_plan(session, principal, plan.id)
    planning.approve_plan(session, principal, plan.id, "test approval")
    session.commit()
    return ex, plan


# ---------------------------------------------------------------------------
# Test 1: Simulator exercise plan has null target-pinning fields
# ---------------------------------------------------------------------------


def test_simulator_plan_has_null_target_pinning(session, principal, template_version):
    """A plain Simulator exercise must produce a plan with null target fields."""
    template, version = template_version
    ex = exercises.create_exercise(
        session, principal, template_id=template.id, version_id=version.id, name="sim-ex"
    )
    exercises.validate_exercise(session, principal, ex.id)
    plan = planning.generate_plan(session, principal, ex.id)
    session.flush()

    assert plan.execution_target_id is None
    assert plan.target_config_hash is None
    assert "execution_target" not in plan.summary


# ---------------------------------------------------------------------------
# Test 2: Target-bound plan stores correct target ID and immutable config hash
# ---------------------------------------------------------------------------


def test_target_bound_plan_stores_target_id_and_config_hash(
    session, principal, proxmox_target, template_version
):
    """Plan for a target-bound exercise must pin target ID and config hash."""
    template, version = template_version
    ex, plan = _approved_target_exercise(session, principal, proxmox_target, template, version)

    assert plan.execution_target_id == proxmox_target.id
    assert plan.target_config_hash == proxmox_target.config_hash
    assert plan.target_config_hash.startswith("sha256:")


# ---------------------------------------------------------------------------
# Test 3: Plan summary contains the pinned target information
# ---------------------------------------------------------------------------


def test_plan_summary_contains_target_info(session, principal, proxmox_target, template_version):
    """Plan summary must include target ID, plugin name, display name, config hash."""
    template, version = template_version
    ex, plan = _approved_target_exercise(
        session, principal, proxmox_target, template, version, name="sumex"
    )

    target_info = plan.summary.get("execution_target")
    assert target_info is not None, "summary must contain 'execution_target' key"
    assert target_info["id"] == str(proxmox_target.id)
    assert target_info["plugin_name"] == "proxmox"
    assert target_info["display_name"] == "Lab Proxmox"
    assert target_info["config_hash"] == proxmox_target.config_hash


# ---------------------------------------------------------------------------
# Test 4: Disabled targets cannot be used for new plan generation
# ---------------------------------------------------------------------------


def test_disabled_target_cannot_be_used_for_plan(
    session, principal, proxmox_target, template_version
):
    """Generating a plan against a disabled target must be refused."""
    from secp_api.services.targets import disable_target

    template, version = template_version
    ex = exercises.create_exercise(
        session,
        principal,
        template_id=template.id,
        version_id=version.id,
        name="dis-ex",
        execution_target_id=proxmox_target.id,
    )
    exercises.validate_exercise(session, principal, ex.id)
    disable_target(session, principal, proxmox_target.id)
    session.commit()

    with pytest.raises(DomainError, match="not active"):
        planning.generate_plan(session, principal, ex.id)


# ---------------------------------------------------------------------------
# Test 5: Cross-organization target binding is denied
# ---------------------------------------------------------------------------


def test_cross_org_target_binding_denied(
    session, principal, other_org_principal, proxmox_target, template_version
):
    """An exercise in a different organization cannot bind a target it does not own."""
    # proxmox_target belongs to `principal`'s org.
    # other_org_principal is in a different org and must not be able to bind it.
    template, version = template_version

    # other_org_principal creates its own template + version first.
    other_template = create_template(
        session, other_org_principal, name="Other Pin", slug="other-pin"
    )
    other_version = create_version(
        session,
        other_org_principal,
        template_id=other_template.id,
        definition=version.spec,
    )
    session.flush()

    with pytest.raises(AuthorizationError):
        exercises.create_exercise(
            session,
            other_org_principal,
            template_id=other_template.id,
            version_id=other_version.id,
            name="cross-org-ex",
            execution_target_id=proxmox_target.id,  # belongs to a different org
        )


# ---------------------------------------------------------------------------
# Test 6: Target config cannot be changed after a plan exists
# ---------------------------------------------------------------------------


def test_target_config_immutable_after_plan(session, principal, proxmox_target, template_version):
    """The immutability guard must prevent changing a target's config once it has
    been used for a plan.  The config_hash captured in the plan must remain stable."""
    template, version = template_version
    _, plan = _approved_target_exercise(
        session, principal, proxmox_target, template, version, name="immex"
    )

    original_hash = plan.target_config_hash

    # Attempt to mutate the target config directly (bypassing the service layer).
    proxmox_target.config = {"base_url": "https://evil.example.test:8006", "verify_tls": True}
    with pytest.raises(ImmutableResourceError):
        session.flush()

    # Roll back and confirm the plan still holds the original hash.
    session.rollback()
    session.expire_all()
    reloaded = session.get(type(plan), plan.id)
    assert reloaded.target_config_hash == original_hash


# ---------------------------------------------------------------------------
# Tests 7, 8, 9: Proxmox-bound plans cannot deploy in SECP-002A
# ---------------------------------------------------------------------------


def test_proxmox_bound_plan_deploy_refused_in_secp002a(
    session, principal, proxmox_target, template_version
):
    """Test 7 + 8: deploy against a real target raises InlineExecutionForbidden BEFORE
    any state mutation, provider invocation, secret resolution, or workflow creation."""
    template, version = template_version
    ex, plan = _approved_target_exercise(
        session, principal, proxmox_target, template, version, name="prxex"
    )
    # Count workflow runs and exercise state before the attempt.
    workflow_count_before = (
        session.query(WorkflowRun).filter(WorkflowRun.exercise_id == ex.id).count()
    )
    state_before = ex.lifecycle_state

    with pytest.raises(InlineExecutionForbidden) as exc_info:
        exercises.start_exercise(session, principal, ex.id)

    assert "non-simulator execution target" in str(exc_info.value)
    assert "SECP-002A" in str(exc_info.value)

    # Test 8: no provider/Temporal interaction happened — no workflow was created.
    workflow_count_after = (
        session.query(WorkflowRun).filter(WorkflowRun.exercise_id == ex.id).count()
    )
    assert workflow_count_after == workflow_count_before, (
        "no WorkflowRun must be created during a provisioning-refused deployment"
    )

    # Exercise state must be unchanged (approved, not deploying/running).
    session.expire(ex)
    refreshed = session.get(Exercise, ex.id)
    assert refreshed.lifecycle_state == state_before, (
        f"exercise state must not change on refusal; "
        f"expected {state_before.value!r}, got {refreshed.lifecycle_state.value!r}"
    )


def test_proxmox_deploy_refusal_creates_audit_event(
    session, principal, proxmox_target, template_version
):
    """Test 9: the refusal must be recorded as an audit event."""
    template, version = template_version
    ex, plan = _approved_target_exercise(
        session, principal, proxmox_target, template, version, name="audex"
    )

    with pytest.raises(InlineExecutionForbidden):
        exercises.start_exercise(session, principal, ex.id)

    # The refusal audit is written in a separate transaction (survives the rollback).
    from secp_api.db import session_scope

    with session_scope() as audit_session:
        refusals = (
            audit_session.query(AuditEvent)
            .filter(
                AuditEvent.action == AuditAction.execution_refused.value,
                AuditEvent.outcome == "denied",
            )
            .all()
        )
        assert len(refusals) >= 1, "a refusal audit event must exist after the deploy attempt"
        # Confirm the message identifies the reason as non-simulator target.
        reasons = [r.data.get("reason", "") for r in refusals]
    assert any("non-simulator" in r for r in reasons), (
        f"refusal audit must name the non-simulator target; got reasons: {reasons}"
    )


# ---------------------------------------------------------------------------
# Tests 10-12: requiredPlugins list-order must not determine execution provider
# ---------------------------------------------------------------------------


def test_simulator_plan_uses_execution_provider_simulator(session, principal, template_version):
    """A simulator-only exercise plan must record execution_provider='simulator'."""
    template, version = template_version
    ex = exercises.create_exercise(
        session, principal, template_id=template.id, version_id=version.id, name="ep-sim"
    )
    exercises.validate_exercise(session, principal, ex.id)
    plan = planning.generate_plan(session, principal, ex.id)
    session.flush()

    assert plan.summary["execution_provider"] == "simulator"
    assert "topology_preview_provider" not in plan.summary


def test_target_bound_plan_summary_records_execution_and_preview_providers(
    session, principal, proxmox_target, template_version
):
    """A target-bound plan must record execution_provider from the target and
    topology_preview_provider='simulator' (the only topology preview in SECP-002A)."""
    template, version = template_version
    _, plan = _approved_target_exercise(
        session, principal, proxmox_target, template, version, name="ep-tgt"
    )

    assert plan.summary["execution_provider"] == "proxmox"
    assert plan.summary["topology_preview_provider"] == "simulator"
    # The topology preview must have produced real plan data (non-empty).
    assert plan.summary["total_nodes"] > 0


def test_requiredplugins_order_does_not_change_target_bound_execution_provider(
    session, principal, valid_definition, proxmox_target
):
    """Reordering requiredPlugins must not change a target-bound plan's execution_provider.
    The provider is taken from the pinned target, not from the plugin list order."""
    import copy

    # Build a definition variant with a non-simulator plugin listed first.
    # This exercises the old (buggy) code path that would return the first
    # registered match from requiredPlugins.
    definition_variant = copy.deepcopy(valid_definition)
    # Put a fictional registered name first — in the old code, if "simulator"
    # were registered as "alt-simulator", this would return a different name.
    # Here we verify that the target's plugin_name always wins regardless.
    definition_variant["spec"]["requiredPlugins"] = ["simulator", "proxmox"]

    template = create_template(
        session, principal, name="EP-order", slug=f"ep-order-{proxmox_target.id.hex[:8]}"
    )
    version = create_version(
        session, principal, template_id=template.id, definition=definition_variant
    )
    ex = exercises.create_exercise(
        session,
        principal,
        template_id=template.id,
        version_id=version.id,
        name="ep-order-ex",
        execution_target_id=proxmox_target.id,
    )
    exercises.validate_exercise(session, principal, ex.id)
    plan = planning.generate_plan(session, principal, ex.id)
    session.flush()

    # Despite ["simulator", "proxmox"] order, execution_provider comes from the target.
    assert plan.summary["execution_provider"] == "proxmox", (
        "execution_provider must be the target's plugin_name, "
        f"not the first requiredPlugins entry; got {plan.summary['execution_provider']!r}"
    )
    assert plan.summary["topology_preview_provider"] == "simulator"
