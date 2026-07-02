"""SECP-002B-1B-0 — standard deployments are automated + declarative, and real
provisioning requires an approved & active target onboarding. All fakes."""

from __future__ import annotations

import pytest
from secp_api.config import Settings
from secp_api.enums import ProvisioningOperationKind
from secp_api.errors import ProvisioningRefusedError
from secp_api.services import onboarding as onb
from secp_worker.provisioning import FakeProcessExecutor, build_fixture_show_json
from secp_worker.provisioning.execution import run_real_provisioning

REAL_ON = Settings(
    app_env="test",
    provisioning_application_mode="isolated_lab",
    enable_real_provisioning=True,
    workflow_dispatch_mode="temporal",
)


# --- plans/manifests state that SECP creates scenario resources automatically -


def test_plan_summary_states_automated_declarative_deployment(lab_env):
    env = lab_env()
    dc = env.plan.summary["deployment_contract"]
    assert dc["mode"] == "automated"
    assert dc["provisioning_model"] == "declarative"
    assert dc["scenario_resources_created_by_secp"] is True
    assert dc["manual_pre_creation_required"] is False
    assert dc["user_provided_preexisting_assets"] == []
    assert dc["subject_to_approval"] is True and dc["subject_to_scope_policy"] is True
    for action in ("allocate_vm_ids", "allocate_addresses", "create_networks", "create_vms"):
        assert action in dc["secp_automated_actions"]


def test_manifest_states_automated_deployment(lab_env):
    env = lab_env()
    dep = env.manifest.content["deployment"]
    assert dep["mode"] == "automated"
    assert dep["scenario_resources_created_by_secp"] is True
    assert dep["manual_pre_creation_required"] is False
    assert dep["user_provided_preexisting_assets"] == []


def test_no_standard_plan_requires_manual_guests(lab_env):
    """The standard workflow never requires manually created VMs/containers."""
    env = lab_env()
    assert env.plan.summary["deployment_contract"]["manual_pre_creation_required"] is False
    assert env.manifest.content["deployment"]["manual_pre_creation_required"] is False


# --- real provisioning requires an approved & active onboarding ---------------


def _run_dry(session, manifest):
    return run_real_provisioning(
        session,
        manifest.id,
        ProvisioningOperationKind.dry_run,
        executor=FakeProcessExecutor(show_json=build_fixture_show_json(manifest.content)),
        settings=REAL_ON,
        dispatch_mode="temporal",
    )


def test_real_provisioning_requires_active_onboarding(session, principal, lab_env):
    env = lab_env()
    # Sanity: with the active onboarding present, the real dry run is allowed.
    _run_dry(session, env.manifest)
    session.commit()
    # Retire the onboarding → the target is no longer cleared for real provisioning.
    onb.retire_onboarding(session, principal, env.onboarding.id)
    session.commit()
    with pytest.raises(ProvisioningRefusedError, match="onboarding"):
        _run_dry(session, env.manifest)


def test_active_onboarding_is_present_for_lab(session, principal, lab_env):
    env = lab_env()
    active = onb.active_onboarding_for_target(session, env.target.id)
    assert active is not None and active.id == env.onboarding.id
