"""SECP-002B-1B-0 correction pass — the effective execution boundary (declared onboarding
boundary ∩ target scope policy) is computed, persisted, hash-bound into plan/manifest/content,
recomputed + required to agree at manifest generation and the worker gate, and enforced against
every declared manifest action. Fakes only; nothing real is contacted."""

from __future__ import annotations

import copy

import pytest
from secp_api.config import Settings
from secp_api.enums import ProvisioningOperationKind
from secp_api.errors import ProvisioningRefusedError, ValidationFailedError
from secp_api.models import DeploymentPlan, ProvisioningManifest
from secp_api.onboarding import (
    OnboardingBoundarySpec,
    effective_boundary,
    effective_boundary_hash,
    effective_boundary_is_empty,
)
from secp_api.services import manifests
from secp_worker.provisioning import FakeProcessExecutor, build_fixture_show_json
from secp_worker.provisioning.boundary import (
    enforce_manifest_within_boundary,
    totals_within_quotas,
)
from secp_worker.provisioning.execution import run_real_provisioning
from tests.conftest import VALID_ONBOARDING_BOUNDARY, VALID_PROVISIONING_SCOPE  # type: ignore

REAL_ON = Settings(
    app_env="test",
    provisioning_application_mode="isolated_lab",
    enable_real_provisioning=True,
    workflow_dispatch_mode="temporal",
)


def _dry(session, manifest):
    return run_real_provisioning(
        session,
        manifest.id,
        ProvisioningOperationKind.dry_run,
        executor=FakeProcessExecutor(show_json=build_fixture_show_json(manifest.content)),
        settings=REAL_ON,
        dispatch_mode="temporal",
    )


# --- pure computation --------------------------------------------------------


def _eb():
    spec = OnboardingBoundarySpec.model_validate(VALID_ONBOARDING_BOUNDARY)
    return effective_boundary(spec, {"provisioning": VALID_PROVISIONING_SCOPE})


def test_effective_boundary_equals_declared_when_within_scope():
    eb = _eb()
    assert set(eb["nodes"]) == set(VALID_ONBOARDING_BOUNDARY["nodes"])
    assert eb["storage"] == VALID_ONBOARDING_BOUNDARY["storage"]
    assert eb["network_segments"] == VALID_ONBOARDING_BOUNDARY["network_segments"]
    assert eb["cidrs"] == VALID_ONBOARDING_BOUNDARY["cidrs"]
    assert eb["vmid_range"] == VALID_ONBOARDING_BOUNDARY["vmid_range"]
    assert eb["quotas"]["max_vms"] == VALID_ONBOARDING_BOUNDARY["quotas"]["max_vms"]
    assert eb["external_connectivity"]["policy"] == "deny"


def test_effective_boundary_hash_is_deterministic():
    assert effective_boundary_hash(_eb()) == effective_boundary_hash(_eb())


def test_empty_effective_boundary_is_detected():
    assert effective_boundary_is_empty({}) is True
    assert effective_boundary_is_empty({**_eb(), "nodes": []}) is True
    assert (
        effective_boundary_is_empty({**_eb(), "vmid_range": {"start": 9100, "end": 9000}}) is True
    )
    assert effective_boundary_is_empty(_eb()) is False


# --- worker enforcement seam (fake action fixtures) --------------------------

_IN_BOUND_CONTENT = {
    "topology": [
        {
            "team_ref": "team1",
            "networks": [
                {
                    "name": "team-network",
                    "cidr": "10.60.5.0/24",
                    "bridge": "vmbr0",
                    "isolated": True,
                }
            ],
            "nodes": [
                {"ref": "attacker", "node": "pve-node-1", "storage": "local-lvm", "vmid": 9000}
            ],
        }
    ],
    "requested_totals": {
        "teams": 1,
        "vms": 1,
        "containers": 0,
        "total_vcpu": 2,
        "total_memory_mb": 4096,
        "total_disk_gb": 40,
    },
    "scope_policy": {"external_connectivity": {"policy": "deny"}},
}


def test_in_bound_manifest_passes_enforcement():
    assert enforce_manifest_within_boundary(_IN_BOUND_CONTENT, _eb()) == []


@pytest.mark.parametrize(
    "mutate",
    [
        lambda c: c["topology"][0]["nodes"][0].update(node="pve-node-9"),
        lambda c: c["topology"][0]["nodes"][0].update(storage="local-zfs"),
        lambda c: c["topology"][0]["networks"][0].update(bridge="vmbr9"),
        lambda c: c["topology"][0]["networks"][0].update(cidr="10.99.0.0/24"),
        lambda c: c["topology"][0]["nodes"][0].update(vmid=9999),
        lambda c: c["requested_totals"].update(total_vcpu=9999),
        lambda c: c["requested_totals"].update(vms=9999),
        lambda c: c["scope_policy"]["external_connectivity"].update(policy="allow"),
    ],
)
def test_out_of_bound_action_is_refused(mutate):
    content = copy.deepcopy(_IN_BOUND_CONTENT)
    mutate(content)
    problems = enforce_manifest_within_boundary(content, _eb())
    assert problems, "expected an out-of-bound violation"


def test_totals_within_quotas_helper():
    eb = _eb()
    assert totals_within_quotas(eb, {"vms": 1}) == []
    assert totals_within_quotas(eb, {"vms": eb["quotas"]["max_vms"] + 1})


# --- persisted + hash-bound through plan/manifest/gate -----------------------


def test_plan_and_manifest_carry_effective_boundary(lab_env):
    env = lab_env()
    assert env.plan.effective_boundary_hash
    assert env.plan.effective_boundary_hash == env.manifest.effective_boundary_hash
    assert env.plan.effective_boundary == env.manifest.effective_boundary
    assert env.manifest.content["onboarding"]["effective_boundary"] == env.plan.effective_boundary
    content_hash = env.manifest.content["onboarding"]["effective_boundary_hash"]
    assert content_hash == env.plan.effective_boundary_hash
    # And the recomputed boundary matches.
    spec = OnboardingBoundarySpec.model_validate(env.onboarding.declared_boundary)
    recomputed = effective_boundary(spec, env.target.scope_policy or {})
    assert recomputed == env.plan.effective_boundary
    assert effective_boundary_hash(recomputed) == env.plan.effective_boundary_hash


def test_gate_allows_in_bound_manifest(session, principal, lab_env):
    env = lab_env()
    op = _dry(session, env.manifest)
    assert op is not None  # the dry run passed the effective-boundary gate


def test_plan_effective_boundary_tamper_refuses_manifest_generation(session, principal):
    """A plan whose effective-boundary hash no longer matches the recomputed boundary is
    refused at manifest generation (direct-SQL corruption of the immutable plan field)."""
    from secp_api.services import catalog, exercises, planning, reservations, targets
    from secp_api.services import toolchain as toolchain_svc

    # Build an approved plan WITHOUT a manifest, then corrupt its effective boundary hash.
    from tests.conftest import (
        VALID_DEFINITION,
        VALID_TOOLCHAIN_PROFILE,
        onboard_and_activate,
    )

    target = targets.register_target(
        session,
        principal,
        display_name="EBTamper",
        plugin_name="proxmox",
        config={"base_url": "https://proxmox.example.test:8006/api2/json", "verify_tls": True},
        secret_ref="env:SECP_PROVIDER_SECRET__EBT",
        scope_policy={"provisioning": copy.deepcopy(VALID_PROVISIONING_SCOPE)},
        address_spaces=[{"cidr_block": "10.60.0.0/16", "subnet_prefix": 24}],
    )
    toolchain_svc.register_toolchain_profile(
        session,
        principal,
        target_id=target.id,
        name="tc",
        profile=copy.deepcopy(VALID_TOOLCHAIN_PROFILE),
    )
    onboard_and_activate(session, principal, target)
    tmpl = catalog.create_template(session, principal, name="EBT", slug="ebt")
    ver = catalog.create_version(
        session, principal, template_id=tmpl.id, definition=VALID_DEFINITION
    )
    ex = exercises.create_exercise(
        session,
        principal,
        template_id=tmpl.id,
        version_id=ver.id,
        name="ebt",
        execution_target_id=target.id,
    )
    exercises.validate_exercise(session, principal, ex.id)
    plan = planning.generate_plan(session, principal, ex.id)
    planning.submit_plan(session, principal, plan.id)
    planning.approve_plan(session, principal, plan.id, "ok")
    for team in ("team1", "team2"):
        reservations.reserve_network(
            session, principal, target_id=target.id, team_ref=team, exercise_id=ex.id
        )
    session.commit()

    session.execute(
        DeploymentPlan.__table__.update()
        .where(DeploymentPlan.__table__.c.id == plan.id)
        .values(effective_boundary_hash="sha256:tampered")
    )
    session.commit()
    session.expire_all()
    with pytest.raises(ValidationFailedError, match="effective"):
        manifests.generate_manifest(session, principal, plan.id)


def test_plan_effective_boundary_object_tamper_refuses_manifest_generation(
    session, principal, lab_env
):
    env = lab_env()
    tampered = copy.deepcopy(env.plan.effective_boundary)
    tampered["nodes"] = ["pve-node-99"]
    session.execute(
        DeploymentPlan.__table__.update()
        .where(DeploymentPlan.__table__.c.id == env.plan.id)
        .values(effective_boundary=tampered)
    )
    session.commit()
    session.expire_all()
    with pytest.raises(ValidationFailedError, match="effective"):
        manifests.generate_manifest(session, principal, env.plan.id)


def test_manifest_effective_boundary_tamper_refuses_real_provisioning(session, principal, lab_env):
    env = lab_env()
    _dry(session, env.manifest)  # sanity: intact binding passes
    session.commit()
    session.execute(
        ProvisioningManifest.__table__.update()
        .where(ProvisioningManifest.__table__.c.id == env.manifest.id)
        .values(effective_boundary_hash="sha256:tampered")
    )
    session.commit()
    session.expire_all()
    with pytest.raises(ProvisioningRefusedError, match="effective boundary"):
        _dry(session, env.manifest)


def test_manifest_effective_boundary_object_tamper_refuses_real_provisioning(
    session, principal, lab_env
):
    env = lab_env()
    _dry(session, env.manifest)  # sanity: intact binding passes
    session.commit()
    tampered = copy.deepcopy(env.manifest.effective_boundary)
    tampered["nodes"] = ["pve-node-99"]
    session.execute(
        ProvisioningManifest.__table__.update()
        .where(ProvisioningManifest.__table__.c.id == env.manifest.id)
        .values(effective_boundary=tampered)
    )
    session.commit()
    session.expire_all()
    with pytest.raises(ProvisioningRefusedError, match="effective boundary"):
        _dry(session, env.manifest)


def test_manifest_content_effective_boundary_tamper_refuses_real_provisioning(
    session, principal, lab_env
):
    from secp_scenario_schema import content_hash

    env = lab_env()
    _dry(session, env.manifest)  # sanity: intact binding passes
    session.commit()
    tampered = copy.deepcopy(env.manifest.content)
    tampered["onboarding"]["effective_boundary"]["nodes"] = ["pve-node-99"]
    session.execute(
        ProvisioningManifest.__table__.update()
        .where(ProvisioningManifest.__table__.c.id == env.manifest.id)
        .values(content=tampered, content_hash=content_hash(tampered))
    )
    session.commit()
    session.expire_all()
    with pytest.raises(ProvisioningRefusedError, match="content effective boundary"):
        _dry(session, env.manifest)
