"""SECP-002B-1B-0 correction pass — the effective execution boundary (declared onboarding
boundary ∩ target scope policy) is computed, persisted, hash-bound into plan/manifest/content,
recomputed + required to agree at manifest generation and the worker gate, and enforced against
every declared manifest action. Fakes only; nothing real is contacted."""

from __future__ import annotations

import copy
from types import SimpleNamespace

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


def _broad_scope_for_narrow_boundary() -> dict:
    scope = copy.deepcopy(VALID_PROVISIONING_SCOPE)
    scope["allowed_storage"] = ["local-lvm", "local-zfs"]
    scope["allowed_bridges"] = ["vmbr0", "vmbr1"]
    scope["allowed_cidr_reservations"] = ["10.60.0.0/16"]
    scope["vmid_range"] = {"start": 9000, "end": 9100}
    scope["max_teams"] = 4
    scope["max_vms"] = 20
    scope["max_containers"] = 10
    scope["max_total_vcpu"] = 64
    scope["max_total_memory_mb"] = 131072
    scope["max_total_disk_gb"] = 2048
    return scope


def _narrow_boundary() -> dict:
    return {
        "nodes": ["pve-node-2"],
        "storage": ["local-zfs"],
        "network_segments": ["vmbr1"],
        "cidrs": ["10.60.42.0/24"],
        "vmid_range": {"start": 9050, "end": 9060},
        "quotas": {
            "max_teams": 2,
            "max_vms": 4,
            "max_containers": 2,
            "max_total_vcpu": 8,
            "max_total_memory_mb": 14336,
            "max_total_disk_gb": 140,
        },
        "external_connectivity": {"policy": "deny"},
        "credential_scope": "least_privilege",
    }


def _build_narrow_boundary_plan(session, principal, slug: str, *, address_spaces=None):
    from secp_api.services import catalog, exercises, planning, reservations, targets
    from tests.conftest import VALID_DEFINITION, onboard_and_activate

    target = targets.register_target(
        session,
        principal,
        display_name=f"Narrow Boundary {slug}",
        plugin_name="proxmox",
        config={"base_url": "https://proxmox.example.test:8006/api2/json", "verify_tls": True},
        secret_ref=f"env:SECP_PROVIDER_SECRET__{slug.upper()}",
        scope_policy={"provisioning": _broad_scope_for_narrow_boundary()},
        address_spaces=address_spaces or [{"cidr_block": "10.60.42.0/24", "subnet_prefix": 25}],
    )
    onboarding = onboard_and_activate(session, principal, target, boundary=_narrow_boundary())
    tmpl = catalog.create_template(session, principal, name=f"NB-{slug}", slug=f"nb-{slug}")
    ver = catalog.create_version(
        session, principal, template_id=tmpl.id, definition=VALID_DEFINITION
    )
    exercise = exercises.create_exercise(
        session,
        principal,
        template_id=tmpl.id,
        version_id=ver.id,
        name=f"nb-{slug}",
        execution_target_id=target.id,
    )
    exercises.validate_exercise(session, principal, exercise.id)
    plan = planning.generate_plan(session, principal, exercise.id)
    planning.submit_plan(session, principal, plan.id)
    planning.approve_plan(session, principal, plan.id, "ok")
    for team in ("team1", "team2"):
        reservations.reserve_network(
            session, principal, target_id=target.id, team_ref=team, exercise_id=exercise.id
        )
    session.commit()
    return SimpleNamespace(target=target, onboarding=onboarding, exercise=exercise, plan=plan)


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


def test_manifest_generation_uses_narrow_effective_policy(session, principal):
    env = _build_narrow_boundary_plan(session, principal, "inside")
    manifest = manifests.generate_manifest(session, principal, env.plan.id)
    session.commit()

    target_policy = env.target.scope_policy["provisioning"]
    snapshot = manifest.content["scope_policy"]
    narrow = _narrow_boundary()

    # The target remains broader than the selected onboarding boundary.
    assert "pve-node-1" in target_policy["allowed_nodes"]
    assert "local-lvm" in target_policy["allowed_storage"]
    assert "vmbr0" in target_policy["allowed_bridges"]
    assert target_policy["allowed_cidr_reservations"] == ["10.60.0.0/16"]

    # The manifest execution view is narrowed to the effective boundary.
    assert snapshot["allowed_nodes"] == narrow["nodes"]
    assert snapshot["allowed_storage"] == narrow["storage"]
    assert snapshot["allowed_bridges"] == narrow["network_segments"]
    assert snapshot["allowed_cidr_reservations"] == narrow["cidrs"]
    assert snapshot["vmid_range"] == narrow["vmid_range"]
    assert snapshot["allowed_templates"] == VALID_PROVISIONING_SCOPE["allowed_templates"]
    assert snapshot["node_sizing"] == VALID_PROVISIONING_SCOPE["node_sizing"]
    assert manifest.content["resource_limits"] == narrow["quotas"]

    nodes = [node for team in manifest.content["topology"] for node in team["nodes"]]
    networks = [net for team in manifest.content["topology"] for net in team["networks"]]
    assert {node["node"] for node in nodes} == {"pve-node-2"}
    assert {node["storage"] for node in nodes} == {"local-zfs"}
    assert {net["bridge"] for net in networks} == {"vmbr1"}
    assert {net["cidr"] for net in networks} == {"10.60.42.0/25", "10.60.42.128/25"}
    assert sorted(node["vmid"] for node in nodes) == list(range(9050, 9056))
    assert manifest.content["requested_totals"] == {
        "teams": 2,
        "vms": 4,
        "containers": 2,
        "total_vcpu": 8,
        "total_memory_mb": 14336,
        "total_disk_gb": 140,
    }
    assert enforce_manifest_within_boundary(manifest.content, manifest.effective_boundary) == []


def test_reservation_outside_narrow_boundary_refuses_manifest_generation(session, principal):
    env = _build_narrow_boundary_plan(
        session,
        principal,
        "outside",
        address_spaces=[{"cidr_block": "10.60.0.0/16", "subnet_prefix": 24}],
    )

    with pytest.raises(ValidationFailedError, match="effective boundary CIDRs"):
        manifests.generate_manifest(session, principal, env.plan.id)
    assert (
        session.query(ProvisioningManifest)
        .filter(ProvisioningManifest.deployment_plan_id == env.plan.id)
        .count()
        == 0
    )


def test_generated_escape_is_refused_before_manifest_persist(session, principal, monkeypatch):
    env = _build_narrow_boundary_plan(session, principal, "escape")
    original_build_topology = manifests._build_topology

    def escaping_topology(definition, reservations_by_team, policy):
        topology, totals = original_build_topology(definition, reservations_by_team, policy)
        topology[0]["nodes"][0]["node"] = "pve-node-1"
        return topology, totals

    monkeypatch.setattr(manifests, "_build_topology", escaping_topology)
    with pytest.raises(ValidationFailedError, match="outside the effective execution boundary"):
        manifests.generate_manifest(session, principal, env.plan.id)
    assert (
        session.query(ProvisioningManifest)
        .filter(ProvisioningManifest.deployment_plan_id == env.plan.id)
        .count()
        == 0
    )


def test_full_scope_onboarding_manifest_still_works(session, principal, provisioning_env):
    env = provisioning_env()
    manifest = manifests.generate_manifest(session, principal, env.plan.id)
    session.commit()

    assert (
        manifest.content["scope_policy"]["allowed_nodes"]
        == VALID_PROVISIONING_SCOPE["allowed_nodes"]
    )
    assert (
        manifest.content["scope_policy"]["allowed_storage"]
        == VALID_PROVISIONING_SCOPE["allowed_storage"]
    )
    assert (
        manifest.content["scope_policy"]["allowed_bridges"]
        == VALID_PROVISIONING_SCOPE["allowed_bridges"]
    )
    assert enforce_manifest_within_boundary(manifest.content, manifest.effective_boundary) == []


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
