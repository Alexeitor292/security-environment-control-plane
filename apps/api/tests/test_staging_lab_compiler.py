"""SECP-002B-1B-9 — provider-neutral staging-lab compiler tests (fake-only, no infrastructure).

Covers every allowed and rejected spec, deterministic immutable plan generation + hashing, the
required logical resources with ownership labeling, and the absence of any real infrastructure or
secret value in the compiled plan.
"""

from __future__ import annotations

import json

import pytest
from secp_api.enums import (
    StagingLabProfile,
    StagingLabPurpose,
    StagingNetworkIntent,
    StagingResourceClass,
    StagingRollbackPolicy,
)
from secp_api.staging_lab import (
    RESOURCE_CHECKPOINT,
    RESOURCE_CONNECTION_POLICY,
    RESOURCE_CONTROL_PLANE,
    RESOURCE_ISOLATED_NETWORK,
    RESOURCE_NESTED_TARGET,
    RESOURCE_TEARDOWN,
    STAGING_CONTROL_PLANE_COMPONENTS,
    StagingLabPlanError,
    StagingLabSpec,
    compile_staging_plan,
    staging_plan_hash,
)


def _spec(**over) -> StagingLabSpec:
    fields = dict(
        ownership_label="secp-lab-alpha",
        bootstrap_artifact_profile_id="approved-offline-profile-a",
        substrate_approved=True,
    )
    fields.update(over)
    return StagingLabSpec(**fields)


def test_valid_spec_compiles_to_the_required_logical_resources():
    plan = compile_staging_plan(_spec())
    kinds = {r["kind"] for r in plan["resources"]}
    assert kinds == {
        RESOURCE_ISOLATED_NETWORK,
        RESOURCE_CONTROL_PLANE,
        RESOURCE_NESTED_TARGET,
        RESOURCE_CONNECTION_POLICY,
        RESOURCE_CHECKPOINT,
        RESOURCE_TEARDOWN,
    }
    # Exactly one target-facing network, one nested target, one connection policy.
    counts = {k: sum(1 for r in plan["resources"] if r["kind"] == k) for k in kinds}
    assert counts[RESOURCE_ISOLATED_NETWORK] == 1
    assert counts[RESOURCE_NESTED_TARGET] == 1
    assert counts[RESOURCE_CONNECTION_POLICY] == 1


def test_every_resource_carries_the_ownership_label():
    plan = compile_staging_plan(_spec(ownership_label="secp-lab-owner"))
    assert plan["ownership_label"] == "secp-lab-owner"
    assert all(r["owner"] == "secp-lab-owner" for r in plan["resources"])


def test_control_plane_is_self_contained_with_all_three_components():
    plan = compile_staging_plan(_spec())
    cp = next(r for r in plan["resources"] if r["kind"] == RESOURCE_CONTROL_PLANE)
    assert cp["self_contained"] is True
    assert cp["uses_production_control_plane"] is False
    assert cp["uses_production_database"] is False
    assert set(cp["components"]) == set(STAGING_CONTROL_PLANE_COMPONENTS)
    assert cp["local_control_plane_transport"] == "loopback_or_internal_container_network"


def test_isolated_network_has_no_uplink_gateway_or_dns():
    plan = compile_staging_plan(_spec())
    net = next(r for r in plan["resources"] if r["kind"] == RESOURCE_ISOLATED_NETWORK)
    assert net["network_intent"] == "host_only_no_uplink"
    assert net["uplink"] == "none"
    assert net["default_gateway"] == "none"
    assert net["dns"] == "none"
    assert net["reachable_networks"] == "none"


def test_single_target_facing_connection_is_worker_to_target_read_only():
    plan = compile_staging_plan(_spec())
    conn = next(r for r in plan["resources"] if r["kind"] == RESOURCE_CONNECTION_POLICY)
    assert conn["source"] == "staging_worker"
    assert conn["destination"] == "nested_target_read_only_api"
    assert conn["direction"] == "worker_to_target"
    assert conn["access"] == "read_only"
    assert conn["count"] == 1


def test_plan_declares_no_infrastructure_and_offline_bootstrap():
    plan = compile_staging_plan(_spec())
    assert plan["creates_infrastructure"] is False
    assert plan["simulation_only"] is True
    assert plan["bootstrap"]["post_isolation_internet_dependency"] == "forbidden"
    assert plan["bootstrap"]["source"] == "operator_approved_prestaged_offline_artifacts"


def test_plan_is_deterministic_and_hash_stable():
    p1 = compile_staging_plan(_spec())
    p2 = compile_staging_plan(_spec())
    assert p1 == p2
    assert staging_plan_hash(p1) == staging_plan_hash(p2)
    assert staging_plan_hash(p1).startswith("sha256:")


def test_different_ownership_label_changes_the_plan_hash():
    a = compile_staging_plan(_spec(ownership_label="lab-a"))
    b = compile_staging_plan(_spec(ownership_label="lab-b"))
    assert staging_plan_hash(a) != staging_plan_hash(b)


@pytest.mark.parametrize(
    ("over", "reason"),
    [
        (dict(substrate_approved=False), "unapproved_substrate"),
        (dict(self_contained_control_plane=False), "production_control_plane_reuse_rejected"),
        (
            dict(reuses_production_components=("production_api",)),
            "production_control_plane_reuse_rejected",
        ),
        (
            dict(network_intent=StagingNetworkIntent.shared_or_production),
            "shared_or_production_network_rejected",
        ),
        (dict(nested_target_count=2), "nested_target_count_invalid"),
        (dict(target_facing_connection_count=2), "target_facing_connection_count_invalid"),
        (dict(standing_authorization=True), "standing_authorization_rejected"),
        (dict(ownership_label="  "), "ownership_label_missing"),
        (dict(bootstrap_artifact_profile_id=""), "bootstrap_artifact_profile_missing"),
        (
            dict(bootstrap_artifact_profile_id="https://example/iso"),
            "bootstrap_artifact_profile_invalid",
        ),
        (dict(bootstrap_artifact_profile_id="path/to/iso"), "bootstrap_artifact_profile_invalid"),
    ],
)
def test_rejections_fail_closed_with_reason_code(over, reason):
    with pytest.raises(StagingLabPlanError) as exc:
        compile_staging_plan(_spec(**over))
    assert exc.value.reason_code == reason


def test_plan_contains_no_real_infrastructure_or_secret_tokens():
    plan = compile_staging_plan(
        _spec(
            ownership_label="secp-lab-alpha",
            bootstrap_artifact_profile_id="approved-offline-profile-a",
            resource_class=StagingResourceClass.medium_lab,
            profile=StagingLabProfile.nested_proxmox,
            purpose=StagingLabPurpose.disposable_readonly_staging,
            rollback_policy=StagingRollbackPolicy.destroy_and_rebuild,
        )
    )
    blob = json.dumps(plan)
    # No endpoint/URL/port/secret/credential-ish content in a purely logical plan.
    for forbidden in (
        "http://",
        "https://",
        "://",
        "token",
        "secret",
        "password",
        "credential",
        "@pam",
    ):
        assert forbidden not in blob.lower()
