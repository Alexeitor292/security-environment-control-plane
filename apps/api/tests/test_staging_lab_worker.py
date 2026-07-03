"""SECP-002B-1B-9 — worker fake staging-lab executor tests (fake-only, no infrastructure).

Covers ownership/blast-radius refusal, idempotent/retry-safe simulation, fake teardown/rollback,
and a static proof that the worker staging-lab modules contain no network/transport/subprocess/
secret code and never invoke a real collector/transport/runner.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest
from secp_api.enums import StagingLabProfile, StagingNetworkIntent, StagingResourceClass
from secp_api.staging_lab import StagingLabSpec, compile_staging_plan
from secp_worker.staging_lab import executor as executor_mod
from secp_worker.staging_lab import orchestration as orchestration_mod
from secp_worker.staging_lab.executor import (
    FakeStagingLabExecutor,
    StagingLabOwnershipError,
    assert_owned,
    assert_plan_blast_radius,
)


def _plan(label="secp-lab-alpha"):
    return compile_staging_plan(
        StagingLabSpec(
            ownership_label=label,
            bootstrap_artifact_profile_id="approved-offline-profile-a",
            substrate_approved=True,
        )
    )


def test_simulation_produces_owned_logical_observations_only():
    plan = _plan()
    observed = FakeStagingLabExecutor().simulate(plan=plan, prior_observed=None)
    assert observed["simulated"] is True
    assert observed["creates_infrastructure"] is False
    assert observed["ownership_label"] == "secp-lab-alpha"
    assert len(observed["resources"]) == 6
    assert all(r["owner"] == "secp-lab-alpha" for r in observed["resources"])
    assert all(r["observed_phase"] == "simulated_provisioned" for r in observed["resources"])


def test_simulation_is_idempotent_no_duplicates_on_retry():
    plan = _plan()
    ex = FakeStagingLabExecutor()
    first = ex.simulate(plan=plan, prior_observed=None)
    second = ex.simulate(plan=plan, prior_observed=first)
    assert first == second
    ids = [r["resource_id"] for r in second["resources"]]
    assert len(ids) == len(set(ids))


def test_retry_with_divergent_prior_state_is_refused():
    plan = _plan()
    ex = FakeStagingLabExecutor()
    bogus_prior = {"resources": [{"resource_id": "sim:deadbeef"}]}
    with pytest.raises(StagingLabOwnershipError) as exc:
        ex.simulate(plan=plan, prior_observed=bogus_prior)
    assert exc.value.reason_code == "idempotency_violation"


def test_teardown_marks_resources_destroyed():
    plan = _plan()
    observed = FakeStagingLabExecutor().teardown(plan=plan, prior_observed=None)
    assert all(r["observed_phase"] == "simulated_destroyed" for r in observed["resources"])


def test_assert_owned_refuses_unowned_resource():
    with pytest.raises(StagingLabOwnershipError) as exc:
        assert_owned({"kind": "x", "owner": "other-lab"}, "secp-lab-alpha")
    assert exc.value.reason_code == "unowned_resource"


def test_blast_radius_refuses_second_target_facing_network():
    plan = _plan()
    plan["resources"].append(
        {
            "kind": "isolated_target_facing_network",
            "owner": "secp-lab-alpha",
            "network_intent": "host_only_no_uplink",
            "uplink": "none",
        }
    )
    with pytest.raises(StagingLabOwnershipError) as exc:
        assert_plan_blast_radius(plan, "secp-lab-alpha")
    assert exc.value.reason_code == "multiple_target_facing_networks_rejected"


def test_blast_radius_refuses_second_nested_target():
    plan = _plan()
    plan["resources"].append(
        {"kind": "disposable_nested_proxmox_target", "owner": "secp-lab-alpha"}
    )
    with pytest.raises(StagingLabOwnershipError) as exc:
        assert_plan_blast_radius(plan, "secp-lab-alpha")
    assert exc.value.reason_code == "multiple_nested_targets_rejected"


def test_blast_radius_refuses_production_control_plane_reuse():
    plan = _plan()
    cp = next(r for r in plan["resources"] if r["kind"] == "self_contained_staging_control_plane")
    cp["uses_production_database"] = True
    with pytest.raises(StagingLabOwnershipError) as exc:
        assert_plan_blast_radius(plan, "secp-lab-alpha")
    assert exc.value.reason_code == "production_control_plane_reuse_rejected"


def test_blast_radius_refuses_standing_authorization_association():
    plan = _plan()
    plan["resources"][0]["standing_authorization"] = True
    with pytest.raises(StagingLabOwnershipError) as exc:
        assert_plan_blast_radius(plan, "secp-lab-alpha")
    assert exc.value.reason_code == "standing_authorization_rejected"


def test_worker_staging_lab_modules_have_no_network_or_secret_code():
    forbidden = (
        "import httpx",
        "from httpx",
        "import requests",
        "import aiohttp",
        "import socket",
        "from socket",
        "import subprocess",
        "from subprocess",
        "import ssl",
        "import paramiko",
        "SecretResolver",
        "HttpxReadOnlyTransport",
        "LiveReadOnlyProxmoxCollector",
        "run_live_readonly_collection",
    )
    for module in (executor_mod, orchestration_mod):
        src = inspect.getsource(module)
        for token in forbidden:
            assert token not in src, f"{module.__name__} must not reference `{token}`"


def test_worker_staging_lab_makes_no_transport_or_subprocess_calls():
    pkg_dir = Path(executor_mod.__file__).resolve().parent
    # Unambiguous network/subprocess primitives (ORM `.get`/`.run` names are intentionally
    # excluded — the network guarantee is also covered by the import scan above).
    forbidden_calls = {
        "Popen",
        "urlopen",
        "create_connection",
        "getaddrinfo",
        "check_output",
        "check_call",
        "socket",
        "connect",
    }
    for path in pkg_dir.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                assert name not in forbidden_calls, f"{path.name} calls forbidden {name}"


def test_full_spec_variants_compile_and_simulate():
    for label, rc, profile, ni in [
        (
            "lab-small",
            StagingResourceClass.small_lab,
            StagingLabProfile.nested_proxmox,
            StagingNetworkIntent.host_only_no_uplink,
        ),
        (
            "lab-medium",
            StagingResourceClass.medium_lab,
            StagingLabProfile.nested_proxmox,
            StagingNetworkIntent.host_only_no_uplink,
        ),
    ]:
        plan = compile_staging_plan(
            StagingLabSpec(
                ownership_label=label,
                bootstrap_artifact_profile_id="approved-offline-profile-a",
                substrate_approved=True,
                resource_class=rc,
                profile=profile,
                network_intent=ni,
            )
        )
        observed = FakeStagingLabExecutor().simulate(plan=plan, prior_observed=None)
        assert observed["ownership_label"] == label
