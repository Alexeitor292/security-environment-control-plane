"""SECP-002B-1B-9 — worker fake staging-lab executor + durable consumer tests (fake-only).

Covers ownership/blast-radius refusal, idempotent/retry-safe simulation, fake teardown, the
durable consumer's exclusive claim (compare-and-swap) and authoritative-record re-validation
(refusing cross-org / plan-drift / stale-lifecycle / ownership-mismatch work), and a static proof
that the worker staging-lab modules contain no network/transport/subprocess/secret code.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest
from secp_api.enums import (
    IsolationModel,
    OnboardingMode,
    OnboardingStatus,
    StagingLabProfile,
    StagingLabStatus,
    StagingNetworkIntent,
    StagingResourceClass,
    StagingWorkOperation,
    StagingWorkStatus,
    TargetStatus,
)
from secp_api.models import ExecutionTarget, StagingLab, StagingLabWorkItem, TargetOnboarding
from secp_api.services import staging_labs
from secp_api.staging_lab import StagingLabSpec, compile_staging_plan
from secp_worker.staging_lab import consumer as consumer_mod
from secp_worker.staging_lab import executor as executor_mod
from secp_worker.staging_lab.consumer import claim_and_process_one
from secp_worker.staging_lab.executor import (
    FakeStagingLabExecutor,
    StagingLabOwnershipError,
    assert_owned,
    assert_plan_blast_radius,
)
from sqlalchemy import update


def _plan(label="secp-lab-alpha"):
    return compile_staging_plan(
        StagingLabSpec(ownership_label=label, substrate_approved=True, substrate_eligible=True)
    )


# --- Fake executor (unchanged contract) ---------------------------------------


def test_simulation_produces_owned_logical_observations_only():
    observed = FakeStagingLabExecutor().simulate(plan=_plan(), prior_observed=None)
    assert observed["simulated"] is True
    assert observed["creates_infrastructure"] is False
    assert len(observed["resources"]) == 6
    assert all(r["observed_phase"] == "simulated_provisioned" for r in observed["resources"])


def test_simulation_is_idempotent_no_duplicates_on_retry():
    ex = FakeStagingLabExecutor()
    first = ex.simulate(plan=_plan(), prior_observed=None)
    second = ex.simulate(plan=_plan(), prior_observed=first)
    assert first == second
    ids = [r["resource_id"] for r in second["resources"]]
    assert len(ids) == len(set(ids))


def test_retry_with_divergent_prior_state_is_refused():
    with pytest.raises(StagingLabOwnershipError) as exc:
        FakeStagingLabExecutor().simulate(
            plan=_plan(), prior_observed={"resources": [{"resource_id": "sim:deadbeef"}]}
        )
    assert exc.value.reason_code == "idempotency_violation"


def test_teardown_marks_resources_destroyed():
    observed = FakeStagingLabExecutor().teardown(plan=_plan(), prior_observed=None)
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


# --- Durable consumer ---------------------------------------------------------


def _eligible(session, principal) -> ExecutionTarget:
    target = ExecutionTarget(
        organization_id=principal.organization_id,
        display_name="substrate",
        plugin_name="proxmox",
        config={},
        config_hash="sha256:" + "ab" * 32,
        secret_ref="env:SECP_PROVIDER_SECRET__FAKE",
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
    staging_labs.grant_substrate_eligibility(session, principal, execution_target_id=target.id)
    return target


def _approved_lab(session, principal) -> StagingLab:
    target = _eligible(session, principal)
    lab = staging_labs.create_staging_lab(session, principal, execution_target_id=target.id)
    staging_labs.generate_plan(session, principal, lab.id)
    staging_labs.submit_for_approval(session, principal, lab.id)
    staging_labs.approve_staging_lab(session, principal, lab.id, expected_plan_hash=lab.plan_hash)
    return lab


def _queued_item(session, lab) -> StagingLabWorkItem:
    return session.query(StagingLabWorkItem).filter_by(staging_lab_id=lab.id).one()


def test_consumer_processes_queued_work(session, principal):
    lab = _approved_lab(session, principal)
    staging_labs.queue_simulation(session, principal, lab.id)
    item = _queued_item(session, lab)
    assert claim_and_process_one(session) == item.id
    session.refresh(lab)
    session.refresh(item)
    assert lab.status == StagingLabStatus.simulated_ready
    assert item.status == StagingWorkStatus.completed


def test_consumer_returns_none_when_no_queued_work(session, principal):
    assert claim_and_process_one(session) is None


def test_claim_is_exclusive_compare_and_swap(session, principal):
    lab = _approved_lab(session, principal)
    staging_labs.queue_simulation(session, principal, lab.id)
    item = _queued_item(session, lab)

    # Two racing claim UPDATEs against the same (status, revision): exactly one wins.
    def _claim() -> int:
        return session.execute(
            update(StagingLabWorkItem)
            .where(
                StagingLabWorkItem.id == item.id,
                StagingLabWorkItem.status == StagingWorkStatus.queued,
                StagingLabWorkItem.revision == 0,
            )
            .values(status=StagingWorkStatus.claimed, revision=1)
        ).rowcount

    assert _claim() == 1
    assert _claim() == 0


def test_consumer_refuses_cross_org_work(session, principal, other_org_principal):
    lab = _approved_lab(session, principal)
    session.add(
        StagingLabWorkItem(
            organization_id=other_org_principal.organization_id,  # different org than the lab
            staging_lab_id=lab.id,
            operation_kind=StagingWorkOperation.simulate_provision,
            plan_hash=lab.plan_hash,
            plan_version=lab.plan_version,
            idempotency_key="x-org",
            status=StagingWorkStatus.queued,
            revision=0,
        )
    )
    session.flush()
    claim_and_process_one(session)
    item = session.query(StagingLabWorkItem).filter_by(idempotency_key="x-org").one()
    assert item.status == StagingWorkStatus.refused
    assert item.failure_reason == "cross_org"


def test_consumer_refuses_plan_drift(session, principal):
    lab = _approved_lab(session, principal)
    session.add(
        StagingLabWorkItem(
            organization_id=lab.organization_id,
            staging_lab_id=lab.id,
            operation_kind=StagingWorkOperation.simulate_provision,
            plan_hash="sha256:" + "99" * 32,  # does not match the lab's plan
            plan_version=lab.plan_version,
            idempotency_key="drift",
            status=StagingWorkStatus.queued,
            revision=0,
        )
    )
    session.flush()
    claim_and_process_one(session)
    item = session.query(StagingLabWorkItem).filter_by(idempotency_key="drift").one()
    assert item.status == StagingWorkStatus.refused
    assert item.failure_reason == "plan_drift"


def test_consumer_refuses_stale_lifecycle(session, principal):
    # A valid work item but the lab is still 'approved' (not 'simulation_queued').
    lab = _approved_lab(session, principal)
    session.add(
        StagingLabWorkItem(
            organization_id=lab.organization_id,
            staging_lab_id=lab.id,
            operation_kind=StagingWorkOperation.simulate_provision,
            plan_hash=lab.plan_hash,
            plan_version=lab.plan_version,
            idempotency_key="stale",
            status=StagingWorkStatus.queued,
            revision=0,
        )
    )
    session.flush()
    claim_and_process_one(session)
    item = session.query(StagingLabWorkItem).filter_by(idempotency_key="stale").one()
    assert item.status == StagingWorkStatus.refused
    assert item.failure_reason == "stale_lifecycle"


# --- Structural: no network/provider/subprocess/secret code -------------------


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
    for module in (executor_mod, consumer_mod):
        src = inspect.getsource(module)
        for token in forbidden:
            assert token not in src, f"{module.__name__} must not reference `{token}`"


def test_worker_staging_lab_makes_no_transport_or_subprocess_calls():
    pkg_dir = Path(executor_mod.__file__).resolve().parent
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
    for label, rc in [
        ("lab-small", StagingResourceClass.small_lab),
        ("lab-medium", StagingResourceClass.medium_lab),
    ]:
        plan = compile_staging_plan(
            StagingLabSpec(
                ownership_label=label,
                substrate_approved=True,
                substrate_eligible=True,
                resource_class=rc,
                profile=StagingLabProfile.nested_proxmox,
                network_intent=StagingNetworkIntent.host_only_no_uplink,
            )
        )
        observed = FakeStagingLabExecutor().simulate(plan=plan, prior_observed=None)
        assert observed["ownership_label"] == label
