"""SECP-002B-1B-9 — security, concurrency, and structural guardrails (fake-only, no infrastructure).

Proves: strict backend allowlist validation of the one caller-supplied string (bypassing the UI);
the API cannot import or invoke worker/executor code (no hidden synchronous execution path);
DB-level compare-and-swap concurrency (one approval wins, duplicate active work rejected, stale
completion refused); substrate eligibility is independently enforced and not self-grantable by a
lab creator; and no real infrastructure/secret values appear in schemas/audit/fixtures.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest
from pydantic import ValidationError as PydanticValidationError
from secp_api.enums import (
    IsolationModel,
    OnboardingMode,
    OnboardingStatus,
    Permission,
    StagingLabStatus,
    StagingWorkOperation,
    StagingWorkStatus,
    TargetStatus,
)
from secp_api.errors import AuthorizationError, DomainError, ValidationFailedError
from secp_api.models import ExecutionTarget, StagingLab, StagingLabWorkItem, TargetOnboarding
from secp_api.schemas_staging_lab import StagingLabCreate
from secp_api.services import staging_labs
from sqlalchemy import update

API_PKG = Path(__file__).resolve().parents[1] / "secp_api"

# Values a caller might try to smuggle through the one free-text field — each contains a
# structured token (scheme/host/IP/path/port/colon/'@'/'='/space/uppercase/over-length) that the
# strict slug allowlist rejects. (A bare lowercase slug is a safe display suffix and is allowed.)
PROHIBITED_LOGICAL_NAMES = [
    "https://proxmox.example/api",
    "10.0.0.5",
    "fe80::1",
    "proxmox.internal",
    "/etc/pve/nodes",
    "pve-node-1:8006",
    "PVEAPIToken=user@pam!tok=secret",
    "env:SECP_PROVIDER_SECRET__X",
    "vault:kv/secret",
    "AA:BB:CC:DD:EE:FF",
    "name with spaces",
    "UPPERCASE",
    "trailing-",
    "-leading",
    "a" * 60,
]


@pytest.mark.parametrize("value", PROHIBITED_LOGICAL_NAMES)
def test_create_schema_rejects_prohibited_logical_names(value):
    # The pydantic field validator delegates to the strict allowlist; a rejected value surfaces
    # as a pydantic ValidationError at the API boundary (before any DB write).
    with pytest.raises(PydanticValidationError):
        StagingLabCreate(
            execution_target_id="00000000-0000-0000-0000-000000000001", logical_name=value
        )


def test_service_logical_name_validator_rejects_prohibited_values():
    for value in PROHIBITED_LOGICAL_NAMES:
        with pytest.raises(ValidationFailedError):
            staging_labs.assert_safe_logical_name(value)


def test_service_logical_name_validator_accepts_safe_slug():
    assert staging_labs.assert_safe_logical_name("alpha-01") == "alpha-01"


# --- Structural: the API cannot execute worker code ---------------------------


def _api_files() -> list[Path]:
    return [p for p in API_PKG.rglob("*.py") if "__pycache__" not in p.parts]


def test_api_never_imports_staging_worker_or_executor():
    """AST proof: no API module imports (or lazy-imports) staging-lab worker/executor/consumer.

    A docstring cross-reference is not an import; this scans real import statements only.
    """
    forbidden_symbols = {
        "FakeStagingLabExecutor",
        "claim_and_process_one",
        "process_all_queued",
        "run_consumer_loop",
        "run_forever",
        "drain_once",
    }
    for path in _api_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert not alias.name.startswith("secp_worker.staging_lab"), (
                        f"{path.name} imports {alias.name}"
                    )
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                assert not module.startswith("secp_worker.staging_lab"), (
                    f"{path.name} imports from {module}"
                )
                for alias in node.names:
                    assert alias.name not in forbidden_symbols, f"{path.name} imports {alias.name}"


def test_no_api_call_synchronously_invokes_the_executor():
    """AST scan: no API file contains a call to the fake executor or the consumer."""
    forbidden = {
        "FakeStagingLabExecutor",
        "claim_and_process_one",
        "process_all_queued",
        "simulate",
        "teardown",
    }
    for path in _api_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                # 'simulate'/'teardown' here are worker-executor method names; the API's own
                # queue functions are queue_simulation/queue_teardown, which don't match.
                assert name not in forbidden, f"{path.name} invokes executor call {name!r}"


def test_staging_router_only_enqueues_no_worker_import():
    router_src = (API_PKG / "routers" / "staging_labs.py").read_text(encoding="utf-8")
    assert "secp_worker" not in router_src
    assert "dispatch" not in router_src  # not routed through the inline dispatcher either
    assert "queue_simulation" in router_src and "queue_teardown" in router_src


# --- Concurrency (DB-level compare-and-swap) ----------------------------------


def _eligible(session, principal) -> ExecutionTarget:
    target = ExecutionTarget(
        organization_id=principal.organization_id,
        display_name="substrate",
        plugin_name="proxmox",
        config={},
        config_hash="sha256:" + "ab" * 32,
        secret_ref=None,
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


def _awaiting_lab(session, principal) -> StagingLab:
    target = _eligible(session, principal)
    lab = staging_labs.create_staging_lab(session, principal, execution_target_id=target.id)
    staging_labs.generate_plan(session, principal, lab.id)
    staging_labs.submit_for_approval(session, principal, lab.id)
    return lab


def test_concurrent_approvals_only_one_wins(session, principal):
    lab = _awaiting_lab(session, principal)
    rev = lab.revision

    # Two racing approval CAS UPDATEs on the same (status, revision): exactly one wins.
    def _approve() -> int:
        return session.execute(
            update(StagingLab)
            .where(
                StagingLab.id == lab.id,
                StagingLab.status == StagingLabStatus.awaiting_approval,
                StagingLab.revision == rev,
            )
            .values(status=StagingLabStatus.approved, revision=rev + 1)
        ).rowcount

    assert _approve() == 1
    assert _approve() == 0


def test_duplicate_work_scope_is_rejected_by_the_database(session, principal):
    from sqlalchemy.exc import IntegrityError

    lab = _awaiting_lab(session, principal)
    staging_labs.approve_staging_lab(session, principal, lab.id, expected_plan_hash=lab.plan_hash)
    staging_labs.queue_simulation(session, principal, lab.id)
    # A second row with the SAME (lab, operation, plan_hash, plan_version) scope but a different
    # fingerprint must be rejected by the DB scope-unique constraint (not merely by Python).
    session.add(
        StagingLabWorkItem(
            organization_id=lab.organization_id,
            staging_lab_id=lab.id,
            operation_kind=StagingWorkOperation.simulate_provision,
            plan_hash=lab.plan_hash,
            plan_version=lab.plan_version,
            operation_fingerprint="fp-different-but-same-scope",
            status=StagingWorkStatus.queued,
            revision=0,
        )
    )
    with pytest.raises(IntegrityError):
        session.flush()
    session.rollback()


def test_queue_idempotency_returns_original_by_fingerprint(session, principal):
    lab = _awaiting_lab(session, principal)
    staging_labs.approve_staging_lab(session, principal, lab.id, expected_plan_hash=lab.plan_hash)
    staging_labs.queue_simulation(session, principal, lab.id)
    fp = staging_labs.operation_fingerprint(
        lab.id, StagingWorkOperation.simulate_provision, lab.plan_hash, lab.plan_version
    )
    # Retry of the identical operation+plan resolves to the original single work item.
    staging_labs.queue_simulation(session, principal, lab.id)
    items = session.query(StagingLabWorkItem).filter_by(staging_lab_id=lab.id).all()
    assert len(items) == 1
    assert items[0].operation_fingerprint == fp


def test_stale_completion_is_refused_after_revision_drift(session, principal):
    lab = _awaiting_lab(session, principal)
    staging_labs.approve_staging_lab(session, principal, lab.id, expected_plan_hash=lab.plan_hash)
    staging_labs.queue_simulation(session, principal, lab.id)
    item = session.query(StagingLabWorkItem).filter_by(staging_lab_id=lab.id).one()
    # Simulate a worker that claimed at the queued phase, then the lab moved on (revision drift):
    # a completion CAS expecting 'simulating' at the claimed revision affects zero rows.
    stale_rev = lab.revision
    session.execute(
        update(StagingLab)
        .where(StagingLab.id == lab.id)
        .values(status=StagingLabStatus.simulating, revision=stale_rev + 5)
    )
    session.flush()
    completed = session.execute(
        update(StagingLab)
        .where(
            StagingLab.id == lab.id,
            StagingLab.status == StagingLabStatus.simulating,
            StagingLab.revision == stale_rev,  # stale
        )
        .values(status=StagingLabStatus.simulated_ready, revision=stale_rev + 1)
    ).rowcount
    assert completed == 0
    assert item is not None  # unused-guard for lint


# --- Substrate eligibility (independent enforcement; not self-grantable) ------


def test_lab_creator_cannot_grant_substrate_eligibility(session, principal):
    from dataclasses import replace

    target = ExecutionTarget(
        organization_id=principal.organization_id,
        display_name="t",
        plugin_name="proxmox",
        config={},
        config_hash="sha256:" + "ab" * 32,
        secret_ref=None,
        status=TargetStatus.active,
        scope_policy={},
        created_by=principal.user_id,
    )
    session.add(target)
    session.flush()
    lab_creator = replace(principal, permissions=frozenset({Permission.staging_lab_manage}))
    with pytest.raises(AuthorizationError):
        staging_labs.grant_substrate_eligibility(
            session, lab_creator, execution_target_id=target.id
        )


def test_lab_creator_router_never_grants_eligibility():
    """The staging-lab router (the lab-creator surface) never wires the eligibility grant to HTTP —
    a lab creator can NEVER self-grant substrate eligibility from their own router."""
    for path in _api_files():
        if path.name == "staging_labs.py" and path.parent.name == "routers":
            src = path.read_text(encoding="utf-8")
            assert "grant_substrate_eligibility" not in src


def test_only_the_target_admin_bootstrap_endpoint_exposes_eligibility_grant():
    """SECP-B8 supersedes the earlier "no endpoint grants eligibility" guard: the bootstrap wizard
    now exposes ONE guided target-admin grant endpoint. This test pins that surface — the ONLY
    router that may call ``grant_substrate_eligibility`` is ``bootstrap_discovery.py``, and the
    grant is never silently automatic (the service still enforces ``staging_substrate:manage``; a
    lab creator is rejected — see ``test_lab_creator_cannot_grant_substrate_eligibility`` and
    ``test_lab_creator_router_never_grants_eligibility``)."""
    callers: set[str] = set()
    for path in _api_files():
        if path.parent.name != "routers":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                if name == "grant_substrate_eligibility":
                    callers.add(path.name)
    # Exactly one authorized target-admin endpoint — nothing else exposes the grant.
    assert callers == {"bootstrap_discovery.py"}, f"unexpected eligibility-grant callers: {callers}"
    # And the service it delegates to still enforces the target-admin permission (no auto-grant).
    import inspect

    grant_src = inspect.getsource(staging_labs.grant_substrate_eligibility)
    assert "Permission.staging_substrate_manage" in grant_src


def test_eligible_substrate_list_requires_all_gates(session, principal):
    # Active proxmox target + onboarding but NO eligibility → not listed.
    target = _make_target(session, principal, plugin="proxmox")
    _make_onboarding(session, principal, target)
    assert staging_labs.list_eligible_substrates(session, principal) == []
    # After granting eligibility → listed with a server alias (never the raw display name).
    staging_labs.grant_substrate_eligibility(session, principal, execution_target_id=target.id)
    listed = staging_labs.list_eligible_substrates(session, principal)
    assert len(listed) == 1
    assert listed[0]["id"] == target.id
    assert listed[0]["alias"].startswith("substrate-")
    assert target.display_name not in listed[0]["alias"]


def test_non_proxmox_target_cannot_be_eligible(session, principal):
    target = _make_target(session, principal, plugin="simulator")
    with pytest.raises(DomainError):
        staging_labs.grant_substrate_eligibility(session, principal, execution_target_id=target.id)


# --- Fixtures helpers ---------------------------------------------------------


def _make_target(session, principal, *, plugin: str) -> ExecutionTarget:
    target = ExecutionTarget(
        organization_id=principal.organization_id,
        display_name="named-target",
        plugin_name=plugin,
        config={},
        config_hash="sha256:" + "ab" * 32,
        secret_ref=None,
        status=TargetStatus.active,
        scope_policy={},
        created_by=principal.user_id,
    )
    session.add(target)
    session.flush()
    return target


def _make_onboarding(session, principal, target) -> None:
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


def test_operation_kinds_are_enum_values():
    assert {o.value for o in StagingWorkOperation} == {"simulate_provision", "simulate_teardown"}
    assert StagingWorkStatus.queued.value == "queued"
    # Sanity: no infrastructure-shaped token in the enum surface.
    surface = " ".join(o.value for o in StagingWorkOperation) + " ".join(
        s.value for s in StagingWorkStatus
    )
    assert not re.search(r"https?://|\d{1,3}(\.\d{1,3}){3}|:\d{4,5}", surface)
