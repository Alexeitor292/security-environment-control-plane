"""Durable Temporal dispatch + worker-origination for the eligibility preflight (B1B-PR3 amendment).

Proves: the API is enqueue-only (durable WorkflowRun + outbox, no target contact); inline execution
is refused with no in-process fallback; the workflow + activity are registered by the WORKER only;
the activity loads authoritative records and runs the sealed-by-default seam end to end (refusing at
the seal, contacting nothing); and live-evidence persistence is structurally worker-originated (the
API imports none of the worker execution/persistence symbols; the recorder's only caller is the
worker seam).
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from secp_api.config import Settings
from secp_api.dispatch import InlineDispatcher, TemporalDispatcher
from secp_api.enums import WorkflowKind
from secp_api.models import (
    TargetEvidenceRecord,
    TargetPreflight,
    WorkflowDispatchOutbox,
    WorkflowRun,
)
from secp_api.safety import InlineExecutionForbidden
from sqlalchemy import select
from tests._eligibility_fixtures import NOW, _build_chain  # type: ignore

_REPO = Path(__file__).resolve().parents[2]


# --- Enqueue-only durable dispatch ---------------------------------------------------------------


def test_temporal_dispatch_enqueues_durable_state_and_contacts_nothing(session, principal):
    chain = _build_chain(session)
    dispatcher = TemporalDispatcher(Settings(app_env="test", workflow_dispatch_mode="temporal"))
    run = dispatcher.dispatch_real_eligibility_preflight(session, chain.onboarding.id)

    assert run.kind == WorkflowKind.eligibility_preflight
    assert run.organization_id == chain.org_id
    assert run.execution_target_id == chain.target.id
    assert run.workflow_id == f"eligibility_preflight-{run.id}"

    outbox = session.execute(
        select(WorkflowDispatchOutbox).where(WorkflowDispatchOutbox.workflow_run_id == run.id)
    ).scalar_one()
    assert outbox.workflow == "EligibilityPreflightWorkflow"
    assert outbox.args == {
        "onboarding_id": str(chain.onboarding.id),
        "workflow_run_id": str(run.id),
    }
    assert outbox.status == "pending"

    # Enqueue contacted nothing: no evidence/preflight was created by the API.
    assert session.execute(select(TargetPreflight)).scalars().all() == []
    assert session.execute(select(TargetEvidenceRecord)).scalars().all() == []


def test_inline_dispatch_refuses_with_no_fallback(session, principal):
    chain = _build_chain(session)
    with pytest.raises(InlineExecutionForbidden):
        InlineDispatcher().dispatch_real_eligibility_preflight(session, chain.onboarding.id)
    # No durable state and no evidence were created by the refused inline attempt.
    assert session.execute(select(WorkflowRun)).scalars().all() == []
    assert session.execute(select(TargetPreflight)).scalars().all() == []


def test_api_request_refuses_inline_and_creates_no_run(session, principal):
    from secp_api.services import eligibility as elig

    chain = _build_chain(session)
    with pytest.raises(InlineExecutionForbidden):
        elig.request_eligibility_preflight(session, principal, chain.onboarding.id)
    assert session.execute(select(WorkflowRun)).scalars().all() == []


# --- Worker-only registration --------------------------------------------------------------------


def test_activity_and_workflow_defined_and_registered_by_worker_only():
    from secp_worker import temporal_app

    assert hasattr(temporal_app, "eligibility_preflight_activity")
    assert hasattr(temporal_app, "EligibilityPreflightWorkflow")

    main_src = (_REPO / "worker" / "secp_worker" / "main.py").read_text(encoding="utf-8")
    assert "EligibilityPreflightWorkflow" in main_src
    assert "eligibility_preflight_activity" in main_src


# --- Structural worker-origination of live evidence ----------------------------------------------


def _imported_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            names.update(a.name for a in node.names)
            if node.module:
                names.add(node.module)
        elif isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
    return names


def test_api_imports_no_worker_live_execution_or_persistence_symbols():
    forbidden = {
        "run_real_eligibility_preflight",
        "run_live_readonly_collection",
        "record_live_eligibility_evidence",
        "LiveReadOnlyProxmoxCollector",
        "build_eligibility_composition",
        "secp_worker.onboarding.eligibility_preflight",
        "secp_worker.onboarding.eligibility_recorder",
        "secp_worker.onboarding.live_readonly",
    }
    api_pkg = _REPO / "api" / "secp_api"
    for path in api_pkg.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        leaked = _imported_names(path) & forbidden
        assert not leaked, f"API file {path.name} imports worker live symbols {leaked}"


def test_recorder_is_worker_only_and_sole_caller_is_the_seam():
    # The recorder physically lives in the worker package (API cannot import it).
    assert (_REPO / "worker" / "secp_worker" / "onboarding" / "eligibility_recorder.py").exists()
    assert not (_REPO / "api" / "secp_api" / "services" / "eligibility_recorder.py").exists()

    # The only non-test worker source that calls the recorder is the eligibility seam.
    worker_pkg = _REPO / "worker" / "secp_worker"
    callers = []
    for path in worker_pkg.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        if "record_live_eligibility_evidence(" in path.read_text(encoding="utf-8"):
            callers.append(path.name)
    assert set(callers) <= {"eligibility_preflight.py", "eligibility_recorder.py"}, callers


def test_run_real_eligibility_preflight_sole_caller_is_the_activity():
    worker_pkg = _REPO / "worker" / "secp_worker"
    callers = []
    for path in worker_pkg.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        if "run_real_eligibility_preflight(" in text:
            callers.append(path.name)
    # Defined + called in eligibility_preflight.py; invoked by the Temporal activity body in
    # in temporal_app.py. No other worker source calls it.
    assert set(callers) <= {"eligibility_preflight.py", "temporal_app.py"}, callers


# --- Durable activity body runs the sealed seam end to end ----------------------------------------


def test_activity_body_runs_sealed_seam_and_persists_nothing(session, principal):
    from secp_worker.onboarding.eligibility_provider import SealedEligibilityCompositionProvider
    from secp_worker.temporal_app import run_eligibility_preflight_activity_body

    chain = _build_chain(session)
    dispatcher = TemporalDispatcher(Settings(app_env="test", workflow_dispatch_mode="temporal"))
    run = dispatcher.dispatch_real_eligibility_preflight(session, chain.onboarding.id)
    session.commit()  # the activity opens its OWN worker session_scope; it must see committed state

    # The shipped worker injects the SEALED provider; the body obtains the composition from it only.
    outcome = run_eligibility_preflight_activity_body(
        {"onboarding_id": str(chain.onboarding.id), "workflow_run_id": str(run.id)},
        eligibility_provider=SealedEligibilityCompositionProvider(),
    )
    assert outcome == "refused"  # sealed composition → refused before any contact

    session.expire_all()
    # No live evidence was persisted (the seam refused at the seal).
    assert session.execute(select(TargetPreflight)).scalars().all() == []
    assert session.execute(select(TargetEvidenceRecord)).scalars().all() == []
    # The durable run was completed by the activity.
    reloaded = session.get(WorkflowRun, run.id)
    assert reloaded is not None and reloaded.status.value == "completed"


def test_resolution_fails_closed_when_no_approved_authorization(session, principal):
    """When no approved live-read authorization exists, resolution fails closed (no request), so the
    activity refuses without any seam contact."""
    from secp_api.enums import LiveReadAuthorizationStatus
    from secp_worker.onboarding.eligibility_preflight import resolve_eligibility_preflight_request

    chain = _build_chain(session, over={"auth_status": LiveReadAuthorizationStatus.draft})
    request, reason = resolve_eligibility_preflight_request(session, chain.onboarding.id, NOW)
    assert request is None
    assert reason is not None and reason.value == "authorization_invalid"


def test_resolution_succeeds_with_full_chain(session, principal):
    from secp_worker.onboarding.eligibility_preflight import resolve_eligibility_preflight_request

    chain = _build_chain(session)
    request, reason = resolve_eligibility_preflight_request(session, chain.onboarding.id, NOW)
    assert reason is None
    assert request is not None
    assert request.onboarding_id == chain.onboarding.id
    assert request.authorization_id == chain.authorization.id
    assert request.worker_identity_registration_id == chain.worker_reg.id
