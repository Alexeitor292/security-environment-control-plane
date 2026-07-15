"""B1B-PR5B — deterministic Temporal task-queue routing (ADR-022 §12).

The controlled-live real-plan-generation workflow and its operator readiness prerequisites route to
the DISTINCT operator queue WHEN one is configured; every other workflow (and ALL workflows when no
operator worker is deployed) stays on the shipped queue where the sealed worker refuses. These prove
the routing is deterministic per workflow kind, that a shared/blank/wildcard operator queue is
refused or treated as unconfigured, and that the outbox row pins the resolved queue at enqueue time.
"""

from __future__ import annotations

import uuid

import pytest
from secp_api.config import Settings
from secp_api.enums import WorkflowKind
from secp_api.workflow_routing import (
    CONTROLLED_LIVE_OPERATOR_WORKFLOW_KINDS,
    OperatorTaskQueueUnavailable,
    is_controlled_live_operator_kind,
    operator_queue_configured,
    resolve_operator_task_queue,
    resolve_task_queue,
)

_OPERATOR_QUEUE = "secp-operator-plan"


def _settings(**over) -> Settings:
    base = dict(temporal_task_queue="secp-orchestration")
    base.update(over)
    return Settings(**base)


# --- the controlled-live kind set ----------------------------------------------------------------


def test_controlled_live_kinds_are_exactly_the_five_operator_owned_workflows():
    assert CONTROLLED_LIVE_OPERATOR_WORKFLOW_KINDS == {
        WorkflowKind.eligibility_preflight.value,
        WorkflowKind.toolchain_attestation.value,
        WorkflowKind.remote_state_readiness.value,
        WorkflowKind.plan_secret_readiness.value,
        WorkflowKind.real_plan_generation.value,
    }
    # Deploy / reset / destroy / discover are NEVER operator-owned.
    for kind in (
        WorkflowKind.deploy,
        WorkflowKind.reset,
        WorkflowKind.destroy,
        WorkflowKind.discover,
    ):
        assert not is_controlled_live_operator_kind(kind)
    # Accepts either the enum or its string value.
    assert is_controlled_live_operator_kind(WorkflowKind.real_plan_generation)
    assert is_controlled_live_operator_kind("real_plan_generation")


# --- resolve_task_queue: deterministic per kind --------------------------------------------------


def test_unconfigured_operator_queue_keeps_everything_on_the_shipped_queue():
    settings = _settings()  # operator queue empty (ordinary production; sealed worker)
    assert not operator_queue_configured(settings)
    for kind in WorkflowKind:
        assert resolve_task_queue(settings, kind) == "secp-orchestration"


def test_configured_operator_queue_routes_only_controlled_live_kinds_to_it():
    settings = _settings(temporal_operator_task_queue=_OPERATOR_QUEUE)
    assert operator_queue_configured(settings)
    # Controlled-live kinds route to the operator queue.
    for value in CONTROLLED_LIVE_OPERATOR_WORKFLOW_KINDS:
        assert resolve_task_queue(settings, value) == _OPERATOR_QUEUE
    # Ordinary kinds stay on the shipped queue.
    for kind in (
        WorkflowKind.deploy,
        WorkflowKind.reset,
        WorkflowKind.destroy,
        WorkflowKind.discover,
    ):
        assert resolve_task_queue(settings, kind) == "secp-orchestration"


def test_resolve_operator_task_queue_fails_closed_without_a_distinct_queue():
    with pytest.raises(OperatorTaskQueueUnavailable):
        resolve_operator_task_queue(_settings())
    # When configured, it returns exactly the distinct operator queue.
    settings = _settings(temporal_operator_task_queue=_OPERATOR_QUEUE)
    assert resolve_operator_task_queue(settings) == _OPERATOR_QUEUE


# --- config validation: distinct, whitespace-free, non-wildcard ----------------------------------


def test_operator_queue_equal_to_shipped_queue_is_refused():
    with pytest.raises(ValueError, match="DISTINCT"):
        _settings(temporal_operator_task_queue="secp-orchestration")


@pytest.mark.parametrize(
    "bad",
    ["secp operator", "secp-op*", "secp-op\tqueue", "x" * 201],
)
def test_operator_queue_shape_is_validated(bad):
    with pytest.raises(ValueError, match="SECP_TEMPORAL_OPERATOR_TASK_QUEUE"):
        _settings(temporal_operator_task_queue=bad)


def test_blank_operator_queue_is_the_default_and_valid():
    settings = _settings()
    assert settings.temporal_operator_task_queue == ""
    assert not operator_queue_configured(settings)


# --- the dispatcher pins the resolved queue on the committed outbox row ---------------------------


class _FakeSession:
    def __init__(self) -> None:
        self.added: list = []

    def add(self, obj) -> None:  # noqa: ANN001
        self.added.append(obj)

    def flush(self) -> None:
        pass


class _Run:
    def __init__(self, kind: WorkflowKind) -> None:
        self.workflow_id = f"{kind.value}-1"
        self.organization_id = uuid.uuid4()
        self.id = uuid.uuid4()
        self.kind = kind


@pytest.mark.parametrize(
    ("kind", "expected"),
    [
        (WorkflowKind.real_plan_generation, _OPERATOR_QUEUE),
        (WorkflowKind.remote_state_readiness, _OPERATOR_QUEUE),
        (WorkflowKind.plan_secret_readiness, _OPERATOR_QUEUE),
        (WorkflowKind.toolchain_attestation, _OPERATOR_QUEUE),
        (WorkflowKind.eligibility_preflight, _OPERATOR_QUEUE),
        (WorkflowKind.deploy, "secp-orchestration"),
        (WorkflowKind.discover, "secp-orchestration"),
    ],
)
def test_queue_outbox_pins_the_resolved_task_queue_per_kind(kind, expected):
    from secp_api.dispatch import TemporalDispatcher

    settings = _settings(temporal_operator_task_queue=_OPERATOR_QUEUE)
    dispatcher = TemporalDispatcher(settings, submitter=object())
    session = _FakeSession()
    dispatcher._queue_outbox(session, _Run(kind), workflow="W", args={})
    assert len(session.added) == 1
    assert session.added[0].task_queue == expected


def test_without_operator_queue_controlled_live_outbox_stays_on_shipped_queue():
    from secp_api.dispatch import TemporalDispatcher

    settings = _settings()  # no operator worker deployed
    dispatcher = TemporalDispatcher(settings, submitter=object())
    session = _FakeSession()
    dispatcher._queue_outbox(
        session, _Run(WorkflowKind.real_plan_generation), workflow="W", args={}
    )
    # Controlled-live work still enqueues to the shipped queue → the sealed worker refuses
    # (unchanged behaviour), never a silent hang on an unpolled operator queue.
    assert session.added[0].task_queue == "secp-orchestration"


class _StubSettings:
    """A duck-typed settings that BYPASSES Settings validation (proves routing's own defence)."""

    def __init__(self, shipped: str, operator: str) -> None:
        self.temporal_task_queue = shipped
        self.temporal_operator_task_queue = operator


def test_routing_defends_in_depth_against_an_equal_queue_even_past_settings_validation():
    # A shared queue that somehow bypassed Settings validation is still treated as unconfigured, so
    # controlled-live work stays on the shipped queue and resolve_operator_task_queue fails closed.
    stub = _StubSettings(shipped="secp-orchestration", operator="secp-orchestration")
    assert not operator_queue_configured(stub)
    assert resolve_task_queue(stub, WorkflowKind.real_plan_generation) == "secp-orchestration"
    with pytest.raises(OperatorTaskQueueUnavailable):
        resolve_operator_task_queue(stub)


def test_queue_selection_never_appears_in_request_data_or_temporal_args():
    from secp_api.dispatch import TemporalDispatcher

    settings = _settings(temporal_operator_task_queue=_OPERATOR_QUEUE)
    dispatcher = TemporalDispatcher(settings, submitter=object())
    session = _FakeSession()
    args = {"manifest_id": "m-1", "workflow_run_id": "r-1"}
    dispatcher._queue_outbox(
        session,
        _Run(WorkflowKind.real_plan_generation),
        workflow="RealPlanGenerationWorkflow",
        args=args,
    )
    outbox = session.added[0]
    # The queue is a routing column resolved server-side by KIND — never a caller/request field and
    # never a Temporal workflow argument.
    assert outbox.task_queue == _OPERATOR_QUEUE
    assert "task_queue" not in outbox.args
    assert "queue" not in outbox.args
    assert set(outbox.args) == {"manifest_id", "workflow_run_id"}
