"""Slice 8 — Temporal dispatcher enqueues (queued runs + request construction)."""

from __future__ import annotations

import pytest
from secp_api.config import Settings
from secp_api.dispatch import (
    InlineDispatcher,
    TemporalDispatcher,
    TemporalWorkflowRequest,
    get_dispatcher,
)
from secp_api.enums import WorkflowKind, WorkflowStatus


class FakeSubmitter:
    def __init__(self):
        self.requests: list[TemporalWorkflowRequest] = []

    def submit(self, request: TemporalWorkflowRequest) -> None:
        self.requests.append(request)


def _settings():
    return Settings(app_env="test", workflow_dispatch_mode="temporal", auth_dev_mode=True)


def test_get_dispatcher_returns_temporal_in_temporal_mode():
    sub = FakeSubmitter()
    dispatcher = get_dispatcher(_settings(), submitter=sub)
    assert isinstance(dispatcher, TemporalDispatcher)


def test_dispatch_deploy_queues_run_and_submits_request(session, principal, valid_definition):
    from secp_api.services import catalog, exercises

    template = catalog.create_template(session, principal, name="T", slug="t-temporal")
    version = catalog.create_version(
        session, principal, template_id=template.id, definition=valid_definition
    )
    exercise = exercises.create_exercise(
        session, principal, template_id=template.id, version_id=version.id, name="x"
    )
    session.commit()

    sub = FakeSubmitter()
    dispatcher = TemporalDispatcher(_settings(), submitter=sub)
    run = dispatcher.dispatch_deploy(session, exercise.id)
    session.commit()

    assert run.kind == WorkflowKind.deploy
    assert run.status == WorkflowStatus.queued
    assert run.dispatch_mode == "temporal"
    assert run.workflow_id and run.workflow_id.startswith("deploy-")
    assert len(sub.requests) == 1
    req = sub.requests[0]
    assert req.workflow == "DeployWorkflow"
    assert req.args["exercise_id"] == str(exercise.id)
    assert req.args["workflow_run_id"] == str(run.id)


def test_dispatch_discovery_queues_run_and_submits_request(session, principal):
    from secp_api.services import inventory, targets

    target = targets.register_target(
        session,
        principal,
        display_name="Lab",
        plugin_name="proxmox",
        config={"base_url": "https://proxmox.example.test:8006"},
        secret_ref="env:SECP_PROVIDER_SECRET__T",
        address_spaces=[],
    )
    snap = inventory.request_discovery(session, principal, target.id)
    session.commit()

    sub = FakeSubmitter()
    dispatcher = TemporalDispatcher(_settings(), submitter=sub)
    run = dispatcher.dispatch_discovery(session, snap.id)
    session.commit()

    assert run.kind == WorkflowKind.discover
    assert run.status == WorkflowStatus.queued
    assert run.exercise_id is None
    assert run.snapshot_id == snap.id
    assert run.execution_target_id == target.id
    req = sub.requests[0]
    assert req.workflow == "DiscoverWorkflow"
    assert req.args["snapshot_id"] == str(snap.id)


def test_inline_dispatcher_refuses_discovery(session, principal):
    from secp_api.safety import InlineExecutionForbidden
    from secp_api.services import inventory, targets

    target = targets.register_target(
        session,
        principal,
        display_name="Lab",
        plugin_name="proxmox",
        config={"base_url": "https://proxmox.example.test:8006"},
        secret_ref="env:SECP_PROVIDER_SECRET__T",
        address_spaces=[],
    )
    snap = inventory.request_discovery(session, principal, target.id)
    session.commit()
    with pytest.raises(InlineExecutionForbidden):
        InlineDispatcher().dispatch_discovery(session, snap.id)
