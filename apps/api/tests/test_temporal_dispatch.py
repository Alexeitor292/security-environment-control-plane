"""Slice 8 — Temporal dispatcher enqueues (queued runs + request construction)."""

from __future__ import annotations

import pytest
from secp_api.config import Settings
from secp_api.dispatch import (
    InlineDispatcher,
    TemporalDispatcher,
    TemporalWorkflowRequest,
    WorkflowOutboxPublisher,
    get_dispatcher,
)
from secp_api.enums import WorkflowKind, WorkflowStatus
from secp_api.models import WorkflowDispatchOutbox


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

    assert run.kind == WorkflowKind.deploy
    assert run.status == WorkflowStatus.queued
    assert run.dispatch_mode == "temporal"
    assert run.workflow_id and run.workflow_id.startswith("deploy-")
    assert sub.requests == []
    outbox = session.query(WorkflowDispatchOutbox).one()
    assert outbox.status == "pending"
    assert outbox.workflow == "DeployWorkflow"
    assert outbox.args["exercise_id"] == str(exercise.id)
    assert outbox.args["workflow_run_id"] == str(run.id)

    session.commit()
    assert WorkflowOutboxPublisher(_settings(), submitter=sub).publish_pending(session) == 1
    session.commit()
    assert len(sub.requests) == 1
    req = sub.requests[0]
    assert req.workflow == "DeployWorkflow"
    assert req.args["exercise_id"] == str(exercise.id)
    assert req.args["workflow_run_id"] == str(run.id)
    assert session.query(WorkflowDispatchOutbox).one().status == "submitted"


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

    assert run.kind == WorkflowKind.discover
    assert run.status == WorkflowStatus.queued
    assert run.exercise_id is None
    assert run.snapshot_id == snap.id
    assert run.execution_target_id == target.id
    assert sub.requests == []
    outbox = session.query(WorkflowDispatchOutbox).one()
    assert outbox.workflow == "DiscoverWorkflow"
    assert outbox.args["snapshot_id"] == str(snap.id)

    session.commit()
    WorkflowOutboxPublisher(_settings(), submitter=sub).publish_pending(session)
    session.commit()
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


def test_temporal_submission_waits_for_committed_outbox(session, principal, valid_definition):
    from secp_api.db import get_sessionmaker
    from secp_api.services import catalog, exercises

    template = catalog.create_template(session, principal, name="T2", slug="t-temporal-2")
    version = catalog.create_version(
        session, principal, template_id=template.id, definition=valid_definition
    )
    exercise = exercises.create_exercise(
        session, principal, template_id=template.id, version_id=version.id, name="x2"
    )
    session.commit()

    sub = FakeSubmitter()
    dispatcher = TemporalDispatcher(_settings(), submitter=sub)
    dispatcher.dispatch_deploy(session, exercise.id)

    factory = get_sessionmaker()
    independent = factory()
    try:
        assert WorkflowOutboxPublisher(_settings(), submitter=sub).publish_pending(independent) == 0
        independent.commit()
    finally:
        independent.close()
    assert sub.requests == []

    session.commit()
    independent = factory()
    try:
        assert WorkflowOutboxPublisher(_settings(), submitter=sub).publish_pending(independent) == 1
        independent.commit()
    finally:
        independent.close()
    assert len(sub.requests) == 1


def test_rollback_creates_no_temporal_submission(session, principal, valid_definition):
    from secp_api.services import catalog, exercises

    template = catalog.create_template(session, principal, name="T3", slug="t-temporal-3")
    version = catalog.create_version(
        session, principal, template_id=template.id, definition=valid_definition
    )
    exercise = exercises.create_exercise(
        session, principal, template_id=template.id, version_id=version.id, name="x3"
    )
    session.commit()

    sub = FakeSubmitter()
    TemporalDispatcher(_settings(), submitter=sub).dispatch_deploy(session, exercise.id)
    session.rollback()

    assert WorkflowOutboxPublisher(_settings(), submitter=sub).publish_pending(session) == 0
    assert sub.requests == []


def test_discovery_outbox_is_not_visible_before_snapshot_and_run_commit(session, principal):
    from secp_api.db import get_sessionmaker
    from secp_api.services import inventory, targets

    target = targets.register_target(
        session,
        principal,
        display_name="Lab",
        plugin_name="proxmox",
        config={"base_url": "https://proxmox.example.test:8006", "verify_tls": True},
        secret_ref="env:SECP_PROVIDER_SECRET__T",
        address_spaces=[],
    )
    dispatcher = TemporalDispatcher(_settings())
    snap = inventory.request_discovery(session, principal, target.id, dispatcher=dispatcher)
    assert snap.workflow_run_id is not None

    sub = FakeSubmitter()
    factory = get_sessionmaker()
    independent = factory()
    try:
        assert WorkflowOutboxPublisher(_settings(), submitter=sub).publish_pending(independent) == 0
        independent.commit()
    finally:
        independent.close()
    assert sub.requests == []

    session.commit()
    independent = factory()
    try:
        assert WorkflowOutboxPublisher(_settings(), submitter=sub).publish_pending(independent) == 1
        independent.commit()
    finally:
        independent.close()
    assert sub.requests[0].workflow == "DiscoverWorkflow"
    assert sub.requests[0].args["snapshot_id"] == str(snap.id)


def test_publish_failure_remains_retryable_and_retry_is_idempotent(
    session, principal, valid_definition
):
    from secp_api.services import catalog, exercises

    class FlakySubmitter:
        def __init__(self):
            self.requests: list[TemporalWorkflowRequest] = []
            self.fail = True

        def submit(self, request: TemporalWorkflowRequest) -> None:
            self.requests.append(request)
            if self.fail:
                raise RuntimeError("boom with no secret")

    template = catalog.create_template(session, principal, name="T4", slug="t-temporal-4")
    version = catalog.create_version(
        session, principal, template_id=template.id, definition=valid_definition
    )
    exercise = exercises.create_exercise(
        session, principal, template_id=template.id, version_id=version.id, name="x4"
    )
    session.commit()

    dispatcher = TemporalDispatcher(_settings())
    dispatcher.dispatch_deploy(session, exercise.id)
    session.commit()

    submitter = FlakySubmitter()
    publisher = WorkflowOutboxPublisher(_settings(), submitter=submitter)
    assert publisher.publish_pending(session) == 0
    outbox = session.query(WorkflowDispatchOutbox).one()
    assert outbox.status == "failed"
    assert outbox.attempts == 1
    assert outbox.last_error == "RuntimeError: workflow submission failed"

    submitter.fail = False
    assert publisher.publish_pending(session) == 1
    assert session.query(WorkflowDispatchOutbox).one().status == "submitted"
    assert len({request.workflow_id for request in submitter.requests}) == 1

    assert publisher.publish_pending(session) == 0
    assert len(submitter.requests) == 2
