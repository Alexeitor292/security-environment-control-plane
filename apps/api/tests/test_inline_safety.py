"""Hardening §1 — the InlineDispatcher safety boundary.

Proves inline (in-process) execution is impossible for production and for any
non-simulated (real provider) plugin, and that refusals are audited.
"""

from __future__ import annotations

import copy

import pytest
from secp_api.config import Settings
from secp_api.dispatch import InlineDispatcher, get_dispatcher
from secp_api.enums import AuditAction
from secp_api.models import AuditEvent
from secp_api.registry import get_registry
from secp_api.safety import InlineExecutionForbidden, assert_inline_execution_allowed
from secp_plugin_api.v1 import HealthReport
from secp_plugin_simulator import SimulatorPlugin


class FakeRealPlugin:
    """A stand-in for a future real provider plugin (e.g. Proxmox).

    Read-only capabilities delegate to the Simulator so plan generation works, but
    it declares simulated=false and refuses to perform side effects, mirroring a
    real plugin that must run only through the worker/Temporal path.
    """

    name = "fake-real"
    version = "0.0.1"
    simulated = False

    def __init__(self) -> None:
        self._sim = SimulatorPlugin()

    def health(self) -> HealthReport:
        return HealthReport(
            name=self.name,
            version=self.version,
            contract_version="1",
            healthy=True,
            simulated=False,  # <-- the critical flag
            capabilities=["validate", "plan", "apply", "status", "reset", "destroy", "health"],
        )

    def validate(self, spec):
        return self._sim.validate(spec)

    def plan(self, spec, targets):
        return self._sim.plan(spec, targets)

    def apply(self, plan, context):  # pragma: no cover - must never run inline
        raise AssertionError("real plugin apply must not run inline")

    def status(self, instance_id, context):  # pragma: no cover
        raise AssertionError("not used")

    def reset(self, plan, instance_id, context):  # pragma: no cover
        raise AssertionError("real plugin reset must not run inline")

    def destroy(self, instance_ids, context):  # pragma: no cover
        raise AssertionError("real plugin destroy must not run inline")


# --- unit-level guard tests ---------------------------------------------------


def test_guard_allows_simulated_plugin_in_dev():
    settings = Settings(app_env="dev", auth_dev_mode=True, workflow_dispatch_mode="inline")
    # Should not raise.
    assert_inline_execution_allowed(SimulatorPlugin(), settings=settings)


def test_guard_refuses_non_simulated_plugin():
    settings = Settings(app_env="dev", auth_dev_mode=True, workflow_dispatch_mode="inline")
    with pytest.raises(InlineExecutionForbidden):
        assert_inline_execution_allowed(FakeRealPlugin(), settings=settings)


def test_guard_refuses_production():
    settings = Settings(
        app_env="production", auth_dev_mode=False, workflow_dispatch_mode="temporal"
    )
    with pytest.raises(InlineExecutionForbidden):
        assert_inline_execution_allowed(SimulatorPlugin(), settings=settings)


def test_get_dispatcher_refuses_inline_in_production():
    # A valid production Settings forces temporal; force the unsafe combination by
    # constructing a non-production Settings then flipping app_env for the check.
    settings = Settings(
        app_env="production", auth_dev_mode=False, workflow_dispatch_mode="temporal"
    )
    object.__setattr__(settings, "workflow_dispatch_mode", "inline")
    with pytest.raises(InlineExecutionForbidden):
        get_dispatcher(settings)


def test_get_dispatcher_returns_inline_in_dev():
    settings = Settings(app_env="dev", auth_dev_mode=True, workflow_dispatch_mode="inline")
    assert isinstance(get_dispatcher(settings), InlineDispatcher)


# --- end-to-end: deploy with a real plugin is refused and audited -------------


@pytest.fixture
def fake_real_registered():
    reg = get_registry()
    reg.register(FakeRealPlugin())
    try:
        yield
    finally:
        reg.unregister("fake-real")


def _real_plugin_definition(valid_definition):
    d = copy.deepcopy(valid_definition)
    # Select the real plugin first so orchestration picks it.
    d["spec"]["requiredPlugins"] = ["fake-real", "simulator"]
    return d


def test_inline_deploy_with_real_plugin_is_refused_and_audited(
    session, principal, valid_definition, fake_real_registered
):
    from secp_api.services import catalog, exercises, planning

    definition = _real_plugin_definition(valid_definition)
    template = catalog.create_template(session, principal, name="T", slug="t-real")
    version = catalog.create_version(
        session, principal, template_id=template.id, definition=definition
    )
    exercise = exercises.create_exercise(
        session, principal, template_id=template.id, version_id=version.id, name="x"
    )
    exercises.validate_exercise(session, principal, exercise.id)
    plan = planning.generate_plan(session, principal, exercise.id)  # read-only plan OK
    planning.submit_plan(session, principal, plan.id)
    planning.approve_plan(session, principal, plan.id, "approved")
    session.commit()

    # Even with an APPROVED plan, inline execution of a non-simulated plugin fails.
    with pytest.raises(InlineExecutionForbidden):
        exercises.start_exercise(session, principal, exercise.id)

    refusals = (
        session.query(AuditEvent)
        .filter(AuditEvent.action == AuditAction.execution_refused.value)
        .all()
    )
    assert len(refusals) >= 1
    assert refusals[0].outcome == "denied"

    # The exercise did not advance into deploying/running.
    refreshed = exercises.get_exercise(session, principal, exercise.id)
    assert refreshed.lifecycle_state.value == "approved"
