"""Hardening §1 — the InlineDispatcher safety boundary (closed-world allowlist).

Proves inline (in-process) execution is impossible for production and for any
plugin not explicitly registered as inline-safe by the trusted PluginRegistry,
regardless of what the plugin's health() method reports.
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
    """Stand-in for a future real provider plugin (e.g. Proxmox).

    Declares simulated=False — must be refused by the registry allowlist check.
    """

    name = "fake-real"
    version = "0.0.1"

    def __init__(self) -> None:
        self._sim = SimulatorPlugin()

    def health(self) -> HealthReport:
        return HealthReport(
            name=self.name,
            version=self.version,
            contract_version="1",
            healthy=True,
            simulated=False,
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


class FakeSimulatedClaimPlugin(FakeRealPlugin):
    """A plugin that dishonestly claims simulated=True.

    Under the old self-attestation model this would bypass the guard.
    Under the closed-world allowlist model it must still be refused because it
    is not registered with inline_safe=True.
    """

    name = "fake-simulated-claim"

    def health(self) -> HealthReport:
        return HealthReport(
            name=self.name,
            version=self.version,
            contract_version="1",
            healthy=True,
            simulated=True,  # dishonest claim — must not be authoritative
            capabilities=["validate", "plan", "apply", "status", "reset", "destroy", "health"],
        )


# ---------------------------------------------------------------------------
# Unit-level guard tests
# ---------------------------------------------------------------------------


def test_guard_allows_builtin_simulator_in_dev():
    """Built-in SimulatorPlugin is in the closed-world allowlist — must succeed."""
    settings = Settings(app_env="dev", auth_dev_mode=True, workflow_dispatch_mode="inline")
    # Should not raise.
    assert_inline_execution_allowed(SimulatorPlugin(), settings=settings)


def test_guard_refuses_non_simulated_plugin():
    """Plugin with simulated=False that is not in the allowlist must be refused."""
    settings = Settings(app_env="dev", auth_dev_mode=True, workflow_dispatch_mode="inline")
    plugin = FakeRealPlugin()
    # Must be refused even though it is registered (no inline_safe=True).
    get_registry()  # ensure registry is initialized
    with pytest.raises(InlineExecutionForbidden):
        assert_inline_execution_allowed(plugin, settings=settings)


def test_guard_refuses_plugin_claiming_simulated_true_when_not_allowlisted():
    """A plugin that reports simulated=True but is NOT registry-allowlisted must be refused.

    This is the critical closed-world test: plugin self-attestation via
    health().simulated is not the authorization control.
    """
    settings = Settings(app_env="dev", auth_dev_mode=True, workflow_dispatch_mode="inline")
    plugin = FakeSimulatedClaimPlugin()
    # Confirm the plugin claims simulated=True.
    assert plugin.health().simulated is True
    # The plugin is not registered with inline_safe=True, so must be refused.
    with pytest.raises(InlineExecutionForbidden) as exc_info:
        assert_inline_execution_allowed(plugin, settings=settings)
    assert "not in the inline-execution allowlist" in str(exc_info.value)


def test_guard_refuses_production():
    """Production must always refuse inline execution, even for the Simulator."""
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


def test_registry_inline_safe_only_for_simulator():
    """Only the SimulatorPlugin is inline-safe in the standard registry."""
    reg = get_registry()
    assert reg.is_inline_safe("simulator") is True


def test_registry_inline_safe_false_by_default_for_new_plugin():
    """A plugin registered without inline_safe=True must not be inline-safe."""
    reg = get_registry()
    # Register without inline_safe (the default).
    fake = FakeRealPlugin()
    reg.register(fake)
    try:
        assert reg.is_inline_safe("fake-real") is False
    finally:
        reg.unregister("fake-real")


# ---------------------------------------------------------------------------
# End-to-end: deploy with a non-allowlisted plugin is refused and audited
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_real_registered():
    reg = get_registry()
    reg.register(FakeRealPlugin())  # no inline_safe=True
    try:
        yield
    finally:
        reg.unregister("fake-real")


@pytest.fixture
def fake_simulated_claim_registered():
    reg = get_registry()
    reg.register(FakeSimulatedClaimPlugin())  # no inline_safe=True, but claims simulated=True
    try:
        yield
    finally:
        reg.unregister("fake-simulated-claim")


def _real_plugin_definition(valid_definition):
    d = copy.deepcopy(valid_definition)
    d["spec"]["requiredPlugins"] = ["fake-real", "simulator"]
    return d


def _simulated_claim_definition(valid_definition):
    d = copy.deepcopy(valid_definition)
    d["spec"]["requiredPlugins"] = ["fake-simulated-claim", "simulator"]
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
    plan = planning.generate_plan(session, principal, exercise.id)
    planning.submit_plan(session, principal, plan.id)
    planning.approve_plan(session, principal, plan.id, "approved")
    session.commit()

    with pytest.raises(InlineExecutionForbidden):
        exercises.start_exercise(session, principal, exercise.id)

    refusals = (
        session.query(AuditEvent)
        .filter(AuditEvent.action == AuditAction.execution_refused.value)
        .all()
    )
    assert len(refusals) >= 1
    assert refusals[0].outcome == "denied"

    # Exercise must not have advanced past approved.
    refreshed = exercises.get_exercise(session, principal, exercise.id)
    assert refreshed.lifecycle_state.value == "approved"


def test_inline_deploy_refused_even_when_plugin_claims_simulated_true(
    session, principal, valid_definition, fake_simulated_claim_registered
):
    """A plugin claiming simulated=True but not in the allowlist must be refused.

    This is the closed-world e2e test: self-attestation must not bypass the guard
    even at the full service-layer level.
    """
    from secp_api.services import catalog, exercises, planning

    definition = _simulated_claim_definition(valid_definition)
    template = catalog.create_template(session, principal, name="T2", slug="t-simclaim")
    version = catalog.create_version(
        session, principal, template_id=template.id, definition=definition
    )
    exercise = exercises.create_exercise(
        session, principal, template_id=template.id, version_id=version.id, name="x2"
    )
    exercises.validate_exercise(session, principal, exercise.id)
    plan = planning.generate_plan(session, principal, exercise.id)
    planning.submit_plan(session, principal, plan.id)
    planning.approve_plan(session, principal, plan.id, "approved")
    session.commit()

    # Must be refused despite health().simulated == True.
    with pytest.raises(InlineExecutionForbidden) as exc_info:
        exercises.start_exercise(session, principal, exercise.id)
    assert "not in the inline-execution allowlist" in str(exc_info.value)

    # Refusal was audited.
    refusals = (
        session.query(AuditEvent)
        .filter(AuditEvent.action == AuditAction.execution_refused.value)
        .all()
    )
    assert len(refusals) >= 1
    # Exercise state unchanged.
    refreshed = exercises.get_exercise(session, principal, exercise.id)
    assert refreshed.lifecycle_state.value == "approved"
