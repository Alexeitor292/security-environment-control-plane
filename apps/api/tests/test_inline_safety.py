"""Hardening §1 — the InlineDispatcher safety boundary (identity-based closed-world).

The inline-execution guard is now fully closed-world and identity-based:

* ``PluginRegistry.register()`` has NO ``inline_safe`` argument — normal
  registration never grants inline permission.
* ``is_inline_safe(plugin)`` performs a Python ``is`` identity check against the
  exact ``SimulatorPlugin`` instance created during bootstrap.
* A fake plugin named "simulator", a new ``SimulatorPlugin()`` instance, or any
  plugin with ``health().simulated=True`` are all refused unless they ARE the
  bootstrapped instance.
"""

from __future__ import annotations

import copy
import inspect

import pytest
from secp_api.config import Settings
from secp_api.dispatch import InlineDispatcher, get_dispatcher
from secp_api.enums import AuditAction
from secp_api.models import AuditEvent
from secp_api.registry import PluginRegistry, PluginRegistryError, get_registry
from secp_api.safety import InlineExecutionForbidden, assert_inline_execution_allowed
from secp_plugin_api.v1 import HealthReport
from secp_plugin_simulator import SimulatorPlugin


class FakeRealPlugin:
    """Stand-in for a future real provider plugin (e.g. Proxmox)."""

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

    def apply(self, plan, context):  # pragma: no cover
        raise AssertionError("real plugin apply must not run inline")

    def status(self, instance_id, context):  # pragma: no cover
        raise AssertionError("not used")

    def reset(self, plan, instance_id, context):  # pragma: no cover
        raise AssertionError("real plugin reset must not run inline")

    def destroy(self, instance_ids, context):  # pragma: no cover
        raise AssertionError("real plugin destroy must not run inline")


class FakeSimulatedClaimPlugin(FakeRealPlugin):
    """Plugin that dishonestly claims simulated=True — must still be refused."""

    name = "fake-simulated-claim"

    def health(self) -> HealthReport:
        return HealthReport(
            name=self.name,
            version=self.version,
            contract_version="1",
            healthy=True,
            simulated=True,  # dishonest — must not be authoritative
            capabilities=["validate", "plan", "apply", "status", "reset", "destroy", "health"],
        )


class FakeSimulatorNamePlugin(FakeRealPlugin):
    """Plugin with name='simulator' — must NOT be able to replace the built-in."""

    name = "simulator"


# ---------------------------------------------------------------------------
# Registry invariant tests
# ---------------------------------------------------------------------------


def test_register_has_no_inline_safe_argument():
    """The public register() API must not expose an inline_safe parameter."""
    sig = inspect.signature(PluginRegistry.register)
    assert "inline_safe" not in sig.parameters, (
        "register() must not have an inline_safe argument; "
        "inline-safe registration is only available via _register_builtin_simulator"
    )


def test_normal_registration_never_inline_safe():
    """Any plugin registered via the public API is never inline-safe."""
    reg = get_registry()
    fake = FakeRealPlugin()
    reg.register(fake)
    try:
        assert reg.is_inline_safe(fake) is False
    finally:
        reg.unregister("fake-real")


def test_is_inline_safe_is_identity_based():
    """Only the exact bootstrapped instance passes is_inline_safe()."""
    reg = get_registry()
    bootstrapped = reg.get("simulator")
    other_instance = SimulatorPlugin()

    assert reg.is_inline_safe(bootstrapped) is True, "bootstrapped instance must be inline-safe"
    assert reg.is_inline_safe(other_instance) is False, (
        "a different SimulatorPlugin() instance must NOT be inline-safe"
    )


def test_fake_plugin_named_simulator_cannot_replace_builtin():
    """Registering a plugin with name='simulator' is refused after bootstrap."""
    reg = get_registry()
    impersonator = FakeSimulatorNamePlugin()
    with pytest.raises(PluginRegistryError, match="already registered"):
        reg.register(impersonator)


def test_builtin_simulator_cannot_be_unregistered():
    """The built-in Simulator cannot be removed from the registry."""
    reg = get_registry()
    with pytest.raises(PluginRegistryError, match="cannot be unregistered"):
        reg.unregister("simulator")


def test_duplicate_plugin_registration_refused():
    """Registering the same name twice is always refused."""
    reg = get_registry()
    fake = FakeRealPlugin()
    reg.register(fake)
    try:
        with pytest.raises(PluginRegistryError, match="already registered"):
            reg.register(FakeRealPlugin())
    finally:
        reg.unregister("fake-real")


# ---------------------------------------------------------------------------
# Guard unit tests
# ---------------------------------------------------------------------------


def test_guard_allows_bootstrapped_simulator_in_dev():
    """The bootstrapped SimulatorPlugin (registry.get('simulator')) passes the guard."""
    settings = Settings(app_env="dev", auth_dev_mode=True, workflow_dispatch_mode="inline")
    bootstrapped = get_registry().get("simulator")
    # Should not raise.
    assert_inline_execution_allowed(bootstrapped, settings=settings)


def test_guard_refuses_new_simulator_instance():
    """A fresh SimulatorPlugin() that is not the bootstrapped instance is refused."""
    settings = Settings(app_env="dev", auth_dev_mode=True, workflow_dispatch_mode="inline")
    other_instance = SimulatorPlugin()
    with pytest.raises(InlineExecutionForbidden):
        assert_inline_execution_allowed(other_instance, settings=settings)


def test_guard_refuses_non_simulated_plugin():
    """Plugin with simulated=False that is not the bootstrapped Simulator is refused."""
    settings = Settings(app_env="dev", auth_dev_mode=True, workflow_dispatch_mode="inline")
    with pytest.raises(InlineExecutionForbidden):
        assert_inline_execution_allowed(FakeRealPlugin(), settings=settings)


def test_guard_refuses_plugin_claiming_simulated_true():
    """A plugin reporting simulated=True that is not the bootstrapped instance is refused."""
    settings = Settings(app_env="dev", auth_dev_mode=True, workflow_dispatch_mode="inline")
    plugin = FakeSimulatedClaimPlugin()
    assert plugin.health().simulated is True  # confirms the claim
    with pytest.raises(InlineExecutionForbidden) as exc_info:
        assert_inline_execution_allowed(plugin, settings=settings)
    assert "not the built-in Simulator" in str(exc_info.value)


def test_guard_refuses_production_for_any_plugin():
    """Production always refuses inline execution, even for the bootstrapped Simulator."""
    settings = Settings(
        app_env="production",
        auth_dev_mode=False,
        workflow_dispatch_mode="temporal",
        oidc_issuer="https://idp.example.test/realms/secp",
        oidc_audience="secp-api",
        public_origin="https://secp.example.test",
        cors_allow_origins=[],
    )
    bootstrapped = get_registry().get("simulator")
    with pytest.raises(InlineExecutionForbidden):
        assert_inline_execution_allowed(bootstrapped, settings=settings)


def test_get_dispatcher_refuses_inline_in_production():
    settings = Settings(
        app_env="production",
        auth_dev_mode=False,
        workflow_dispatch_mode="temporal",
        oidc_issuer="https://idp.example.test/realms/secp",
        oidc_audience="secp-api",
        public_origin="https://secp.example.test",
        cors_allow_origins=[],
    )
    object.__setattr__(settings, "workflow_dispatch_mode", "inline")
    with pytest.raises(InlineExecutionForbidden):
        get_dispatcher(settings)


def test_get_dispatcher_returns_inline_in_dev():
    settings = Settings(app_env="dev", auth_dev_mode=True, workflow_dispatch_mode="inline")
    assert isinstance(get_dispatcher(settings), InlineDispatcher)


# ---------------------------------------------------------------------------
# End-to-end: non-bootstrapped plugins are refused and the refusal is audited
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_real_registered():
    reg = get_registry()
    reg.register(FakeRealPlugin())
    try:
        yield
    finally:
        reg.unregister("fake-real")


@pytest.fixture
def fake_simulated_claim_registered():
    reg = get_registry()
    reg.register(FakeSimulatedClaimPlugin())
    try:
        yield
    finally:
        reg.unregister("fake-simulated-claim")


def _plugin_definition(valid_definition, plugins):
    d = copy.deepcopy(valid_definition)
    d["spec"]["requiredPlugins"] = plugins
    return d


def test_inline_deploy_with_real_plugin_is_refused_and_audited(
    session, principal, valid_definition, fake_real_registered
):
    from secp_api.services import catalog, exercises, planning

    definition = _plugin_definition(valid_definition, ["fake-real", "simulator"])
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
    refreshed = exercises.get_exercise(session, principal, exercise.id)
    assert refreshed.lifecycle_state.value == "approved"


def test_inline_deploy_refused_even_when_plugin_claims_simulated_true(
    session, principal, valid_definition, fake_simulated_claim_registered
):
    """Self-attestation (simulated=True) does not bypass the identity guard."""
    from secp_api.services import catalog, exercises, planning

    definition = _plugin_definition(valid_definition, ["fake-simulated-claim", "simulator"])
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

    with pytest.raises(InlineExecutionForbidden) as exc_info:
        exercises.start_exercise(session, principal, exercise.id)
    assert "not the built-in Simulator" in str(exc_info.value)

    refusals = (
        session.query(AuditEvent)
        .filter(AuditEvent.action == AuditAction.execution_refused.value)
        .all()
    )
    assert len(refusals) >= 1
    refreshed = exercises.get_exercise(session, principal, exercise.id)
    assert refreshed.lifecycle_state.value == "approved"
