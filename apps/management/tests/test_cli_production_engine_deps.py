"""secpctl production management-engine deps wiring (SECP-PR5H-B2, Phase 2a).

The supported production CLI entrypoint composes the real hardened engine adapters via
``production_engine_deps`` for the bootstrap/adopt/status/evidence/rollback groups, exactly as the
enrollment/worker groups already compose their real controller client — and BOTH fall back to their
SEALED default on any error, so an unprovisioned / non-POSIX host fails closed rather than crashing
or acting on an unverified adapter.
"""

from __future__ import annotations

import dataclasses

import pytest
from secp_management import ManagementError, cli

# --- Stream B integration tripwire ----------------------------------------------------------------


def test_enrollment_deps_compose_a_real_controller_ca_bundle_provider():
    """``secpctl enrollment invite create`` must compose a REAL controller-CA provider, never the
    sealed one — with the sealed default every invitation fails
    ``secpctl_controller_ca_unavailable`` and the whole enrollment feature is inert while every
    test still passes.

    ``ca_bundle`` and ``LocatorControllerCaBundleProvider`` are Stream B's, and at this branch's
    merge base (``e72f28f``) they do not exist: ``EnrollmentCliDeps`` has no ``ca_bundle`` field.
    Wiring them here today would raise inside ``_production_enrollment_deps``'s ``except Exception``
    and silently return FULLY sealed deps — strictly worse than the current state, and invisible.

    So this asserts the wiring the moment the field appears, and explains itself until then. It is
    deliberately NOT a permanent conditional skip: once Stream B merges, it fails until
    ``_production_enrollment_deps`` passes ``ca_bundle=LocatorControllerCaBundleProvider(fs,
    locator_provider)`` reusing the SAME locator instance the controller client is built from.
    """
    from secp_management.enrollment_cli import EnrollmentCliDeps

    field_names = {field.name for field in dataclasses.fields(EnrollmentCliDeps)}
    if "ca_bundle" not in field_names:
        pytest.skip(
            "EnrollmentCliDeps has no `ca_bundle` field at this merge base; Stream B "
            "(feature/secp-production-worker-installation) has not landed. This test starts "
            "enforcing the cli.py wiring the moment it does."
        )

    import secp_commissioning.runtime as runtime
    from secp_management.enrollment_cli import (  # type: ignore[attr-defined]
        LocatorControllerCaBundleProvider,
        SealedControllerCaBundleProvider,
    )

    # the composition is POSIX-gated through RealFilesystem; stub it so this asserts the WIRING
    # rather than the host, exactly as the auth-deps tests below do.
    class _StubFilesystem:
        pass

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(runtime, "RealFilesystem", _StubFilesystem)
        deps = cli._production_enrollment_deps()

    assert not isinstance(deps.ca_bundle, SealedControllerCaBundleProvider), (
        "enrollment invite create composed the SEALED CA provider: every invitation will fail "
        "secpctl_controller_ca_unavailable"
    )
    assert isinstance(deps.ca_bundle, LocatorControllerCaBundleProvider)


def test_production_engine_deps_falls_back_to_sealed_when_unprovisioned(monkeypatch):
    import secp_management.production as prod

    def _boom(**_kw):
        raise ManagementError("production_input_unavailable")

    monkeypatch.setattr(prod, "production_engine_deps", _boom)
    # None => run() builds a sealed EngineDeps(); the command then fails closed with a bounded code
    assert cli._production_engine_deps() is None


def test_production_engine_deps_returns_the_real_deps_when_provisioned(monkeypatch):
    import secp_management.production as prod

    sentinel = object()
    monkeypatch.setattr(prod, "production_engine_deps", lambda **_kw: sentinel)
    assert cli._production_engine_deps() is sentinel


def test_main_wires_engine_deps_for_engine_groups(monkeypatch):
    captured: dict = {}

    def _fake_run(argv, deps=None, *, enrollment_deps=None, auth_deps=None):
        captured["deps"] = deps
        captured["enr"] = enrollment_deps
        captured["auth"] = auth_deps
        return (0, {})

    monkeypatch.setattr(cli, "_production_engine_deps", lambda: "ENGINE_DEPS")
    monkeypatch.setattr(cli, "_production_enrollment_deps", lambda: "ENR_DEPS")
    monkeypatch.setattr(cli, "run", _fake_run)

    cli.main(["status", "controller", "--json"])
    assert captured == {"deps": "ENGINE_DEPS", "enr": None, "auth": None}


def test_main_wires_enrollment_deps_for_enrollment_groups(monkeypatch):
    captured: dict = {}

    def _fake_run(argv, deps=None, *, enrollment_deps=None, auth_deps=None):
        captured["deps"] = deps
        captured["enr"] = enrollment_deps
        captured["auth"] = auth_deps
        return (0, {})

    monkeypatch.setattr(cli, "_production_engine_deps", lambda: "ENGINE_DEPS")
    monkeypatch.setattr(cli, "_production_enrollment_deps", lambda: "ENR_DEPS")
    monkeypatch.setattr(cli, "run", _fake_run)

    cli.main(["enrollment", "status", "sha256:" + "a" * 64, "--json"])
    # enrollment/worker groups keep deps=None (sealed engine) and get the real enrollment deps
    assert captured == {"deps": None, "enr": "ENR_DEPS", "auth": None}


def test_main_wires_auth_deps_only_for_the_auth_group(monkeypatch):
    """The auth group composes ONLY the credential store + locator: it must never receive engine
    deps, so a login cannot reach a filesystem/service mutation adapter."""
    captured: dict = {}

    def _fake_run(argv, deps=None, *, enrollment_deps=None, auth_deps=None):
        captured["deps"] = deps
        captured["enr"] = enrollment_deps
        captured["auth"] = auth_deps
        return (0, {})

    monkeypatch.setattr(cli, "_production_engine_deps", lambda: "ENGINE_DEPS")
    monkeypatch.setattr(cli, "_production_enrollment_deps", lambda: "ENR_DEPS")
    monkeypatch.setattr(cli, "_production_auth_deps", lambda: "AUTH_DEPS")
    monkeypatch.setattr(cli, "run", _fake_run)

    cli.main(["auth", "status", "--json"])
    assert captured == {"deps": None, "enr": None, "auth": "AUTH_DEPS"}


class _StubFilesystem:
    """A stand-in for the POSIX-only ``RealFilesystem``.

    Without it these two tests are vacuous on a Windows development host: ``RealFilesystem()``
    refuses off-POSIX, so ``_production_auth_deps`` would take the fallback branch on BOTH of them
    and neither would be able to tell the branches apart.
    """


def _composable_runtime(monkeypatch) -> None:
    import secp_commissioning.runtime as runtime

    monkeypatch.setattr(runtime, "RealFilesystem", _StubFilesystem)


def test_production_auth_deps_wires_the_recorded_controller_locator(monkeypatch):
    """The success path, so the fallback test below can actually distinguish the two."""
    import secp_management.controller_api_locator as locator_module

    _composable_runtime(monkeypatch)
    deps = cli._production_auth_deps()
    assert isinstance(deps.locator_provider, locator_module.FileControllerApiLocatorProvider)


def test_production_auth_deps_falls_back_to_sealed_defaults(monkeypatch):
    """An unprovisioned / non-POSIX host must yield sealed auth deps, never a crash.

    The assertion is on the LOCATOR, not the credential store. ``_production_auth_deps`` evaluates
    its arguments left to right, so ``build_operator_credential_store()`` has already returned
    before the locator raises — the store therefore looks the same on the success and fallback
    paths and cannot distinguish them. The locator can: it is sealed only on the fallback.
    """
    import secp_management.controller_api_locator as locator_module

    def _boom(*_args, **_kw):
        raise ManagementError("locator_unavailable")

    _composable_runtime(monkeypatch)  # so the LOCATOR is the only thing that fails
    monkeypatch.setattr(locator_module, "FileControllerApiLocatorProvider", _boom)
    deps = cli._production_auth_deps()
    assert isinstance(deps.locator_provider, locator_module.SealedControllerApiLocatorProvider)
    with pytest.raises(ManagementError):
        deps.locator_provider.locate()


def test_main_wires_auth_deps_for_every_auth_subcommand(monkeypatch):
    """The engine must stay ``None`` for the whole auth group, not just for ``status`` — a login,
    refresh or logout must be equally unable to reach a filesystem/service mutation adapter."""
    captured: list[dict] = []

    def _fake_run(argv, deps=None, *, enrollment_deps=None, auth_deps=None):
        captured.append({"deps": deps, "enr": enrollment_deps, "auth": auth_deps})
        return (0, {})

    monkeypatch.setattr(cli, "_production_engine_deps", lambda: "ENGINE_DEPS")
    monkeypatch.setattr(cli, "_production_enrollment_deps", lambda: "ENR_DEPS")
    monkeypatch.setattr(cli, "_production_auth_deps", lambda: "AUTH_DEPS")
    monkeypatch.setattr(cli, "run", _fake_run)

    for argv in (
        ["auth", "login", "--write", "--confirm"],
        ["auth", "refresh", "--write", "--confirm"],
        ["auth", "logout", "--write", "--confirm"],
        ["--json", "auth", "status"],
    ):
        cli.main(argv)
    assert captured == [{"deps": None, "enr": None, "auth": "AUTH_DEPS"}] * 4
