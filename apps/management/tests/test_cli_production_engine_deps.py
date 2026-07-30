"""secpctl production management-engine deps wiring (SECP-PR5H-B2, Phase 2a).

The supported production CLI entrypoint composes the real hardened engine adapters via
``production_engine_deps`` for the bootstrap/adopt/status/evidence/rollback groups, exactly as the
enrollment/worker groups already compose their real controller client — and BOTH fall back to their
SEALED default on any error, so an unprovisioned / non-POSIX host fails closed rather than crashing
or acting on an unverified adapter.
"""

from __future__ import annotations

import pytest
from secp_management import ManagementError, cli


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


def test_production_auth_deps_falls_back_to_sealed_defaults(monkeypatch):
    """An unprovisioned / non-POSIX host must yield sealed auth deps, never a crash."""
    import secp_management.controller_api_locator as locator_module

    def _boom(*_args, **_kw):
        raise ManagementError("locator_unavailable")

    monkeypatch.setattr(locator_module, "FileControllerApiLocatorProvider", _boom)
    deps = cli._production_auth_deps()
    with pytest.raises(ManagementError):
        deps.credential_store.access_token()
