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

    def _fake_run(argv, deps=None, *, enrollment_deps=None):
        captured["deps"] = deps
        captured["enr"] = enrollment_deps
        return (0, {})

    monkeypatch.setattr(cli, "_production_engine_deps", lambda: "ENGINE_DEPS")
    monkeypatch.setattr(cli, "_production_enrollment_deps", lambda: "ENR_DEPS")
    monkeypatch.setattr(cli, "run", _fake_run)

    cli.main(["status", "controller", "--json"])
    assert captured == {"deps": "ENGINE_DEPS", "enr": None}


def test_main_wires_enrollment_deps_for_enrollment_groups(monkeypatch):
    captured: dict = {}

    def _fake_run(argv, deps=None, *, enrollment_deps=None):
        captured["deps"] = deps
        captured["enr"] = enrollment_deps
        return (0, {})

    monkeypatch.setattr(cli, "_production_engine_deps", lambda: "ENGINE_DEPS")
    monkeypatch.setattr(cli, "_production_enrollment_deps", lambda: "ENR_DEPS")
    monkeypatch.setattr(cli, "run", _fake_run)

    cli.main(["enrollment", "status", "sha256:" + "a" * 64, "--json"])
    # enrollment/worker groups keep deps=None (sealed engine) and get the real enrollment deps
    assert captured == {"deps": None, "enr": "ENR_DEPS"}


# --- what `_production_enrollment_deps` ACTUALLY composes -----------------------------------------
#
# Every test above monkeypatches this function away, which is exactly how it shipped with no CA
# provider: the field silently fell back to the sealed default and `enrollment invite create` would
# have refused `secpctl_controller_ca_unavailable` on every host, with nothing failing.
#
# `RealFilesystem()` refuses on a non-POSIX host, so the whole composition falls back to sealed
# there. These tests substitute a stand-in backend rather than skipping off POSIX: the defect they
# guard against is a missing keyword argument, which has nothing to do with the platform, and a
# guard that only runs on Linux CI would not have caught it on the machine it was written on.
# Every collaborator only stores the backend at construction, so a stand-in is sufficient.


@pytest.fixture
def posix_backend(monkeypatch):
    """Let the real composition run anywhere by standing in for the POSIX-only backend."""

    class _Backend:
        def __repr__(self) -> str:
            return "StandInFilesystem()"

    backend = _Backend()
    monkeypatch.setattr("secp_commissioning.runtime.RealFilesystem", lambda: backend)
    return backend


def test_production_enrollment_deps_composes_a_real_ca_provider(posix_backend):
    """THE REGRESSION GUARD. A sealed `ca_bundle` means the CA feature is inert in production:
    the invitation cannot carry a controller CA, so no worker can ever verify the controller's TLS.
    Asserting the concrete type is the point — `is not Sealed...` alone would pass on any stray
    object, including a future third provider that also fails closed."""
    from secp_management.enrollment_cli import (
        LocatorControllerCaBundleProvider,
        SealedControllerCaBundleProvider,
    )

    deps = cli._production_enrollment_deps()

    assert isinstance(deps.ca_bundle, LocatorControllerCaBundleProvider)
    assert not isinstance(deps.ca_bundle, SealedControllerCaBundleProvider)


def test_the_bare_default_really_is_sealed_so_the_guard_above_can_fail():
    """Anti-vacuity: if the default were already a real provider, the assertion above would pass
    without the wiring existing at all."""
    from secp_management.enrollment_cli import (
        EnrollmentCliDeps,
        SealedControllerCaBundleProvider,
    )

    assert isinstance(EnrollmentCliDeps().ca_bundle, SealedControllerCaBundleProvider)


def test_the_ca_provider_and_the_controller_client_share_one_locator(posix_backend):
    """They must resolve the SAME locator. The client pins its TLS to the recorded CA path and the
    invitation hands that same CA to the worker; two instances could resolve two different locators
    and give the worker a chain the operator's own client never trusted.

    Reaching into the private attributes is deliberate — the shared-instance property is not
    observable any other way, and it is the property that matters."""
    deps = cli._production_enrollment_deps()

    client_locator = deps.controller_client._locator_provider  # type: ignore[attr-defined]
    ca_locator = deps.ca_bundle._locator_provider  # type: ignore[attr-defined]
    assert client_locator is ca_locator
    # and both were handed the same backend, so they cannot read two different locator files
    assert ca_locator._fs is posix_backend  # type: ignore[attr-defined]


def test_the_real_composition_also_wires_a_real_worker_enroller(posix_backend):
    """The sibling failure this branch already fixed once — pinned so it cannot regress here."""
    from secp_management.worker_enroller import DriverWorkerEnroller

    assert isinstance(cli._production_enrollment_deps().worker_enroller, DriverWorkerEnroller)


def test_production_enrollment_deps_falls_back_to_sealed_on_any_construction_failure(
    posix_backend, monkeypatch
):
    """The fallback must stay COMPLETE: a partially-composed deps object would be worse than a
    sealed one, because some commands would appear to work.

    The POSIX stand-in is applied here too, so the fallback is attributable to the INJECTED failure
    rather than to `RealFilesystem` refusing off POSIX — otherwise this test would pass on Windows
    without the injected fault ever mattering."""
    import secp_management.enrollment_controller_client as client_mod
    from secp_management.enrollment_cli import (
        SealedControllerCaBundleProvider,
        SealedEnrollmentControllerClient,
        SealedWorkerEnroller,
    )

    # sanity: without the fault, this same environment composes the REAL deps
    assert not isinstance(
        cli._production_enrollment_deps().controller_client, SealedEnrollmentControllerClient
    )

    def _boom(**_kw):
        raise RuntimeError("unprovisioned host")

    monkeypatch.setattr(client_mod, "HttpsEnrollmentControllerClient", _boom)

    deps = cli._production_enrollment_deps()

    assert isinstance(deps.controller_client, SealedEnrollmentControllerClient)
    assert isinstance(deps.ca_bundle, SealedControllerCaBundleProvider)
    assert isinstance(deps.worker_enroller, SealedWorkerEnroller)
