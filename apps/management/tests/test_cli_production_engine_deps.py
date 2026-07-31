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
from secp_management.auth_cli import AuthCliDeps
from secp_management.enrollment_cli import EnrollmentCliDeps

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


# --- the credential store must actually back authenticated calls ----------------------------------
#
# `secpctl auth login` writing a credential into the OS keystore is worth nothing unless the client
# that makes authenticated calls READS it. It did not: `_production_enrollment_deps` composed
# `ProtectedTokenFileProvider` or the sealed provider and never touched
# `build_operator_credential_store()`, so the only working operator-auth path on a real host was a
# plaintext token FILE and `auth login` was decorative. These pin the wiring so that cannot recur.


def _enrollment_deps_with_stubbed_host(monkeypatch, *, token_file: str = ""):
    """Compose the real enrollment deps with the POSIX filesystem stubbed, so this asserts the
    WIRING rather than the host — the same idiom as the Stream B tripwire above."""
    import secp_commissioning.runtime as runtime

    class _StubFilesystem:
        pass

    monkeypatch.setattr(runtime, "RealFilesystem", _StubFilesystem)
    monkeypatch.setenv("SECP_OPERATOR_TOKEN_FILE", token_file) if token_file else (
        monkeypatch.delenv("SECP_OPERATOR_TOKEN_FILE", raising=False)
    )
    return cli._production_enrollment_deps()


def test_enrollment_deps_read_the_operator_credential_store_not_a_plaintext_file(monkeypatch):
    """The headline outcome of this workstream: what `auth login` stores is what authenticated
    commands use. With no token-file env var set, the client's token provider must be the
    controller-scoped OS credential store — never the sealed provider, which would make every
    authenticated command fail even after a successful login."""
    from secp_management.operator_auth import SealedOperatorAccessTokenProvider
    from secp_management.operator_credential_store import ControllerScopedCredentialProvider

    deps = _enrollment_deps_with_stubbed_host(monkeypatch)
    provider = deps.controller_client._token_provider

    assert not isinstance(provider, SealedOperatorAccessTokenProvider), (
        "the enrollment client composed the SEALED token provider: `secpctl auth login` would "
        "store a credential that nothing ever reads"
    )
    assert isinstance(provider, ControllerScopedCredentialProvider)


def test_the_token_file_is_reachable_only_by_explicit_opt_in(monkeypatch):
    """The protected token FILE stays a recovery seam an operator must ASK for. It is never an
    automatic fallback from the credential store — `operator_auth` and `operator_credential_store`
    both state that rule, and this is what enforces it."""
    from secp_management.operator_auth import ProtectedTokenFileProvider

    deps = _enrollment_deps_with_stubbed_host(monkeypatch, token_file="/etc/secp/operator.token")
    assert isinstance(deps.controller_client._token_provider, ProtectedTokenFileProvider)


def test_the_client_and_the_credential_provider_share_one_locator(monkeypatch):
    """The credential read must be scoped to the controller the request is actually sent to. Two
    locator instances could disagree and serve one controller's credential to another."""
    deps = _enrollment_deps_with_stubbed_host(monkeypatch)
    client = deps.controller_client
    assert client._token_provider._locator_provider is client._locator_provider


def test_an_unavailable_keystore_composes_the_sealed_store_not_a_file(monkeypatch):
    """Fail-closed survives the wiring: with no OS keystore the composed provider is backed by the
    SEALED store. It must not quietly become a token file."""
    import secp_management.operator_credential_store as store_module
    from secp_management.operator_credential_store import (
        ControllerScopedCredentialProvider,
        SealedOperatorCredentialStore,
    )

    monkeypatch.setattr(store_module, "resolve_secret_store_binding", lambda: None)
    provider = _enrollment_deps_with_stubbed_host(monkeypatch).controller_client._token_provider
    assert isinstance(provider, ControllerScopedCredentialProvider)
    assert isinstance(provider._store, SealedOperatorCredentialStore)


def test_a_controller_scoped_provider_over_a_sealed_store_refuses():
    """The behaviour behind the composition above, asserted without the stubbed host: an
    unavailable keystore is a bounded refusal, never a degradation to some other location."""
    from secp_management import ManagementError
    from secp_management.controller_api_locator import ControllerApiLocator
    from secp_management.operator_credential_store import (
        ControllerScopedCredentialProvider,
        SealedOperatorCredentialStore,
    )

    class _Locator:
        def locate(self):
            return ControllerApiLocator(
                canonical_origin="https://controller.invalid",
                ca_bundle_path="/etc/secp/controller/ca.pem",
            )

    provider = ControllerScopedCredentialProvider(SealedOperatorCredentialStore(), _Locator())
    with pytest.raises(ManagementError) as ei:
        provider.access_token()
    assert ei.value.reason_code == "secpctl_credential_store_unavailable"


def test_sealed_because_unbootstrapped_is_distinguishable_from_sealed_because_the_wiring_threw():
    """The `except Exception` in `_production_enrollment_deps` turns ANY composition error into
    fully sealed deps -- invisibly. The `ca_bundle` tripwire above documents that trap; this asserts
    the credential wiring does not walk into it.

    Account derivation raises `secpctl_controller_locator_unavailable` on an unbootstrapped host. If
    that ran at COMPOSITION time it would seal the entire enrollment surface. It must not: binding
    is lazy, so composition succeeds and the refusal arrives per-command instead.
    """
    from secp_management import ManagementError
    from secp_management.operator_credential_store import ControllerScopedCredentialProvider

    class _UnbootstrappedLocator:
        def locate(self):
            raise ManagementError("secpctl_controller_locator_unavailable")

    class _Store:
        def for_account(self, account):  # pragma: no cover - must never be reached
            raise AssertionError("the account must not be derived before a token is needed")

    # Composition with an unbootstrapped locator must SUCCEED (nothing resolved yet)...
    provider = ControllerScopedCredentialProvider(_Store(), _UnbootstrappedLocator())

    # ...and the refusal must arrive on use, bounded, naming the locator rather than the store.
    with pytest.raises(ManagementError) as ei:
        provider.access_token()
    assert ei.value.reason_code == "secpctl_controller_locator_unavailable"


def test_composing_the_credential_provider_resolves_no_locator(monkeypatch):
    """The concrete form of the rule above, against the real composition: building the deps must not
    call `locate()` even once. If it did, an unbootstrapped host would silently seal everything."""
    calls: list[str] = []

    import secp_management.controller_api_locator as locator_module

    real = locator_module.FileControllerApiLocatorProvider

    class _CountingLocator(real):  # type: ignore[misc, valid-type]
        def locate(self):
            calls.append("locate")
            return super().locate()

    monkeypatch.setattr(locator_module, "FileControllerApiLocatorProvider", _CountingLocator)
    _enrollment_deps_with_stubbed_host(monkeypatch)
    assert calls == [], "composition resolved the locator; an unbootstrapped host would seal"


@pytest.mark.parametrize("boom", [NameError, AttributeError, ImportError, AssertionError])
def test_a_coding_defect_in_a_composition_is_loud_not_a_silent_seal(monkeypatch, boom):
    """The characteristic hazard of this file: a broad `except` around a composition converts ANY
    error inside it into a silent, total, host-only degradation. That is how an `os` name out of
    scope in `_production_auth_deps` would have sealed the auth deps on every real host while every
    test passed -- invisible on a dev box where the composition already seals for another reason.

    Environmental failures must still seal (that is the point of the handler). Programming errors
    must propagate.
    """
    import secp_commissioning.runtime as runtime

    def _explode():
        raise boom("a coding defect, not an environment")

    monkeypatch.setattr(runtime, "RealFilesystem", _explode)
    with pytest.raises(boom):
        cli._production_auth_deps()
    with pytest.raises(boom):
        cli._production_enrollment_deps()


def test_an_environmental_failure_still_seals_rather_than_propagating(monkeypatch):
    """The other half: a non-POSIX host or an unprovisioned filesystem must still fail closed."""
    import secp_commissioning.runtime as runtime
    from secp_commissioning.runtime import FilesystemError

    def _unsupported():
        raise FilesystemError("filesystem_backend_non_posix")

    monkeypatch.setattr(runtime, "RealFilesystem", _unsupported)
    auth = cli._production_auth_deps()
    assert isinstance(auth, AuthCliDeps)
    # sealed, and honest about not knowing which provider is live
    assert auth.token_file_active() is None
    assert isinstance(cli._production_enrollment_deps(), EnrollmentCliDeps)


def test_a_tripwire_on_a_seam_inside_the_guarded_region_can_actually_fire():
    """A raising tripwire installed on a seam INSIDE a broad `except` is swallowed exactly as
    readily as a real error, so the guard looks green and proves nothing. That is the hazard, and
    it is why `AssertionError` propagates from these compositions.

    Verified by execution rather than by reading the handler: before this, a tripwire of exactly
    this shape was demonstrably inert.
    """
    import secp_commissioning.runtime as runtime

    def _tripwire():
        raise AssertionError("this seam must not be reached")

    for composition in (cli._production_auth_deps, cli._production_enrollment_deps):
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(runtime, "RealFilesystem", _tripwire)
            with pytest.raises(AssertionError, match="this seam must not be reached"):
                composition()
