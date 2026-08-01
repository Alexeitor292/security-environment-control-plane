"""secpctl production management-engine deps wiring (SECP-PR5H-B2, Phase 2a).

The supported production CLI entrypoint composes the real hardened engine adapters via
``production_engine_deps`` for the bootstrap/adopt/status/evidence/rollback groups, exactly as the
enrollment/worker groups already compose their real controller client — and BOTH fall back to their
SEALED default on any error, so an unprovisioned / non-POSIX host fails closed rather than crashing
or acting on an unverified adapter.
"""

from __future__ import annotations

import json

import pytest
from secp_management import ManagementError, cli
from secp_management.auth_cli import AuthCliDeps
from secp_management.enrollment_cli import EnrollmentCliDeps


def _assert_shared_enrollment_locator(deps: EnrollmentCliDeps) -> None:
    from secp_management.controller_api_locator import FileControllerApiLocatorProvider
    from secp_management.enrollment_cli import LocatorControllerCaBundleProvider
    from secp_management.enrollment_controller_client import HttpsEnrollmentControllerClient
    from secp_management.operator_credential_store import ControllerScopedCredentialProvider

    client = deps.controller_client
    assert isinstance(client, HttpsEnrollmentControllerClient)
    credential = client._token_provider
    assert isinstance(credential, ControllerScopedCredentialProvider)
    ca_bundle = deps.ca_bundle
    assert isinstance(ca_bundle, LocatorControllerCaBundleProvider)

    shared = client._locator_provider
    assert isinstance(shared, FileControllerApiLocatorProvider)
    assert credential._locator_provider is shared, "credential locator split"
    assert ca_bundle._locator_provider is shared, "CA locator split"


def test_enrollment_deps_compose_a_real_controller_ca_bundle_provider(monkeypatch):
    """The live composition shares one recorded locator across the HTTPS destination, credential
    scope, and invitation CA. A sealed or split graph would make enrollment inert or cross
    scopes."""
    _assert_shared_enrollment_locator(_enrollment_deps_with_stubbed_host(monkeypatch))


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


def test_auth_status_probe_uses_the_same_token_file_path_grammar_as_enrollment(monkeypatch):
    from secp_management.enrollment_controller_client import SealedEnrollmentControllerClient
    from secp_management.operator_auth import SealedOperatorAccessTokenProvider

    _composable_runtime(monkeypatch)
    monkeypatch.setenv("SECP_OPERATOR_TOKEN_FILE", "relative-and-invalid.token")

    auth = cli._production_auth_deps()
    assert auth.token_file_active() is None
    assert isinstance(auth.token_file_provider, SealedOperatorAccessTokenProvider)
    # The enrollment composition applies the same ProtectedTokenFileProvider constructor and seals
    # on this invalid path; auth status must not contradict it by claiming the file provider active.
    assert isinstance(
        cli._production_enrollment_deps().controller_client,
        SealedEnrollmentControllerClient,
    )


def test_valid_token_file_selection_shares_one_truthful_provider_and_probe(monkeypatch):
    from secp_management.operator_auth import ProtectedTokenFileProvider

    _composable_runtime(monkeypatch)
    monkeypatch.setenv("SECP_OPERATOR_TOKEN_FILE", "/etc/secp/operator.token")
    auth = cli._production_auth_deps()
    assert auth.token_file_active() is True
    assert isinstance(auth.token_file_provider, ProtectedTokenFileProvider)


def test_production_auth_deps_seals_only_the_failed_locator(monkeypatch):
    """A locator construction failure must not erase independent credential/provider truth."""
    import secp_management.controller_api_locator as locator_module
    import secp_management.operator_credential_store as store_module
    from secp_management.auth_cli import StoredCredentialStatus
    from secp_management.operator_auth import ProtectedTokenFileProvider
    from secp_management.transaction import WriteGate

    class _StatusStore:
        def describe(self):
            return StoredCredentialStatus(backend="windows_credential_manager", available=True)

    store = _StatusStore()

    def _boom(*_args, **_kw):
        raise locator_module.ControllerApiLocatorError("secpctl_controller_locator_unavailable")

    _composable_runtime(monkeypatch)  # so the LOCATOR is the only thing that fails
    monkeypatch.setattr(store_module, "build_operator_credential_store", lambda: store)
    monkeypatch.setattr(locator_module, "FileControllerApiLocatorProvider", _boom)
    monkeypatch.setenv("SECP_OPERATOR_TOKEN_FILE", "/etc/secp/operator.token")
    deps = cli._production_auth_deps()

    assert deps.credential_store is store
    assert deps.token_file_active() is True
    assert isinstance(deps.token_file_provider, ProtectedTokenFileProvider)
    assert isinstance(deps.locator_provider, locator_module.SealedControllerApiLocatorProvider)
    with pytest.raises(ManagementError, match="secpctl_controller_locator_unavailable"):
        deps.locator_provider.locate()

    exit_code, status = cli.auth_status(deps)
    assert exit_code == 0
    assert status["account_selected"] is False
    assert status["credential_backend"] == "windows_credential_manager"
    assert status["active_token_provider"] == "token_file"
    assert status["token_file_override_active"] is True

    exit_code, login = cli.auth_login(deps, gate=WriteGate(write=True, confirm=True))
    assert exit_code != 0
    assert login["reason_code"] == "secpctl_controller_locator_unavailable"


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
    WIRING rather than the host — the same idiom as the live CA composition test above."""
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


@pytest.mark.parametrize(
    ("split_target", "expected_message"),
    (("credential", "credential locator split"), ("ca_bundle", "CA locator split")),
)
def test_the_shared_locator_identity_check_detects_a_split(
    monkeypatch, split_target, expected_message
):
    """The live identity assertion must fail if either downstream consumer is rewired."""
    from secp_management.controller_api_locator import FileControllerApiLocatorProvider

    deps = _enrollment_deps_with_stubbed_host(monkeypatch)
    client = deps.controller_client
    target = client._token_provider if split_target == "credential" else deps.ca_bundle
    original = target._locator_provider
    split = FileControllerApiLocatorProvider(deps.ca_bundle._fs)
    assert split is not original
    monkeypatch.setattr(target, "_locator_provider", split)

    with pytest.raises(AssertionError, match=expected_message):
        _assert_shared_enrollment_locator(deps)


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
    fully sealed deps -- invisibly. The live CA composition test above exposes that trap; this
    asserts the credential wiring does not walk into it.

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


@pytest.mark.parametrize("boom", [TypeError, ValueError, RuntimeError])
def test_auth_locator_programming_defects_outside_the_legacy_allowlist_are_loud(monkeypatch, boom):
    import secp_commissioning.runtime as runtime

    def _explode():
        raise boom("constructor contract drift")

    monkeypatch.setattr(runtime, "RealFilesystem", _explode)
    with pytest.raises(boom, match="constructor contract drift"):
        cli._production_auth_deps()


def test_an_environmental_failure_still_seals_rather_than_propagating(monkeypatch):
    """A non-POSIX locator still fails closed without erasing independent auth state."""
    import secp_commissioning.runtime as runtime
    from secp_commissioning.runtime import FilesystemError
    from secp_management.controller_api_locator import SealedControllerApiLocatorProvider

    def _unsupported():
        raise FilesystemError("filesystem_backend_non_posix")

    monkeypatch.setattr(runtime, "RealFilesystem", _unsupported)
    auth = cli._production_auth_deps()
    assert isinstance(auth, AuthCliDeps)
    assert isinstance(auth.locator_provider, SealedControllerApiLocatorProvider)
    # The absent token-file selection is known even though the independent locator is unavailable.
    assert auth.token_file_active() is False
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


# --- an unexpected failure leaves as a bounded report, never a traceback --------------------------
#
# `_production_*_deps` now let programming and packaging errors propagate rather than silently
# sealing. That is right -- a silent seal is invisible -- but loud must not mean a raw traceback on
# a customer-facing installer. `build_worker_enroller()` lazily imports `secp_worker.enrollment_
# driver` INSIDE the guarded region, so on a partial install an ImportError reached the operator
# uncaught, where previously they got a bounded code and exit 3.


def _break_enrollment_driver_import(monkeypatch):
    import builtins
    import sys

    # The missing driver is imported transitively by this module. Re-establish that exact import
    # boundary so the fake below engages even when an earlier test legitimately cached the module.
    # MonkeyPatch restores the prior object afterward; no package-tree purge or class reload occurs.
    monkeypatch.delitem(sys.modules, "secp_worker.enrollment_state_store", raising=False)

    real = builtins.__import__

    def _fake(name, *args, **kwargs):
        if "enrollment_driver" in name:
            raise ImportError("No module named 'secp_worker.enrollment_driver'")
        return real(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _fake)
    _composable_runtime(monkeypatch)


def test_a_packaging_failure_exits_bounded_rather_than_as_a_traceback(monkeypatch, capsys):
    _break_enrollment_driver_import(monkeypatch)
    code = cli.main(["enrollment", "status", "--enrollment-id", "e", "--json"])
    out = capsys.readouterr().out

    assert code == 2
    payload = json.loads(out)
    assert payload == {"command": "secpctl", "reason_code": "secpctl_internal_error"}
    # the exception MESSAGE is where module and filesystem paths live; it must not appear
    assert "secp_worker" not in out and "No module named" not in out
    assert "Traceback" not in out


def test_the_bounded_failure_never_renders_an_exception_message():
    """A message can carry an absolute path, a module layout, or a hostname. Only a bounded
    `reason_code` is eligible, and only if it matches the grammar -- anything else is REPLACED
    wholesale rather than trimmed, because a partial match is how a path fragment gets through."""
    from secp_management.cli import INTERNAL_ERROR_REASON, _bounded_failure_reason

    hostile = [
        ImportError("No module named 'secp_worker.enrollment_driver'"),
        OSError("/etc/secp/controller/ca.pem: permission denied"),
        RuntimeError(r"C:\Users\operator\AppData\secrets"),
        ValueError("x" * 200),
        RuntimeError("UPPERCASE_REASON"),
        RuntimeError(""),
    ]
    for exc in hostile:
        assert _bounded_failure_reason(exc) == INTERNAL_ERROR_REASON

    # a genuine bounded ManagementError reason is passed through
    assert _bounded_failure_reason(ManagementError("secpctl_controller_unavailable")) == (
        "secpctl_controller_unavailable"
    )


@pytest.mark.parametrize(
    "reason",
    ["/etc/passwd", "x" * 200, "Has Spaces", "UPPER", "ab", "has-hyphen", "", None, 7],
)
def test_a_hostile_reason_code_on_an_exception_is_replaced_not_trimmed(reason):
    """The token is attacker-influenceable only via a `reason_code` attribute, but the grammar is
    enforced regardless of where it came from."""
    from secp_management.cli import INTERNAL_ERROR_REASON, _bounded_failure_reason

    class _Odd(Exception):
        pass

    exc = _Odd("boom")
    exc.reason_code = reason  # type: ignore[attr-defined]
    assert _bounded_failure_reason(exc) == INTERNAL_ERROR_REASON


def test_systemexit_and_keyboardinterrupt_still_propagate(monkeypatch):
    """`--help` and usage errors exit through SystemExit, and Ctrl-C is an operator action --
    neither is a failure to be rendered as a bounded report."""
    monkeypatch.setattr(cli, "_dispatch_main", lambda _argv: (_ for _ in ()).throw(SystemExit(2)))
    with pytest.raises(SystemExit):
        cli.main(["--help"])

    monkeypatch.setattr(
        cli, "_dispatch_main", lambda _argv: (_ for _ in ()).throw(KeyboardInterrupt())
    )
    with pytest.raises(KeyboardInterrupt):
        cli.main(["host", "inspect"])


def test_the_bounded_failure_renders_for_humans_too(monkeypatch, capsys):
    _break_enrollment_driver_import(monkeypatch)
    code = cli.main(["enrollment", "status", "--enrollment-id", "e"])
    out = capsys.readouterr().out
    assert code == 2
    assert "reason_code=secpctl_internal_error" in out
    assert "secp_worker" not in out and "Traceback" not in out
