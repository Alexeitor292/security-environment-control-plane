"""Operator credential-store policy and no-plaintext-fallback rules (SECP-PR5H-B2, Workstream C).

The store now has real OS backends, so these tests cover two things: the POLICY layer driven through
a fake binding (account selection, expiry, record validation, deletion), and the source-level rules
that keep a future edit from reintroducing a plaintext degradation.

The source-scan tests are the Python analogue of ``apps/web/src/auth/boundary.test.ts``: they strip
docstrings and comments first (descriptive prose legitimately names the forbidden things) and assert
on CODE only.
"""

from __future__ import annotations

import ast
import copy
import pathlib
import pickle

import pytest
import secp_management.auth_cli as auth_cli_module
import secp_management.operator_credential_backends as backends_module
import secp_management.operator_credential_store as store_module
from secp_management import ManagementError
from secp_management.controller_api_locator import ControllerApiLocator
from secp_management.operator_auth import OperatorAccessToken, OperatorAccessTokenProvider
from secp_management.operator_credential_backends import (
    MAX_SECRET_BYTES,
    resolve_secret_store_binding,
)
from secp_management.operator_credential_store import (
    BACKEND_SEALED,
    CREDENTIAL_SERVICE_NAME,
    CredentialRecord,
    OsKeystoreCredentialStore,
    SealedOperatorCredentialStore,
    account_fingerprint,
    account_for_controller,
    build_operator_credential_store,
    subject_fingerprint,
    validate_account,
)

TOKEN = OperatorAccessToken("a" * 40)
OTHER_TOKEN = OperatorAccessToken("b" * 40)
ACCOUNT = "https://controller-a.invalid"
OTHER_ACCOUNT = "https://controller-b.invalid"
FUTURE = 2_000_000_000


def _code(module) -> str:
    """The module's CODE with every docstring and comment removed (comments never reach the AST)."""
    tree = ast.parse(pathlib.Path(module.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", [])
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                node.body = body[1:] or [ast.Pass()]
    return ast.unparse(tree)


STORE_CODE = _code(store_module)
AUTH_CLI_CODE = _code(auth_cli_module)
BACKENDS_CODE = _code(backends_module)


class FakeBinding:
    """An in-memory stand-in for one OS keystore, so the POLICY above it is exercised on every
    platform. It exists ONLY in this test module — ``resolve_secret_store_binding`` can never return
    it, which is what ``test_no_in_memory_binding_is_reachable_from_production`` pins."""

    backend_id = "fake_os_keystore"

    def __init__(self, *, fail=None):
        self.entries: dict[tuple[str, str], bytes] = {}
        self.fail = fail

    def set_secret(self, *, service, account, secret):
        if self.fail:
            raise ManagementError(self.fail)
        self.entries[(service, account)] = bytes(secret)

    def get_secret(self, *, service, account):
        if self.fail:
            raise ManagementError(self.fail)
        return self.entries.get((service, account))

    def delete_secret(self, *, service, account):
        if self.fail:
            raise ManagementError(self.fail)
        return self.entries.pop((service, account), None) is not None


def _store(binding=None, *, account=ACCOUNT, now=1_000_000_000.0):
    base = OsKeystoreCredentialStore(
        binding if binding is not None else FakeBinding(), now_epoch=lambda: now
    )
    return base.for_account(account) if account else base


# --- the sealed default fails closed --------------------------------------------------------------


def test_sealed_store_refuses_to_load_with_a_bounded_code():
    with pytest.raises(ManagementError) as ei:
        SealedOperatorCredentialStore().access_token()
    assert ei.value.reason_code == "secpctl_credential_store_unavailable"


def test_sealed_store_refuses_to_store_with_a_bounded_code():
    with pytest.raises(ManagementError) as ei:
        SealedOperatorCredentialStore().store(TOKEN, expires_at_epoch=FUTURE)
    assert ei.value.reason_code == "secpctl_credential_store_unavailable"


def test_sealed_store_refuses_to_delete_with_a_bounded_code():
    with pytest.raises(ManagementError) as ei:
        SealedOperatorCredentialStore().delete()
    assert ei.value.reason_code == "secpctl_credential_store_unavailable"


def test_selecting_an_account_never_unseals_the_sealed_store():
    """`for_account` is a selection, not a capability: it must not turn a sealed store into a
    storable one."""
    selected = SealedOperatorCredentialStore().for_account(ACCOUNT)
    assert isinstance(selected, SealedOperatorCredentialStore)
    with pytest.raises(ManagementError) as ei:
        selected.store(TOKEN, expires_at_epoch=FUTURE)
    assert ei.value.reason_code == "secpctl_credential_store_unavailable"


def test_sealed_store_describes_itself_without_a_secret():
    status = SealedOperatorCredentialStore().describe()
    assert status.backend == BACKEND_SEALED
    assert status.available is False
    assert status.has_credential is False
    report = status.to_report()
    assert report == {
        "credential_backend": "sealed",
        "credential_store_available": False,
        "has_credential": False,
        "credential_expired": False,
    }


def test_the_builder_composes_an_os_backed_store_or_the_sealed_default_and_nothing_else():
    """Resolution is BINARY. Whatever this platform offers, the result is either a real OS keystore
    store or the sealed one — there is no third, degraded outcome."""
    store = build_operator_credential_store()
    binding = resolve_secret_store_binding()
    if binding is None:
        assert isinstance(store, SealedOperatorCredentialStore)
    else:
        assert isinstance(store, OsKeystoreCredentialStore)
        assert store.describe().backend == binding.backend_id
        assert store.describe().available is True


def test_no_resolvable_backend_means_the_sealed_store_never_a_file(monkeypatch):
    monkeypatch.setattr(store_module, "resolve_secret_store_binding", lambda: None)
    store = build_operator_credential_store()
    assert isinstance(store, SealedOperatorCredentialStore)
    for attempt in (
        lambda: store.access_token(),
        lambda: store.store(TOKEN, expires_at_epoch=FUTURE),
        lambda: store.delete(),
    ):
        with pytest.raises(ManagementError) as ei:
            attempt()
        assert ei.value.reason_code == "secpctl_credential_store_unavailable"


def test_no_in_memory_binding_is_reachable_from_production(monkeypatch):
    """The fake binding in THIS module must not be reachable from the shipped resolver on any
    platform — the resolver returns a specific OS binding or nothing."""
    for platform in ("win32", "darwin", "linux", "freebsd", "aix", ""):
        monkeypatch.setattr(backends_module.sys, "platform", platform)
        binding = resolve_secret_store_binding()
        assert binding is None or binding.backend_id in {
            backends_module.BACKEND_WINDOWS_CREDENTIAL_MANAGER,
            backends_module.BACKEND_MACOS_KEYCHAIN,
            backends_module.BACKEND_SECRET_SERVICE,
        }


def test_sealed_store_repr_is_constant_and_secret_free():
    assert repr(SealedOperatorCredentialStore()) == "SealedOperatorCredentialStore(<sealed>)"


def test_sealed_store_cannot_be_pickled_or_copied():
    store = SealedOperatorCredentialStore()
    for attempt in (lambda: pickle.dumps(store), lambda: copy.deepcopy(store)):
        with pytest.raises(ManagementError) as ei:
            attempt()
        assert ei.value.reason_code == "secpctl_credential_store_not_serializable"


def test_the_os_backed_store_cannot_be_pickled_or_copied():
    store = _store()
    for attempt in (lambda: pickle.dumps(store), lambda: copy.deepcopy(store)):
        with pytest.raises(ManagementError) as ei:
            attempt()
        assert ei.value.reason_code == "secpctl_credential_store_not_serializable"


def test_a_store_satisfies_the_existing_token_provider_protocol():
    """The store is a superset of ``OperatorAccessTokenProvider``, so it drops into
    ``HttpsEnrollmentControllerClient`` with no change to that client.
    ``OperatorAccessTokenProvider`` is a plain (non-runtime-checkable) Protocol, so the structural
    match is asserted directly."""
    provider_methods = {
        name for name in vars(OperatorAccessTokenProvider) if not name.startswith("_")
    }
    assert provider_methods
    for store in (SealedOperatorCredentialStore(), _store()):
        assert callable(getattr(store, "access_token", None))
        assert provider_methods <= {m for m in dir(store) if not m.startswith("_")}


# --- bounded identifiers --------------------------------------------------------------------------


def test_service_name_is_bounded_and_code_owned():
    assert CREDENTIAL_SERVICE_NAME == "secp-secpctl-operator"
    assert 0 < len(CREDENTIAL_SERVICE_NAME) <= 255
    assert CREDENTIAL_SERVICE_NAME.isprintable() and " " not in CREDENTIAL_SERVICE_NAME


def test_valid_account_identifiers_are_accepted():
    assert validate_account("operator@example.invalid") == "operator@example.invalid"


@pytest.mark.parametrize("value", ["", " ", "a" * 256, "has space", "new\nline", None, 42])
def test_malformed_account_identifiers_are_refused(value):
    with pytest.raises(ManagementError) as ei:
        validate_account(value)
    assert ei.value.reason_code == "secpctl_credential_account_invalid"


@pytest.mark.parametrize("value", ["a" * 256, "has space", "new\nline"])
def test_an_account_refusal_never_echoes_the_offending_value(value):
    with pytest.raises(ManagementError) as ei:
        validate_account(value)
    assert value not in f"{ei.value!r} {ei.value}"


# --- account selection is DERIVED from the reviewed controller ------------------------------------


def test_the_account_is_the_reviewed_controller_origin():
    locator = ControllerApiLocator(
        canonical_origin="https://controller.invalid", ca_bundle_path="/etc/secp/controller/ca.pem"
    )
    assert account_for_controller(locator) == "https://controller.invalid"


@pytest.mark.parametrize("locator", [None, object(), "https://controller.invalid"])
def test_an_account_cannot_be_derived_from_something_that_is_not_a_locator(locator):
    with pytest.raises(ManagementError) as ei:
        account_for_controller(locator)
    assert ei.value.reason_code == "secpctl_credential_account_invalid"


def test_the_account_fingerprint_is_stable_and_never_reveals_the_origin():
    fingerprint = account_fingerprint(ACCOUNT)
    assert fingerprint == account_fingerprint(ACCOUNT)
    assert fingerprint != account_fingerprint(OTHER_ACCOUNT)
    assert len(fingerprint) == 16 and all(c in "0123456789abcdef" for c in fingerprint)
    assert "controller-a" not in fingerprint and ACCOUNT not in fingerprint


def test_the_subject_fingerprint_is_stable_and_never_reveals_the_subject():
    subject = "5ec9ad00-0000-4000-8000-000000000001"
    fingerprint = subject_fingerprint(subject)
    assert fingerprint == subject_fingerprint(subject)
    assert fingerprint != subject_fingerprint("5ec9ad00-0000-4000-8000-000000000002")
    assert len(fingerprint) == 32 and subject not in fingerprint


# --- lifecycle over a keystore --------------------------------------------------------------------


def test_a_stored_credential_round_trips_through_the_keystore():
    store = _store()
    store.store(TOKEN, expires_at_epoch=FUTURE, subject_fingerprint="ab" * 16)
    assert store.access_token().authorization_header() == TOKEN.authorization_header()
    status = store.describe()
    assert (status.has_credential, status.expired, status.available) == (True, False, True)
    assert status.subject_fingerprint == "ab" * 16


def test_an_absent_credential_is_a_refusal_not_an_empty_token():
    with pytest.raises(ManagementError) as ei:
        _store().access_token()
    assert ei.value.reason_code == "secpctl_credential_absent"


def test_an_expired_credential_is_refused_rather_than_replayed():
    """The CLI must not hand a stale token to the controller to find out it is stale."""
    binding = FakeBinding()
    _store(binding, now=1_000.0).store(TOKEN, expires_at_epoch=2_000)
    stale = _store(binding, now=2_001.0)
    with pytest.raises(ManagementError) as ei:
        stale.access_token()
    assert ei.value.reason_code == "secpctl_credential_expired"
    assert stale.describe().expired is True


def test_expiry_is_refused_exactly_at_the_boundary():
    binding = FakeBinding()
    _store(binding, now=1_000.0).store(TOKEN, expires_at_epoch=2_000)
    with pytest.raises(ManagementError) as ei:
        _store(binding, now=2_000.0).access_token()
    assert ei.value.reason_code == "secpctl_credential_expired"


def test_storing_replaces_the_previous_credential_for_that_account():
    binding = FakeBinding()
    store = _store(binding)
    store.store(TOKEN, expires_at_epoch=FUTURE)
    store.store(OTHER_TOKEN, expires_at_epoch=FUTURE)
    assert store.access_token().authorization_header() == OTHER_TOKEN.authorization_header()
    assert len(binding.entries) == 1


def test_deleting_removes_the_credential_and_nothing_survives_in_memory():
    """After logout there must be no cached copy that a later call can still serve."""
    store = _store()
    store.store(TOKEN, expires_at_epoch=FUTURE)
    assert store.delete() is True
    with pytest.raises(ManagementError) as ei:
        store.access_token()
    assert ei.value.reason_code == "secpctl_credential_absent"
    assert store.delete() is False


def test_a_credential_for_one_controller_is_never_served_to_another():
    """Multi-controller selection: two controllers are two keystore entries, and neither can be
    reached through the other's account."""
    binding = FakeBinding()
    _store(binding, account=ACCOUNT).store(TOKEN, expires_at_epoch=FUTURE)
    other = _store(binding, account=OTHER_ACCOUNT)
    with pytest.raises(ManagementError) as ei:
        other.access_token()
    assert ei.value.reason_code == "secpctl_credential_absent"
    assert other.describe().has_credential is False
    # deleting one controller's credential must not touch the other's
    other.delete()
    assert _store(binding, account=ACCOUNT).describe().has_credential is True


def test_a_record_minted_for_another_account_is_refused_even_if_the_keystore_returns_it():
    """Defence in depth for a case-insensitive keystore (Windows target names are): the account is
    re-checked INSIDE the record, so a collision cannot serve a foreign credential."""
    binding = FakeBinding()
    foreign = CredentialRecord(
        account=OTHER_ACCOUNT, token="c" * 40, expires_at_epoch=FUTURE
    ).to_bytes()
    binding.entries[(CREDENTIAL_SERVICE_NAME, ACCOUNT)] = foreign
    store = _store(binding)
    with pytest.raises(ManagementError) as ei:
        store.access_token()
    assert ei.value.reason_code == "secpctl_credential_account_mismatch"


def test_an_unbound_store_can_describe_the_backend_but_never_read_or_write():
    """There is no 'default account': a store that has not selected a controller must refuse every
    credential operation rather than guessing one."""
    unbound = OsKeystoreCredentialStore(FakeBinding())
    status = unbound.describe()
    assert (status.backend, status.available, status.has_credential) == (
        "fake_os_keystore",
        True,
        False,
    )
    for attempt in (
        lambda: unbound.access_token(),
        lambda: unbound.store(TOKEN, expires_at_epoch=FUTURE),
        lambda: unbound.delete(),
    ):
        with pytest.raises(ManagementError) as ei:
            attempt()
        assert ei.value.reason_code == "secpctl_credential_account_invalid"


def test_an_unreachable_keystore_is_never_reported_as_an_absent_credential():
    """A locked or unreachable keyring must not look like 'not logged in' — that would invite a
    silent re-login loop against a store that cannot hold the result."""
    store = _store(FakeBinding(fail="secpctl_credential_backend_failed"))
    status = store.describe()
    assert status.available is False
    assert status.has_credential is False
    with pytest.raises(ManagementError) as ei:
        store.access_token()
    assert ei.value.reason_code == "secpctl_credential_backend_failed"


# --- the stored record ----------------------------------------------------------------------------


def test_a_record_round_trips_exactly():
    record = CredentialRecord(
        account=ACCOUNT, token="a" * 40, expires_at_epoch=FUTURE, subject_fingerprint="cd" * 16
    )
    assert CredentialRecord.from_bytes(record.to_bytes()) == record


def test_a_record_never_reveals_the_token_in_its_repr_or_a_pickle():
    record = CredentialRecord(account=ACCOUNT, token="a" * 40, expires_at_epoch=FUTURE)
    assert repr(record) == "CredentialRecord(<redacted>)"
    assert "a" * 40 not in repr(record)
    for attempt in (lambda: pickle.dumps(record), lambda: copy.deepcopy(record)):
        with pytest.raises(ManagementError):
            attempt()


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"not json",
        b"[]",
        b'{"v":2,"a":"x","e":1,"s":"","t":"t"}',  # wrong schema version
        b'{"v":1,"a":"https://c.invalid","e":true,"s":"","t":"tok"}',  # bool expiry
        b'{"v":1,"a":"https://c.invalid","e":0,"s":"","t":"tok"}',  # non-positive expiry
        b'{"v":1,"a":"https://c.invalid","e":1,"s":"NOTHEX","t":"tok"}',
        b'{"v":1,"a":"https://c.invalid","e":1,"s":"","t":""}',  # empty token
        b'{"v":1,"a":"has space","e":1,"s":"","t":"tok"}',  # malformed account
    ],
)
def test_a_malformed_record_is_one_bounded_refusal(raw):
    with pytest.raises(ManagementError) as ei:
        CredentialRecord.from_bytes(raw)
    assert ei.value.reason_code in {
        "secpctl_credential_record_invalid",
        "secpctl_credential_account_invalid",
    }


def test_a_record_larger_than_every_supported_keystore_is_refused_before_any_os_call():
    oversized = CredentialRecord(
        account=ACCOUNT, token="a" * (MAX_SECRET_BYTES + 1), expires_at_epoch=FUTURE
    )
    with pytest.raises(ManagementError) as ei:
        oversized.to_bytes()
    assert ei.value.reason_code == "secpctl_credential_too_large"


def test_storing_an_oversized_token_refuses_and_leaves_the_keystore_untouched():
    binding = FakeBinding()
    store = _store(binding)
    with pytest.raises(ManagementError) as ei:
        store.store(OperatorAccessToken("a" * (MAX_SECRET_BYTES + 1)), expires_at_epoch=FUTURE)
    assert ei.value.reason_code == "secpctl_credential_too_large"
    assert binding.entries == {}


# --- rules a backend must obey --------------------------------------------------------------------

#: Backends that store secrets in cleartext or trivially reversible encoding. `keyrings.alt` in
#: particular would satisfy a naive "is a keyring available?" probe while writing tokens in the
#: clear, which is strictly worse than refusing.
PLAINTEXT_CAPABLE_BACKENDS = (
    "keyrings.alt",
    "keyrings_alt",
    "PlaintextKeyring",
    "EncryptedKeyring",
    "UncryptedFileKeyring",
    "ChainerBackend",
)

#: Every file-WRITE shape. `write` alone is deliberately NOT in this set: `present_device_prompt`
#: legitimately calls `sys.stderr.write` to show the operator their user code, and a bare substring
#: scan would either forbid that or be silently dropped -- which is exactly how `auth_cli` came
#: to be exempt from this scan in the first place. The precise rule lives in
#: `test_the_only_write_call_in_the_auth_surface_is_the_operator_presenter`, which checks the AST.
FILE_WRITE_SHAPES = ("open(", "Path(", "os.makedirs", "mkdir", "write_text", "write_bytes")


#: The POSITIVE control for every negative source scan below. A scan that says "this string is
#: absent" proves nothing if the blob it scans is empty or is the wrong module — and `_code()`
#: silently returns something for any importable module. Each blob must therefore also be shown to
#: contain a sentinel that only THAT module can contain.
SCANNED_MODULES = (
    (lambda: STORE_CODE, "SealedOperatorCredentialStore"),
    (lambda: BACKENDS_CODE, "resolve_secret_store_binding"),
    (lambda: AUTH_CLI_CODE, "auth_login"),
)


@pytest.mark.parametrize(("blob", "sentinel"), SCANNED_MODULES)
def test_each_scanned_blob_is_really_the_module_it_claims_to_be(blob, sentinel):
    """Without this, pointing ``_code()`` at the wrong module in a refactor would leave every scan
    below passing while checking nothing at all."""
    code = blob()
    assert len(code) > 500, "an empty or truncated blob would satisfy every negative scan"
    assert sentinel in code, f"expected {sentinel!r} in the scanned code"


@pytest.mark.parametrize("forbidden", PLAINTEXT_CAPABLE_BACKENDS)
def test_no_module_in_the_credential_surface_references_a_plaintext_capable_backend(forbidden):
    for code in (STORE_CODE, BACKENDS_CODE, AUTH_CLI_CODE):
        assert forbidden not in code


@pytest.mark.parametrize("forbidden", FILE_WRITE_SHAPES)
def test_no_module_in_the_credential_surface_writes_a_file_as_a_fallback(forbidden):
    """An unavailable backend must be a refusal, not a degradation to disk. All three modules are
    scanned: the store holds the policy, the backends module holds the only OS calls, and
    ``auth_cli`` holds the one place a token exists in memory."""
    for code in (STORE_CODE, BACKENDS_CODE, AUTH_CLI_CODE):
        assert forbidden not in code


def test_the_only_write_call_in_the_auth_surface_is_the_operator_presenter():
    """The precise form of the rule above. A substring scan for `write` cannot be used because the
    operator prompt is written to stderr, so the shape is asserted structurally instead: every
    `.write*` call in ``auth_cli`` must target ``sys.stderr``, and there must be at least one (a
    vacuous pass would mean the presenter had been removed and the scan silently proved nothing)."""
    tree = ast.parse(AUTH_CLI_CODE)
    targets = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in ("write", "writelines", "writestr", "write_text", "write_bytes"):
                targets.append(ast.unparse(node.func.value))
    assert targets, "expected the operator presenter's stderr writes to be found"
    assert set(targets) == {"sys.stderr"}, targets


def test_no_module_in_the_credential_surface_reads_an_environment_variable():
    """No token, and no backend selection, may come from the environment.

    ``secretstorage``/jeepney read the session D-Bus address from the environment inside the
    library — that is inherent to reaching the operator's own session bus, and it happens in-process
    with no subprocess anywhere (avoiding one is the whole reason ``secretstorage`` was chosen over
    ``secret-tool``; the test below pins that). No code in these three modules reads, writes or
    branches on a variable."""
    for forbidden in ("os.environ", "os.getenv", "getenv", "environb"):
        for code in (STORE_CODE, BACKENDS_CODE, AUTH_CLI_CODE):
            assert forbidden not in code


def test_the_credential_surface_spawns_no_process_and_resolves_no_executable():
    """SECP-PR5E §12 forbids the management installer from driving a process at all
    (``tests/test_management_plane_boundary.py`` bans the ``subprocess`` import over the whole
    package). This pins the same rule against the evasions that a plain import ban does not catch:
    a raw ``posix_spawn``/``fork``/``exec``, and any ``PATH`` resolution of a binary."""
    for forbidden in (
        "subprocess",
        "posix_spawn",
        "os.fork",
        "os.exec",
        "popen",
        "os.system",
        "which(",
        "find_library",
        "shutil",
    ):
        for code in (STORE_CODE, BACKENDS_CODE, AUTH_CLI_CODE):
            assert forbidden not in code


def test_the_only_libraries_loaded_are_fixed_absolute_system_frameworks():
    """A framework loaded by bare name would be resolved through the loader's search path; the
    macOS binding must name the system frameworks by absolute path."""
    for constant in (backends_module._CORE_FOUNDATION_PATH, backends_module._SECURITY_PATH):
        assert constant.startswith("/System/Library/Frameworks/")


def test_credential_store_holds_no_module_level_token_cache():
    """A module-level mutable holding a token would be an in-memory session fallback that survives
    a refused store for the life of the process."""
    for code in (STORE_CODE, BACKENDS_CODE):
        tree = ast.parse(code)
        for node in tree.body:
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = {t.id for t in targets if isinstance(t, ast.Name)}
            if names == {"__all__"}:  # the export list is not state
                continue
            assert not isinstance(node.value, (ast.List, ast.Dict, ast.Set)), (
                f"module-level mutable state {names} could cache a credential"
            )


def test_login_has_no_fallback_branch_around_the_persist_call():
    """``auth_login`` must not wrap the store call in its own handler that writes the token
    elsewhere. The only handler is the outer bounded-refusal one, and the only thing it may DO is
    build that refusal — asserted on the calls it makes, not on a substring of its text."""
    tree = ast.parse(AUTH_CLI_CODE)
    login = next(
        n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "auth_login"
    )
    handlers = [n for n in ast.walk(login) if isinstance(n, ast.ExceptHandler)]
    assert len(handlers) == 1, "auth_login must have exactly one bounded refusal handler"
    called = [
        ast.unparse(call.func)
        for handler in handlers
        for node in handler.body
        for call in ast.walk(node)
        if isinstance(call, ast.Call)
    ]
    assert called == ["_refused"], called
    body = ast.unparse(ast.Module(body=handlers[0].body, type_ignores=[]))
    for forbidden in (*FILE_WRITE_SHAPES, "environ", "store", "write"):
        assert forbidden not in body


def test_every_write_command_persists_through_exactly_one_call_site():
    """A second persist call site is how a fallback gets added without touching the handler above.
    ``login`` and ``refresh`` may each reach the store exactly once."""
    tree = ast.parse(AUTH_CLI_CODE)
    for name in ("auth_login", "auth_refresh"):
        function = next(
            n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name
        )
        persists = [
            node
            for node in ast.walk(function)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "store"
        ]
        assert len(persists) == 1, f"{name} must persist at exactly one call site"


def test_auth_surface_never_implements_a_password_or_client_credentials_grant():
    """ADR-028 §3: a provider without the device grant is reported as that limitation and never
    downgraded. `directAccessGrantsEnabled` is off on every dev client for the same reason."""
    import secp_management.device_grant as device_grant_module
    import secp_management.operator_device_auth as device_auth_module

    device_auth_code = _code(device_auth_module)
    for code in (
        STORE_CODE,
        AUTH_CLI_CODE,
        BACKENDS_CODE,
        _code(device_grant_module),
        device_auth_code,
    ):
        for forbidden in (
            "client_secret",
            "client_credentials",
            "resource_owner",
            "directAccessGrants",
            "getpass",
            "input(",
        ):
            assert forbidden not in code

    # The ONLY `password` reference permitted anywhere in the surface is the urlsplit userinfo
    # REJECTION check — never a credential the CLI collects, stores or sends.
    for code in (STORE_CODE, AUTH_CLI_CODE, BACKENDS_CODE):
        assert "password" not in code
    for code in (device_auth_code, _code(device_grant_module)):
        assert code.count("password") == code.count("parsed.password") == 1


def test_the_apple_keychain_api_names_are_the_only_capitalised_password_symbols():
    """``kSecClassGenericPassword`` is Apple's SDK symbol for a generic keychain item, not a
    credential secpctl collects. Pinning WHICH capitalised names appear stops the lowercase scan
    above from being quietly satisfied by a differently-cased local variable."""
    capitalised = {
        node.value
        for node in ast.walk(ast.parse(BACKENDS_CODE))
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and "Password" in node.value
    }
    assert capitalised == {"kSecClassGenericPassword"}


def test_the_only_grant_type_in_the_auth_surface_is_the_device_grant():
    """A single literal, and it is the RFC 8628 URN. No second grant can be reached."""
    import secp_management.device_grant as device_grant_module
    import secp_management.operator_device_auth as device_auth_module

    literals: list[str] = []
    for code in (
        AUTH_CLI_CODE,
        _code(device_grant_module),
        _code(device_auth_module),
        STORE_CODE,
        BACKENDS_CODE,
    ):
        for node in ast.walk(ast.parse(code)):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if "grant-type" in node.value or "grant_type" in node.value:
                    literals.append(node.value)
    # "grant_type" is the RFC 8628 §3.4 form key; "grant_types_supported" is the discovery field
    # read to CONFIRM the provider advertises the device grant. Neither is a second grant.
    assert set(literals) == {
        "urn:ietf:params:oauth:grant-type:device_code",
        "grant_type",
        "grant_types_supported",
    }


def test_auth_surface_never_requests_or_stores_a_long_lived_renewal_credential():
    """`secpctl auth refresh` re-runs the device grant; it does not redeem an OAuth refresh token.
    The CLI must not ask for `offline_access` and must not store one, mirroring the browser posture
    ADR-018 established (and the dev client pins `use.refresh.tokens=false`)."""
    import secp_management.operator_device_auth as device_auth_module

    for code in (AUTH_CLI_CODE, _code(device_auth_module), STORE_CODE, BACKENDS_CODE):
        assert "offline_access" not in code
        assert "refresh_token" not in code
