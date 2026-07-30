"""Operator credential-store seam and its no-plaintext-fallback rules (SECP-PR5H-B2, Workstream C).

This slice ships the seam and the SEALED default; it ships no OS credential backend. The rules that
a backend must obey are therefore encoded HERE, now, before the backend exists — so the slice that
adds one cannot quietly satisfy "is a keyring available?" with a plaintext-capable provider, or add
a consolation fallback when no backend is present.

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
import secp_management.operator_credential_store as store_module
from secp_management import ManagementError
from secp_management.operator_auth import OperatorAccessToken, OperatorAccessTokenProvider
from secp_management.operator_credential_store import (
    BACKEND_SEALED,
    CREDENTIAL_SERVICE_NAME,
    SealedOperatorCredentialStore,
    build_operator_credential_store,
    validate_account,
)

TOKEN = OperatorAccessToken("a" * 40)


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


# --- the sealed default fails closed --------------------------------------------------------------


def test_sealed_store_refuses_to_load_with_a_bounded_code():
    with pytest.raises(ManagementError) as ei:
        SealedOperatorCredentialStore().access_token()
    assert ei.value.reason_code == "secpctl_credential_store_unavailable"


def test_sealed_store_refuses_to_store_with_a_bounded_code():
    with pytest.raises(ManagementError) as ei:
        SealedOperatorCredentialStore().store(TOKEN, expires_at_epoch=2_000_000_000)
    assert ei.value.reason_code == "secpctl_credential_store_unavailable"


def test_sealed_store_refuses_to_delete_with_a_bounded_code():
    with pytest.raises(ManagementError) as ei:
        SealedOperatorCredentialStore().delete()
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


def test_this_slice_composes_the_sealed_store():
    assert isinstance(build_operator_credential_store(), SealedOperatorCredentialStore)


def test_sealed_store_repr_is_constant_and_secret_free():
    assert repr(SealedOperatorCredentialStore()) == "SealedOperatorCredentialStore(<sealed>)"


def test_sealed_store_cannot_be_pickled_or_copied():
    store = SealedOperatorCredentialStore()
    for attempt in (lambda: pickle.dumps(store), lambda: copy.deepcopy(store)):
        with pytest.raises(ManagementError) as ei:
            attempt()
        assert ei.value.reason_code == "secpctl_credential_store_not_serializable"


def test_a_store_satisfies_the_existing_token_provider_protocol():
    """The store is a superset of ``OperatorAccessTokenProvider``, so it drops into
    ``HttpsEnrollmentControllerClient`` with no change to that client.
    ``OperatorAccessTokenProvider`` is a plain (non-runtime-checkable) Protocol, so the structural
    match is asserted directly."""
    store = SealedOperatorCredentialStore()
    assert callable(getattr(store, "access_token", None))
    provider_methods = {
        name for name in vars(OperatorAccessTokenProvider) if not name.startswith("_")
    }
    assert provider_methods and provider_methods <= {m for m in dir(store) if not m.startswith("_")}


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


# --- rules a future backend must obey (encoded before the backend exists) -------------------------

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


@pytest.mark.parametrize("forbidden", PLAINTEXT_CAPABLE_BACKENDS)
def test_credential_store_never_references_a_plaintext_capable_backend(forbidden):
    assert forbidden not in STORE_CODE


def test_credential_store_writes_no_file_as_a_fallback():
    """An unavailable backend must be a refusal, not a degradation to disk."""
    for forbidden in ("open(", "Path(", "os.makedirs", "mkdir", "write_text", "write_bytes"):
        assert forbidden not in STORE_CODE


def test_credential_store_reads_no_environment_variable():
    """No token, and no backend selection, may come from the environment."""
    for forbidden in ("os.environ", "os.getenv", "getenv"):
        assert forbidden not in STORE_CODE
        assert forbidden not in AUTH_CLI_CODE


def test_credential_store_holds_no_module_level_token_cache():
    """A module-level mutable holding a token would be an in-memory session fallback that survives
    a refused store for the life of the process."""
    tree = ast.parse(STORE_CODE)
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
    elsewhere. The only handler is the outer bounded-refusal one."""
    tree = ast.parse(AUTH_CLI_CODE)
    login = next(
        n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "auth_login"
    )
    handlers = [n for n in ast.walk(login) if isinstance(n, ast.ExceptHandler)]
    assert len(handlers) == 1, "auth_login must have exactly one bounded refusal handler"
    body = ast.unparse(ast.Module(body=handlers[0].body, type_ignores=[]))
    assert "_refused" in body
    for forbidden in ("open(", "environ", "store", "write"):
        assert forbidden not in body


def test_auth_surface_never_implements_a_password_or_client_credentials_grant():
    """ADR-028 §3: a provider without the device grant is reported as that limitation and never
    downgraded. `directAccessGrantsEnabled` is off on every dev client for the same reason."""
    import secp_management.device_grant as device_grant_module
    import secp_management.operator_device_auth as device_auth_module

    device_auth_code = _code(device_auth_module)
    for code in (STORE_CODE, AUTH_CLI_CODE, _code(device_grant_module), device_auth_code):
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
    for code in (STORE_CODE, AUTH_CLI_CODE):
        assert "password" not in code
    for code in (device_auth_code, _code(device_grant_module)):
        assert code.count("password") == code.count("parsed.password") == 1


def test_the_only_grant_type_in_the_auth_surface_is_the_device_grant():
    """A single literal, and it is the RFC 8628 URN. No second grant can be reached."""
    import secp_management.device_grant as device_grant_module
    import secp_management.operator_device_auth as device_auth_module

    literals: list[str] = []
    for code in (AUTH_CLI_CODE, _code(device_grant_module), _code(device_auth_module), STORE_CODE):
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


def test_auth_surface_never_requests_offline_access():
    """No refresh token in this slice: the CLI must not ask for `offline_access`, mirroring the
    browser posture ADR-018 established (and the dev client pins `use.refresh.tokens=false`)."""
    import secp_management.operator_device_auth as device_auth_module

    for code in (AUTH_CLI_CODE, _code(device_auth_module), STORE_CODE):
        assert "offline_access" not in code
        assert "refresh_token" not in code
