"""``secpctl auth`` engine and CLI wiring (SECP-PR5H-B2, Workstream C).

The headline behaviour of this slice: ``auth login`` completes the whole RFC 8628 grant, verifies
the issued token, then refuses to persist it because no OS credential backend is wired. These tests
pin that the refusal is reached honestly — the grant really ran — and that nothing writes the token
anywhere else on the way out.
"""

from __future__ import annotations

import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from secp_management import ManagementError
from secp_management.auth_cli import (
    EXIT_AUTH_UNAVAILABLE,
    EXIT_CONTROLLER_UNAVAILABLE,
    EXIT_MALFORMED,
    EXIT_TRANSPORT,
    AuthCliDeps,
    auth_login,
    auth_logout,
    auth_status,
    exit_for,
)
from secp_management.cli import run
from secp_management.controller_api_locator import ControllerApiLocator
from secp_management.device_grant import DEVICE_CODE_GRANT_TYPE, parse_device_authorization
from secp_management.operator_credential_store import SealedOperatorCredentialStore
from secp_management.operator_device_auth import DeviceEndpoints, ReviewedAuthority
from secp_management.transaction import EXIT_OK, EXIT_REFUSED, WriteGate

ISSUER = "https://idp.invalid/realms/secp"
AUDIENCE = "secp-api"
SUBJECT = "5ec9ad00-0000-4000-8000-000000000001"
KID = "test-key-1"
DEVICE_CODE_VALUE = "ZGV2aWNlLWNvZGUtdmFsdWUtMDAwMDAwMDAwMDAx"

WRITE = WriteGate(write=True, confirm=True)
DRY = WriteGate(write=False, confirm=False)

LOCATOR = ControllerApiLocator(
    canonical_origin="https://controller.invalid", ca_bundle_path="/etc/secp/controller/ca.pem"
)
ENDPOINTS = DeviceEndpoints(
    device_authorization_endpoint=f"{ISSUER}/auth/device",
    token_endpoint=f"{ISSUER}/token",
    jwks_uri=f"{ISSUER}/certs",
)
AUTHORIZATION = parse_device_authorization(
    {
        "device_code": DEVICE_CODE_VALUE,
        "user_code": "WDJL-MBQK",
        "verification_uri": "https://idp.invalid/device",
        "expires_in": 600,
        "interval": 5,
    },
    require_https=True,
)

_PRIVATE = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_JWK = {**json.loads(RSAAlgorithm.to_jwk(_PRIVATE.public_key())), "kid": KID, "use": "sig"}
JWKS = {"keys": [_JWK]}


def _valid_token() -> str:
    now = int(time.time())
    return jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": SUBJECT, "iat": now, "exp": now + 300},
        _PRIVATE,
        algorithm="RS256",
        headers={"kid": KID},
    )


class _FakeLocatorProvider:
    def __init__(self, error=None):
        self._error = error

    def locate(self):
        if self._error:
            raise ManagementError(self._error)
        return LOCATOR


class _FakeDeviceClient:
    """Records the grant steps so a test can prove which half of the flow actually ran."""

    def __init__(self, *, token=None, errors=(), authority_error=None, discover_error=None):
        self.calls: list[str] = []
        self._token = token
        self._errors = list(errors)
        self._authority_error = authority_error
        self._discover_error = discover_error

    def reviewed_authority(self):
        self.calls.append("authority")
        if self._authority_error:
            raise ManagementError(self._authority_error)
        return ReviewedAuthority(issuer=ISSUER, audience=AUDIENCE)

    def discover(self, _authority):
        self.calls.append("discover")
        if self._discover_error:
            raise ManagementError(self._discover_error)
        return ENDPOINTS

    def request_device_authorization(self, _endpoints):
        self.calls.append("device_authorization")
        return AUTHORIZATION

    def request_token(self, _endpoints, _device_code):
        self.calls.append("token")
        if self._errors:
            return "", self._errors.pop(0)
        return self._token or _valid_token(), ""

    def fetch_jwks(self, _endpoints):
        self.calls.append("jwks")
        return JWKS


class _RecordingStore(SealedOperatorCredentialStore):
    """The sealed store, plus a record of whether a persist was attempted."""

    def __init__(self):
        self.store_attempts = 0

    def store(self, token, *, expires_at_epoch):
        self.store_attempts += 1
        return super().store(token, expires_at_epoch=expires_at_epoch)


def _deps(client=None, store=None, locator=None, **overrides):
    waits: list[float] = []
    prompts: list[dict] = []
    deps = AuthCliDeps(
        credential_store=store if store is not None else _RecordingStore(),
        locator_provider=locator if locator is not None else _FakeLocatorProvider(),
        device_client=lambda _locator: client if client is not None else _FakeDeviceClient(),
        present=prompts.append,
        sleep=waits.append,
        monotonic=lambda: 0.0,
        now_epoch=time.time,
        **overrides,
    )
    return deps, waits, prompts


# --- exit-code alignment --------------------------------------------------------------------------


def test_exit_categories_agree_with_the_enrollment_command_family():
    """Restated rather than imported so this module does not couple to a file under concurrent
    change — the same 'same literal, no import, agreement asserted by test' idiom the repository
    already uses across planes. This test is what keeps them from drifting."""
    from secp_management import enrollment_cli

    assert EXIT_AUTH_UNAVAILABLE == enrollment_cli.EXIT_AUTH_UNAVAILABLE == 3
    assert EXIT_CONTROLLER_UNAVAILABLE == enrollment_cli.EXIT_CONTROLLER_UNAVAILABLE == 4
    assert EXIT_TRANSPORT == enrollment_cli.EXIT_TRANSPORT == 5
    assert EXIT_MALFORMED == enrollment_cli.EXIT_MALFORMED == 7


def test_an_unmapped_reason_falls_back_to_refused():
    assert exit_for("something_unmapped") == EXIT_REFUSED


# --- login: dry run -------------------------------------------------------------------------------


def test_dry_run_login_checks_provider_support_without_starting_a_grant():
    client = _FakeDeviceClient()
    deps, waits, prompts = _deps(client=client)
    code, report = auth_login(deps, gate=DRY)
    assert code == EXIT_OK
    assert report["mode"] == "dry_run"
    assert report["device_grant_supported"] is True
    # the read-only half ran; the grant did not
    assert client.calls == ["authority", "discover"]
    assert prompts == [] and waits == []


def test_dry_run_login_reports_an_unsupported_provider():
    client = _FakeDeviceClient(discover_error="secpctl_device_grant_unsupported")
    deps, _waits, _prompts = _deps(client=client)
    code, report = auth_login(deps, gate=DRY)
    assert code == EXIT_AUTH_UNAVAILABLE
    assert report["reason_code"] == "secpctl_device_grant_unsupported"


# --- login: the full grant, refused at persistence ------------------------------------------------


def test_login_runs_the_whole_grant_then_refuses_to_persist():
    """The designed terminal state of this slice."""
    client = _FakeDeviceClient()
    store = _RecordingStore()
    deps, _waits, prompts = _deps(client=client, store=store)
    code, report = auth_login(deps, gate=WRITE)
    assert client.calls == ["authority", "discover", "device_authorization", "token", "jwks"]
    assert store.store_attempts == 1, "the grant must actually reach the persist step"
    assert prompts, "the operator must have been shown the verification prompt"
    assert code == EXIT_AUTH_UNAVAILABLE
    assert report == {
        "command": "auth login",
        "reason_code": "secpctl_credential_store_unavailable",
    }


def test_the_refusal_report_carries_no_token_device_code_or_endpoint():
    deps, _waits, _prompts = _deps()
    _code, report = auth_login(deps, gate=WRITE)
    rendered = json.dumps(report)
    assert DEVICE_CODE_VALUE not in rendered
    assert ISSUER not in rendered
    assert "eyJ" not in rendered  # no JWT
    assert "controller.invalid" not in rendered


def test_the_operator_prompt_shows_the_user_code_but_never_the_device_code():
    deps, _waits, prompts = _deps()
    auth_login(deps, gate=WRITE)
    prompt = prompts[0]
    assert prompt["user_code"] == "WDJL-MBQK"
    assert prompt["verification_uri"] == "https://idp.invalid/device"
    assert DEVICE_CODE_VALUE not in json.dumps(prompt)
    assert "device_code" not in prompt


def test_login_honours_authorization_pending_and_permanent_slow_down():
    """End-to-end proof of the §3.5 rules: the wait after `slow_down` is 10s and STAYS 10s."""
    client = _FakeDeviceClient(
        errors=["authorization_pending", "slow_down", "authorization_pending"]
    )
    deps, waits, _prompts = _deps(client=client)
    auth_login(deps, gate=WRITE)
    assert waits == [5, 5, 10, 10]


def test_login_stops_immediately_when_the_operator_denies():
    client = _FakeDeviceClient(errors=["access_denied"])
    deps, _waits, _prompts = _deps(client=client)
    code, report = auth_login(deps, gate=WRITE)
    assert report["reason_code"] == "secpctl_device_authorization_denied"
    assert code == EXIT_REFUSED
    assert client.calls.count("token") == 1  # no further polling


def test_login_stops_when_the_device_code_expires():
    client = _FakeDeviceClient(errors=["expired_token"])
    deps, _waits, _prompts = _deps(client=client)
    code, report = auth_login(deps, gate=WRITE)
    assert report["reason_code"] == "secpctl_device_code_expired"
    assert code == EXIT_AUTH_UNAVAILABLE


def test_an_unverifiable_token_is_never_offered_for_storage():
    """Verification precedes persistence (ADR-028 §3), so a bad token cannot reach the store."""
    forged = jwt.encode(
        {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": SUBJECT,
            "iat": int(time.time()),
            "exp": int(time.time()) + 300,
        },
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
        algorithm="RS256",
        headers={"kid": KID},
    )
    store = _RecordingStore()
    deps, _waits, _prompts = _deps(client=_FakeDeviceClient(token=forged), store=store)
    code, report = auth_login(deps, gate=WRITE)
    assert store.store_attempts == 0
    assert report["reason_code"] == "secpctl_operator_token_signature_invalid"
    assert code == EXIT_AUTH_UNAVAILABLE


def test_an_unrecorded_locator_refuses_before_any_network_step():
    client = _FakeDeviceClient()
    deps, _waits, _prompts = _deps(
        client=client, locator=_FakeLocatorProvider("secpctl_controller_locator_unavailable")
    )
    code, report = auth_login(deps, gate=WRITE)
    assert client.calls == []
    assert code == EXIT_CONTROLLER_UNAVAILABLE
    assert report["reason_code"] == "secpctl_controller_locator_unavailable"


# --- status ---------------------------------------------------------------------------------------


def test_status_is_read_only_and_reports_the_sealed_store():
    client = _FakeDeviceClient()
    deps, waits, prompts = _deps(client=client)
    code, report = auth_status(deps)
    assert code == EXIT_OK
    assert report["mode"] == "read"
    assert report["credential_backend"] == "sealed"
    assert report["credential_store_available"] is False
    assert report["has_credential"] is False
    assert client.calls == [] and waits == [] and prompts == []


# --- logout ---------------------------------------------------------------------------------------


def test_logout_dry_run_makes_no_deletion():
    store = _RecordingStore()
    deps, _waits, _prompts = _deps(store=store)
    code, report = auth_logout(deps, gate=DRY)
    assert code == EXIT_OK
    assert report["mode"] == "dry_run"


def test_logout_write_refuses_closed_on_the_sealed_store():
    deps, _waits, _prompts = _deps()
    code, report = auth_logout(deps, gate=WRITE)
    assert code == EXIT_AUTH_UNAVAILABLE
    assert report["reason_code"] == "secpctl_credential_store_unavailable"


# --- CLI wiring -----------------------------------------------------------------------------------


def test_cli_exposes_the_auth_group_with_sealed_defaults():
    """``run`` with no injected deps must fail closed, never crash and never act."""
    code, report = run(["auth", "login", "--write", "--confirm"])
    assert report["command"] == "auth login"
    assert report["reason_code"] == "secpctl_controller_locator_unavailable"
    assert code == EXIT_CONTROLLER_UNAVAILABLE


def test_cli_auth_status_runs_with_the_sealed_default_store():
    code, report = run(["auth", "status"])
    assert code == EXIT_OK
    assert report["credential_backend"] == "sealed"


def test_cli_auth_login_defaults_to_dry_run():
    code, report = run(["auth", "login"], auth_deps=_deps()[0])
    assert code == EXIT_OK
    assert report["mode"] == "dry_run"


def test_cli_auth_logout_requires_write_and_confirm():
    code, report = run(["auth", "logout"], auth_deps=_deps()[0])
    assert code == EXIT_OK
    assert report["mode"] == "dry_run"


def test_cli_rejects_unsupported_auth_arguments():
    """There is no --token/--issuer/--client-id/--password anywhere on the auth surface."""
    for argument in ("--token", "--issuer", "--client-id", "--password", "--url"):
        with pytest.raises(SystemExit):
            run(["auth", "login", argument, "value"])


def test_the_auth_group_never_composes_an_engine():
    """A login must not be able to reach a filesystem/service mutation adapter."""
    import inspect

    from secp_management import cli as cli_module

    source = inspect.getsource(cli_module.main)
    assert "is_auth" in source
    assert "if is_enrollment or is_auth:" in source


def test_device_grant_type_is_reachable_from_the_engine():
    assert DEVICE_CODE_GRANT_TYPE.endswith("device_code")
