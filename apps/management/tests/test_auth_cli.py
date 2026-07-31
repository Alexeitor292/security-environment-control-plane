"""``secpctl auth`` engine and CLI wiring (SECP-PR5H-B2, Workstream C).

Two headline behaviours are pinned here. With NO OS keystore available, ``auth login`` completes the
whole RFC 8628 grant, verifies the issued token, and then refuses to persist it — reached honestly,
with nothing written anywhere on the way out. With a keystore available, the credential lands under
the account DERIVED from the reviewed controller, and every later command selects that same account
and no other.
"""

from __future__ import annotations

import json
import sys
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
    auth_refresh,
    auth_status,
    exit_for,
)
from secp_management.cli import run
from secp_management.controller_api_locator import ControllerApiLocator
from secp_management.device_grant import DEVICE_CODE_GRANT_TYPE, parse_device_authorization
from secp_management.operator_credential_store import (
    OsKeystoreCredentialStore,
    SealedOperatorCredentialStore,
    account_fingerprint,
    subject_fingerprint,
)
from secp_management.operator_device_auth import DeviceEndpoints, ReviewedAuthority
from secp_management.operator_token_revoke import (
    OUTCOME_NOT_REQUIRED,
    OUTCOME_REVOKED,
    OUTCOME_UNAVAILABLE,
    OUTCOME_UNSUPPORTED,
    RevocationOutcome,
)
from secp_management.transaction import EXIT_OK, EXIT_REFUSED, WriteGate

ISSUER = "https://idp.invalid/realms/secp"
AUDIENCE = "secp-api"
SUBJECT = "5ec9ad00-0000-4000-8000-000000000001"
OTHER_SUBJECT = "5ec9ad00-0000-4000-8000-000000000002"
KID = "test-key-1"
DEVICE_CODE_VALUE = "ZGV2aWNlLWNvZGUtdmFsdWUtMDAwMDAwMDAwMDAx"

WRITE = WriteGate(write=True, confirm=True)
DRY = WriteGate(write=False, confirm=False)

ORIGIN = "https://controller.invalid"
OTHER_ORIGIN = "https://controller-b.invalid"
LOCATOR = ControllerApiLocator(
    canonical_origin=ORIGIN, ca_bundle_path="/etc/secp/controller/ca.pem"
)
OTHER_LOCATOR = ControllerApiLocator(
    canonical_origin=OTHER_ORIGIN, ca_bundle_path="/etc/secp/controller/ca.pem"
)
ENDPOINTS = DeviceEndpoints(
    device_authorization_endpoint=f"{ISSUER}/auth/device",
    token_endpoint=f"{ISSUER}/token",
    jwks_uri=f"{ISSUER}/certs",
    revocation_endpoint=f"{ISSUER}/revoke",
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


def _valid_token(subject: str = SUBJECT, *, lifetime: int = 300) -> str:
    now = int(time.time())
    return jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": subject, "iat": now, "exp": now + lifetime},
        _PRIVATE,
        algorithm="RS256",
        headers={"kid": KID},
    )


class _FakeLocatorProvider:
    def __init__(self, error=None, locator=LOCATOR):
        self._error = error
        self._locator = locator

    def locate(self):
        if self._error:
            raise ManagementError(self._error)
        return self._locator


class _FakeDeviceClient:
    """Records the grant steps so a test can prove which half of the flow actually ran."""

    def __init__(
        self,
        *,
        token=None,
        errors=(),
        authority_error=None,
        discover_error=None,
        revocation=None,
    ):
        self.calls: list[str] = []
        self.revoked: list[str] = []
        self._token = token
        self._errors = list(errors)
        self._authority_error = authority_error
        self._discover_error = discover_error
        self._revocation = (
            revocation if revocation is not None else RevocationOutcome(OUTCOME_REVOKED)
        )

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

    def revoke_token(self, _endpoints, token):
        self.calls.append("revoke")
        # Recorded so a test can prove the RAW token — not a header, not a fingerprint — is what
        # reaches the revocation request, which is what RFC 7009 §2.1 requires.
        self.revoked.append(token)
        return self._revocation


class _RecordingStore(SealedOperatorCredentialStore):
    """The sealed store, plus a record of whether a persist was attempted."""

    def __init__(self):
        self.store_attempts = 0

    def store(self, token, *, expires_at_epoch, subject_fingerprint=""):
        self.store_attempts += 1
        return super().store(
            token, expires_at_epoch=expires_at_epoch, subject_fingerprint=subject_fingerprint
        )


class _FakeKeystore:
    """An in-memory stand-in for one OS keystore, so the commands can be driven all the way through
    a SUCCESSFUL persist. Nothing in the shipped resolver can ever return it."""

    backend_id = "fake_os_keystore"

    def __init__(self):
        self.entries: dict[tuple[str, str], bytes] = {}

    def set_secret(self, *, service, account, secret):
        self.entries[(service, account)] = bytes(secret)

    def get_secret(self, *, service, account):
        return self.entries.get((service, account))

    def delete_secret(self, *, service, account):
        return self.entries.pop((service, account), None) is not None


def _working_store(keystore=None, *, now=None):
    return OsKeystoreCredentialStore(
        keystore if keystore is not None else _FakeKeystore(),
        now_epoch=now if now is not None else time.time,
    )


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
    """With no OS keystore wired, the grant still runs in full and the refusal is honest."""
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


# --- the no-plaintext-fallback floor, end to end --------------------------------------------------
#
# Adding a Linux backend must not weaken the fail-closed behaviour that shipped before it. These
# drive the WHOLE command with `secretstorage` importable but the Secret Service unusable, which is
# the realistic Linux failure (headless host, no session bus, locked keyring). The floor is: nothing
# is written anywhere and `auth login` refuses at exit 3.
#
# The two unreachable modes seal the store and report `secpctl_credential_store_unavailable`. A
# LOCKED keyring deliberately keeps its own code (`secpctl_credential_store_locked`) rather than
# collapsing into the generic one — same exit, same refusal, but the operator is told to unlock
# rather than told nothing. Both halves are asserted, per mode, so neither can drift.


class _NoConnection:
    def close(self):
        return None


class _LockedCollection:
    def is_locked(self):
        return True


class _UnusableSecretStorage:
    """`secretstorage` present and importable, but the Secret Service is not usable."""

    def __init__(self, mode):
        self.mode = mode

    def dbus_init(self):
        if self.mode == "no_dbus":
            raise RuntimeError("cannot connect to the session bus")
        return _NoConnection()

    def get_default_collection(self, connection):
        if self.mode == "no_service":
            raise RuntimeError("org.freedesktop.secrets is not available")
        return _LockedCollection()


#: mode -> (does the store seal?, the reason the operator is given)
UNUSABLE_MODES = {
    "no_dbus": (True, "secpctl_credential_store_unavailable"),
    "no_service": (True, "secpctl_credential_store_unavailable"),
    "locked": (False, "secpctl_credential_store_locked"),
}


@pytest.mark.parametrize("mode", sorted(UNUSABLE_MODES))
def test_an_unusable_secret_service_never_yields_a_usable_store(mode, monkeypatch):
    import secp_management.operator_credential_backends as backends
    from secp_management.operator_credential_store import build_operator_credential_store

    monkeypatch.setattr(backends.sys, "platform", "linux")
    monkeypatch.setitem(sys.modules, "secretstorage", _UnusableSecretStorage(mode))
    seals, _reason = UNUSABLE_MODES[mode]

    store = build_operator_credential_store()
    assert (backends.resolve_secret_store_binding() is None) is seals
    assert isinstance(store, SealedOperatorCredentialStore) is seals
    # sealed or bound, it can hold nothing and reports itself unusable
    assert store.for_account(ORIGIN).describe().available is False


@pytest.mark.parametrize("mode", sorted(UNUSABLE_MODES))
def test_login_still_refuses_with_exit_3_when_the_secret_service_is_unusable(mode, monkeypatch):
    """The floor the new backend must not lower: an unusable keystore is a refusal, never a file."""
    import secp_management.operator_credential_backends as backends
    from secp_management.operator_credential_store import build_operator_credential_store

    monkeypatch.setattr(backends.sys, "platform", "linux")
    monkeypatch.setitem(sys.modules, "secretstorage", _UnusableSecretStorage(mode))
    _seals, reason = UNUSABLE_MODES[mode]

    client = _FakeDeviceClient()
    deps, _waits, prompts = _deps(client=client, store=build_operator_credential_store())
    code, report = auth_login(deps, gate=WRITE)

    assert code == EXIT_AUTH_UNAVAILABLE == 3
    assert report == {"command": "auth login", "reason_code": reason}
    # the grant really ran and really reached the persist step before refusing
    assert client.calls == ["authority", "discover", "device_authorization", "token", "jwks"]
    assert prompts


def test_a_locked_keyring_tells_the_operator_to_unlock_rather_than_nothing(monkeypatch):
    """N1: the locked code must reach the OPERATOR, not just exist in the backend. Collapsing it
    into the generic unavailable code would hand them the one message that says nothing."""
    import secp_management.operator_credential_backends as backends
    from secp_management.operator_credential_store import build_operator_credential_store

    monkeypatch.setattr(backends.sys, "platform", "linux")
    monkeypatch.setitem(sys.modules, "secretstorage", _UnusableSecretStorage("locked"))

    deps, _waits, _prompts = _deps(store=build_operator_credential_store())
    for command, result in (
        ("auth login", auth_login(deps, gate=WRITE)),
        ("auth logout", auth_logout(deps, gate=WRITE)),
    ):
        code, report = result
        assert code == EXIT_AUTH_UNAVAILABLE
        assert report == {"command": command, "reason_code": "secpctl_credential_store_locked"}
    # and `auth status` names the real backend rather than reporting a sealed one
    status = auth_status(deps)[1]
    assert status["credential_backend"] == "secret_service"
    assert status["credential_store_available"] is False


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


# --- cancellation ---------------------------------------------------------------------------------


def test_a_cancelled_grant_stops_polling_and_persists_nothing():
    client = _FakeDeviceClient()
    store = _RecordingStore()
    deps, waits, _prompts = _deps(client=client, store=store, cancelled=lambda: True)
    code, report = auth_login(deps, gate=WRITE)
    assert report["reason_code"] == "secpctl_device_authorization_cancelled"
    assert code == EXIT_REFUSED
    assert "token" not in client.calls and waits == []
    assert store.store_attempts == 0


def test_an_operator_interrupt_is_a_bounded_refusal_not_a_traceback():
    """Ctrl-C during the poll must end the command with a reason code, never an unbounded crash,
    and must never reach the persist step."""

    class _Interrupting(_FakeDeviceClient):
        def request_token(self, _endpoints, _device_code):
            self.calls.append("token")
            raise KeyboardInterrupt

    store = _RecordingStore()
    deps, _waits, _prompts = _deps(client=_Interrupting(), store=store)
    code, report = auth_login(deps, gate=WRITE)
    assert report == {
        "command": "auth login",
        "reason_code": "secpctl_device_authorization_cancelled",
    }
    assert code == EXIT_REFUSED
    assert store.store_attempts == 0


def test_cancellation_is_checked_before_every_attempt_not_only_the_first():
    calls = {"n": 0}

    def _cancel_after_two():
        calls["n"] += 1
        return calls["n"] > 2

    client = _FakeDeviceClient(errors=["authorization_pending", "authorization_pending"])
    deps, _waits, _prompts = _deps(client=client, cancelled=_cancel_after_two)
    _code, report = auth_login(deps, gate=WRITE)
    assert report["reason_code"] == "secpctl_device_authorization_cancelled"
    assert client.calls.count("token") == 2


# --- a working keystore: persistence, selection, replay -------------------------------------------


def test_login_persists_under_the_account_derived_from_the_reviewed_controller():
    keystore = _FakeKeystore()
    deps, _waits, _prompts = _deps(store=_working_store(keystore))
    code, report = auth_login(deps, gate=WRITE)
    assert code == EXIT_OK
    assert report["mode"] == "written"
    assert report["authenticated"] is True
    assert report["has_credential"] is True
    assert report["account"] == account_fingerprint(ORIGIN)
    assert report["credential_subject"] == subject_fingerprint(SUBJECT)
    assert list(keystore.entries) == [("secp-secpctl-operator", ORIGIN)]


def test_a_successful_login_report_still_carries_no_token_or_origin():
    deps, _waits, _prompts = _deps(store=_working_store())
    _code, report = auth_login(deps, gate=WRITE)
    rendered = json.dumps(report)
    assert "eyJ" not in rendered
    assert ORIGIN not in rendered and "controller.invalid" not in rendered
    assert DEVICE_CODE_VALUE not in rendered and ISSUER not in rendered


def test_a_credential_for_one_controller_is_never_selected_for_another():
    """Multi-controller selection, end to end: two controllers are two accounts, and a command run
    against the second cannot see the first's credential."""
    keystore = _FakeKeystore()
    first, _w, _p = _deps(store=_working_store(keystore))
    assert auth_login(first, gate=WRITE)[0] == EXIT_OK

    second, _w2, _p2 = _deps(
        store=_working_store(keystore), locator=_FakeLocatorProvider(locator=OTHER_LOCATOR)
    )
    code, report = auth_status(second)
    assert code == EXIT_OK
    assert report["has_credential"] is False
    assert report["account"] == account_fingerprint(OTHER_ORIGIN)

    # and logging out of the second controller must not remove the first's credential
    assert auth_logout(second, gate=WRITE)[1]["removed"] is False
    assert list(keystore.entries) == [("secp-secpctl-operator", ORIGIN)]


def test_a_logged_out_credential_cannot_be_replayed():
    keystore = _FakeKeystore()
    deps, _waits, _prompts = _deps(store=_working_store(keystore))
    auth_login(deps, gate=WRITE)
    code, report = auth_logout(deps, gate=WRITE)
    assert code == EXIT_OK and report["removed"] is True
    assert keystore.entries == {}
    with pytest.raises(ManagementError) as ei:
        _working_store(keystore).for_account(ORIGIN).access_token()
    assert ei.value.reason_code == "secpctl_credential_absent"
    assert auth_status(deps)[1]["has_credential"] is False


# --- logout: RFC 7009 revocation ------------------------------------------------------------------


def test_logout_revokes_the_token_at_the_provider_before_deleting_it_locally():
    """Deleting the local copy is not a logout on its own: the token stays valid at the provider
    until it expires. RFC 7009 is what actually ends the session, and the ORDER matters — revocation
    needs the token, so deleting first would throw away the only thing that can end it."""
    keystore = _FakeKeystore()
    client = _FakeDeviceClient()
    deps, _w, _p = _deps(store=_working_store(keystore))
    auth_login(deps, gate=WRITE)
    stored = json.loads(keystore.entries[("secp-secpctl-operator", ORIGIN)])["t"]

    out, _w2, _p2 = _deps(client=client, store=_working_store(keystore))
    code, report = auth_logout(out, gate=WRITE)

    assert code == EXIT_OK
    assert report["revoked"] is True
    assert report["revocation_outcome"] == OUTCOME_REVOKED
    assert report["token_still_live"] is False
    assert report["removed"] is True
    # The RAW token reached the revocation request — not a header, not a fingerprint.
    assert client.revoked == [stored]
    assert not client.revoked[0].startswith("Bearer ")
    # ORDERING: the revocation carried the stored token, which is only readable while the credential
    # still exists. Had the delete run first, `access_token()` would have refused and the outcome
    # would have been `not_required` with no request made at all.
    assert "revoke" in client.calls
    assert report["revocation_outcome"] != OUTCOME_NOT_REQUIRED
    # ...and the credential is gone once the command returns.
    assert keystore.entries == {}


@pytest.mark.parametrize(
    ("outcome", "still_live"),
    [
        (
            RevocationOutcome(
                OUTCOME_UNAVAILABLE, reason_code="secpctl_revocation_provider_unavailable"
            ),
            True,
        ),
        (
            RevocationOutcome(
                OUTCOME_UNSUPPORTED, reason_code="secpctl_revocation_endpoint_absent"
            ),
            True,
        ),
        (RevocationOutcome("refused", reason_code="secpctl_revocation_refused"), True),
        (RevocationOutcome(OUTCOME_REVOKED), False),
    ],
)
def test_the_local_credential_is_deleted_whatever_the_provider_answers(outcome, still_live):
    """A revocation failure must never strand the credential in the keystore — that would be
    strictly worse than the state the operator asked for. The report stays honest about whether the
    token is still usable at the provider, and the EXIT CODE agrees with the report: a logout that
    could not end the session must not exit 0."""
    keystore = _FakeKeystore()
    deps, _w, _p = _deps(store=_working_store(keystore))
    auth_login(deps, gate=WRITE)

    out, _w2, _p2 = _deps(
        client=_FakeDeviceClient(revocation=outcome), store=_working_store(keystore)
    )
    code, report = auth_logout(out, gate=WRITE)

    # the local credential is gone either way
    assert report["removed"] is True
    assert keystore.entries == {}
    assert report["token_still_live"] is still_live
    assert report["revoked"] is (not still_live)

    if still_live:
        assert code != EXIT_OK, "a still-live token must never exit 0"
        assert code == exit_for(outcome.reason_code)
        assert report["reason_code"] == outcome.reason_code
    else:
        assert code == EXIT_OK
        assert "reason_code" not in report


def test_a_script_chaining_on_logout_success_is_never_misled():
    """`secpctl auth logout && echo revoked` must not print a falsehood. This is the whole reason
    the exit code tracks revocation rather than local deletion."""
    keystore = _FakeKeystore()
    deps, _w, _p = _deps(store=_working_store(keystore))
    auth_login(deps, gate=WRITE)

    unrevokable = _FakeDeviceClient(
        revocation=RevocationOutcome(
            OUTCOME_UNSUPPORTED, reason_code="secpctl_revocation_endpoint_absent"
        )
    )
    out, _w2, _p2 = _deps(client=unrevokable, store=_working_store(keystore))
    code, report = auth_logout(out, gate=WRITE)

    assert code == EXIT_AUTH_UNAVAILABLE
    assert report["token_still_live"] is True
    # ...and the operator is still told the local half succeeded, so they do not retry blindly
    assert report["removed"] is True


def test_logout_deletes_locally_even_when_the_provider_cannot_be_discovered():
    keystore = _FakeKeystore()
    deps, _w, _p = _deps(store=_working_store(keystore))
    auth_login(deps, gate=WRITE)

    broken = _FakeDeviceClient(discover_error="secpctl_device_discovery_invalid")
    out, _w2, _p2 = _deps(client=broken, store=_working_store(keystore))
    code, report = auth_logout(out, gate=WRITE)

    # local deletion still happened — an unreachable provider must not strand the credential
    assert keystore.entries == {}
    assert report["removed"] is True
    # ...but the token is still live, so the command does not claim success
    assert code != EXIT_OK
    assert report["revoked"] is False
    assert report["token_still_live"] is True
    assert broken.revoked == []


def test_logout_with_nothing_stored_makes_no_revocation_request():
    client = _FakeDeviceClient()
    deps, _w, _p = _deps(client=client, store=_working_store())
    code, report = auth_logout(deps, gate=WRITE)
    assert code == EXIT_OK
    assert report["revocation_outcome"] == OUTCOME_NOT_REQUIRED
    assert report["revoked"] is False
    assert report["token_still_live"] is False
    assert report["removed"] is False
    assert client.calls == []


def test_logout_of_an_expired_credential_needs_no_revocation_request():
    """An expired token is already unusable; RFC 7009 §2.2 would have the provider answer 200 for it
    anyway. Skipping the round trip is not a shortfall, so `token_still_live` stays false."""
    keystore = _FakeKeystore()
    deps, _w, _p = _deps(store=_working_store(keystore))
    auth_login(deps, gate=WRITE)

    later = time.time() + 10_000
    client = _FakeDeviceClient()
    aged, _w2, _p2 = _deps(client=client, store=_working_store(keystore, now=lambda: later))
    code, report = auth_logout(aged, gate=WRITE)

    assert code == EXIT_OK
    assert report["revocation_outcome"] == OUTCOME_NOT_REQUIRED
    assert report["token_still_live"] is False
    assert report["removed"] is True and keystore.entries == {}
    assert client.calls == []


def test_logout_dry_run_opens_no_socket_and_revokes_nothing():
    keystore = _FakeKeystore()
    deps, _w, _p = _deps(store=_working_store(keystore))
    auth_login(deps, gate=WRITE)
    before = dict(keystore.entries)

    client = _FakeDeviceClient()
    out, waits, prompts = _deps(client=client, store=_working_store(keystore))
    code, report = auth_logout(out, gate=DRY)

    assert code == EXIT_OK
    assert report["mode"] == "dry_run"
    assert report["revocation_planned"] is True
    assert client.calls == [] and waits == [] and prompts == []
    assert keystore.entries == before


def test_a_logout_report_never_carries_the_token_or_the_origin():
    keystore = _FakeKeystore()
    deps, _w, _p = _deps(store=_working_store(keystore))
    auth_login(deps, gate=WRITE)
    out, _w2, _p2 = _deps(store=_working_store(keystore))
    rendered = json.dumps(auth_logout(out, gate=WRITE)[1])
    assert "eyJ" not in rendered
    assert ORIGIN not in rendered and "controller.invalid" not in rendered
    assert ISSUER not in rendered


def test_an_expired_stored_credential_is_reported_expired_and_never_replayed():
    keystore = _FakeKeystore()
    deps, _waits, _prompts = _deps(store=_working_store(keystore))
    auth_login(deps, gate=WRITE)

    later = time.time() + 10_000
    aged, _w, _p = _deps(store=_working_store(keystore, now=lambda: later))
    status = auth_status(aged)[1]
    assert status["has_credential"] is True and status["credential_expired"] is True
    with pytest.raises(ManagementError) as ei:
        _working_store(keystore, now=lambda: later).for_account(ORIGIN).access_token()
    assert ei.value.reason_code == "secpctl_credential_expired"


# --- refresh --------------------------------------------------------------------------------------


def test_refresh_refuses_when_there_is_nothing_to_renew():
    deps, _waits, _prompts = _deps(store=_working_store())
    code, report = auth_refresh(deps, gate=WRITE)
    assert code == EXIT_AUTH_UNAVAILABLE
    assert report == {"command": "auth refresh", "reason_code": "secpctl_credential_absent"}


def test_refresh_dry_run_reports_renewal_need_without_starting_a_grant():
    keystore = _FakeKeystore()
    deps, _waits, _prompts = _deps(store=_working_store(keystore))
    auth_login(deps, gate=WRITE)

    client = _FakeDeviceClient()
    fresh, waits, prompts = _deps(client=client, store=_working_store(keystore))
    code, report = auth_refresh(fresh, gate=DRY)
    assert code == EXIT_OK
    assert report["mode"] == "dry_run"
    assert report["renewal_required"] is False
    assert client.calls == [] and waits == [] and prompts == []


def test_refresh_replaces_the_stored_credential_with_a_newly_granted_one():
    keystore = _FakeKeystore()
    deps, _waits, _prompts = _deps(store=_working_store(keystore))
    auth_login(deps, gate=WRITE)
    original = keystore.entries[("secp-secpctl-operator", ORIGIN)]

    renewed_token = _valid_token(lifetime=1200)
    client = _FakeDeviceClient(token=renewed_token)
    fresh, _w, prompts = _deps(client=client, store=_working_store(keystore))
    code, report = auth_refresh(fresh, gate=WRITE)
    assert code == EXIT_OK and report["mode"] == "written"
    assert client.calls == ["authority", "discover", "device_authorization", "token", "jwks"]
    assert prompts, "renewal is interactive: the operator must approve it again"
    assert keystore.entries[("secp-secpctl-operator", ORIGIN)] != original
    assert list(keystore.entries) == [("secp-secpctl-operator", ORIGIN)]


def test_refresh_refuses_to_switch_the_stored_identity_to_a_different_operator():
    """A renewal that comes back as somebody else must not overwrite the credential."""
    keystore = _FakeKeystore()
    deps, _waits, _prompts = _deps(store=_working_store(keystore))
    auth_login(deps, gate=WRITE)
    original = keystore.entries[("secp-secpctl-operator", ORIGIN)]

    other = _FakeDeviceClient(token=_valid_token(OTHER_SUBJECT))
    fresh, _w, _p = _deps(client=other, store=_working_store(keystore))
    code, report = auth_refresh(fresh, gate=WRITE)
    assert code == EXIT_REFUSED
    assert report == {
        "command": "auth refresh",
        "reason_code": "secpctl_credential_subject_changed",
    }
    assert keystore.entries[("secp-secpctl-operator", ORIGIN)] == original


def test_refresh_never_asks_the_provider_for_a_renewal_credential():
    """`secp-cli` is a public client with refresh tokens off; renewal re-runs the grant. The client
    the engine drives is the same device-grant client, with no second redemption step."""
    keystore = _FakeKeystore()
    deps, _waits, _prompts = _deps(store=_working_store(keystore))
    auth_login(deps, gate=WRITE)
    client = _FakeDeviceClient()
    fresh, _w, _p = _deps(client=client, store=_working_store(keystore))
    auth_refresh(fresh, gate=WRITE)
    assert set(client.calls) <= {"authority", "discover", "device_authorization", "token", "jwks"}


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


def test_status_reports_the_backend_even_when_no_controller_is_recorded():
    """On a host that has not been bootstrapped, "a keystore exists but nothing is selected" is
    exactly what the operator needs to see — not a refusal."""
    deps, _waits, _prompts = _deps(
        store=_working_store(),
        locator=_FakeLocatorProvider("secpctl_controller_locator_unavailable"),
    )
    code, report = auth_status(deps)
    assert code == EXIT_OK
    assert report["account_selected"] is False
    assert report["account"] == ""
    assert report["credential_backend"] == "fake_os_keystore"
    assert report["has_credential"] is False


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


def test_cli_auth_refresh_requires_write_and_confirm():
    keystore = _FakeKeystore()
    deps, _waits, _prompts = _deps(store=_working_store(keystore))
    auth_login(deps, gate=WRITE)
    fresh, _w, _p = _deps(store=_working_store(keystore))
    code, report = run(["auth", "refresh"], auth_deps=fresh)
    assert code == EXIT_OK
    assert report["mode"] == "dry_run"


def test_cli_rejects_unsupported_auth_arguments():
    """There is no --token/--issuer/--client-id/--password/--account anywhere on the auth surface:
    no identity, endpoint, trust input or credential ACCOUNT is selectable by a flag."""
    for action in ("login", "refresh", "logout"):
        for argument in (
            "--token",
            "--issuer",
            "--client-id",
            "--password",
            "--url",
            "--account",
            "--controller",
        ):
            with pytest.raises(SystemExit):
                run(["auth", action, argument, "value"])


def test_the_auth_and_enrollment_groups_are_mutually_exclusive():
    """An auth composition failure can never poison an enrollment command, and vice versa, because
    no argv is ever classified as both."""
    from secp_management import cli as cli_module

    for argv in (
        ["auth", "login"],
        ["auth", "status"],
        ["auth", "refresh"],
        ["auth", "logout"],
        ["enrollment", "status", "--enrollment-id", "x"],
        ["worker", "enroll", "--invitation", "/x"],
        ["--json", "auth", "status"],
        ["status", "controller"],
        [],
    ):
        is_auth = cli_module._is_auth_group(argv)
        is_enrollment = cli_module._is_enrollment_group(argv)
        assert not (is_auth and is_enrollment), argv
    assert cli_module._is_auth_group(["auth", "login"]) is True
    assert cli_module._is_enrollment_group(["worker", "enroll"]) is True


def test_device_grant_type_is_reachable_from_the_engine():
    assert DEVICE_CODE_GRANT_TYPE.endswith("device_code")


# --- human output must tell the same truth as the exit code and the JSON -------------------------
#
# `_render_human` used a FIXED key allowlist, so `token_still_live` never printed: a logout that
# failed to revoke emitted `[auth logout] exit=0 mode=written` while the token stayed valid at the
# issuer. An operator who believes they revoked and did not is a security outcome, not a display
# bug. These pin both halves of the fix -- the field is visible, and it is visible as a WARNING.


def test_human_output_warns_when_the_token_is_still_live():
    from secp_management.cli import _render_human

    rendered = _render_human(
        EXIT_AUTH_UNAVAILABLE,
        {
            "command": "auth logout",
            "mode": "written",
            "removed": True,
            "revoked": False,
            "token_still_live": True,
            "revocation_outcome": "unsupported",
            "reason_code": "secpctl_revocation_endpoint_absent",
        },
    )
    assert "token_still_live=True" in rendered
    assert "WARNING" in rendered
    assert "STILL VALID" in rendered
    assert "exit=3" in rendered
    # the operator is still told the local half succeeded
    assert "removed=True" in rendered


def test_human_output_does_not_warn_on_a_real_revocation():
    from secp_management.cli import _render_human

    rendered = _render_human(
        EXIT_OK,
        {
            "command": "auth logout",
            "mode": "written",
            "removed": True,
            "revoked": True,
            "token_still_live": False,
            "revocation_outcome": "revoked",
        },
    )
    assert "WARNING" not in rendered
    assert "token_still_live=False" in rendered


def test_human_output_no_longer_silently_drops_unknown_fields():
    """The renderer must not use a fixed allowlist. One did, and it swallowed the single field that
    told an operator their session was still live -- turning every NEW report field into an
    invisible one."""
    from secp_management.cli import _render_human

    rendered = _render_human(EXIT_OK, {"command": "auth status", "a_brand_new_field": "visible"})
    assert "a_brand_new_field=visible" in rendered


def test_auth_status_reports_credential_state_in_human_output():
    from secp_management.cli import _render_human

    _code, report = auth_status(_deps(store=_working_store())[0])
    rendered = _render_human(EXIT_OK, report)
    for key in ("has_credential", "credential_backend", "credential_store_available"):
        assert f"{key}=" in rendered, f"{key} missing from human output"


def test_a_rendered_report_still_carries_no_token_or_origin():
    """Printing every scalar is only safe because reports are bounded and secret-free."""
    from secp_management.cli import _render_human

    keystore = _FakeKeystore()
    deps, _w, _p = _deps(store=_working_store(keystore))
    auth_login(deps, gate=WRITE)
    out, _w2, _p2 = _deps(store=_working_store(keystore))
    code, report = auth_logout(out, gate=WRITE)
    rendered = _render_human(code, report)
    assert "eyJ" not in rendered
    assert ORIGIN not in rendered and ISSUER not in rendered
