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
from secp_management.operator_auth import OperatorAccessToken
from secp_management.operator_credential_store import (
    CredentialMutationResult,
    OsKeystoreCredentialStore,
    SealedOperatorCredentialStore,
    account_fingerprint,
    subject_fingerprint,
)
from secp_management.operator_device_auth import (
    DeviceEndpoints,
    ResolvedOperatorPrincipal,
    ReviewedAuthority,
)
from secp_management.operator_token_revoke import (
    OUTCOME_CONCURRENT_REPLACEMENT,
    OUTCOME_NOT_REQUIRED,
    OUTCOME_PARTIAL,
    OUTCOME_REVOKED,
    OUTCOME_UNAVAILABLE,
    OUTCOME_UNREADABLE,
    OUTCOME_UNSUPPORTED,
    RevocationOutcome,
)
from secp_management.transaction import EXIT_OK, EXIT_REFUSED, WriteGate

ISSUER = "https://idp.invalid/realms/secp"
AUDIENCE = "secp-api"
SUBJECT = "5ec9ad00-0000-4000-8000-000000000001"
OTHER_SUBJECT = "5ec9ad00-0000-4000-8000-000000000002"
ORGANIZATION_ID = "6ec9ad00-0000-4000-8000-000000000001"
OPERATOR_EMAIL = "operator@example.invalid"
OPERATOR_PERMISSIONS = ("enrollment:manage", "enrollment:read")
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
PRINCIPAL = ResolvedOperatorPrincipal(
    user_id=SUBJECT,
    organization_id=ORGANIZATION_ID,
    email=OPERATOR_EMAIL,
    permissions=OPERATOR_PERMISSIONS,
    is_dev_fallback=False,
)


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


class _StaticTokenProvider:
    def __init__(self, token=None):
        self._token = token or OperatorAccessToken("f" * 40)
        self.calls = 0

    def access_token(self):
        self.calls += 1
        return self._token


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
        principal=None,
        principal_error=None,
        events=None,
    ):
        self.calls: list[str] = []
        self.revoked: list[str] = []
        self._token = token
        self._errors = list(errors)
        self._authority_error = authority_error
        self._discover_error = discover_error
        self._principal = principal if principal is not None else PRINCIPAL
        self._principal_error = principal_error
        self._events = events
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

    def resolve_principal(self, token):
        self.calls.append("principal")
        if self._events is not None:
            self._events.append("principal")
        if self._principal_error:
            raise ManagementError(self._principal_error)
        # Exercise the purpose-specific bearer accessor without retaining or reporting its value.
        assert token.authorization_header().startswith("Bearer ")
        return self._principal

    def revoke_token(self, _endpoints, token):
        self.calls.append("revoke")
        # Recorded so a test can prove the RAW token — not a header, not a fingerprint — is what
        # reaches the revocation request, which is what RFC 7009 §2.1 requires.
        self.revoked.append(token)
        return self._revocation


class _RecordingStore(SealedOperatorCredentialStore):
    """An available-at-preflight store that records and then refuses the actual persist."""

    def __init__(self):
        self.store_attempts = 0

    def store(self, token, *, expires_at_epoch, subject_fingerprint=""):
        self.store_attempts += 1
        return super().store(
            token, expires_at_epoch=expires_at_epoch, subject_fingerprint=subject_fingerprint
        )

    def snapshot(self):
        return None

    def compare_and_store(
        self, expected_generation, token, *, expires_at_epoch, subject_fingerprint=""
    ):
        self.store(
            token, expires_at_epoch=expires_at_epoch, subject_fingerprint=subject_fingerprint
        )
        return CredentialMutationResult.STORED

    def describe(self):
        from secp_management.operator_credential_store import StoredCredentialStatus

        return StoredCredentialStatus(backend="recording", available=True)


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


class _FailingReadKeystore(_FakeKeystore):
    def __init__(self, reason):
        super().__init__()
        self._reason = reason

    def get_secret(self, *, service, account):
        raise ManagementError(self._reason)


class _FailingWriteKeystore(_FakeKeystore):
    def __init__(self):
        super().__init__()
        self.fail_writes = False

    def set_secret(self, *, service, account, secret):
        if self.fail_writes:
            raise ManagementError("secpctl_credential_backend_failed")
        return super().set_secret(service=service, account=account, secret=secret)


def _working_store(keystore=None, *, now=None):
    return OsKeystoreCredentialStore(
        keystore if keystore is not None else _FakeKeystore(),
        now_epoch=now if now is not None else time.time,
    )


def _deps(client=None, store=None, locator=None, **overrides):
    waits: list[float] = []
    prompts: list[dict] = []
    # Production composition always resolves the token-file probe to true/false/unknown. Most
    # command tests model the ordinary unset case; tests for an active or broken override pass it
    # explicitly. The sealed AuthCliDeps default remains unknown and is tested directly below.
    overrides.setdefault("token_file_active", lambda: False)
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


def _assert_refusal(report, command, reason, *, remedy_expected=None):
    """A refusal report carries the command, the reason, and AT MOST a code-owned remedy.

    This preserves the strength of the original exact-dict assertions — nothing unexpected may
    appear in a refusal — while allowing the one field deliberately added. `remedy_expected=True`
    additionally requires the remedy to be present and to name an action.
    """
    assert report["command"] == command
    assert report["reason_code"] == reason
    assert set(report) <= {"command", "reason_code", "remedy"}, (
        f"unexpected fields in a refusal report: "
        f"{set(report) - {'command', 'reason_code', 'remedy'}}"
    )
    if remedy_expected:
        assert report.get("remedy"), f"{reason} should tell the operator what to do"
        # a remedy is code-owned prose, never a value from the environment or the provider
        assert ORIGIN not in report["remedy"] and ISSUER not in report["remedy"]


class _AfterPrincipalClient(_FakeDeviceClient):
    def __init__(self, *, after_principal, **kwargs):
        super().__init__(**kwargs)
        self._after_principal = after_principal

    def resolve_principal(self, token):
        principal = super().resolve_principal(token)
        callback, self._after_principal = self._after_principal, None
        if callback is not None:
            callback()
        return principal


class _AfterRevokeClient(_FakeDeviceClient):
    def __init__(self, *, after_revoke, **kwargs):
        super().__init__(**kwargs)
        self._after_revoke = after_revoke

    def revoke_token(self, endpoints, token):
        outcome = super().revoke_token(endpoints, token)
        callback, self._after_revoke = self._after_revoke, None
        if callback is not None:
            callback()
        return outcome


class _SequentialRevocationClient(_FakeDeviceClient):
    """Return one deterministic outcome per unique token while recording every attempt."""

    def __init__(self, outcomes):
        super().__init__()
        self._outcomes = list(outcomes)

    def revoke_token(self, _endpoints, token):
        self.calls.append("revoke")
        self.revoked.append(token)
        assert self._outcomes, "logout attempted more revocations than the test supplied"
        return self._outcomes.pop(0)


class _ExplodingTokenProvider:
    def access_token(self):
        raise RuntimeError("C:\\private\\operator.jwt eyJ-provider-secret")


class _HostileReasonTokenProvider:
    def access_token(self):
        raise ManagementError("C:\\private\\operator.jwt eyJ-provider-secret")


def _stored_auth_fixture(*, lifetime=300):
    binding = _FakeKeystore()
    store = _working_store(binding)
    raw = _valid_token(lifetime=lifetime)
    store.for_account(ORIGIN).store(
        OperatorAccessToken(raw),
        expires_at_epoch=int(time.time()) + lifetime,
        subject_fingerprint=subject_fingerprint(SUBJECT),
    )
    return binding, store, raw


def _assert_logout_report_secret_free(report, *tokens):
    rendered = json.dumps(report, sort_keys=True)
    for secret in (*tokens, ORIGIN, ISSUER, "C:\\private\\operator.jwt", "provider-secret"):
        assert secret not in rendered


def test_refresh_vs_logout_logout_wins_and_the_minted_token_is_compensated():
    _binding, store, old_raw = _stored_auth_fixture(lifetime=310)
    minted_raw = _valid_token(lifetime=311)
    logout_client = _FakeDeviceClient()
    logout_result = []

    def logout_between_snapshot_and_cas():
        deps, _waits, _prompts = _deps(client=logout_client, store=store)
        logout_result.append(auth_logout(deps, gate=WRITE))

    refresh_client = _AfterPrincipalClient(
        token=minted_raw, after_principal=logout_between_snapshot_and_cas
    )
    deps, _waits, _prompts = _deps(client=refresh_client, store=store)
    code, report = auth_refresh(deps, gate=WRITE)

    assert logout_result[0][0] == EXIT_OK
    assert logout_client.revoked == [old_raw]
    assert code == EXIT_REFUSED
    assert report["reason_code"] == "secpctl_credential_generation_changed"
    assert refresh_client.revoked == [minted_raw]
    assert store.for_account(ORIGIN).snapshot() is None


def test_generation_conflict_refuses_live_when_compensating_revocation_fails():
    _binding, store, _old_raw = _stored_auth_fixture(lifetime=312)
    minted_raw = _valid_token(lifetime=313)

    def delete_between_snapshot_and_cas():
        current = store.for_account(ORIGIN).snapshot()
        assert current is not None
        assert (
            store.for_account(ORIGIN).delete_if_generation(current.generation)
            is CredentialMutationResult.DELETED
        )

    refresh_client = _AfterPrincipalClient(
        token=minted_raw,
        after_principal=delete_between_snapshot_and_cas,
        revocation=RevocationOutcome(
            OUTCOME_UNAVAILABLE, reason_code="secpctl_revocation_provider_unavailable"
        ),
    )
    deps, _waits, _prompts = _deps(client=refresh_client, store=store)
    code, report = auth_refresh(deps, gate=WRITE)

    assert code == EXIT_CONTROLLER_UNAVAILABLE
    assert report["token_still_live"] is True
    assert report["credential_refusal_reason_code"] == ("secpctl_credential_generation_changed")
    assert report["reason_code"] == "secpctl_revocation_provider_unavailable"
    assert refresh_client.revoked == [minted_raw]


def test_refresh_vs_logout_refresh_wins_and_logout_reports_the_new_generation_live():
    _binding, store, old_raw = _stored_auth_fixture(lifetime=320)
    minted_raw = _valid_token(lifetime=321)
    refresh_client = _FakeDeviceClient(token=minted_raw)
    refresh_result = []

    def refresh_during_revocation():
        deps, _waits, _prompts = _deps(client=refresh_client, store=store)
        refresh_result.append(auth_refresh(deps, gate=WRITE))

    logout_client = _AfterRevokeClient(after_revoke=refresh_during_revocation)
    deps, _waits, _prompts = _deps(client=logout_client, store=store)
    code, report = auth_logout(deps, gate=WRITE)

    assert logout_client.revoked == [old_raw]
    assert refresh_result[0][0] == EXIT_OK
    assert code == EXIT_REFUSED
    assert report["reason_code"] == "secpctl_credential_generation_changed"
    assert report["token_still_live"] is True
    assert report["concurrent_credential_present"] is True
    current = store.for_account(ORIGIN).snapshot()
    assert current is not None
    assert current.token.authorization_header() == f"Bearer {minted_raw}"


def test_refresh_vs_refresh_has_one_durable_winner_and_revokes_the_loser():
    _binding, store, _old_raw = _stored_auth_fixture(lifetime=330)
    losing_raw = _valid_token(lifetime=331)
    winning_raw = _valid_token(lifetime=332)
    winner_client = _FakeDeviceClient(token=winning_raw)
    winner_result = []

    def winning_refresh_between_snapshot_and_cas():
        deps, _waits, _prompts = _deps(client=winner_client, store=store)
        winner_result.append(auth_refresh(deps, gate=WRITE))

    loser_client = _AfterPrincipalClient(
        token=losing_raw, after_principal=winning_refresh_between_snapshot_and_cas
    )
    deps, _waits, _prompts = _deps(client=loser_client, store=store)
    loser_code, loser_report = auth_refresh(deps, gate=WRITE)

    assert winner_result[0][0] == EXIT_OK
    assert loser_code == EXIT_REFUSED
    assert loser_report["reason_code"] == "secpctl_credential_generation_changed"
    assert loser_client.revoked == [losing_raw]
    assert winner_client.revoked == []
    current = store.for_account(ORIGIN).snapshot()
    assert current is not None
    assert current.token.authorization_header() == f"Bearer {winning_raw}"


def test_logout_vs_login_replacement_never_deletes_or_calls_the_replacement_dead():
    _binding, store, old_raw = _stored_auth_fixture(lifetime=340)
    replacement_raw = _valid_token(lifetime=341)
    login_client = _FakeDeviceClient(token=replacement_raw)
    login_result = []

    def replace_during_revocation():
        deps, _waits, _prompts = _deps(client=login_client, store=store)
        login_result.append(auth_login(deps, gate=WRITE))

    logout_client = _AfterRevokeClient(after_revoke=replace_during_revocation)
    deps, _waits, _prompts = _deps(client=logout_client, store=store)
    code, report = auth_logout(deps, gate=WRITE)

    assert logout_client.revoked == [old_raw]
    assert login_result[0][0] == EXIT_OK
    assert code == EXIT_REFUSED
    assert report["removed"] is False
    assert report["token_still_live"] is True
    assert report["reason_code"] == "secpctl_credential_generation_changed"
    assert report["revocation_outcome"] == OUTCOME_CONCURRENT_REPLACEMENT
    current = store.for_account(ORIGIN).snapshot()
    assert current is not None
    assert current.token.authorization_header() == f"Bearer {replacement_raw}"


def _assert_compensated_refusal(report, command, reason):
    assert report["command"] == command
    assert report["reason_code"] == reason
    assert report["credential_stored"] is False
    assert report["revocation_outcome"] == OUTCOME_REVOKED
    assert report["revoked"] is True
    assert report["token_still_live"] is False


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


# --- login: preflight plus post-issuance compensation ---------------------------------------------


def test_login_refuses_an_unavailable_store_before_starting_a_grant():
    client = _FakeDeviceClient()
    deps, waits, prompts = _deps(client=client, store=SealedOperatorCredentialStore())
    code, report = auth_login(deps, gate=WRITE)

    assert client.calls == [] and waits == [] and prompts == []
    assert code == EXIT_AUTH_UNAVAILABLE
    _assert_refusal(
        report, "auth login", "secpctl_credential_store_unavailable", remedy_expected=True
    )


def test_a_store_failure_after_issuance_revokes_the_new_token_and_keeps_no_orphan():
    client = _FakeDeviceClient()
    store = _RecordingStore()
    deps, _waits, prompts = _deps(client=client, store=store)
    code, report = auth_login(deps, gate=WRITE)

    assert client.calls == [
        "authority",
        "discover",
        "device_authorization",
        "token",
        "jwks",
        "principal",
        "revoke",
    ]
    assert store.store_attempts == 1, "the grant must actually reach the persist step"
    assert prompts, "the operator must have been shown the verification prompt"
    assert code == EXIT_AUTH_UNAVAILABLE
    assert report["reason_code"] == "secpctl_credential_store_unavailable"
    assert report["credential_stored"] is False
    assert report["revoked"] is True and report["token_still_live"] is False
    assert client.revoked and not client.revoked[0].startswith("Bearer ")


def test_post_issue_compensation_reports_a_live_token_when_revocation_is_unavailable():
    unavailable = RevocationOutcome(
        OUTCOME_UNAVAILABLE, reason_code="secpctl_revocation_provider_unavailable"
    )
    client = _FakeDeviceClient(revocation=unavailable)
    store = _RecordingStore()
    deps, _waits, _prompts = _deps(client=client, store=store)

    code, report = auth_login(deps, gate=WRITE)

    assert code == EXIT_CONTROLLER_UNAVAILABLE
    assert report["reason_code"] == "secpctl_revocation_provider_unavailable"
    assert report["credential_refusal_reason_code"] == ("secpctl_credential_store_unavailable")
    assert report["credential_stored"] is False
    assert report["token_still_live"] is True and report["revoked"] is False
    assert store.store_attempts == 1
    assert client.calls[-1] == "revoke"


def test_failed_relogin_revokes_only_the_new_token_and_preserves_the_existing_credential():
    keystore = _FailingWriteKeystore()
    initial, _waits, _prompts = _deps(store=_working_store(keystore))
    assert auth_login(initial, gate=WRITE)[0] == EXIT_OK
    original = dict(keystore.entries)
    keystore.fail_writes = True

    replacement = _valid_token(lifetime=1200)
    client = _FakeDeviceClient(token=replacement)
    deps, _waits, _prompts = _deps(client=client, store=_working_store(keystore))
    code, report = auth_login(deps, gate=WRITE)

    assert code == EXIT_AUTH_UNAVAILABLE
    _assert_compensated_refusal(report, "auth login", "secpctl_credential_backend_failed")
    assert client.revoked == [replacement]
    assert keystore.entries == original


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
    _assert_refusal(report, "auth login", reason)
    # Preflight prevents an orphan provider token when this store can never persist it.
    assert client.calls == []
    assert prompts == []


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
        if command == "auth logout":
            assert report["reason_code"] == "secpctl_credential_store_locked"
            assert report["token_still_live"] is True
            assert report["removed"] is False
            assert report.get("remedy")
        else:
            _assert_refusal(
                report, command, "secpctl_credential_store_locked", remedy_expected=True
            )
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
    client = _FakeDeviceClient(token=forged)
    deps, _waits, _prompts = _deps(client=client, store=store)
    code, report = auth_login(deps, gate=WRITE)
    assert store.store_attempts == 0
    assert report["reason_code"] == "secpctl_operator_token_signature_invalid"
    assert code == EXIT_AUTH_UNAVAILABLE
    assert client.revoked == [forged]
    assert "principal" not in client.calls and client.calls[-1] == "revoke"


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
    _assert_refusal(report, "auth login", "secpctl_device_authorization_cancelled")
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
    assert client.calls.count("token") == 1


def test_cancellation_that_arrives_during_sleep_posts_no_final_token_request():
    checks = iter((False, True))
    client = _FakeDeviceClient()
    store = _RecordingStore()
    deps, waits, _prompts = _deps(
        client=client,
        store=store,
        cancelled=lambda: next(checks),
    )

    code, report = auth_login(deps, gate=WRITE)

    assert code == EXIT_REFUSED
    _assert_refusal(report, "auth login", "secpctl_device_authorization_cancelled")
    assert waits == [AUTHORIZATION.interval]
    assert "token" not in client.calls
    assert "principal" not in client.calls
    assert store.store_attempts == 0


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


def test_login_resolves_the_authoritative_principal_before_the_first_os_write():
    events: list[str] = []

    class _EventKeystore(_FakeKeystore):
        def set_secret(self, *, service, account, secret):
            events.append("store")
            return super().set_secret(service=service, account=account, secret=secret)

    client = _FakeDeviceClient(events=events)
    deps, _waits, _prompts = _deps(client=client, store=_working_store(_EventKeystore()))
    code, report = auth_login(deps, gate=WRITE)

    assert code == EXIT_OK
    assert events == ["principal", "store"]
    assert report["stored_principal_user_id"] == SUBJECT
    assert report["stored_principal_organization_id"] == ORGANIZATION_ID
    assert report["stored_principal_permissions"] == list(OPERATOR_PERMISSIONS)


def test_login_persists_nothing_when_the_controller_cannot_resolve_the_principal():
    keystore = _FakeKeystore()
    client = _FakeDeviceClient(principal_error="secpctl_operator_principal_unavailable")
    deps, _waits, _prompts = _deps(client=client, store=_working_store(keystore))

    code, report = auth_login(deps, gate=WRITE)

    assert code == EXIT_AUTH_UNAVAILABLE
    _assert_compensated_refusal(report, "auth login", "secpctl_operator_principal_unavailable")
    assert client.calls[-2:] == ["principal", "revoke"]
    assert keystore.entries == {}


def test_login_never_persists_a_token_that_verified_only_inside_clock_leeway():
    """PyJWT accepts exp=now-30 with the verifier's 60-second leeway; the write boundary must not
    turn that into an authenticated credential that its own reader immediately calls expired."""
    keystore = _FakeKeystore()
    client = _FakeDeviceClient(token=_valid_token(lifetime=-30))
    deps, _waits, _prompts = _deps(client=client, store=_working_store(keystore))

    code, report = auth_login(deps, gate=WRITE)

    assert code == EXIT_AUTH_UNAVAILABLE
    _assert_compensated_refusal(report, "auth login", "secpctl_credential_expired")
    assert client.calls[-2:] == ["principal", "revoke"]
    assert keystore.entries == {}


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


def test_logout_with_token_file_only_revokes_it_and_never_mutates_the_file():
    raw = _valid_token(lifetime=401)
    provider = _StaticTokenProvider(OperatorAccessToken(raw))
    client = _FakeDeviceClient()
    deps, _waits, _prompts = _deps(
        client=client,
        store=_working_store(),
        token_file_active=lambda: True,
        token_file_provider=provider,
    )

    code, report = auth_logout(deps, gate=WRITE)

    assert code == EXIT_OK
    assert client.revoked == [raw]
    assert report["revocation_outcome"] == OUTCOME_REVOKED
    assert report["token_still_live"] is False
    assert report["removed"] is False
    assert provider.calls == 1
    assert provider.access_token().authorization_header() == f"Bearer {raw}"
    _assert_logout_report_secret_free(report, raw)


def test_logout_with_the_same_file_and_os_token_revokes_once_and_deletes_only_os():
    _binding, store, raw = _stored_auth_fixture(lifetime=402)
    provider = _StaticTokenProvider(OperatorAccessToken(raw))
    client = _FakeDeviceClient()
    deps, _waits, _prompts = _deps(
        client=client,
        store=store,
        token_file_active=lambda: True,
        token_file_provider=provider,
    )

    code, report = auth_logout(deps, gate=WRITE)

    assert code == EXIT_OK
    assert client.revoked == [raw], "an identical token from two sources must be submitted once"
    assert report["removed"] is True
    assert store.for_account(ORIGIN).snapshot() is None
    assert provider.access_token().authorization_header() == f"Bearer {raw}"
    _assert_logout_report_secret_free(report, raw)


def test_logout_with_different_file_and_os_tokens_revokes_both_in_fixed_order():
    _binding, store, os_raw = _stored_auth_fixture(lifetime=403)
    file_raw = _valid_token(lifetime=404)
    provider = _StaticTokenProvider(OperatorAccessToken(file_raw))
    client = _SequentialRevocationClient(
        (RevocationOutcome(OUTCOME_REVOKED), RevocationOutcome(OUTCOME_REVOKED))
    )
    deps, _waits, _prompts = _deps(
        client=client,
        store=store,
        token_file_active=lambda: True,
        token_file_provider=provider,
    )

    code, report = auth_logout(deps, gate=WRITE)

    assert code == EXIT_OK
    assert client.revoked == [file_raw, os_raw]
    assert report["revocation_outcome"] == OUTCOME_REVOKED
    assert report["removed"] is True
    assert provider.access_token().authorization_header() == f"Bearer {file_raw}"
    _assert_logout_report_secret_free(report, file_raw, os_raw)


@pytest.mark.parametrize("failed_index", (0, 1), ids=("file-fails", "os-fails"))
def test_logout_attempts_both_tokens_and_reports_partial_when_one_revocation_fails(failed_index):
    _binding, store, os_raw = _stored_auth_fixture(lifetime=405)
    file_raw = _valid_token(lifetime=406)
    unavailable = RevocationOutcome(
        OUTCOME_UNAVAILABLE, reason_code="secpctl_revocation_provider_unavailable"
    )
    revoked = RevocationOutcome(OUTCOME_REVOKED)
    outcomes = [revoked, revoked]
    outcomes[failed_index] = unavailable
    client = _SequentialRevocationClient(outcomes)
    provider = _StaticTokenProvider(OperatorAccessToken(file_raw))
    deps, _waits, _prompts = _deps(
        client=client,
        store=store,
        token_file_active=lambda: True,
        token_file_provider=provider,
    )

    code, report = auth_logout(deps, gate=WRITE)

    assert code == EXIT_CONTROLLER_UNAVAILABLE
    assert client.revoked == [file_raw, os_raw], "one failure must not suppress the other attempt"
    assert report["revocation_outcome"] == OUTCOME_PARTIAL
    assert report["token_still_live"] is True
    assert report["reason_code"] == "secpctl_revocation_provider_unavailable"
    assert report["removed"] is True
    assert provider.access_token().authorization_header() == f"Bearer {file_raw}"
    _assert_logout_report_secret_free(report, file_raw, os_raw)


def test_logout_revokes_a_readable_file_even_when_the_os_record_is_unreadable():
    file_raw = _valid_token(lifetime=407)
    provider = _StaticTokenProvider(OperatorAccessToken(file_raw))
    client = _FakeDeviceClient()
    deps, _waits, _prompts = _deps(
        client=client,
        store=_working_store(_FailingReadKeystore("secpctl_credential_store_locked")),
        token_file_active=lambda: True,
        token_file_provider=provider,
    )

    code, report = auth_logout(deps, gate=WRITE)

    assert code == EXIT_AUTH_UNAVAILABLE
    assert client.revoked == [file_raw]
    assert report["revocation_outcome"] == OUTCOME_PARTIAL
    assert report["reason_code"] == "secpctl_credential_store_locked"
    assert report["token_still_live"] is True
    assert report["removed"] is False
    _assert_logout_report_secret_free(report, file_raw)


@pytest.mark.parametrize(
    "unreadable_provider",
    (_ExplodingTokenProvider(), _HostileReasonTokenProvider()),
    ids=("raw-exception", "hostile-reason"),
)
def test_logout_revokes_and_deletes_os_even_when_the_token_file_is_unreadable(
    unreadable_provider,
):
    _binding, store, os_raw = _stored_auth_fixture(lifetime=408)
    client = _FakeDeviceClient()
    deps, _waits, _prompts = _deps(
        client=client,
        store=store,
        token_file_active=lambda: True,
        token_file_provider=unreadable_provider,
    )

    code, report = auth_logout(deps, gate=WRITE)

    assert code == EXIT_AUTH_UNAVAILABLE
    assert client.revoked == [os_raw]
    assert report["revocation_outcome"] == OUTCOME_PARTIAL
    assert report["reason_code"] == "secpctl_operator_auth_unavailable"
    assert report["token_still_live"] is True
    assert report["removed"] is True
    assert store.for_account(ORIGIN).snapshot() is None
    _assert_logout_report_secret_free(report, os_raw)


def test_logout_without_a_revocation_endpoint_keeps_the_token_file_and_refuses_success():
    raw = _valid_token(lifetime=409)
    provider = _StaticTokenProvider(OperatorAccessToken(raw))
    client = _FakeDeviceClient(
        revocation=RevocationOutcome(
            OUTCOME_UNSUPPORTED, reason_code="secpctl_revocation_endpoint_absent"
        )
    )
    deps, _waits, _prompts = _deps(
        client=client,
        store=_working_store(),
        token_file_active=lambda: True,
        token_file_provider=provider,
    )

    code, report = auth_logout(deps, gate=WRITE)

    assert code == EXIT_AUTH_UNAVAILABLE
    assert client.revoked == [raw]
    assert report["revocation_outcome"] == OUTCOME_UNSUPPORTED
    assert report["token_still_live"] is True
    assert report["removed"] is False
    assert provider.access_token().authorization_header() == f"Bearer {raw}"
    _assert_logout_report_secret_free(report, raw)


def test_logout_with_a_malformed_expiry_neither_revokes_nor_deletes_the_unowned_record():
    keystore = _FakeKeystore()
    deps, _waits, _prompts = _deps(store=_working_store(keystore))
    assert auth_login(deps, gate=WRITE)[0] == EXIT_OK
    key = ("secp-secpctl-operator", ORIGIN)
    malformed = json.loads(keystore.entries[key])
    malformed["e"] = "not-an-expiry"
    keystore.entries[key] = json.dumps(malformed).encode()
    client = _FakeDeviceClient()
    out, _waits2, _prompts2 = _deps(client=client, store=_working_store(keystore))

    code, report = auth_logout(out, gate=WRITE)

    assert code == EXIT_MALFORMED
    assert client.calls == []
    assert report["revocation_outcome"] == OUTCOME_UNREADABLE
    assert report["reason_code"] == "secpctl_credential_record_invalid"
    assert report["token_still_live"] is True
    assert report["removed"] is False
    assert key in keystore.entries
    _assert_logout_report_secret_free(report, malformed["t"])


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


def test_logout_still_revokes_a_locally_expired_credential():
    """Local expiry blocks replay but cannot prove the issuer's clock also considers the token dead.

    RFC 7009 revocation is idempotent for an already-dead token, so the conservative path submits
    the retained credential and only reports it dead after the provider answers successfully.
    """
    keystore = _FakeKeystore()
    deps, _w, _p = _deps(store=_working_store(keystore))
    auth_login(deps, gate=WRITE)
    stored = json.loads(keystore.entries[("secp-secpctl-operator", ORIGIN)])["t"]

    later = time.time() + 10_000
    client = _FakeDeviceClient()
    aged, _w2, _p2 = _deps(client=client, store=_working_store(keystore, now=lambda: later))
    with pytest.raises(ManagementError) as ei:
        aged.credential_store.for_account(ORIGIN).access_token()
    assert ei.value.reason_code == "secpctl_credential_expired"

    code, report = auth_logout(aged, gate=WRITE)

    assert code == EXIT_OK
    assert report["revocation_outcome"] == OUTCOME_REVOKED
    assert report["token_still_live"] is False
    assert report["removed"] is True and keystore.entries == {}
    assert client.revoked == [stored]
    assert client.calls == ["authority", "discover", "revoke"]


def test_a_locally_expired_credential_is_assumed_live_when_revocation_is_unavailable():
    keystore = _FakeKeystore()
    deps, _w, _p = _deps(store=_working_store(keystore))
    auth_login(deps, gate=WRITE)

    unavailable = RevocationOutcome(
        OUTCOME_UNAVAILABLE, reason_code="secpctl_revocation_provider_unavailable"
    )
    client = _FakeDeviceClient(revocation=unavailable)
    aged, _w2, _p2 = _deps(
        client=client,
        store=_working_store(keystore, now=lambda: time.time() + 10_000),
    )
    code, report = auth_logout(aged, gate=WRITE)

    assert code != EXIT_OK
    assert report["revocation_outcome"] == OUTCOME_UNAVAILABLE
    assert report["token_still_live"] is True
    assert report["removed"] is True and keystore.entries == {}
    assert client.calls == ["authority", "discover", "revoke"]


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


def test_logout_dry_run_plans_revocation_even_when_local_expiry_has_passed():
    keystore = _FakeKeystore()
    deps, _w, _p = _deps(store=_working_store(keystore))
    auth_login(deps, gate=WRITE)
    before = dict(keystore.entries)

    client = _FakeDeviceClient()
    aged, waits, prompts = _deps(
        client=client,
        store=_working_store(keystore, now=lambda: time.time() + 10_000),
    )
    code, report = auth_logout(aged, gate=DRY)

    assert code == EXIT_OK
    assert report["credential_expired"] is True
    assert report["revocation_planned"] is True
    assert client.calls == [] and waits == [] and prompts == []
    assert keystore.entries == before


@pytest.mark.parametrize(
    "reason",
    [
        "secpctl_credential_store_locked",
        "secpctl_credential_backend_failed",
    ],
)
def test_logout_dry_run_refuses_an_unreadable_store_instead_of_planning_nothing(reason):
    client = _FakeDeviceClient()
    deps, waits, prompts = _deps(
        client=client,
        store=_working_store(_FailingReadKeystore(reason)),
    )
    code, report = auth_logout(deps, gate=DRY)

    assert code == EXIT_AUTH_UNAVAILABLE
    _assert_refusal(report, "auth logout", reason)
    assert client.calls == [] and waits == [] and prompts == []


def test_logout_dry_run_refuses_a_corrupt_record_instead_of_planning_nothing():
    keystore = _FakeKeystore()
    keystore.entries[("secp-secpctl-operator", ORIGIN)] = b"not-json"
    client = _FakeDeviceClient()
    deps, waits, prompts = _deps(client=client, store=_working_store(keystore))
    code, report = auth_logout(deps, gate=DRY)

    assert code == EXIT_MALFORMED
    _assert_refusal(report, "auth logout", "secpctl_credential_record_invalid")
    assert "was removed" not in report["remedy"]
    assert "OS keystore" in report["remedy"]
    assert client.calls == [] and waits == [] and prompts == []


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
    _assert_refusal(report, "auth refresh", "secpctl_credential_absent")


@pytest.mark.parametrize(
    "reason",
    [
        "secpctl_credential_store_locked",
        "secpctl_credential_backend_failed",
    ],
)
def test_refresh_preserves_the_exact_unreadable_store_reason(reason):
    client = _FakeDeviceClient()
    deps, waits, prompts = _deps(
        client=client,
        store=_working_store(_FailingReadKeystore(reason)),
    )
    code, report = auth_refresh(deps, gate=WRITE)

    assert code == EXIT_AUTH_UNAVAILABLE
    _assert_refusal(report, "auth refresh", reason)
    assert client.calls == [] and waits == [] and prompts == []


def test_refresh_preserves_a_corrupt_record_reason_instead_of_calling_it_absent():
    keystore = _FakeKeystore()
    keystore.entries[("secp-secpctl-operator", ORIGIN)] = b"not-json"
    client = _FakeDeviceClient()
    deps, waits, prompts = _deps(client=client, store=_working_store(keystore))

    code, report = auth_refresh(deps, gate=WRITE)

    assert code == EXIT_MALFORMED
    _assert_refusal(report, "auth refresh", "secpctl_credential_record_invalid")
    assert "was removed" not in report["remedy"]
    assert "OS keystore" in report["remedy"]
    assert client.calls == [] and waits == [] and prompts == []
    assert keystore.entries[("secp-secpctl-operator", ORIGIN)] == b"not-json"


def test_refresh_refuses_a_record_without_an_identity_binding_before_the_grant():
    keystore = _FakeKeystore()
    store = _working_store(keystore)
    store.for_account(ORIGIN).store(
        OperatorAccessToken(_valid_token()),
        expires_at_epoch=int(time.time()) + 300,
        subject_fingerprint="",
    )
    before = dict(keystore.entries)
    client = _FakeDeviceClient(token=_valid_token(OTHER_SUBJECT))
    deps, waits, prompts = _deps(client=client, store=store)

    code, report = auth_refresh(deps, gate=WRITE)

    assert code == EXIT_MALFORMED
    _assert_refusal(report, "auth refresh", "secpctl_credential_record_invalid")
    assert client.calls == [] and waits == [] and prompts == []
    assert keystore.entries == before


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
    assert client.calls == [
        "authority",
        "discover",
        "device_authorization",
        "token",
        "jwks",
        "principal",
    ]
    assert prompts, "renewal is interactive: the operator must approve it again"
    assert keystore.entries[("secp-secpctl-operator", ORIGIN)] != original
    assert list(keystore.entries) == [("secp-secpctl-operator", ORIGIN)]


def test_refresh_resolves_the_principal_before_replacing_the_os_record():
    events: list[str] = []

    class _EventKeystore(_FakeKeystore):
        def set_secret(self, *, service, account, secret):
            events.append("store")
            return super().set_secret(service=service, account=account, secret=secret)

    keystore = _EventKeystore()
    initial, _waits, _prompts = _deps(store=_working_store(keystore))
    assert auth_login(initial, gate=WRITE)[0] == EXIT_OK
    events.clear()

    client = _FakeDeviceClient(token=_valid_token(lifetime=1200), events=events)
    deps, _waits, _prompts = _deps(client=client, store=_working_store(keystore))
    assert auth_refresh(deps, gate=WRITE)[0] == EXIT_OK
    assert events == ["principal", "store"]


def test_refresh_principal_failure_preserves_the_original_credential():
    keystore = _FakeKeystore()
    initial, _waits, _prompts = _deps(store=_working_store(keystore))
    assert auth_login(initial, gate=WRITE)[0] == EXIT_OK
    original = dict(keystore.entries)

    client = _FakeDeviceClient(principal_error="secpctl_operator_principal_unavailable")
    deps, _waits, _prompts = _deps(client=client, store=_working_store(keystore))
    code, report = auth_refresh(deps, gate=WRITE)

    assert code == EXIT_AUTH_UNAVAILABLE
    _assert_compensated_refusal(report, "auth refresh", "secpctl_operator_principal_unavailable")
    assert client.calls[-2:] == ["principal", "revoke"]
    assert keystore.entries == original


def test_refresh_store_failure_revokes_only_the_replacement_and_preserves_the_original():
    keystore = _FailingWriteKeystore()
    initial, _waits, _prompts = _deps(store=_working_store(keystore))
    assert auth_login(initial, gate=WRITE)[0] == EXIT_OK
    original = dict(keystore.entries)
    keystore.fail_writes = True

    replacement = _valid_token(lifetime=1200)
    client = _FakeDeviceClient(token=replacement)
    deps, _waits, _prompts = _deps(client=client, store=_working_store(keystore))
    code, report = auth_refresh(deps, gate=WRITE)

    assert code == EXIT_AUTH_UNAVAILABLE
    _assert_compensated_refusal(report, "auth refresh", "secpctl_credential_backend_failed")
    assert client.revoked == [replacement]
    assert keystore.entries == original


def test_refresh_refuses_to_switch_the_stored_identity_to_a_different_operator():
    """A renewal that comes back as somebody else must not overwrite the credential."""
    keystore = _FakeKeystore()
    deps, _waits, _prompts = _deps(store=_working_store(keystore))
    auth_login(deps, gate=WRITE)
    original = keystore.entries[("secp-secpctl-operator", ORIGIN)]

    replacement = _valid_token(OTHER_SUBJECT)
    other = _FakeDeviceClient(token=replacement)
    fresh, _w, _p = _deps(client=other, store=_working_store(keystore))
    code, report = auth_refresh(fresh, gate=WRITE)
    assert code == EXIT_REFUSED
    _assert_compensated_refusal(report, "auth refresh", "secpctl_credential_subject_changed")
    assert other.revoked == [replacement]
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
    assert set(client.calls) <= {
        "authority",
        "discover",
        "device_authorization",
        "token",
        "jwks",
        "principal",
    }


# --- status ---------------------------------------------------------------------------------------


def test_status_is_read_only_and_reports_the_sealed_store():
    client = _FakeDeviceClient()
    deps, waits, prompts = _deps(client=client, store=SealedOperatorCredentialStore())
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


def test_status_refuses_an_invalid_locator_instead_of_calling_it_unrecorded():
    deps, _waits, _prompts = _deps(
        store=_working_store(),
        locator=_FakeLocatorProvider("secpctl_controller_locator_invalid"),
    )
    code, report = auth_status(deps)
    assert code == EXIT_CONTROLLER_UNAVAILABLE
    _assert_refusal(report, "auth status", "secpctl_controller_locator_invalid")


# --- logout ---------------------------------------------------------------------------------------


def test_logout_dry_run_makes_no_deletion():
    store = _RecordingStore()
    deps, _waits, _prompts = _deps(store=store)
    code, report = auth_logout(deps, gate=DRY)
    assert code == EXIT_OK
    assert report["mode"] == "dry_run"


def test_logout_write_refuses_closed_on_the_sealed_store():
    deps, _waits, _prompts = _deps(store=SealedOperatorCredentialStore())
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
    assert "INCOMPLETE" in rendered
    assert "token file is never deleted" in rendered
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


_TERMINAL_CONTROL_VALUE = (
    "visible\n[forged command] exit=0\r"
    "\x00\t\x1b[31mred\x1b[0m\x7f\x85\x9b"
    "\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
    '"quoted"\\tail'
)
_BIDI_CONTROLS = frozenset(
    "\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
)


@pytest.mark.parametrize(
    "field",
    ("command", "role", "mode", "status", "ok", "trusted", "reason_code", "other"),
)
def test_every_human_scalar_string_is_terminal_escaped_on_one_physical_line(field):
    """Command, priority and ordinary fields all cross the same terminal-safety boundary."""
    from secp_management.cli import _render_human

    payload = {"command": "safe command", "ordinary": "still visible"}
    payload[field] = _TERMINAL_CONTROL_VALUE
    rendered = _render_human(EXIT_OK, payload)

    assert rendered.endswith("\n")
    assert rendered.count("\n") == 1
    line = rendered.removesuffix("\n")
    assert json.dumps(_TERMINAL_CONTROL_VALUE, ensure_ascii=True)[1:-1] in line
    assert r"\n[forged command] exit=0\r" in line
    assert r"\u001b[31m" in line and r"\u009b" in line
    assert r"\u202e" in line
    assert r"\"quoted\"\\tail" in line
    assert all(
        not (ord(char) < 0x20 or 0x7F <= ord(char) <= 0x9F or char in _BIDI_CONTROLS)
        for char in line
    )


def test_live_human_command_cannot_forge_a_report_line_through_site_input(monkeypatch, capsys):
    """Exercise parser -> command report -> stdout, not just the renderer in isolation."""
    import secp_management.cli as cli_module
    from secp_management.enrollment_cli import EnrollmentCliDeps

    malicious_site = 'north\n[auth logout] exit=0 status=revoked\r\x1b[2J\u202e"\\south'
    monkeypatch.setattr(cli_module, "_production_enrollment_deps", EnrollmentCliDeps)

    code = cli_module._dispatch_main(["enrollment", "invite", "create", "--site", malicious_site])
    rendered = capsys.readouterr().out

    assert code == EXIT_OK
    assert rendered.count("\n") == 1
    assert len(rendered.splitlines()) == 1
    assert f"deployment_site_label={json.dumps(malicious_site)[1:-1]}" in rendered
    assert "\n[auth logout]" not in rendered
    assert "\r" not in rendered and "\x1b" not in rendered and "\u202e" not in rendered


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


# --- an UNREADABLE credential is not "nothing to revoke" ------------------------------------------
#
# A snapshot refusal is not absence. A corrupt or foreign-account record can hold a live token, and
# without a validated immutable generation logout neither revokes nor deletes it.


class _UnreadableStore(SealedOperatorCredentialStore):
    """A store whose credential cannot be read, with a deletion tripwire."""

    def __init__(self, reason):
        self._reason = reason
        self.deleted = 0

    def for_account(self, account):
        return self

    def revocation_token(self):
        raise ManagementError(self._reason)

    def snapshot(self):
        if self._reason == "secpctl_credential_absent":
            return None
        raise ManagementError(self._reason)

    def describe(self):
        from secp_management.operator_credential_store import StoredCredentialStatus

        return StoredCredentialStatus(backend="fake", available=True, has_credential=True)

    def delete(self):
        self.deleted += 1
        return True


@pytest.mark.parametrize(
    "reason",
    [
        "secpctl_credential_record_invalid",
        "secpctl_credential_account_mismatch",
        "secpctl_credential_store_locked",
        "secpctl_credential_backend_failed",
    ],
)
def test_an_unreadable_credential_is_never_reported_as_nothing_to_revoke(reason):
    store = _UnreadableStore(reason)
    deps, _w, _p = _deps(store=store)
    code, report = auth_logout(deps, gate=WRITE)

    assert report["revocation_outcome"] == OUTCOME_UNREADABLE
    assert report["token_still_live"] is True, (
        "a credential that could not be READ may still be live at the provider; reporting it as "
        "'nothing to revoke' is a false negative"
    )
    assert report["revoked"] is False
    assert code != EXIT_OK
    # Without a validated generation the operation owns nothing and must not delete the entry.
    assert store.deleted == 0 and report["removed"] is False


def test_an_absent_credential_really_is_nothing_to_revoke():
    """The other side of the split: absent material genuinely leaves nothing to submit."""
    store = _UnreadableStore("secpctl_credential_absent")
    deps, _w, _p = _deps(store=store)
    code, report = auth_logout(deps, gate=WRITE)

    assert report["revocation_outcome"] == OUTCOME_NOT_REQUIRED
    assert report["token_still_live"] is False
    assert code == EXIT_OK


# --- a refusal after interactive approval must name the remedy ------------------------------------
#
# `MAX_SECRET_BYTES` is a real Windows limit (CRED_MAX_CREDENTIAL_BLOB_SIZE) and is correct, but a
# Keycloak token carrying realm/resource role claims can exceed it. The grant completes, the
# operator approves interactively, and only THEN does the persist refuse -- so a bare reason code
# strands them with no idea what to do. The size is not knowable before approval (the token does
# not exist until the operator approves), so the remedy is the recoverable part.


class _TooLargeStore(_RecordingStore):
    def store(self, token, *, expires_at_epoch, subject_fingerprint=""):
        raise ManagementError("secpctl_credential_too_large")


def test_an_oversized_token_refusal_names_the_remedy():
    deps, _w, prompts = _deps(store=_TooLargeStore())
    code, report = auth_login(deps, gate=WRITE)

    assert code == EXIT_AUTH_UNAVAILABLE
    assert report["reason_code"] == "secpctl_credential_too_large"
    assert prompts, "this refusal is only reachable AFTER the operator approved interactively"
    remedy = report.get("remedy", "")
    assert remedy, "a post-approval refusal with no remedy strands the operator"
    assert "roles" in remedy, "the remedy must name the actual fix (the roles client scope)"


def test_a_remedy_is_code_owned_and_leaks_nothing():
    """Remedies are fixed strings keyed by bounded reason code — never built from the environment,
    the provider, or the failure itself."""
    from secp_management.auth_cli import _REMEDY_BY_REASON

    for reason, remedy in _REMEDY_BY_REASON.items():
        assert reason.startswith("secpctl_")
        assert ORIGIN not in remedy and ISSUER not in remedy
        assert "eyJ" not in remedy


def test_remedies_are_rendered_to_the_operator():
    """A remedy in the report is useless if the human renderer drops it — the exact failure mode
    that hid `token_still_live`."""
    from secp_management.cli import _render_human

    deps, _w, _p = _deps(store=_TooLargeStore())
    code, report = auth_login(deps, gate=WRITE)
    assert "remedy=" in _render_human(code, report)


# --- the round trip the wiring fix exists to guarantee -------------------------------------------
#
# The earlier wiring tests assert provider TYPE, locator identity and the sealed-store refusal.
# None of them proves the token `auth login` stored comes back OUT through the provider the
# authenticated client uses -- so a regression that broke the binding would leave them all green.
# For the fix to a defect that was precisely "the store is wired to nothing", a guard that cannot
# detect the store being wired to nothing again is the wrong guard.


def test_a_token_stored_by_login_comes_back_out_through_the_provider():
    """End to end: `auth login` persists, and the provider the enrollment client holds returns THAT
    token. This is the property the whole BLOCKER 1 fix exists to establish."""
    from secp_management.operator_credential_store import ControllerScopedCredentialProvider

    keystore = _FakeKeystore()
    deps, _w, _p = _deps(store=_working_store(keystore))
    assert auth_login(deps, gate=WRITE)[0] == EXIT_OK

    # the provider composed exactly as `_production_enrollment_deps` composes it
    provider = ControllerScopedCredentialProvider(_working_store(keystore), _FakeLocatorProvider())
    token = provider.access_token()

    stored = json.loads(keystore.entries[("secp-secpctl-operator", ORIGIN)])["t"]
    assert token.authorization_header() == f"Bearer {stored}"


def test_the_provider_serves_no_token_for_a_controller_that_was_never_logged_in():
    """Cross-account isolation through the provider seam, not just the store."""
    from secp_management.operator_credential_store import ControllerScopedCredentialProvider

    keystore = _FakeKeystore()
    deps, _w, _p = _deps(store=_working_store(keystore))
    auth_login(deps, gate=WRITE)

    other = ControllerScopedCredentialProvider(
        _working_store(keystore), _FakeLocatorProvider(locator=OTHER_LOCATOR)
    )
    with pytest.raises(ManagementError) as ei:
        other.access_token()
    assert ei.value.reason_code == "secpctl_credential_absent"


def test_the_provider_refuses_an_expired_credential_rather_than_serving_it():
    from secp_management.operator_credential_store import ControllerScopedCredentialProvider

    keystore = _FakeKeystore()
    deps, _w, _p = _deps(store=_working_store(keystore))
    auth_login(deps, gate=WRITE)

    later = time.time() + 10_000
    provider = ControllerScopedCredentialProvider(
        _working_store(keystore, now=lambda: later), _FakeLocatorProvider()
    )
    with pytest.raises(ManagementError) as ei:
        provider.access_token()
    assert ei.value.reason_code == "secpctl_credential_expired"


def test_a_logout_makes_the_provider_stop_serving_the_token():
    """Revocation and deletion must be observable through the SAME seam authenticated commands use,
    not only through the store."""
    from secp_management.operator_credential_store import ControllerScopedCredentialProvider

    keystore = _FakeKeystore()
    deps, _w, _p = _deps(store=_working_store(keystore))
    auth_login(deps, gate=WRITE)
    provider = ControllerScopedCredentialProvider(_working_store(keystore), _FakeLocatorProvider())
    assert provider.access_token() is not None

    out, _w2, _p2 = _deps(store=_working_store(keystore))
    assert auth_logout(out, gate=WRITE)[0] == EXIT_OK
    with pytest.raises(ManagementError) as ei:
        provider.access_token()
    assert ei.value.reason_code == "secpctl_credential_absent"


def test_the_provider_never_reveals_the_token_in_a_repr():
    from secp_management.operator_credential_store import ControllerScopedCredentialProvider

    provider = ControllerScopedCredentialProvider(_working_store(), _FakeLocatorProvider())
    assert repr(provider) == "ControllerScopedCredentialProvider(<redacted>)"
    assert ORIGIN not in repr(provider)


# --- N2: which provider is actually live ----------------------------------------------------------


def test_auth_status_names_the_os_keystore_when_the_probe_says_so():
    deps, _w, _p = _deps(store=_working_store(), token_file_active=lambda: False)
    code, report = auth_status(deps)
    assert code == EXIT_OK
    assert report["active_token_provider"] == "os_keystore"
    assert report["token_file_override_active"] is False
    assert report["active_principal_resolved"] is False


def test_auth_status_never_calls_a_sealed_store_an_active_os_keystore():
    deps, _w, _p = _deps(
        store=SealedOperatorCredentialStore(),
        token_file_active=lambda: False,
    )
    code, report = auth_status(deps)
    assert code == EXIT_OK
    assert report["credential_store_available"] is False
    assert report["active_token_provider"] == "unavailable"
    assert report["token_file_override_active"] is False
    assert report["active_principal_resolved"] is False


def test_auth_status_resolves_the_live_os_credential_as_the_active_principal_for_human_and_json():
    from secp_management.cli import _render_human

    keystore = _FakeKeystore()
    initial, _w, _p = _deps(store=_working_store(keystore))
    assert auth_login(initial, gate=WRITE)[0] == EXIT_OK

    client = _FakeDeviceClient()
    deps, _w2, _p2 = _deps(
        client=client,
        store=_working_store(keystore),
        token_file_active=lambda: False,
    )
    code, report = auth_status(deps)

    assert code == EXIT_OK
    assert report["active_token_provider"] == "os_keystore"
    assert report["active_principal_resolved"] is True
    assert report["active_principal_user_id"] == SUBJECT
    assert report["active_principal_organization_id"] == ORGANIZATION_ID
    assert report["active_principal_permissions"] == list(OPERATOR_PERMISSIONS)
    assert client.calls == ["principal"]

    human = _render_human(code, report)
    assert f"active_principal_user_id={SUBJECT}" in human
    assert f"active_principal_organization_id={ORGANIZATION_ID}" in human
    assert "active_principal_permissions_display=enrollment:manage,enrollment:read" in human
    structured = json.dumps(report)
    assert '"active_principal_permissions": ["enrollment:manage", "enrollment:read"]' in structured
    assert "eyJ" not in structured and ORIGIN not in structured and ISSUER not in structured


def test_auth_status_says_unknown_rather_than_the_reassuring_answer():
    """The shipped default is reached exactly when deps composition FAILED — which is when
    "the keystore is live" is least justified. Reporting the comfortable value for an unknown is
    the same defect as reporting "nothing to revoke" for a credential that could not be read."""
    from secp_management.cli import _render_human

    code, report = auth_status(AuthCliDeps(credential_store=_working_store()))
    assert code == EXIT_OK
    assert report["active_token_provider"] == "unknown"
    # no boolean may be present, because a boolean would read as a settled answer
    assert "token_file_override_active" not in report
    assert "could not be" in _render_human(code, report)
    assert "NOT a statement" in _render_human(code, report)


def test_auth_status_warns_when_a_token_file_silently_overrides_the_keystore():
    """An operator who set the file during rollout, then logged in successfully, keeps sending the
    FILE's token. Login looks fine and the credential it stored is never used."""
    from secp_management.cli import _render_human

    provider = _StaticTokenProvider()
    client = _FakeDeviceClient()
    deps, _w, _p = _deps(
        client=client,
        store=_working_store(),
        token_file_active=lambda: True,
        token_file_provider=provider,
    )
    code, report = auth_status(deps)
    assert code == EXIT_OK
    assert report["active_token_provider"] == "token_file"
    assert report["token_file_override_active"] is True
    assert report["has_credential"] is False
    assert report["active_principal_resolved"] is True
    assert report["active_principal_user_id"] == SUBJECT
    assert "stored_principal_user_id" not in report
    assert provider.calls == 1 and client.calls == ["principal"]

    rendered = _render_human(code, report)
    assert "SECP_OPERATOR_TOKEN_FILE" in rendered
    assert "not the OS keystore" in rendered or "not\n  the OS keystore" in rendered
    assert f"active_principal_user_id={SUBJECT}" in rendered


def test_a_broken_override_probe_reports_unknown_and_never_breaks_a_read_only_status():
    def _explode():
        raise RuntimeError("probe failed")

    deps, _w, _p = _deps(store=_working_store(), token_file_active=_explode)
    code, report = auth_status(deps)
    assert code == EXIT_OK
    # the status still succeeds -- but it does NOT claim the keystore is live
    assert report["active_token_provider"] == "unknown"
    assert "token_file_override_active" not in report


# --- N1: the terminal-disclosure property now covers EVERY command group -------------------------
#
# Removing the renderer's fixed allowlist was right -- an allowlist turns every future report field
# into an invisible one. But it made "reports are safe to display" load-bearing for the WHOLE CLI,
# where before only `--json` carried most fields. That property was asserted for one auth report.
# It is now asserted for every command group, so another stream adding a report field cannot reach
# the terminal by default without this guard being consulted.

#: Shapes that must never reach a terminal, whatever produced the report.
_SECRET_SHAPES = (
    "eyJ",  # a JWT/JWS compact serialization
    "-----BEGIN",  # any PEM private key or certificate body
    "client_secret",
    "password",
    "Bearer ",
    "PRIVATE KEY",
)

#: Every command group `build_parser` exposes, with an invocation that reaches a report. All run
#: against SEALED defaults, so each yields a bounded refusal or a read-only projection -- which is
#: exactly the output an operator sees on an unprovisioned host.
_EVERY_GROUP_INVOCATION = (
    ["release", "verify", "--bundle", "/nonexistent"],
    ["host", "inspect"],
    ["bootstrap", "controller", "--bundle", "/nonexistent"],
    ["adopt", "controller", "--bundle", "/nonexistent"],
    ["status", "controller"],
    ["evidence", "controller"],
    ["rollback", "controller"],
    [
        "controller",
        "install",
        "--bundle",
        "/x",
        "--public-origin",
        "https://c.invalid",
        "--tls-mode",
        "reverse_proxy",
    ],
    ["enrollment", "invite", "create", "--site", "s"],
    ["enrollment", "status", "--enrollment-id", "e"],
    ["worker", "enroll", "--invitation", "/nonexistent"],
    ["worker", "enrollment", "status", "--invitation", "/nonexistent"],
    ["auth", "status"],
    ["auth", "login"],
    ["auth", "logout"],
    ["auth", "refresh"],
)


@pytest.mark.parametrize("argv", _EVERY_GROUP_INVOCATION, ids=lambda a: " ".join(a[:3]))
def test_no_command_groups_terminal_output_can_carry_a_secret(argv):
    """Live invocation where the host allows one. Several engine groups cannot produce a report on
    a non-POSIX host (their sealed deps refuse `filesystem()` before any report exists), so they are
    skipped HERE and covered host-independently by the field-name guard below — the two together,
    not either alone, are what make this property hold for every group."""
    from secp_management.cli import _render_human

    try:
        code, report = run(list(argv))
    except SystemExit as exc:  # pragma: no cover - a parser-invalid entry is a defect, not a skip
        raise AssertionError(
            f"{argv} is not accepted by build_parser(); a permanently-skipping entry in this "
            "table asserts nothing on any host, forever"
        ) from exc
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"group produces no report on this host: {type(exc).__name__}")
    rendered = _render_human(code, report)
    for shape in _SECRET_SHAPES:
        assert shape not in rendered, f"{shape!r} reached the terminal from {argv}"
    for key, value in report.items():
        if isinstance(value, (dict, list)):
            assert f"{key}=" not in rendered, f"nested {key} was rendered to the terminal"


#: Substrings that make a field name secret-shaped wherever they appear. The renderer now prints
#: every scalar to the terminal by default, so a field named like this would leak by default.
_FORBIDDEN_REPORT_FIELD_SHAPES = ("secret", "password", "passphrase", "private_key")

#: Names dangerous only as a WHOLE field name. Matched exactly rather than as a substring, because
#: `authorization` is also a legitimate word inside the RFC 8628 reason codes
#: (`secpctl_device_authorization_denied` and friends) — those are exit-map keys, not report fields,
#: and widening the substring set to catch a header name would flag every one of them.
_FORBIDDEN_EXACT_FIELD_NAMES = frozenset({"authorization", "bearer", "token", "access_token"})

#: Dict keys that legitimately match a forbidden shape. Scoped to (module, key) PAIRS rather than
#: bare names: exempting `token` outright would also exempt a genuine report field called `token`
#: anywhere in the package, which is exactly the over-broad exception that turns a guard into
#: decoration. Each entry is a deliberate, reviewable decision with its reason.
#:
#: The scan reads every dict key in the package, which is a superset of report fields — so REQUEST
#: payload keys legitimately appear here. They are not rendered: they are sent, not reported.
_REVIEWED_FIELD_EXCEPTIONS: frozenset[tuple[str, str]] = frozenset(
    {
        # An outbound HTTP header name, not a report field: `{"Authorization": <bearer>}` on the
        # pinned controller request. The VALUE never enters a report; `_SECRET_SHAPES` covers that.
        ("enrollment_controller_client.py", "Authorization"),
        # The same outbound header on the exact CA-pinned `/api/v1/me` request. It resolves the
        # authoritative DB-backed principal and is never merged into a report.
        ("operator_device_auth.py", "Authorization"),
        # The RFC 7009 §2.1 revocation FORM parameter. Sent in a request body, never reported —
        # `test_a_logout_report_never_carries_the_token_or_the_origin` pins the reporting side.
        ("operator_token_revoke.py", "token"),
        # A boolean capability flag on the credential status projection; carries no secret.
        ("operator_credential_store.py", "has_secret_store"),
    }
)


def _report_key_literals(path) -> set[str]:
    """Every string literal used as a dict key in a file — a superset of its report fields."""
    import ast

    tree = ast.parse(path.read_text(encoding="utf-8"))
    keys: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for k in node.keys:
                if isinstance(k, ast.Constant) and isinstance(k.value, str):
                    keys.add(k.value)
    return keys


def _scanned_modules() -> list:
    """EVERY module in the management package. Not a seed, not a list.

    This guard has now under-covered three times, each time because it enumerated: a hardcoded
    tuple, then a seed matching modules that ASSEMBLE reports (a ``"command"`` key), which missed
    modules that merely CONTRIBUTE fields — ``StoredCredentialStatus.to_report`` and
    ``RevocationOutcome.to_report`` both merge field names into rendered reports without ever
    writing ``"command"``, and both demonstrably reach the terminal.

    Adding ``def to_report`` as a second seed would have worked today and failed the next time
    someone invented a third way to contribute a field. The check is string-set membership over
    dict keys, so scanning everything costs nothing and is the only version that cannot
    under-cover. Legitimate matches are handled by the reviewed exceptions list, where each is a
    deliberate, visible decision.
    """
    import pathlib as _pathlib

    import secp_management

    return sorted(_pathlib.Path(secp_management.__file__).parent.glob("*.py"))


def test_the_scan_covers_report_assemblers_and_contributors_alike():
    """Anti-vacuity, and a regression pin for the two ways this guard has under-covered.

    ``engine``/``enrollment_cli``/``auth_cli`` ASSEMBLE reports. ``operator_credential_store`` and
    ``operator_token_revoke`` only CONTRIBUTE fields, via ``to_report`` merged into a larger report
    — they carry no ``"command"`` key and were invisible to the previous seed, while their fields
    (``credential_backend``, ``token_still_live``, ...) print to the terminal on every `auth`
    command."""
    found = {path.name for path in _scanned_modules()}
    for assembler in ("engine.py", "enrollment_cli.py", "auth_cli.py", "cli.py"):
        assert assembler in found, f"{assembler} assembles reports but is not scanned"
    for contributor in ("operator_credential_store.py", "operator_token_revoke.py"):
        assert contributor in found, f"{contributor} contributes report fields but is not scanned"


def test_no_report_producing_module_emits_a_secret_shaped_field_name():
    """Host-independent, and the control that actually holds the line: the renderer prints every
    scalar, so a field named like a secret would reach the terminal by default. This fails in the
    file another stream would have to edit, rather than only on a host that can run that group."""
    offenders = []
    for path in _scanned_modules():
        for key in _report_key_literals(path):
            if (path.name, key) in _REVIEWED_FIELD_EXCEPTIONS:
                continue
            lowered = key.lower()
            if lowered in _FORBIDDEN_EXACT_FIELD_NAMES or any(
                shape in lowered for shape in _FORBIDDEN_REPORT_FIELD_SHAPES
            ):
                offenders.append(f"{path.name}:{key}")
    assert offenders == [], (
        f"secret-shaped report field names would print to the terminal by default: {offenders}"
    )


def test_an_exception_is_scoped_to_one_module_and_cannot_leak_to_another():
    """`token` is exempt in `operator_token_revoke` because it is an RFC 7009 form parameter. That
    must NOT exempt a report field called `token` anywhere else — an exception scoped by bare name
    would, and that is how a guard becomes decoration."""
    assert ("operator_token_revoke.py", "token") in _REVIEWED_FIELD_EXCEPTIONS
    assert ("auth_cli.py", "token") not in _REVIEWED_FIELD_EXCEPTIONS
    assert all(isinstance(entry, tuple) and len(entry) == 2 for entry in _REVIEWED_FIELD_EXCEPTIONS)


def test_the_field_name_guard_would_actually_catch_one():
    """Anti-vacuity for the guard above, on both matching modes."""
    assert any(shape in "client_secret" for shape in _FORBIDDEN_REPORT_FIELD_SHAPES)
    assert any(shape in "db_password" for shape in _FORBIDDEN_REPORT_FIELD_SHAPES)
    assert "authorization" in _FORBIDDEN_EXACT_FIELD_NAMES
    # ...and the exact-match mode must NOT flag the RFC 8628 reason codes, which are exit-map keys
    assert "secpctl_device_authorization_denied" not in _FORBIDDEN_EXACT_FIELD_NAMES
    assert not any(
        shape in "secpctl_device_authorization_denied" for shape in _FORBIDDEN_REPORT_FIELD_SHAPES
    )


def test_the_secret_shape_guard_would_actually_catch_one():
    """Anti-vacuity: a guard asserting an absence proves nothing unless it can detect a presence."""
    from secp_management.cli import _render_human

    rendered = _render_human(0, {"command": "x", "leaked": "eyJhbGciOiJSUzI1NiJ9.abc.def"})
    assert any(shape in rendered for shape in _SECRET_SHAPES)
