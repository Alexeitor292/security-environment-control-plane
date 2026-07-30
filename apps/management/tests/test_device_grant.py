"""RFC 8628 device-grant protocol core (SECP-PR5H-B2, Workstream C).

These pin the spec rules that implementations most often get wrong — the OPTIONAL `interval` default
and the PERMANENT `slow_down` increase — plus the local bounds that stop a hostile or broken
provider from pinning the CLI, and the redaction posture of the device code.
"""

from __future__ import annotations

import copy
import pickle

import pytest
from secp_management import ManagementError
from secp_management.device_grant import (
    ACTION_POLL,
    ACTION_STOP,
    DEFAULT_INTERVAL_SECONDS,
    DEVICE_CODE_GRANT_TYPE,
    SLOW_DOWN_INCREMENT_SECONDS,
    DeviceCode,
    DevicePollScheduler,
    parse_device_authorization,
)

VALID = {
    "device_code": "Zm9vYmFyLWRldmljZS1jb2RlLXZhbHVlLTAwMDE",
    "user_code": "WDJL-MBQK",
    "verification_uri": "https://idp.invalid/device",
    "expires_in": 600,
    "interval": 5,
}


def _payload(**overrides):
    data = dict(VALID)
    data.update(overrides)
    return data


def _parse(payload):
    return parse_device_authorization(payload, require_https=True)


def _reason(excinfo) -> str:
    return excinfo.value.reason_code


# --- §3.4 grant type ------------------------------------------------------------------------------


def test_grant_type_is_the_exact_rfc_8628_uri():
    assert DEVICE_CODE_GRANT_TYPE == "urn:ietf:params:oauth:grant-type:device_code"


# --- §3.2 response parsing ------------------------------------------------------------------------


def test_valid_response_parses_every_field():
    auth = _parse(_payload(verification_uri_complete="https://idp.invalid/device?user_code=WDJL"))
    assert auth.user_code == "WDJL-MBQK"
    assert auth.verification_uri == "https://idp.invalid/device"
    assert auth.verification_uri_complete == "https://idp.invalid/device?user_code=WDJL"
    assert auth.expires_in == 600
    assert auth.interval == 5
    assert auth.device_code.token_request_value() == VALID["device_code"]


def test_absent_interval_defaults_to_five_seconds():
    """RFC 8628 §3.2: `interval` is OPTIONAL and defaults to 5 seconds. A provider that omits it
    must never be read as licensing a faster poll."""
    payload = _payload()
    del payload["interval"]
    assert _parse(payload).interval == DEFAULT_INTERVAL_SECONDS == 5


def test_null_interval_also_defaults_to_five_seconds():
    assert _parse(_payload(interval=None)).interval == 5


def test_verification_uri_complete_is_optional():
    assert _parse(_payload()).verification_uri_complete is None


@pytest.mark.parametrize("field", ["device_code", "user_code", "verification_uri", "expires_in"])
def test_every_required_field_is_required(field):
    payload = _payload()
    del payload[field]
    with pytest.raises(ManagementError) as ei:
        _parse(payload)
    assert _reason(ei) == "secpctl_device_authorization_invalid"


@pytest.mark.parametrize(
    "value",
    [
        "http://idp.invalid/device",  # plaintext when https is required
        "https://user:pw@idp.invalid/device",  # userinfo
        "https://idp.invalid/dev ice",  # whitespace
        "javascript:alert(1)",  # not http(s)
        "https:///device",  # no host
        "",
        None,
        123,
    ],
)
def test_unsafe_verification_uri_is_refused(value):
    with pytest.raises(ManagementError) as ei:
        _parse(_payload(verification_uri=value))
    assert _reason(ei) == "secpctl_device_authorization_invalid"


def test_plaintext_verification_uri_allowed_only_when_https_not_required():
    auth = parse_device_authorization(
        _payload(verification_uri="http://localhost:8081/device"), require_https=False
    )
    assert auth.verification_uri == "http://localhost:8081/device"


@pytest.mark.parametrize("value", [True, False, "600", 600.5, 0, -1, 10**9])
def test_expires_in_must_be_a_bounded_int_and_never_a_bool(value):
    """`bool` is an `int` subclass — a JSON `true` must never be read as 1."""
    with pytest.raises(ManagementError) as ei:
        _parse(_payload(expires_in=value))
    assert _reason(ei) == "secpctl_device_authorization_invalid"


@pytest.mark.parametrize("value", [True, "5", 5.0, 0, -5, 10**6])
def test_interval_must_be_a_bounded_int_and_never_a_bool(value):
    with pytest.raises(ManagementError) as ei:
        _parse(_payload(interval=value))
    assert _reason(ei) == "secpctl_device_authorization_invalid"


@pytest.mark.parametrize("value", ["", "short", "has space", "a" * 4000, None, 42])
def test_malformed_device_code_is_refused(value):
    with pytest.raises(ManagementError) as ei:
        _parse(_payload(device_code=value))
    assert _reason(ei) == "secpctl_device_authorization_invalid"


@pytest.mark.parametrize("value", ["", "abc", "a" * 100, "code\nwith-newline", None])
def test_malformed_user_code_is_refused(value):
    with pytest.raises(ManagementError) as ei:
        _parse(_payload(user_code=value))
    assert _reason(ei) == "secpctl_device_authorization_invalid"


@pytest.mark.parametrize("payload", [None, [], "string", 7])
def test_non_object_response_is_refused(payload):
    with pytest.raises(ManagementError) as ei:
        _parse(payload)
    assert _reason(ei) == "secpctl_device_authorization_invalid"


# --- device-code secrecy --------------------------------------------------------------------------


def test_device_code_repr_never_reveals_the_value():
    code = DeviceCode(VALID["device_code"])
    assert repr(code) == "DeviceCode(<redacted>)"
    assert VALID["device_code"] not in repr(code)


def test_device_authorization_repr_never_reveals_the_device_code():
    auth = _parse(_payload())
    assert VALID["device_code"] not in repr(auth)


def test_device_code_cannot_be_pickled_or_copied():
    code = DeviceCode(VALID["device_code"])
    for attempt in (lambda: pickle.dumps(code), lambda: copy.deepcopy(code)):
        with pytest.raises(ManagementError) as ei:
            attempt()
        assert _reason(ei) == "secpctl_device_code_not_serializable"


# --- §3.5 poll scheduling -------------------------------------------------------------------------


def _scheduler(interval=5, expires_in=600, max_attempts=600):
    return DevicePollScheduler(
        interval_seconds=interval, expires_in_seconds=expires_in, max_attempts=max_attempts
    )


def test_authorization_pending_keeps_polling_at_the_same_interval():
    sched = _scheduler(interval=5)
    decision = sched.record_error("authorization_pending")
    assert decision.action == ACTION_POLL
    assert decision.wait_seconds == 5
    assert sched.interval_seconds == 5


def test_slow_down_increases_the_interval_by_exactly_five_seconds():
    sched = _scheduler(interval=5)
    decision = sched.record_error("slow_down")
    assert decision.action == ACTION_POLL
    assert sched.interval_seconds == 5 + SLOW_DOWN_INCREMENT_SECONDS == 10
    assert decision.wait_seconds == 10


def test_slow_down_increase_is_permanent_for_all_subsequent_requests():
    """RFC 8628 §3.5: the interval MUST be increased by 5 seconds for THIS AND ALL SUBSEQUENT
    requests. A one-off backoff that reverts on the next `authorization_pending` is wrong."""
    sched = _scheduler(interval=5)
    sched.record_error("slow_down")
    assert sched.interval_seconds == 10
    # a later authorization_pending must NOT revert the interval
    assert sched.record_error("authorization_pending").wait_seconds == 10
    assert sched.interval_seconds == 10
    # and a second slow_down compounds
    sched.record_error("slow_down")
    assert sched.interval_seconds == 15
    assert sched.next_attempt(elapsed_seconds=0).wait_seconds == 15


def test_repeated_slow_down_is_bounded_and_never_grows_without_limit():
    sched = _scheduler(interval=5)
    for _ in range(50):
        sched.record_error("slow_down")
    assert sched.interval_seconds <= 60


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        ("access_denied", "secpctl_device_authorization_denied"),
        ("expired_token", "secpctl_device_code_expired"),
    ],
)
def test_terminal_errors_stop_polling_immediately(error, reason):
    decision = _scheduler().record_error(error)
    assert decision.action == ACTION_STOP
    assert decision.reason_code == reason


@pytest.mark.parametrize(
    "error", ["invalid_grant", "invalid_client", "unsupported_grant_type", "", None, "unknown"]
)
def test_any_other_error_stops_rather_than_polling_on(error):
    """The RFC defines continued polling for exactly two codes. Everything else stops — a client
    that keeps polling on an unrecognised error hammers the provider."""
    decision = _scheduler().record_error(error)
    assert decision.action == ACTION_STOP
    assert decision.reason_code == "secpctl_device_token_refused"


def test_polling_stops_at_the_local_deadline_derived_from_expires_in():
    sched = _scheduler(expires_in=600)
    assert sched.next_attempt(elapsed_seconds=599).action == ACTION_POLL
    decision = sched.next_attempt(elapsed_seconds=600)
    assert decision.action == ACTION_STOP
    assert decision.reason_code == "secpctl_device_code_expired"


def test_polling_stops_when_the_attempt_budget_is_exhausted():
    """An independent bound: a provider answering `authorization_pending` forever, with a clock that
    never advances, still cannot pin the CLI."""
    sched = _scheduler(max_attempts=3)
    for _ in range(3):
        assert sched.next_attempt(elapsed_seconds=0).action == ACTION_POLL
    decision = sched.next_attempt(elapsed_seconds=0)
    assert decision.action == ACTION_STOP
    assert decision.reason_code == "secpctl_device_poll_exhausted"


def test_scheduler_is_built_from_a_parsed_authorization():
    sched = DevicePollScheduler.for_authorization(_parse(_payload(interval=7, expires_in=300)))
    assert sched.interval_seconds == 7
    assert sched.next_attempt(elapsed_seconds=299).action == ACTION_POLL
    assert sched.next_attempt(elapsed_seconds=300).action == ACTION_STOP


@pytest.mark.parametrize(
    ("interval", "expires_in", "attempts"),
    [(0, 600, 10), (5, 0, 10), (5, 600, 0), (999, 600, 10), (5, 10**9, 10)],
)
def test_scheduler_refuses_out_of_bound_construction(interval, expires_in, attempts):
    with pytest.raises(ManagementError):
        DevicePollScheduler(
            interval_seconds=interval, expires_in_seconds=expires_in, max_attempts=attempts
        )


def test_scheduler_refuses_a_non_numeric_elapsed_time():
    with pytest.raises(ManagementError):
        _scheduler().next_attempt(elapsed_seconds="0")


def test_scheduler_performs_no_io():
    """The scheduler must never sleep or read a clock — the caller supplies elapsed time. Proven
    structurally so a future edit cannot quietly introduce a sleep."""
    import ast
    import pathlib

    import secp_management.device_grant as module

    tree = ast.parse(pathlib.Path(module.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = (
                [a.name for a in node.names]
                if isinstance(node, ast.Import)
                else [node.module or ""]
            )
            for name in names:
                assert name.split(".")[0] not in {
                    "time",
                    "socket",
                    "httpx",
                    "os",
                    "pathlib",
                    "subprocess",
                    "requests",
                }
        # no call named sleep/monotonic/time anywhere in the module's CODE
        if isinstance(node, ast.Call):
            target = node.func
            called = target.attr if isinstance(target, ast.Attribute) else getattr(target, "id", "")
            assert called not in {"sleep", "monotonic", "time", "perf_counter"}
