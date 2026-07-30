"""Pure OAuth 2.0 Device Authorization Grant protocol core (RFC 8628) — SECP-PR5H-B2, Workstream C.

This is the DECISION layer of ``secpctl auth login``: it strictly parses a device-authorization
response and schedules the token-endpoint poll. It performs NO I/O — no socket, no sleep, no clock
read, no filesystem, no environment, no logging. Elapsed time arrives as a caller-supplied argument,
so the entire grant is exercisable deterministically in unit tests.

The RFC 8628 rules pinned here are the ones implementations most often get wrong:

* ``interval`` is OPTIONAL in the device-authorization response and DEFAULTS TO 5 SECONDS when it is
  absent (§3.2). A provider that omits it never licenses a faster poll.
* ``slow_down`` increases the interval by 5 seconds **for this and all subsequent requests** (§3.5)
  — a PERMANENT increase, never a one-off backoff.
* ``authorization_pending`` continues polling at the current interval; ``access_denied`` and
  ``expired_token`` stop IMMEDIATELY (§3.5).
* Polling is additionally bounded by a LOCAL deadline derived from ``expires_in`` and by a bounded
  attempt budget, so a provider answering ``authorization_pending`` forever cannot pin the CLI.

The ``device_code`` is a bearer credential: it is held only inside :class:`DeviceCode`, which is
non-serializable and carries a constant redacted repr (the :class:`~secp_management.operator_auth.
OperatorAccessToken` posture). The ``user_code`` and ``verification_uri`` are the operator-facing
values the grant exists to display and are deliberately NOT redacted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import NoReturn
from urllib.parse import urlsplit

from secp_management import ManagementError

# --- RFC 8628 constants ---------------------------------------------------------------------------

#: RFC 8628 §3.4 — the device-code grant type.
DEVICE_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"

#: RFC 8628 §3.2 — the poll interval when the provider omits ``interval``.
DEFAULT_INTERVAL_SECONDS = 5
#: RFC 8628 §3.5 — ``slow_down`` increases the interval by exactly this, PERMANENTLY.
SLOW_DOWN_INCREMENT_SECONDS = 5

#: RFC 8628 §3.5 token-endpoint polling errors.
ERROR_AUTHORIZATION_PENDING = "authorization_pending"
ERROR_SLOW_DOWN = "slow_down"
ERROR_ACCESS_DENIED = "access_denied"
ERROR_EXPIRED_TOKEN = "expired_token"

# --- local bounds (defence against a hostile or broken provider) ----------------------------------

_MIN_INTERVAL_SECONDS = 1
_MAX_INTERVAL_SECONDS = 60
_MIN_EXPIRES_IN_SECONDS = 1
_MAX_EXPIRES_IN_SECONDS = 1800  # 30 minutes; Keycloak's realm default is 600
#: A hard ceiling on poll attempts, independent of the deadline.
DEFAULT_MAX_ATTEMPTS = 600

_MAX_DEVICE_CODE_LEN = 2048
_MIN_DEVICE_CODE_LEN = 8
_MAX_USER_CODE_LEN = 64
_MIN_USER_CODE_LEN = 4
_MAX_URI_LEN = 1024

# A device code is an opaque, whitespace-free, control-free printable string.
_DEVICE_CODE_GRAMMAR = re.compile(r"[\x21-\x7e]{8,2048}")
# A user code is displayed to a human: printable, bounded, no control characters. RFC 8628 §6.1
# recommends a restricted charset, but providers vary (hyphens and lowercase are common), so the
# grammar stays permissive-but-safe rather than guessing the provider's alphabet.
_USER_CODE_GRAMMAR = re.compile(r"[\x20-\x7e]{4,64}")

# --- poll decisions -------------------------------------------------------------------------------

ACTION_POLL = "poll"
ACTION_STOP = "stop"


class DeviceGrantError(ManagementError):
    """A bounded, closed device-grant refusal — carries ONLY a reason code, never the device code,
    user code, provider body, endpoint, or a raw exception."""


def _reject(reason_code: str) -> NoReturn:
    raise DeviceGrantError(reason_code)


class _NonSerializable:
    """Refuses pickling/copying so a secret can never be written to disk or a log by accident."""

    def __reduce__(self) -> NoReturn:
        _reject("secpctl_device_code_not_serializable")

    def __getstate__(self) -> NoReturn:
        _reject("secpctl_device_code_not_serializable")


class DeviceCode(_NonSerializable):
    """Holds the RFC 8628 ``device_code`` IN MEMORY. It is never represented, logged, serialized, or
    copied; it is exposed ONLY as the token-request form value for a single poll."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str) or not _DEVICE_CODE_GRAMMAR.fullmatch(value):
            _reject("secpctl_device_authorization_invalid")
        self._value = value

    def __repr__(self) -> str:  # never the device code
        return "DeviceCode(<redacted>)"

    def token_request_value(self) -> str:
        """The ``device_code`` form parameter for one token request (RFC 8628 §3.4)."""
        return self._value


@dataclass(frozen=True)
class DeviceAuthorization:
    """A validated RFC 8628 §3.2 device-authorization response.

    ``device_code`` is redacted by :class:`DeviceCode`, so this dataclass's generated repr is safe.
    ``user_code`` / ``verification_uri`` / ``verification_uri_complete`` are the operator-facing
    values the grant exists to display and are intentionally in the clear.
    """

    device_code: DeviceCode
    user_code: str
    verification_uri: str
    expires_in: int
    interval: int
    verification_uri_complete: str | None = None


def _bounded_int(value: object, *, low: int, high: int) -> int | None:
    """An int strictly within ``[low, high]``. ``bool`` is refused (it is an ``int`` subclass, and a
    JSON ``true`` must never be read as ``1``). A float/str is refused — no coercion."""
    if not isinstance(value, int) or isinstance(value, bool):
        return None
    return value if low <= value <= high else None


def _safe_uri(value: object, *, require_https: bool) -> str | None:
    """A bare HTTP(S) URL with a host, no userinfo, and no control characters."""
    if not isinstance(value, str) or not (1 <= len(value) <= _MAX_URI_LEN):
        return None
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        return None
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https"):
        return None
    if require_https and parsed.scheme != "https":
        return None
    if parsed.username or parsed.password or "@" in parsed.netloc:
        return None
    if not parsed.hostname:
        return None
    return value


def parse_device_authorization(payload: object, *, require_https: bool) -> DeviceAuthorization:
    """Strictly parse an RFC 8628 §3.2 device-authorization response.

    ``device_code``, ``user_code``, ``verification_uri`` and ``expires_in`` are REQUIRED;
    ``verification_uri_complete`` and ``interval`` are OPTIONAL. A missing ``interval`` becomes
    :data:`DEFAULT_INTERVAL_SECONDS` (5) — never a faster poll. Every value is bounded before use;
    a malformed response is one bounded refusal that never echoes provider content.
    """
    if not isinstance(payload, dict):
        _reject("secpctl_device_authorization_invalid")

    device_code = DeviceCode(payload.get("device_code"))  # validates the grammar, or refuses

    user_code = payload.get("user_code")
    if (
        not isinstance(user_code, str)
        or not (_MIN_USER_CODE_LEN <= len(user_code) <= _MAX_USER_CODE_LEN)
        or not _USER_CODE_GRAMMAR.fullmatch(user_code)
    ):
        _reject("secpctl_device_authorization_invalid")

    verification_uri = _safe_uri(payload.get("verification_uri"), require_https=require_https)
    if verification_uri is None:
        _reject("secpctl_device_authorization_invalid")

    complete_raw = payload.get("verification_uri_complete")
    verification_uri_complete: str | None = None
    if complete_raw is not None:
        verification_uri_complete = _safe_uri(complete_raw, require_https=require_https)
        if verification_uri_complete is None:
            _reject("secpctl_device_authorization_invalid")

    expires_in = _bounded_int(
        payload.get("expires_in"), low=_MIN_EXPIRES_IN_SECONDS, high=_MAX_EXPIRES_IN_SECONDS
    )
    if expires_in is None:
        _reject("secpctl_device_authorization_invalid")

    # RFC 8628 §3.2: `interval` is OPTIONAL and defaults to 5 seconds when absent.
    if "interval" not in payload or payload.get("interval") is None:
        interval = DEFAULT_INTERVAL_SECONDS
    else:
        bounded = _bounded_int(
            payload.get("interval"), low=_MIN_INTERVAL_SECONDS, high=_MAX_INTERVAL_SECONDS
        )
        if bounded is None:
            _reject("secpctl_device_authorization_invalid")
        interval = bounded

    return DeviceAuthorization(
        device_code=device_code,
        user_code=user_code,
        verification_uri=verification_uri,
        expires_in=expires_in,
        interval=interval,
        verification_uri_complete=verification_uri_complete,
    )


@dataclass(frozen=True)
class PollDecision:
    """One bounded scheduling decision. ``reason_code`` is empty while polling continues."""

    action: str
    wait_seconds: int = 0
    reason_code: str = ""

    @property
    def stop(self) -> bool:
        return self.action == ACTION_STOP


class DevicePollScheduler:
    """The RFC 8628 §3.5 token-endpoint poll schedule. Pure: it never sleeps and never reads a
    clock — the caller supplies ``elapsed_seconds`` measured from a monotonic source."""

    __slots__ = ("_interval", "_deadline", "_max_attempts", "_attempts")

    def __init__(
        self,
        *,
        interval_seconds: int,
        expires_in_seconds: int,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    ) -> None:
        if (
            _bounded_int(interval_seconds, low=_MIN_INTERVAL_SECONDS, high=_MAX_INTERVAL_SECONDS)
            is None
        ):
            _reject("secpctl_device_authorization_invalid")
        if (
            _bounded_int(
                expires_in_seconds, low=_MIN_EXPIRES_IN_SECONDS, high=_MAX_EXPIRES_IN_SECONDS
            )
            is None
        ):
            _reject("secpctl_device_authorization_invalid")
        if _bounded_int(max_attempts, low=1, high=DEFAULT_MAX_ATTEMPTS) is None:
            _reject("secpctl_device_authorization_invalid")
        self._interval = interval_seconds
        self._deadline = expires_in_seconds
        self._max_attempts = max_attempts
        self._attempts = 0

    @classmethod
    def for_authorization(
        cls, authorization: DeviceAuthorization, *, max_attempts: int = DEFAULT_MAX_ATTEMPTS
    ) -> DevicePollScheduler:
        return cls(
            interval_seconds=authorization.interval,
            expires_in_seconds=authorization.expires_in,
            max_attempts=max_attempts,
        )

    @property
    def interval_seconds(self) -> int:
        """The CURRENT poll interval, including every permanent ``slow_down`` increase."""
        return self._interval

    @property
    def attempts(self) -> int:
        return self._attempts

    def next_attempt(self, *, elapsed_seconds: float) -> PollDecision:
        """Decide whether to make the next poll attempt, and how long to wait first.

        Stops when the LOCAL deadline derived from ``expires_in`` has passed or the bounded attempt
        budget is exhausted — independent of anything the provider says.
        """
        if not isinstance(elapsed_seconds, (int, float)) or isinstance(elapsed_seconds, bool):
            _reject("secpctl_device_authorization_invalid")
        if elapsed_seconds >= self._deadline:
            return PollDecision(ACTION_STOP, reason_code="secpctl_device_code_expired")
        if self._attempts >= self._max_attempts:
            return PollDecision(ACTION_STOP, reason_code="secpctl_device_poll_exhausted")
        self._attempts += 1
        return PollDecision(ACTION_POLL, wait_seconds=self._interval)

    def record_error(self, error: object) -> PollDecision:
        """Apply an RFC 8628 §3.5 token-endpoint error to the schedule.

        ``authorization_pending`` continues at the current interval. ``slow_down`` continues and
        PERMANENTLY increases the interval by 5 seconds for this and all subsequent requests.
        ``access_denied`` and ``expired_token`` stop immediately, as does any other/unknown error —
        the RFC defines continued polling for exactly two codes and no more.
        """
        if error == ERROR_AUTHORIZATION_PENDING:
            return PollDecision(ACTION_POLL, wait_seconds=self._interval)
        if error == ERROR_SLOW_DOWN:
            # PERMANENT increase — applies to this and every subsequent request (§3.5).
            self._interval = min(
                self._interval + SLOW_DOWN_INCREMENT_SECONDS, _MAX_INTERVAL_SECONDS
            )
            return PollDecision(ACTION_POLL, wait_seconds=self._interval)
        if error == ERROR_ACCESS_DENIED:
            return PollDecision(ACTION_STOP, reason_code="secpctl_device_authorization_denied")
        if error == ERROR_EXPIRED_TOKEN:
            return PollDecision(ACTION_STOP, reason_code="secpctl_device_code_expired")
        # invalid_grant / invalid_client / unsupported_grant_type / unknown -> stop, bounded.
        return PollDecision(ACTION_STOP, reason_code="secpctl_device_token_refused")


__all__ = [
    "ACTION_POLL",
    "ACTION_STOP",
    "DEFAULT_INTERVAL_SECONDS",
    "DEFAULT_MAX_ATTEMPTS",
    "DEVICE_CODE_GRANT_TYPE",
    "ERROR_ACCESS_DENIED",
    "ERROR_AUTHORIZATION_PENDING",
    "ERROR_EXPIRED_TOKEN",
    "ERROR_SLOW_DOWN",
    "SLOW_DOWN_INCREMENT_SECONDS",
    "DeviceAuthorization",
    "DeviceCode",
    "DeviceGrantError",
    "DevicePollScheduler",
    "PollDecision",
    "parse_device_authorization",
]
