"""Operator authentication for secpctl controller enrollment commands (SECP-PR5H-B1, Phase 4).

The controller invitation/status/revoke commands are operator-authenticated API operations over the
existing OIDC bearer boundary. secpctl obtains the short-lived operator access token ONLY from a
protected, operator-owned token FILE — never from a ``--token`` argument, a positional value, a URL,
a JSON payload, or an environment variable carrying the token itself. The file location is named by
a dedicated, validated authentication profile (an env var carrying the PATH, never the token); the
token is read through hardened filesystem checks and attached solely as ``Authorization: Bearer`` on
the pinned controller origin (never forwarded across a redirect — redirects are forbidden).

The token never appears in a repr, exception, log, audit line, or serialized/deterministic-JSON
output. The shipped default provider is SEALED (``secpctl_operator_auth_unavailable``).

Interactive device-authorization login now lives in :mod:`secp_management.auth_cli` (ADR-028 §3),
which obtains and verifies a token and then offers it to
:mod:`secp_management.operator_credential_store`. That store ships only its SEALED default, so no OS
credential BACKEND exists yet and a login cannot complete; the protected token FILE below therefore
remains the only working provider, and stays a deliberate test/recovery seam reachable solely when
an operator sets ``SECP_OPERATOR_TOKEN_FILE``. It is never an automatic fallback from the
credential store.
"""

from __future__ import annotations

import re
from typing import NoReturn, Protocol

from secp_management import ManagementError

#: The dedicated authentication profile: an env var naming the token FILE PATH (never the token).
OPERATOR_TOKEN_FILE_ENV = "SECP_OPERATOR_TOKEN_FILE"

_MAX_TOKEN_BYTES = 8192
_MIN_TOKEN_LEN = 16
# A bearer token is a bounded, whitespace-free, control-free printable string (JWT or opaque).
_TOKEN_GRAMMAR = re.compile(r"[\x21-\x7e]{16,8192}")


class OperatorAuthError(ManagementError):
    """A bounded, closed operator-auth refusal — carries ONLY a reason code, never the token, the
    token-file path, or a raw exception."""


def _reject(reason_code: str) -> NoReturn:
    raise OperatorAuthError(reason_code)


class _NonSerializable:
    def __reduce__(self) -> NoReturn:
        _reject("secpctl_operator_token_not_serializable")

    def __getstate__(self) -> NoReturn:
        _reject("secpctl_operator_token_not_serializable")


class OperatorAccessToken(_NonSerializable):
    """Holds a short-lived operator OIDC access token IN MEMORY. It is never represented, logged,
    serialized, or copied; it is exposed ONLY as the ``Authorization: Bearer`` header value the
    pinned controller client attaches to a single request."""

    __slots__ = ("_token",)

    def __init__(self, token: str) -> None:
        if not isinstance(token, str) or not _TOKEN_GRAMMAR.fullmatch(token):
            _reject("secpctl_operator_token_invalid")
        self._token = token

    def __repr__(self) -> str:  # never the token
        return "OperatorAccessToken(<redacted>)"

    def authorization_header(self) -> str:
        return f"Bearer {self._token}"


class OperatorAccessTokenProvider(Protocol):
    """Resolves the operator access token for a controller enrollment command."""

    def access_token(self) -> OperatorAccessToken: ...


class SealedOperatorAccessTokenProvider:
    """The shipped default: no operator authentication is configured; every attempt fails closed."""

    def __repr__(self) -> str:
        return "SealedOperatorAccessTokenProvider(<sealed>)"

    def access_token(self) -> OperatorAccessToken:
        _reject("secpctl_operator_auth_unavailable")


def parse_operator_token_bytes(raw: bytes) -> str:
    """Validate + normalize a token file's bytes: reject empty / oversized, decode UTF-8, trim
    exactly ONE trailing newline, and require the bounded whitespace-free grammar. Pure + testable;
    it never echoes the token in a refusal."""
    if not isinstance(raw, bytes) or not (1 <= len(raw) <= _MAX_TOKEN_BYTES + 1):
        _reject("secpctl_operator_token_invalid")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        _reject("secpctl_operator_token_invalid")
    if text.endswith("\n"):
        text = text[:-1]  # trim exactly one final newline
    if not (_MIN_TOKEN_LEN <= len(text) <= _MAX_TOKEN_BYTES) or not _TOKEN_GRAMMAR.fullmatch(text):
        _reject("secpctl_operator_token_invalid")
    return text


class ProtectedTokenFileProvider:
    """Reads the operator access token from a protected, OPERATOR-OWNED file (POSIX). The file must
    be a real regular file (never a symlink), not hardlinked, owned by the invoking non-root
    operator, mode ``0600``, under a parent directory owned by the operator (or root) and not
    group/other-writable. Any deviation fails closed with a bounded code; the token and path never
    appear in a refusal."""

    __slots__ = ("_path",)

    def __init__(self, token_file_path: str) -> None:
        if not (
            isinstance(token_file_path, str)
            and token_file_path.startswith("/")
            and 1 < len(token_file_path) <= 4096
            and "\x00" not in token_file_path
        ):
            _reject("secpctl_operator_token_invalid")
        self._path = token_file_path

    def __repr__(self) -> str:  # never the path
        return "ProtectedTokenFileProvider(<redacted>)"

    def access_token(self) -> OperatorAccessToken:
        import os
        import stat

        getuid = getattr(os, "getuid", None)  # noqa: B009 - POSIX only; None off-POSIX
        if getuid is None:
            _reject("secpctl_operator_auth_unavailable")
        operator_uid = getuid()
        self._assert_parent_trusted(os.path.dirname(self._path), operator_uid)
        try:
            st = os.lstat(self._path)
        except OSError:
            _reject("secpctl_operator_auth_unavailable")
        if (
            not stat.S_ISREG(st.st_mode)
            or stat.S_ISLNK(st.st_mode)
            or st.st_nlink != 1
            or st.st_uid != operator_uid
            or stat.S_IMODE(st.st_mode) != 0o600
        ):
            _reject("secpctl_operator_token_unsafe")
        raw = self._read_no_follow(os.path.dirname(self._path), os.path.basename(self._path))
        return OperatorAccessToken(parse_operator_token_bytes(raw))

    def _assert_parent_trusted(self, parent: str, operator_uid: int) -> None:
        import os
        import stat

        try:
            st = os.lstat(parent)
        except OSError:
            _reject("secpctl_operator_token_unsafe")
        if (
            not stat.S_ISDIR(st.st_mode)
            or stat.S_ISLNK(st.st_mode)
            or st.st_uid not in (0, operator_uid)
            or (st.st_mode & 0o022)  # no group/other write on the token's parent
        ):
            _reject("secpctl_operator_token_unsafe")

    def _read_no_follow(self, parent: str, name: str) -> bytes:
        import os

        o_nofollow = getattr(os, "O_NOFOLLOW", 0)  # noqa: B009 - POSIX flag
        try:
            dir_fd = os.open(parent, os.O_RDONLY | o_nofollow)
        except OSError:
            _reject("secpctl_operator_token_unsafe")
        try:
            fd = os.open(name, os.O_RDONLY | o_nofollow, dir_fd=dir_fd)
        except OSError:
            _reject("secpctl_operator_token_unsafe")
        finally:
            os.close(dir_fd)
        try:
            return os.read(fd, _MAX_TOKEN_BYTES + 2)
        except OSError:
            _reject("secpctl_operator_token_unsafe")
        finally:
            os.close(fd)


__all__ = [
    "OPERATOR_TOKEN_FILE_ENV",
    "OperatorAccessToken",
    "OperatorAccessTokenProvider",
    "OperatorAuthError",
    "ProtectedTokenFileProvider",
    "SealedOperatorAccessTokenProvider",
    "parse_operator_token_bytes",
]
