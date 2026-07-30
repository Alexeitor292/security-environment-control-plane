"""Typed OS credential store for the operator access token — SECP-PR5H-B2, Workstream C.

ADR-028 §4 specifies a typed ``OperatorCredentialStore`` implementing
:class:`~secp_management.operator_auth.OperatorAccessTokenProvider` with a SEALED default, bounded
account/service identifiers, an access lifecycle, the non-serializable + constant-redacted-repr
posture, explicit logout deletion, expiry validation, and — the rule this module exists to make
unbreakable — **no silent plaintext fallback**.

This slice ships the seam and the sealed default; it ships NO concrete backend. That is deliberate.
A real backend is either a third-party dependency or a hand-rolled D-Bus wire-protocol client, and
neither belongs in the same change as the protocol work — the choice deserves to be judged on its
own merits. So ``secpctl auth login`` completes the full RFC 8628 grant and verifies the resulting
token, then refuses to PERSIST it with a bounded, actionable reason. That is an honest partial
capability rather than a plausible-looking one built on an unreviewed storage decision.

The refusal is a property of THIS seam, not of any library: with no backend resolved, every store /
load / delete fails closed. There is deliberately no code path that writes the token to a file, an
environment variable, a shell profile, a process-lifetime cache, or any other consolation location.
The protected token FILE (:class:`~secp_management.operator_auth.ProtectedTokenFileProvider`)
remains exactly what it already was — a sealed test/recovery seam reachable only when an operator
explicitly sets ``SECP_OPERATOR_TOKEN_FILE`` — and is never an automatic degradation from this
store.

A future backend must additionally refuse any plaintext-capable provider (e.g. the ``keyrings.alt``
family, which stores secrets in cleartext or trivially reversible encoding and would satisfy a naive
"is a keyring available?" probe). It must assert the SPECIFIC backend it resolved rather than merely
that one exists. ``tests/test_operator_credential_store.py`` pins that rule now, before the backend
exists, so it cannot be forgotten later.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import NoReturn, Protocol, runtime_checkable

from secp_management import ManagementError
from secp_management.operator_auth import OperatorAccessToken

#: The bounded, code-owned service identifier a backend registers credentials under. It is never
#: selected by a CLI flag, an environment variable, or a provider response.
CREDENTIAL_SERVICE_NAME = "secp-secpctl-operator"

#: Backend identifiers reported by :meth:`OperatorCredentialStore.describe`.
BACKEND_SEALED = "sealed"

_MAX_ACCOUNT_LEN = 255
_MIN_ACCOUNT_LEN = 1
# An account identifier is bounded, printable and whitespace-free (it names an operator identity to
# the OS keyring; it is never a secret and never a path).
_ACCOUNT_GRAMMAR = re.compile(r"[\x21-\x7e]{1,255}")


class OperatorCredentialStoreError(ManagementError):
    """A bounded, closed credential-store refusal — carries ONLY a reason code, never the token, the
    account identifier, a backend path, or a raw exception."""


def _reject(reason_code: str) -> NoReturn:
    raise OperatorCredentialStoreError(reason_code)


def validate_account(account: object) -> str:
    """Validate a bounded, non-secret account identifier. Refuses empty / oversized / whitespace /
    control characters without echoing the value."""
    if (
        not isinstance(account, str)
        or not (_MIN_ACCOUNT_LEN <= len(account) <= _MAX_ACCOUNT_LEN)
        or not _ACCOUNT_GRAMMAR.fullmatch(account)
    ):
        _reject("secpctl_credential_account_invalid")
    return account


@dataclass(frozen=True)
class StoredCredentialStatus:
    """The bounded, SECRET-FREE description of what a store currently holds.

    It carries no token, no account identifier and no backend path — only a backend label, whether
    a credential is present, and whether it has expired. Safe for human and ``--json`` output.
    """

    backend: str
    available: bool
    has_credential: bool = False
    expired: bool = False

    def to_report(self) -> dict:
        return {
            "credential_backend": self.backend,
            "credential_store_available": self.available,
            "has_credential": self.has_credential,
            "credential_expired": self.expired,
        }


@runtime_checkable
class OperatorCredentialStore(Protocol):
    """Persists the operator access token in OS-managed storage.

    It is a superset of :class:`~secp_management.operator_auth.OperatorAccessTokenProvider`: an
    implementation satisfies ``access_token()`` too, so a store drops straight into
    ``HttpsEnrollmentControllerClient`` with no client change.
    """

    def access_token(self) -> OperatorAccessToken:
        """The stored token, or a bounded refusal when absent / expired / unavailable."""
        ...

    def store(self, token: OperatorAccessToken, *, expires_at_epoch: int) -> None:
        """Atomically replace any existing credential."""
        ...

    def delete(self) -> bool:
        """Remove ONLY credential material this store owns. Returns whether anything was removed."""
        ...

    def describe(self) -> StoredCredentialStatus:
        """A bounded, secret-free status projection."""
        ...


class _NonSerializable:
    def __reduce__(self) -> NoReturn:
        _reject("secpctl_credential_store_not_serializable")

    def __getstate__(self) -> NoReturn:
        _reject("secpctl_credential_store_not_serializable")


class SealedOperatorCredentialStore(_NonSerializable):
    """The shipped default: no OS credential backend is wired, so every operation fails closed.

    This is the ONLY store this slice ships. It never falls back to a file, an environment variable,
    or an in-memory session — an unavailable backend is a refusal, not a degradation.
    """

    __slots__ = ()

    def __repr__(self) -> str:
        return "SealedOperatorCredentialStore(<sealed>)"

    def access_token(self) -> OperatorAccessToken:
        _reject("secpctl_credential_store_unavailable")

    def store(self, token: OperatorAccessToken, *, expires_at_epoch: int) -> None:
        _reject("secpctl_credential_store_unavailable")

    def delete(self) -> bool:
        _reject("secpctl_credential_store_unavailable")

    def describe(self) -> StoredCredentialStatus:
        return StoredCredentialStatus(backend=BACKEND_SEALED, available=False)


def build_operator_credential_store() -> OperatorCredentialStore:
    """Compose the operator credential store for the production CLI.

    This slice resolves NO backend, so it returns the sealed default and ``auth login`` refuses to
    persist. The composition lives here (not in ``production.py``, which composes only
    ``EngineDeps`` and is operator-owned) so adding a backend later is one reviewed edit at one
    site.
    """
    return SealedOperatorCredentialStore()


__all__ = [
    "BACKEND_SEALED",
    "CREDENTIAL_SERVICE_NAME",
    "OperatorCredentialStore",
    "OperatorCredentialStoreError",
    "SealedOperatorCredentialStore",
    "StoredCredentialStatus",
    "build_operator_credential_store",
    "validate_account",
]
