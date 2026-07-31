"""Typed OS credential store for the operator access token — SECP-PR5H-B2, Workstream C.

ADR-028 §4 specifies a typed ``OperatorCredentialStore`` implementing
:class:`~secp_management.operator_auth.OperatorAccessTokenProvider` with a SEALED default, bounded
account/service identifiers, an access lifecycle, the non-serializable + constant-redacted-repr
posture, explicit logout deletion, expiry validation, and — the rule this module exists to make
unbreakable — **no silent plaintext fallback**.

This module owns the POLICY. The OS keystore calls live in
:mod:`secp_management.operator_credential_backends` behind the narrow ``SecretStoreBinding`` seam,
so the rules below are stated once and cannot drift per platform:

* **No fallback.** When no binding resolves, :func:`build_operator_credential_store` composes the
  SEALED store and every load / store / delete fails closed. No code path writes the token to a
  file, an environment variable, a shell profile, a process-lifetime cache, or any other
  consolation location, and none treats an unavailable keystore as an absent credential.
* **Never a plaintext-capable provider.** A backend must be a real OS keystore, asserted by the
  SPECIFIC backend it resolved — never by a "is a keyring available?" probe that ``keyrings.alt``
  (cleartext or trivially reversible) would also satisfy.
* **One account per controller.** The account is DERIVED from the reviewed controller locator's
  canonical origin, never from a CLI flag or an environment variable. A credential minted against
  one controller is therefore addressed under a different key from every other controller's, and
  the account is additionally re-checked inside the stored record — so a case-folding keystore
  (Windows target names are case-insensitive) cannot serve controller A's token for controller B.
* **Expiry is validated on READ.** A stored credential past its expiry is a refusal, not a value;
  the CLI never replays a stale token at the controller to find out.

The protected token FILE (:class:`~secp_management.operator_auth.ProtectedTokenFileProvider`) stays
exactly what it already was — a sealed test/recovery seam reachable only when an operator sets
``SECP_OPERATOR_TOKEN_FILE`` — and is never an automatic degradation from this store.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, NoReturn, Protocol, runtime_checkable

from secp_management import ManagementError
from secp_management.operator_auth import OperatorAccessToken
from secp_management.operator_credential_backends import (
    MAX_SECRET_BYTES,
    SecretStoreBinding,
    require_storable,
    resolve_secret_store_binding,
)

#: The bounded, code-owned service identifier a backend registers credentials under. It is never
#: selected by a CLI flag, an environment variable, or a provider response.
CREDENTIAL_SERVICE_NAME = "secp-secpctl-operator"

#: Backend identifiers reported by :meth:`OperatorCredentialStore.describe`.
BACKEND_SEALED = "sealed"

#: The stored-record schema version. A record that does not carry EXACTLY this is refused rather
#: than best-effort parsed — a credential is not a place for lenient decoding.
CREDENTIAL_RECORD_VERSION = 1

_MAX_ACCOUNT_LEN = 255
_MIN_ACCOUNT_LEN = 1
# An account identifier is bounded, printable and whitespace-free (it names an operator identity to
# the OS keyring; it is never a secret and never a path).
_ACCOUNT_GRAMMAR = re.compile(r"[\x21-\x7e]{1,255}")

_SUBJECT_FINGERPRINT_LEN = 32
_ACCOUNT_FINGERPRINT_LEN = 16
_FINGERPRINT_GRAMMAR = re.compile(r"[0-9a-f]{0,64}")
_MAX_EXPIRES_AT_EPOCH = 4_102_444_800  # 2100-01-01; a farther expiry is a malformed record
# A stored record can never be larger than what the tightest supported keystore accepts, so the
# read side uses the SAME bound as the write side rather than a second, drifting number.
_MAX_RECORD_BYTES = MAX_SECRET_BYTES


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


def account_for_controller(locator: Any) -> str:
    """The credential account for the controller the reviewed locator names.

    The canonical HTTPS origin IS the account: it is a public deployment fact, it is already
    validated and lower-cased by
    :class:`~secp_management.controller_api_locator.ControllerApiLocator` (so a case-insensitive
    keystore cannot collide two different controllers), and it is the only controller identity
    available WITHOUT a network call — which ``auth status`` must not make.

    A pathological origin longer than the account bound refuses rather than being hashed into
    something unrecognisable in the operator's keyring UI.
    """
    return validate_account(getattr(locator, "canonical_origin", None))


def account_fingerprint(account: str) -> str:
    """A short, stable, non-reversing label for an account, safe for ``--json`` output.

    It exists so a report can distinguish "which controller's credential is this" WITHOUT writing a
    deployment's origin into output an operator may paste into a ticket. It is an identifier, not a
    secrecy mechanism — the origin is public.
    """
    digest = hashlib.sha256(validate_account(account).encode("utf-8")).hexdigest()
    return digest[:_ACCOUNT_FINGERPRINT_LEN]


def subject_fingerprint(subject: object) -> str:
    """A non-reversing fingerprint of a verified token's ``sub``.

    Stored beside the credential so ``auth refresh`` can prove the renewed token belongs to the
    SAME operator, and reported so ``auth status`` can show an identity changed — without ever
    writing the subject itself to disk or to a report.
    """
    if not isinstance(subject, str) or not subject:
        _reject("secpctl_credential_record_invalid")
    return hashlib.sha256(subject.encode("utf-8")).hexdigest()[:_SUBJECT_FINGERPRINT_LEN]


@dataclass(frozen=True)
class StoredCredentialStatus:
    """The bounded, SECRET-FREE description of what a store currently holds.

    It carries no token, no account identifier and no backend path — only a backend label, whether
    a credential is present, whether it has expired, and a NON-REVERSING subject fingerprint. Safe
    for human and ``--json`` output.
    """

    backend: str
    available: bool
    has_credential: bool = False
    expired: bool = False
    subject_fingerprint: str = ""

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

    def store(
        self, token: OperatorAccessToken, *, expires_at_epoch: int, subject_fingerprint: str = ""
    ) -> None:
        """Atomically replace any existing credential for the bound account."""
        ...

    def delete(self) -> bool:
        """Remove ONLY credential material this store owns. Returns whether anything was removed."""
        ...

    def describe(self) -> StoredCredentialStatus:
        """A bounded, secret-free status projection. Never raises."""
        ...

    def for_account(self, account: str) -> OperatorCredentialStore:
        """The same store bound to one controller's account — the multi-controller selection."""
        ...


class _NonSerializable:
    def __reduce__(self) -> NoReturn:
        _reject("secpctl_credential_store_not_serializable")

    def __getstate__(self) -> NoReturn:
        _reject("secpctl_credential_store_not_serializable")


@dataclass(frozen=True, repr=False)
class CredentialRecord(_NonSerializable):
    """What actually goes INTO the OS keystore: the token plus exactly the facts needed to refuse it
    later. Its repr is constant, and it refuses pickling/copying, so the token cannot reach a log or
    a temporary file by accident."""

    account: str
    token: str
    expires_at_epoch: int
    subject_fingerprint: str = ""

    def __repr__(self) -> str:  # never the token
        return "CredentialRecord(<redacted>)"

    def to_bytes(self) -> bytes:
        """The deterministic on-keystore encoding, bounded to what every backend accepts."""
        document = json.dumps(
            {
                "v": CREDENTIAL_RECORD_VERSION,
                "a": self.account,
                "e": int(self.expires_at_epoch),
                "s": self.subject_fingerprint,
                "t": self.token,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return require_storable(document.encode("utf-8"))

    @classmethod
    def from_bytes(cls, raw: object) -> CredentialRecord:
        """Strictly decode a stored record. Anything unexpected is one bounded refusal — a partially
        understood credential is never used."""
        if not isinstance(raw, (bytes, bytearray)) or not (0 < len(raw) <= _MAX_RECORD_BYTES):
            _reject("secpctl_credential_record_invalid")
        try:
            document = json.loads(bytes(raw).decode("utf-8"))
        except Exception:  # noqa: BLE001 - a corrupt record is a bounded refusal
            _reject("secpctl_credential_record_invalid")
        if not isinstance(document, dict) or document.get("v") != CREDENTIAL_RECORD_VERSION:
            _reject("secpctl_credential_record_invalid")

        expires_at = document.get("e")
        if (
            not isinstance(expires_at, int)
            or isinstance(expires_at, bool)
            or not (0 < expires_at <= _MAX_EXPIRES_AT_EPOCH)
        ):
            _reject("secpctl_credential_record_invalid")

        fingerprint = document.get("s")
        if not isinstance(fingerprint, str) or not _FINGERPRINT_GRAMMAR.fullmatch(fingerprint):
            _reject("secpctl_credential_record_invalid")

        token = document.get("t")
        if not isinstance(token, str) or not token:
            _reject("secpctl_credential_record_invalid")

        return cls(
            account=validate_account(document.get("a")),
            token=token,
            expires_at_epoch=expires_at,
            subject_fingerprint=fingerprint,
        )


class SealedOperatorCredentialStore(_NonSerializable):
    """The shipped default when NO OS credential backend resolves, so every operation fails closed.

    It never falls back to a file, an environment variable, or an in-memory session — an unavailable
    backend is a refusal, not a degradation. ``for_account`` returns ``self`` because a sealed store
    holds nothing to select between; selecting an account does not make one storable.
    """

    __slots__ = ()

    def __repr__(self) -> str:
        return "SealedOperatorCredentialStore(<sealed>)"

    def access_token(self) -> OperatorAccessToken:
        _reject("secpctl_credential_store_unavailable")

    def store(
        self, token: OperatorAccessToken, *, expires_at_epoch: int, subject_fingerprint: str = ""
    ) -> None:
        _reject("secpctl_credential_store_unavailable")

    def delete(self) -> bool:
        _reject("secpctl_credential_store_unavailable")

    def describe(self) -> StoredCredentialStatus:
        return StoredCredentialStatus(backend=BACKEND_SEALED, available=False)

    def for_account(self, account: str) -> SealedOperatorCredentialStore:
        return self


class OsKeystoreCredentialStore(_NonSerializable):
    """The operator credential in the OPERATING SYSTEM's keystore, one entry per controller.

    Every read validates the record, its account and its expiry before a token is handed back, so a
    stale or foreign credential is a refusal rather than a request the controller has to reject.
    """

    __slots__ = ("_binding", "_service", "_account", "_now")

    def __init__(
        self,
        binding: SecretStoreBinding,
        *,
        account: str = "",
        service: str = CREDENTIAL_SERVICE_NAME,
        now_epoch: Callable[[], float] = time.time,
    ) -> None:
        self._binding = binding
        self._service = service
        self._account = account
        self._now = now_epoch

    def __repr__(self) -> str:  # never the account / backend detail
        return "OsKeystoreCredentialStore(<redacted>)"

    def for_account(self, account: str) -> OsKeystoreCredentialStore:
        return OsKeystoreCredentialStore(
            self._binding,
            account=validate_account(account),
            service=self._service,
            now_epoch=self._now,
        )

    def _bound_account(self) -> str:
        """The selected account, or a refusal. An UNBOUND store can describe the backend but can
        never read, write or delete a credential — there is no 'default account'."""
        if not self._account:
            _reject("secpctl_credential_account_invalid")
        return validate_account(self._account)

    def _load(self) -> CredentialRecord | None:
        account = self._bound_account()
        raw = self._binding.get_secret(service=self._service, account=account)
        if raw is None:
            return None
        record = CredentialRecord.from_bytes(raw)
        if record.account != account:
            # The keystore returned an entry minted for a DIFFERENT controller (a case-insensitive
            # target name is the realistic way this happens). Never serve it.
            _reject("secpctl_credential_account_mismatch")
        return record

    def access_token(self) -> OperatorAccessToken:
        record = self._load()
        if record is None:
            _reject("secpctl_credential_absent")
        if float(record.expires_at_epoch) <= self._now():
            _reject("secpctl_credential_expired")
        return OperatorAccessToken(record.token)

    def store(
        self, token: OperatorAccessToken, *, expires_at_epoch: int, subject_fingerprint: str = ""
    ) -> None:
        account = self._bound_account()
        if not isinstance(expires_at_epoch, int) or isinstance(expires_at_epoch, bool):
            _reject("secpctl_credential_record_invalid")
        if not isinstance(subject_fingerprint, str) or not _FINGERPRINT_GRAMMAR.fullmatch(
            subject_fingerprint
        ):
            _reject("secpctl_credential_record_invalid")
        record = CredentialRecord(
            account=account,
            token=_bearer_value(token),
            expires_at_epoch=expires_at_epoch,
            subject_fingerprint=subject_fingerprint,
        )
        self._binding.set_secret(service=self._service, account=account, secret=record.to_bytes())

    def delete(self) -> bool:
        account = self._bound_account()
        return bool(self._binding.delete_secret(service=self._service, account=account))

    def describe(self) -> StoredCredentialStatus:
        backend = self._binding.backend_id
        if not self._account:
            # No controller selected yet: the BACKEND is still reportable, and it is the fact
            # `auth status` needs when the locator has not been recorded.
            return StoredCredentialStatus(backend=backend, available=True)
        try:
            record = self._load()
        except ManagementError:
            # An unreachable or locked keystore is NOT an absent credential.
            return StoredCredentialStatus(backend=backend, available=False)
        if record is None:
            return StoredCredentialStatus(backend=backend, available=True)
        return StoredCredentialStatus(
            backend=backend,
            available=True,
            has_credential=True,
            expired=float(record.expires_at_epoch) <= self._now(),
            subject_fingerprint=record.subject_fingerprint,
        )


def _bearer_value(token: OperatorAccessToken) -> str:
    """The raw token from the redacted holder, for the ONE purpose of handing it to the keystore.

    :class:`OperatorAccessToken` deliberately exposes the value only as an ``Authorization`` header,
    so the prefix is stripped here rather than widening that class's surface for a second caller.
    """
    if not isinstance(token, OperatorAccessToken):
        _reject("secpctl_credential_record_invalid")
    header = token.authorization_header()
    prefix = "Bearer "
    if not header.startswith(prefix) or len(header) <= len(prefix):
        _reject("secpctl_credential_record_invalid")
    return header[len(prefix) :]


class ControllerScopedCredentialProvider(_NonSerializable):
    """Resolves the operator access token from the OS credential store for the controller THIS
    invocation targets — the seam that makes ``secpctl auth login`` actually useful.

    Without this, the store and the authenticated client never meet: ``auth login`` writes a
    credential into the OS keystore and every authenticated command keeps reading the protected
    token FILE, so the only working operator-auth path on a real host stays a plaintext file. This
    class is what makes the keystore the PRIMARY provider.

    It satisfies :class:`~secp_management.operator_auth.OperatorAccessTokenProvider` (one
    ``access_token()`` method), so it drops straight into ``HttpsEnrollmentControllerClient`` with
    no client change.

    Binding is LAZY — per call, not at construction. The controller locator is recorded by
    bootstrap and may be absent when the CLI composes its deps; resolving it eagerly would turn "no
    controller recorded yet" into a construction failure that seals the entire enrollment surface,
    which is both wrong and invisible. Resolving per call makes it one bounded refusal on the one
    command that needed a token.

    It never falls back. A sealed store, an unreachable keystore, an absent or expired credential
    are each a bounded refusal; none of them degrades to a file, an environment variable, or a
    cached token.
    """

    __slots__ = ("_store", "_locator_provider")

    def __init__(self, store: OperatorCredentialStore, locator_provider: Any) -> None:
        self._store = store
        self._locator_provider = locator_provider

    def __repr__(self) -> str:  # never the account / origin / token
        return "ControllerScopedCredentialProvider(<redacted>)"

    def access_token(self) -> OperatorAccessToken:
        """The stored token for the recorded controller's account, or a bounded refusal."""
        locator = self._locator_provider.locate()
        return self._store.for_account(account_for_controller(locator)).access_token()


def build_operator_credential_store() -> OperatorCredentialStore:
    """Compose the operator credential store for the production CLI.

    Resolution is BINARY: either a specific OS keystore binding resolves and backs the store, or
    none does and the SEALED store is composed. There is no third outcome and no degradation in
    between. The composition lives here (not in ``production.py``, which composes only
    ``EngineDeps`` and is operator-owned) so the backend decision is one reviewed edit at one site.
    """
    binding = resolve_secret_store_binding()
    if binding is None:
        return SealedOperatorCredentialStore()
    return OsKeystoreCredentialStore(binding)


__all__ = [
    "BACKEND_SEALED",
    "CREDENTIAL_RECORD_VERSION",
    "CREDENTIAL_SERVICE_NAME",
    "ControllerScopedCredentialProvider",
    "CredentialRecord",
    "OperatorCredentialStore",
    "OperatorCredentialStoreError",
    "OsKeystoreCredentialStore",
    "SealedOperatorCredentialStore",
    "StoredCredentialStatus",
    "account_fingerprint",
    "account_for_controller",
    "build_operator_credential_store",
    "subject_fingerprint",
    "validate_account",
]
