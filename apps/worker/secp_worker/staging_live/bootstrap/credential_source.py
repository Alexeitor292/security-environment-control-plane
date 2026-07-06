"""Deployment-local one-time SSH bootstrap-credential seam (SECP-B3).

The one-time SSH bootstrap credential is supplied ONLY through deployment-local injection on the
isolated worker. The API/UI never receives, stores, logs, serializes, or resolves it. There is no
environment-variable "enable live mode" switch. The shipped default source REFUSES. A live source is
injected only into the reviewed worker-owned staging-lab deployment seam.

The credential is held in an :class:`EphemeralBootstrapCredential` that is a context manager: the
material is exposed only inside the ``with`` block and is best-effort zeroed / dropped on exit
(success or failure), so it does not linger in memory after bootstrap. Its ``repr`` is redacted and
it is not serializable; the secret never enters a database, audit, plan, event, exception, or log.
"""

from __future__ import annotations

from types import TracebackType
from typing import Protocol, runtime_checkable


class BootstrapCredentialUnavailable(Exception):
    """Raised by a sealed/failing bootstrap-credential source. Closed reason only; no value leak."""

    def __init__(self, reason_code: str = "bootstrap_credential_unavailable") -> None:
        super().__init__(f"bootstrap credential unavailable: {reason_code}")
        self.reason_code = reason_code


class BootstrapCredentialDisposed(Exception):
    """Raised if disposed credential material is accessed after the ``with`` block."""


class EphemeralBootstrapCredential:
    """A short-lived holder for the one-time bootstrap secret. Exposes the material ONLY inside a
    ``with`` block; disposes it on exit (success or failure). Redacted repr; not serializable."""

    __slots__ = ("_material", "_disposed")

    def __init__(self, material: bytes) -> None:
        self._material = bytearray(material)
        self._disposed = False

    def __enter__(self) -> EphemeralBootstrapCredential:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.dispose()

    def reveal(self) -> bytes:
        """Return the secret material. Only valid before disposal; fails closed afterwards."""
        if self._disposed:
            raise BootstrapCredentialDisposed("bootstrap credential already disposed")
        return bytes(self._material)

    def dispose(self) -> None:
        """Best-effort zero + drop the material. Idempotent."""
        if not self._disposed:
            for i in range(len(self._material)):
                self._material[i] = 0
            self._material = bytearray()
            self._disposed = True

    @property
    def disposed(self) -> bool:
        return self._disposed

    def __repr__(self) -> str:
        return "EphemeralBootstrapCredential(<redacted>)"

    __str__ = __repr__

    def __reduce__(self):  # block pickling so the secret can never be serialized
        raise TypeError("EphemeralBootstrapCredential is not serializable")


@runtime_checkable
class BootstrapCredentialSource(Protocol):
    """Worker-only seam that yields the bootstrap credential from deployment-local material.
    A real source is injected out of band on the isolated worker; the shipped default refuses."""

    def acquire(self) -> EphemeralBootstrapCredential: ...


class SealedBootstrapCredentialSource:
    """The shipped default: NO credential. Refuses — reads no environment/file/host, contacts
    nothing. No configuration/flag makes it yield a credential."""

    def acquire(self) -> EphemeralBootstrapCredential:
        raise BootstrapCredentialUnavailable(
            "no deployment-local bootstrap credential is configured"
        )
