"""Approved-hardened-transport contract for the staging-live canary (SECP-B3).

Closes B2-5-pre activation-review condition B. Previously the canary hardcoded ``readonly_policy
enforced = passed`` regardless of the transport it was handed. Here a transport is trusted for the
canary ONLY if it is an :class:`ApprovedHardenedTransport` whose :class:`HardeningManifest` reports
every required protection ENFORCED (TLS verification, redirects disabled, ambient-proxy/trust-env
disabled, GET-only, bounded timeout). A loose or foreign object (not an approved transport),
or one whose manifest is incomplete — is REJECTED, and the canary records transport-policy evidence
as passed only after this proof plus an observed exactly-one-GET.

This module performs no I/O and imports no HTTP/socket code: it is a pure contract + marker seam. A
production adapter around ``HttpxReadOnlyTransport`` subclasses :class:`ApprovedHardened
Transport` and reports its real enforced configuration; tests inject an approved fake and prove that
non-approved / non-enforcing transports fail closed.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Protocol, runtime_checkable


class TransportHardeningError(Exception):
    """Fail-closed: the transport is not a fully-enforced approved transport."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(f"transport hardening refused: {reason_code}")
        self.reason_code = reason_code


@dataclass(frozen=True)
class HardeningManifest:
    """The verifiable hardening posture an approved transport asserts about itself. All five must be
    enforced for the transport to be trusted; the canary derives its transport-policy evidence from
    these booleans (never hardcoded)."""

    tls_verified: bool
    redirects_disabled: bool
    trust_env_disabled: bool
    get_only: bool
    timeout_bounded: bool

    def all_enforced(self) -> bool:
        return (
            self.tls_verified
            and self.redirects_disabled
            and self.trust_env_disabled
            and self.get_only
            and self.timeout_bounded
        )


@runtime_checkable
class HardenedTransport(Protocol):
    """A GET-only transport that can attest its own hardening posture."""

    def get(self, path: str) -> object: ...
    def hardening_manifest(self) -> HardeningManifest: ...


class ApprovedHardenedTransport(ABC):
    """Nominal marker base an APPROVED transport must subclass. A foreign object that merely
    exposes ``get``/``hardening_manifest`` structurally is NOT approved — approval is nominal so a
    loose duck-typed implementation cannot masquerade as hardened."""

    @abstractmethod
    def get(self, path: str) -> object: ...

    @abstractmethod
    def hardening_manifest(self) -> HardeningManifest: ...


class ApprovedHardenedTransportFactory(ABC):
    """Nominal marker base an approved transport FACTORY must subclass. It builds an
    :class:`ApprovedHardenedTransport` from the re-verified authorization + the resolved opaque
    credential. The composition rejects any factory that is not an instance of this base."""

    @abstractmethod
    def __call__(self, verified: object, secret: str) -> ApprovedHardenedTransport: ...


def assert_approved_hardened_transport(transport: object) -> HardeningManifest:
    """Return the hardening manifest of an approved, fully-enforced transport, else fail closed.

    Rejects a foreign/loose object (not an :class:`ApprovedHardenedTransport`) and an approved
    transport whose manifest does not report every protection enforced.
    """
    if not isinstance(transport, ApprovedHardenedTransport):
        raise TransportHardeningError("transport_not_approved")
    manifest = transport.hardening_manifest()
    if not (isinstance(manifest, HardeningManifest) and manifest.all_enforced()):
        raise TransportHardeningError("hardening_not_enforced")
    return manifest
