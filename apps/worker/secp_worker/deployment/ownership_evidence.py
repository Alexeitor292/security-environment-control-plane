"""Observed-ownership evidence contract (SECP-B4 corrective).

Replaces the previous caller-supplied-tag-string ownership check. Ownership of a resource is NEVER
inferred from a tag a caller passes in; it is proven ONLY by a FRESH observation of the exact
provider/host object at a typed locator, whose provider-visible ownership marker must match this
deployment's expected marker (constant-time). The observation backends (Proxmox read, host-helper
registry read) are sealed, fail-closed seams here — their real implementations are
integration-blocked
against the disposable staging target — so every real ownership check refuses until they are
supplied.

This module contains only the fail-closed DECISION logic + the sealed seams; it performs no I/O.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from secp_worker.deployment.locators import ResourceLocator


class OwnershipObservationUnavailable(Exception):
    """The ownership-observation backend is sealed/unavailable — fail closed (never assume
    owned)."""

    def __init__(self, reason_code: str = "ownership_observation_unavailable") -> None:
        super().__init__(f"ownership observation unavailable: {reason_code}")
        self.reason_code = reason_code


class OwnershipProofFailed(Exception):
    """A fresh observation did NOT prove this deployment owns the exact locator. Closed reason
    only."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(f"ownership proof failed: {reason_code}")
        self.reason_code = reason_code


@dataclass(frozen=True)
class ObservedOwnership:
    """The result of a fresh observation of a locator: whether an object is present, and the exact
    ownership marker read from its provider-visible field (``None`` when absent or unmarked)."""

    present: bool
    owner_marker: str | None = None


@runtime_checkable
class OwnershipObserver(Protocol):
    """Fresh-reads the exact object at a locator and returns its observed ownership marker. A real
    implementation issues ONE hardened read (Proxmox GET / host-helper registry query) immediately
    before the caller mutates. The shipped default refuses (sealed)."""

    def observe(self, locator: ResourceLocator) -> ObservedOwnership: ...


class SealedOwnershipObserver:
    """The shipped default: NO observation backend. Refuses — reads nothing, contacts nothing.

    Its real replacement (Proxmox provider read + host-helper ownership registry) is integration-
    blocked until it can be validated against the disposable isolated staging target.
    """

    def observe(self, locator: ResourceLocator) -> ObservedOwnership:
        raise OwnershipObservationUnavailable()


def _marker_matches(observed: str | None, expected: str) -> bool:
    return bool(observed) and hmac.compare_digest(str(observed), expected)


def assert_absent_or_owned(
    observer: OwnershipObserver, locator: ResourceLocator, *, expected_marker: str
) -> str:
    """Create precondition. Prove the target locator is safe to create into: it must be ABSENT, or
    already present carrying THIS deployment's exact marker (idempotent re-create). A present object
    with a different/absent marker is a foreign/uncertain occupant and is refused (never
    overwritten).

    Returns ``"absent"`` or ``"owned_reusable"``. Fails closed if the observer is sealed.
    """
    observed = observer.observe(locator)  # sealed observer raises OwnershipObservationUnavailable
    if not observed.present:
        return "absent"
    if _marker_matches(observed.owner_marker, expected_marker):
        return "owned_reusable"
    raise OwnershipProofFailed("locator_occupied")


def assert_owned(
    observer: OwnershipObserver, locator: ResourceLocator, *, expected_marker: str
) -> None:
    """Mutate/delete precondition. Fresh-read the exact locator immediately before mutation and
    prove
    it is present AND carries THIS deployment's exact marker. Absent, unmarked, foreign, stale, or
    mismatched all fail closed — so an uncertain or foreign object is never mutated or deleted."""
    observed = observer.observe(locator)  # sealed observer raises OwnershipObservationUnavailable
    if not observed.present:
        raise OwnershipProofFailed("resource_absent")
    if not _marker_matches(observed.owner_marker, expected_marker):
        raise OwnershipProofFailed("resource_not_secp_owned")
