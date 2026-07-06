"""Observed-ownership-gated Proxmox mutation executor (SECP-B4 corrective, §4).

Every mutation is gated, immediately before it is issued, by TWO proofs — neither of which is a
caller-supplied tag string:

1. The concrete transport must PROVE it is hardened from its ACTUAL client configuration (TLS-
   verified, CA-pinned, no ambient proxy, no redirects, bounded timeouts, closed methods) — a real
   ``httpx.Client`` in production, never a self-reported flag.
2. A FRESH observation of the EXACT provider object at the operation's typed locator must prove it
   carries this deployment's unique per-resource ownership marker. For a create, the target must be
   absent or already ours (idempotent), and immediately after creating we re-observe to confirm our
   marker landed. For a delete/revoke, the exact recorded locator must be observed as present AND
   ours right before deletion. Absent / unmarked / foreign / stale / mismatched all fail closed, so
   no unowned or uncertain object (vmbr0, a physical NIC, an existing guest/token/user/firewall
   policy) is ever mutated or deleted.

The ownership observer is a sealed, fail-closed seam here (its real Proxmox/host-helper read is
integration-blocked against the disposable staging target), so every real mutation refuses until it
is supplied. Fully testable with an injected fake transport + fake observer; no real host contact.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from secp_worker.deployment.mutations import MutationRequest, TypedCreate, TypedInverse
from secp_worker.deployment.ownership_evidence import (
    OwnershipObservationUnavailable,
    OwnershipObserver,
    OwnershipProofFailed,
    SealedOwnershipObserver,
    assert_absent_or_owned,
    assert_owned,
)


class MutationExecutorError(Exception):
    """Fail-closed mutation-executor error. Closed reason only — never a host/endpoint/value."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(f"mutation executor refused: {reason_code}")
        self.reason_code = reason_code


@runtime_checkable
class MutationTransport(Protocol):
    """The narrow view the executor needs: prove hardening + apply one closed canonical mutation."""

    def hardening_manifest(self) -> object: ...

    def apply(self, method: str, path: str, *, body: object = None) -> object: ...


@dataclass(frozen=True)
class MutationResult:
    ok: bool
    reason_code: str
    data: object | None = None


def _manifest_enforced(manifest: object) -> bool:
    fn = getattr(manifest, "all_enforced", None)
    return bool(fn()) if callable(fn) else False


class ProxmoxMutationExecutor:
    """Gates and issues ONE typed, ownership-proven Proxmox mutation. Constructed only with an
    injected hardened transport + a fresh-read ownership observer (sealed default refuses)."""

    def __init__(
        self,
        *,
        transport: MutationTransport,
        observer: OwnershipObserver | None = None,
    ) -> None:
        self._transport = transport
        self._observer: OwnershipObserver = observer or SealedOwnershipObserver()

    def transport_is_hardened(self) -> bool:
        """PROOF from the actual transport configuration that all hardening is enforced."""
        return _manifest_enforced(self._transport.hardening_manifest())

    def _issue(self, req: MutationRequest) -> object:
        return self._transport.apply(req.method, req.path, body=req.body)

    def create_owned(self, op: TypedCreate, *, expected_marker: str) -> MutationResult:
        """Create the typed resource only after proving the target locator is absent or already
        ours;
        re-observe immediately after to confirm our marker landed. Fails closed on either gate."""
        if not self.transport_is_hardened():
            return MutationResult(False, "transport_not_hardened")
        try:
            state = assert_absent_or_owned(
                self._observer, op.locator, expected_marker=expected_marker
            )
        except OwnershipObservationUnavailable:
            return MutationResult(False, "ownership_observation_unavailable")
        except OwnershipProofFailed as exc:
            return MutationResult(False, exc.reason_code)  # locator_occupied
        if state == "owned_reusable":
            return MutationResult(True, "already_owned")  # idempotent resume; no second create
        try:
            self._issue(op.request())
        except Exception:  # never surface a raw transport/host error
            return MutationResult(False, "mutation_failed")
        # Re-read the exact object and confirm it now carries our marker before recording it.
        try:
            assert_owned(self._observer, op.locator, expected_marker=expected_marker)
        except OwnershipObservationUnavailable:
            return MutationResult(False, "ownership_observation_unavailable")
        except OwnershipProofFailed as exc:
            return MutationResult(False, exc.reason_code)
        return MutationResult(True, "created")

    def delete_owned(self, op: TypedInverse, *, expected_marker: str) -> MutationResult:
        """Delete/revoke the typed resource only after a FRESH read proves the exact recorded
        locator
        is present AND carries our marker. Foreign / absent / stale / mismatched fail closed."""
        if not self.transport_is_hardened():
            return MutationResult(False, "transport_not_hardened")
        try:
            assert_owned(self._observer, op.locator, expected_marker=expected_marker)
        except OwnershipObservationUnavailable:
            return MutationResult(False, "ownership_observation_unavailable")
        except OwnershipProofFailed as exc:
            # resource_absent / resource_not_secp_owned — never delete an uncertain/foreign object.
            return MutationResult(False, exc.reason_code)
        try:
            self._issue(op.request())
        except Exception:
            return MutationResult(False, "mutation_failed")
        return MutationResult(True, "removed")
