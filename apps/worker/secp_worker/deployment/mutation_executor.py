"""Ownership-gated Proxmox mutation executor (SECP-B4 §4).

Every create/update/delete is gated TWICE, immediately before execution: (1) the concrete transport
must PROVE it is hardened from its ACTUAL client configuration (TLS-verified, CA-pinned, no ambient
proxy, no redirects, bounded timeouts, closed mutation methods) — not a self-reported flag; and
(2) :meth:`LiveProxmoxProvider.assert_mutable` must prove the resource is SECP-owned by THIS lab, so
no unowned/foreign/conflicting resource (vmbr0, a physical NIC, an existing guest/storage/firewall
policy/user/pool, or a non-SECP tag) can ever be modified or deleted. Any failure fails closed with
closed reason code. Fully testable with an injected fake transport + provider; no real host contact.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from secp_worker.staging_live.live_proxmox_provider import (
    LiveProxmoxProvider,
    LiveProxmoxProviderError,
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

    def apply(self, method: str, path: str, *, body: dict | None = None) -> object: ...


@dataclass(frozen=True)
class MutationResult:
    ok: bool
    reason_code: str
    data: object | None = None


def _manifest_enforced(manifest: object) -> bool:
    fn = getattr(manifest, "all_enforced", None)
    return bool(fn()) if callable(fn) else False


class ProxmoxMutationExecutor:
    """Gates and issues one ownership-bound Proxmox mutation. Constructed only with an injected
    hardened transport + the ownership-bounded provider; never a shipped default."""

    def __init__(self, *, transport: MutationTransport, provider: LiveProxmoxProvider) -> None:
        self._transport = transport
        self._provider = provider

    def transport_is_hardened(self) -> bool:
        """PROOF from the actual transport configuration that all hardening is enforced."""
        return _manifest_enforced(self._transport.hardening_manifest())

    def apply_owned(
        self,
        *,
        method: str,
        path: str,
        owner_tag: str,
        body: dict | None = None,
    ) -> MutationResult:
        """Apply ONE mutation only after proving (1) the transport is hardened and (2) the resource
        provably SECP-owned by this lab. Fails closed on either gate."""
        if not self.transport_is_hardened():
            return MutationResult(False, "transport_not_hardened")
        try:
            self._provider.assert_mutable(owner_tag)  # ownership gate, immediately before mutation
        except LiveProxmoxProviderError:
            return MutationResult(False, "resource_not_secp_owned")
        try:
            data = self._transport.apply(method, path, body=body)
        except Exception:  # never surface a raw transport/host error
            return MutationResult(False, "mutation_failed")
        return MutationResult(True, "applied", data=data)
