"""Generated, immutable SECP ownership namespace for host/Proxmox resources (SECP-B3).

A thin worker-side view over the shared :mod:`secp_api.ownership_contract` — the single source of
truth for the ownership fingerprint, tag, and generated resource references, so the app-side
deployment service and the worker-side provider can never disagree about what "provably SECP-owned
by THIS lab" means. The namespace answers exactly one question authoritatively: is this resource
provably SECP-owned by THIS lab? Names are bounded and grammar-checked; nothing here is a real
host/bridge/VMID value, and no I/O is performed.
"""

from __future__ import annotations

from dataclasses import dataclass

from secp_api.ownership_contract import (
    OwnershipContractError,
    compute_ownership_fingerprint,
    compute_ownership_tag,
    compute_resource_ref,
)
from secp_api.ownership_contract import owns as _contract_owns

# Backwards-compatible alias: the shared contract error is the namespace error.
OwnershipNamespaceError = OwnershipContractError


@dataclass(frozen=True)
class SecpOwnershipNamespace:
    """A deterministic, immutable ownership namespace for one lab. Constructed only via
    :func:`ownership_namespace`; all generated names/tags derive from the immutable ownership label.
    """

    ownership_label: str
    fingerprint: str

    @property
    def ownership_tag(self) -> str:
        """The immutable tag stamped on every created resource. Ownership is proven by this tag —
        never inferred from a resource name a third party could also choose."""
        return compute_ownership_tag(self.ownership_label)

    def resource_name(self, kind: str, index: int) -> str:
        """A generated, bounded, ownership-derived resource name (never a caller-supplied name)."""
        return compute_resource_ref(self.ownership_label, kind, index)

    def owns(self, resource_tag: object) -> bool:
        """True ONLY if the resource carries this namespace's exact ownership tag. Anything else —
        an untagged resource, a differently-tagged (other-lab) resource, or a non-string — is not
        owned, so the provider must not mutate or delete it."""
        return _contract_owns(self.ownership_tag, resource_tag)


def ownership_namespace(ownership_label: str) -> SecpOwnershipNamespace:
    """Derive the deterministic ownership namespace for a lab's immutable ownership label."""
    return SecpOwnershipNamespace(
        ownership_label=ownership_label,
        fingerprint=compute_ownership_fingerprint(ownership_label),
    )
