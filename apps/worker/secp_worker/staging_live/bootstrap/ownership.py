"""Generated, immutable SECP ownership namespace for host/Proxmox resources (SECP-B3).

Every resource the live provider creates is named and tagged from a namespace derived DETERMINISTIC
-ally from the lab's immutable ownership label — never from a caller-supplied name. The namespace
answers exactly one question authoritatively: "is this resource provably SECP-owned by THIS lab?".
The provider mutates or deletes only resources whose ownership tag this namespace recognizes, so it
can never touch a pre-existing non-SECP bridge, guest, storage, pool, firewall rule, or user.

Names are bounded and grammar-checked; nothing here is a real host/bridge/VMID value (indices are
app-owned and generated). No I/O is performed.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

# App-owned, bounded generation ranges. These are NOT a user's infrastructure values — they are
# fixed application constants the provider uses to generate isolated, ownership-bound resources.
_MAX_RESOURCE_INDEX = 64
_OWNERSHIP_TAG_PREFIX = "secp-owned"
# A safe ownership label: letters/digits/dot/underscore/hyphen only (no shell/host/path char).
_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$")
# Resource kinds the namespace can name (closed set — a caller cannot introduce a new kind).
_KINDS = frozenset(
    {"bridge", "control_plane_vm", "nested_target_vm", "firewall_chain", "pool", "service_identity"}
)


class OwnershipNamespaceError(ValueError):
    """Raised for an unsafe ownership label or an out-of-range/unknown resource request."""


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
        return f"{_OWNERSHIP_TAG_PREFIX}:{self.fingerprint}"

    def resource_name(self, kind: str, index: int) -> str:
        """A generated, bounded, ownership-derived resource name (never a caller-supplied name)."""
        if kind not in _KINDS:
            raise OwnershipNamespaceError("unknown_resource_kind")
        if not isinstance(index, int) or not (0 <= index < _MAX_RESOURCE_INDEX):
            raise OwnershipNamespaceError("resource_index_out_of_range")
        return f"secp{self.fingerprint[:8]}-{kind}-{index}"

    def owns(self, resource_tag: object) -> bool:
        """True ONLY if the resource carries this namespace's exact ownership tag. Anything else —
        an untagged resource, a differently-tagged (other-lab) resource, or a non-string — is not
        owned, so the provider must not mutate or delete it."""
        return isinstance(resource_tag, str) and resource_tag == self.ownership_tag


def ownership_namespace(ownership_label: str) -> SecpOwnershipNamespace:
    """Derive the deterministic ownership namespace for a lab's immutable ownership label."""
    if not (isinstance(ownership_label, str) and _LABEL_RE.match(ownership_label)):
        raise OwnershipNamespaceError("unsafe_ownership_label")
    fingerprint = hashlib.sha256(ownership_label.encode("utf-8")).hexdigest()
    return SecpOwnershipNamespace(ownership_label=ownership_label, fingerprint=fingerprint)
