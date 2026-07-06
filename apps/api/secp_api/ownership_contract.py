"""Shared, provider-neutral SECP ownership-namespace contract (SECP-B3/B4).

The SINGLE source of truth for deriving a lab's immutable ownership fingerprint, its ownership tag,
and generated ownership-bound resource references. Both the app-side deployment service (which pins
these into immutable plans/approvals) and the worker-side provider (which stamps and later proves
them) import this module, so the API and worker can never disagree about what "provably SECP-owned
by THIS lab" means. It authenticates nothing, contacts nothing, and stores/derives ONLY safe opaque
values — never a real host, endpoint, bridge/VMID/storage name, secret, or credential.
"""

from __future__ import annotations

import hashlib
import re

# App-owned bounded generation range (NOT a user's infrastructure value).
MAX_RESOURCE_INDEX = 64
_TAG_PREFIX = "secp-owned"
# A safe ownership label: letters/digits/dot/underscore/hyphen only (no shell/host/path char).
_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$")
# Closed set of resource CATEGORIES a namespace may name (a caller cannot introduce a new kind).
OWNERSHIP_RESOURCE_KINDS: frozenset[str] = frozenset(
    {
        # B3 provider skeleton kinds.
        "bridge",
        "control_plane_vm",
        "nested_target_vm",
        "firewall_chain",
        "pool",
        "service_identity",
        # B4 deployment-engine resource categories (DeploymentResourceKind values).
        "proxmox_service_identity",
        "host_bootstrap_helper",
        "isolated_bridge",
        "host_firewall_boundary",
        "artifact_stage",
        "openbao_scoped_credential",
    }
)


class OwnershipContractError(ValueError):
    """Raised for an unsafe ownership label or an out-of-range/unknown resource request."""


def validate_ownership_label(label: object) -> str:
    """Return ``label`` if it is a safe opaque identifier, else fail closed. Never echoes it."""
    if not (isinstance(label, str) and _LABEL_RE.match(label)):
        raise OwnershipContractError("unsafe_ownership_label")
    return label


def compute_ownership_fingerprint(label: str) -> str:
    """Deterministic hex fingerprint of the (validated) ownership label."""
    validate_ownership_label(label)
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def compute_ownership_tag(label: str) -> str:
    """The immutable ownership tag stamped on every created resource: ``secp-owned:<fingerprint>``.

    Ownership is proven by this tag, never inferred from a resource name a third party could pick.
    """
    return f"{_TAG_PREFIX}:{compute_ownership_fingerprint(label)}"


def compute_resource_ref(label: str, kind: str, index: int) -> str:
    """A generated, bounded, ownership-derived resource reference (never a caller-supplied name)."""
    if kind not in OWNERSHIP_RESOURCE_KINDS:
        raise OwnershipContractError("unknown_resource_kind")
    if (
        not isinstance(index, int)
        or isinstance(index, bool)
        or not (0 <= index < MAX_RESOURCE_INDEX)
    ):
        raise OwnershipContractError("resource_index_out_of_range")
    return f"secp{compute_ownership_fingerprint(label)[:8]}-{kind}-{index}"


def owns(ownership_tag_of_this_lab: str, resource_tag: object) -> bool:
    """True ONLY if ``resource_tag`` is exactly this lab's ownership tag (constant-time equality).

    An untagged resource, a differently-tagged (other-lab) resource, or a non-string is NOT owned.

    NOTE (SECP-B4 corrective): this proves only that a *tag string* equals this lab's tag. It is NOT
    sufficient as a mutation-authorization gate — a mutation must additionally prove, via a FRESH
    observation of the exact provider object, that the object at the target locator carries this
    lab's per-resource marker (see the deployment engine's observed-ownership evidence contract).
    """
    return isinstance(resource_tag, str) and resource_tag == ownership_tag_of_this_lab


def compute_resource_marker(label: str, kind: str, index: int) -> str:
    """A unique, per-resource, deployment-bound ownership marker to STAMP into a provider-visible
    field on create and read back on a fresh observation before any mutation. It binds the lab's
    ownership tag to the exact generated resource reference, so a foreign or differently-owned
    object
    can never match it."""
    return f"{compute_ownership_tag(label)}#{compute_resource_ref(label, kind, index)}"
