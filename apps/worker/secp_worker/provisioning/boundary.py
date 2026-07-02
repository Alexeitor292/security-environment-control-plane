"""Worker effective-boundary enforcement seam.

The pure enforcement logic lives in ``secp_api.effective_boundary`` so manifest generation
and the worker gate use the same provider-neutral checks. This worker module preserves the
worker-side seam/import path used by execution and tests.
"""

from __future__ import annotations

from secp_api.effective_boundary import (
    BoundaryViolation,
    cidr_within_boundary,
    effective_policy_view,
    enforce_manifest_within_boundary,
    external_connectivity_denied,
    network_within_boundary,
    node_within_boundary,
    storage_within_boundary,
    totals_within_quotas,
    vmid_within_boundary,
)

__all__ = [
    "BoundaryViolation",
    "cidr_within_boundary",
    "effective_policy_view",
    "enforce_manifest_within_boundary",
    "external_connectivity_denied",
    "network_within_boundary",
    "node_within_boundary",
    "storage_within_boundary",
    "totals_within_quotas",
    "vmid_within_boundary",
]
