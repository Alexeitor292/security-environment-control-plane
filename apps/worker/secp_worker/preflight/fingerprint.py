"""Canonical, secret-free operation fingerprint for a read-only-preflight work item (SECP-B2-4).

A single, pure implementation shared by the worker orchestration and the independent
re-verification path, so both derive the *exact same* fingerprint. It is computed only from the
work item's durable identity fields — never config, endpoints, credentials, or secret references.
"""

from __future__ import annotations

import hashlib
import json

from secp_api.models import ReadonlyStagingPreflight


def compute_operation_fingerprint(preflight: ReadonlyStagingPreflight) -> str:
    """Deterministic ``sha256:`` fingerprint over the work item's durable identity fields."""
    identity = {
        "preflight_id": str(preflight.id),
        "organization_id": str(preflight.organization_id),
        "execution_target_id": str(preflight.execution_target_id),
        "onboarding_id": str(preflight.onboarding_id),
        "authorization_id": str(preflight.live_read_authorization_id),
        "authorization_version": preflight.authorization_version,
    }
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()
