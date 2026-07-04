"""Provider-neutral, secret-free resolver-activation contract constants + helpers (SECP-B2-4.1).

Shared by the app-side service (which binds an activation authorization) and the worker-side
verifier (which independently re-checks it) so both compute the *same* operation fingerprint and
evidence fingerprint. This module resolves nothing, contacts nothing, and imports no plugin,
transport, HTTP, or secret code. It stores/derives ONLY safe metadata — never an endpoint,
hostname, port, token, policy, vault path, reference, worker credential, backend config, or secret.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from typing import Any

from secp_api.enums import ResolverActivationEvidenceKind, ResolverActivationEvidenceStatus

# The pinned resolver-adapter contract version an activation authorization binds. MUST equal
# ``secp_worker.preflight.backends.openbao_resolver.RESOLVER_ADAPTER_CONTRACT_VERSION`` (a drift
# guard test asserts the equality). It is a plain label — no endpoint/secret/backend detail.
RESOLVER_ADAPTER_CONTRACT_VERSION = "secp-b2-4/openbao-worker-resolver/v1"

# The only purpose an activation authorization may bind in this phase.
RESOLVER_ACTIVATION_PURPOSE = "readonly_staging_preflight"

# Approval requires EVERY evidence kind present + verified. The closed set mirrors the B2-2 §8
# activation evidence package; it is provider-neutral and records only proof metadata.
REQUIRED_EVIDENCE_KINDS: frozenset[ResolverActivationEvidenceKind] = frozenset(
    ResolverActivationEvidenceKind
)

# An opaque, non-sensitive proof identifier / issuer label: letters, digits, dot, underscore,
# hyphen only — no whitespace, slash, ``:``, ``@``, or scheme, so it cannot carry a vault path,
# URL/endpoint, ``env:``/``vault:`` reference, ``user@host``, or a multi-token secret.
_SAFE_METADATA_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$")


class EvidenceMetadataError(ValueError):
    """Raised when an evidence ``proof_id``/``issuer`` is not a safe closed identifier."""


def validate_evidence_metadata(*, proof_id: str, issuer: str) -> None:
    """Reject non-opaque/free-form/sensitive-looking proof metadata. Never echoes the value."""
    for value in (proof_id, issuer):
        if not (isinstance(value, str) and _SAFE_METADATA_RE.match(value)):
            raise EvidenceMetadataError("evidence metadata must be a safe opaque identifier")


def compute_operation_fingerprint(preflight: object) -> str:
    """Canonical, secret-free ``sha256:`` fingerprint over the work item's durable identity fields.

    Byte-identical to the worker's fingerprint so the API-bound value equals the worker-verified
    value. Derived only from durable ids — never config, endpoints, credentials, or references.
    """
    identity = {
        "preflight_id": str(getattr(preflight, "id", "")),
        "organization_id": str(getattr(preflight, "organization_id", "")),
        "execution_target_id": str(getattr(preflight, "execution_target_id", "")),
        "onboarding_id": str(getattr(preflight, "onboarding_id", "")),
        "authorization_id": str(getattr(preflight, "live_read_authorization_id", "")),
        "authorization_version": getattr(preflight, "authorization_version", None),
    }
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def compute_evidence_fingerprint(items: Iterable[Any]) -> str:
    """Canonical ``sha256:`` fingerprint over the COMPLETE evidence set (secret-free metadata only).

    ``items`` is an iterable of evidence rows with ``.kind``/``.status``/``.proof_id``/``.issuer``/
    ``.verified_at``. The fingerprint folds in only closed metadata; it never includes a value that
    could be sensitive. Approval binds this fingerprint; the worker recomputes + compares it.
    """
    canonical = []
    for item in sorted(items, key=lambda e: _kind_value(e.kind)):
        verified_at = getattr(item, "verified_at", None)
        canonical.append(
            {
                "kind": _kind_value(item.kind),
                "status": _status_value(item.status),
                "proof_id": item.proof_id,
                "issuer": item.issuer,
                "verified_at": verified_at.astimezone().isoformat() if verified_at else "",
            }
        )
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def evidence_is_complete(items: Iterable[Any]) -> bool:
    """True iff every required evidence kind is present with status ``verified``."""
    verified_kinds = {
        _kind_value(e.kind)
        for e in items
        if _status_value(e.status) == ResolverActivationEvidenceStatus.verified.value
    }
    return {k.value for k in REQUIRED_EVIDENCE_KINDS} <= verified_kinds


def _kind_value(kind: object) -> str:
    return getattr(kind, "value", str(kind))


def _status_value(status: object) -> str:
    return getattr(status, "value", str(status))
