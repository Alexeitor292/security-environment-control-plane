"""Provider-neutral, secret-free worker-identity contract constants + helpers (SECP-B2-4.3).

Shared by the app-side service (which binds a durable worker-identity registration) and the
worker-side verifier (which independently re-checks it) so both validate the same grammar and
compute the same verification-anchor + evidence fingerprints. This module authenticates nothing,
performs no mTLS, parses no certificate, accesses no key/CSR/CA, contacts nothing, and imports no
transport/HTTP/secret code. It stores/derives ONLY safe metadata — never a certificate, key, CSR,
CA name, hostname, endpoint, port, token, secret reference, or backend configuration.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from secp_api.enums import WorkerIdentityEvidenceKind, WorkerIdentityEvidenceStatus

# The pinned worker-identity contract version an approved registration binds. MUST equal
# ``secp_worker.preflight.worker_identity_attestation.WORKER_IDENTITY_CONTRACT_VERSION`` (a drift
# guard test asserts the equality). It is a plain label — no endpoint/secret/backend detail.
WORKER_IDENTITY_CONTRACT_VERSION = "secp-b2-4.3/worker-identity/v1"

# Approval requires EVERY evidence kind present + verified. The closed set is provider-neutral and
# records only proof metadata (never a certificate/key/CSR/CA/endpoint/secret).
REQUIRED_WORKER_IDENTITY_EVIDENCE_KINDS: frozenset[WorkerIdentityEvidenceKind] = frozenset(
    WorkerIdentityEvidenceKind
)

# An opaque, non-sensitive identifier: letters, digits, dot, underscore, hyphen only — no
# whitespace, slash, ``:``, ``@``, or scheme, so it cannot carry a hostname/endpoint/URL, an
# ``env:``/``vault:`` reference, a ``user@host``, a PEM block, or a multi-token secret.
_SAFE_METADATA_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$")

# A verification-anchor FINGERPRINT (never the anchor material): a canonical ``sha256:<64 hex>``.
_ANCHOR_FINGERPRINT_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class WorkerIdentityMetadataError(ValueError):
    """Raised when an identity label / deployment binding / anchor fingerprint is not a safe closed
    value. Never echoes the offending value."""


def validate_identity_label(label: str) -> None:
    if not (isinstance(label, str) and _SAFE_METADATA_RE.match(label)):
        raise WorkerIdentityMetadataError("identity_label must be a safe opaque identifier")


def validate_deployment_binding(binding: str) -> None:
    if not (isinstance(binding, str) and _SAFE_METADATA_RE.match(binding)):
        raise WorkerIdentityMetadataError("deployment_binding must be a safe opaque identifier")


def validate_verification_anchor_fingerprint(fingerprint: str) -> None:
    """Reject anything but a canonical ``sha256:<hex>`` fingerprint of a PUBLIC verification anchor.

    The app never stores the anchor material — only its fingerprint — so no certificate/key/PEM can
    be persisted through this field.
    """
    if not (isinstance(fingerprint, str) and _ANCHOR_FINGERPRINT_RE.match(fingerprint)):
        raise WorkerIdentityMetadataError(
            "verification_anchor_fingerprint must be a canonical sha256:<hex> value"
        )


def validate_evidence_metadata(*, proof_id: str, issuer: str) -> None:
    """Reject non-opaque/free-form/sensitive-looking proof metadata. Never echoes the value."""
    for value in (proof_id, issuer):
        if not (isinstance(value, str) and _SAFE_METADATA_RE.match(value)):
            raise WorkerIdentityMetadataError("evidence metadata must be a safe opaque identifier")


def compute_deployment_binding_fingerprint(deployment_binding: str) -> str:
    """Canonical ``sha256:`` fingerprint of the opaque (non-secret) deployment binding.

    Used to carry a non-secret binding identifier on the verified-identity result without echoing
    raw binding value. It hashes an already-opaque grammar-validated string — no certificate/key/
    endpoint/secret is involved.
    """
    return "sha256:" + hashlib.sha256(str(deployment_binding).encode("utf-8")).hexdigest()


def compute_verification_anchor_fingerprint(public_anchor: str) -> str:
    """Canonical ``sha256:`` fingerprint of a PUBLIC verification anchor (e.g. a public-key value).

    The worker verifier recomputes this from an injected attestation claim's public anchor and
    compares it to the stored fingerprint. This is a plain hash of an opaque public string — it
    parses no certificate, accesses no private key, and performs no signing or CA lookup.
    """
    encoded = str(public_anchor).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def compute_worker_identity_evidence_fingerprint(items: Iterable[Any]) -> str:
    """Canonical ``sha256:`` fingerprint over the COMPLETE evidence set (secret-free metadata only).

    ``items`` is an iterable of evidence rows with ``.kind``/``.status``/``.proof_id``/``.issuer``/
    ``.verified_at``. The fingerprint folds in only closed metadata. Approval binds this value;
    the worker recomputes + compares it.
    """
    canonical = []
    for item in sorted(items, key=lambda e: _kind_value(e.kind)):
        canonical.append(
            {
                "kind": _kind_value(item.kind),
                "status": _status_value(item.status),
                "proof_id": item.proof_id,
                "issuer": item.issuer,
                "verified_at": _canonical_verified_at(getattr(item, "verified_at", None)),
            }
        )
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _canonical_verified_at(value: datetime | None) -> str:
    """Canonicalize a verified-at timestamp to UTC ISO-8601 so the fingerprint is deterministic
    across processes and databases (a naive value is treated as UTC)."""
    if value is None:
        return ""
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat()


def worker_identity_evidence_is_complete(items: Iterable[Any]) -> bool:
    """True iff every required evidence kind is present with status ``verified``."""
    verified_kinds = {
        _kind_value(e.kind)
        for e in items
        if _status_value(e.status) == WorkerIdentityEvidenceStatus.verified.value
    }
    return {k.value for k in REQUIRED_WORKER_IDENTITY_EVIDENCE_KINDS} <= verified_kinds


def _kind_value(kind: object) -> str:
    return getattr(kind, "value", str(kind))


def _status_value(status: object) -> str:
    return getattr(status, "value", str(status))
