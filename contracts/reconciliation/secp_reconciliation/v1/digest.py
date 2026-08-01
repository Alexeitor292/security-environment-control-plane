"""Canonical encoding and content addressing for the reconciliation contract (v1).

The single place this contract turns a structure into bytes, so the classifier, the planner, the
reset-intent builder, the evidence builder and any consumer can never disagree about what a digest
covers. Pure: no I/O, no clock, no randomness, no first-party imports.

Encoding rules (identical to the control-plane's existing content-addressed contracts): sorted
keys, no insignificant whitespace, ASCII-escaped, and a ``sha256:``-prefixed lowercase hex digest
over ``"<schema_version>|<canonical json>"`` so the same bytes under a different contract version
never collide.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

# A well-formed content address as this contract emits and accepts it.
_DIGEST_PREFIX = "sha256:"
_DIGEST_HEX_LENGTH = 64
_HEX_ALPHABET = frozenset("0123456789abcdef")


def sha256_digest(canonical: str) -> str:
    """``sha256:``-prefixed lowercase hex digest of an already-canonical string."""
    return _DIGEST_PREFIX + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def canonical_json(document: dict) -> str:
    """Deterministic JSON encoding: sorted keys, no insignificant whitespace, ASCII-escaped."""
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def document_digest(schema_version: str, document: dict) -> str:
    """Content address of a versioned document. The version is folded in, so an identical body
    under a new schema version is a different content address."""
    return sha256_digest(schema_version + "|" + canonical_json(document))


def is_content_digest(value: object) -> bool:
    """True only for a well-formed ``sha256:<64 lowercase hex>`` content address.

    Used by the verification gate: an input that merely *claims* provenance with a malformed digest
    is unverifiable and must refuse, never pass quietly.
    """
    if not isinstance(value, str):
        return False
    if not value.startswith(_DIGEST_PREFIX):
        return False
    hex_part = value[len(_DIGEST_PREFIX) :]
    if len(hex_part) != _DIGEST_HEX_LENGTH:
        return False
    return all(char in _HEX_ALPHABET for char in hex_part)


def as_utc(value: datetime) -> datetime:
    """Treat a naive datetime as UTC (the control-plane convention — SQLite drops tzinfo)."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def canonical_utc(value: datetime) -> str:
    """Canonical UTC ISO-8601 rendering, so two processes in different local timezones fold the
    same bytes into a digest."""
    return as_utc(value).astimezone(UTC).isoformat()
