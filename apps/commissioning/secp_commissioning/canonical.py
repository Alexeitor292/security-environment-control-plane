"""Canonical serialization + deterministic SHA-256 digest (SECP-PR5C, ADR-023).

Every commissioning artifact (descriptor, plan, evidence, rendered manifest) serializes through the
SAME canonical rule and digests to a ``sha256:<64-hex>`` content address, so the descriptor digest,
the plan digest, and each installed-file digest are stable across processes and hosts. This mirrors
``secp_api.deployment_contract.deployment_plan_hash`` (``json.dumps(sort_keys=True,
separators=(",", ":"))`` -> ``sha256:``).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

_SHA256_PREFIX = "sha256:"


def canonical_json(payload: Any) -> str:
    """Deterministic canonical JSON: sorted keys, no insignificant whitespace, UTF-8, no NaN.

    ``ensure_ascii`` is left default (True) so the byte stream is pure ASCII and identical on every
    platform. ``allow_nan=False`` refuses non-finite floats (a canonical artifact never carries
    one).
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
        ensure_ascii=True,
    )


def sha256_digest(payload: Any) -> str:
    """The ``sha256:<hex>`` content address of a payload's canonical JSON encoding."""
    encoded = canonical_json(payload).encode("utf-8")
    return _SHA256_PREFIX + hashlib.sha256(encoded).hexdigest()


def sha256_bytes(data: bytes) -> str:
    """The ``sha256:<hex>`` content address of raw bytes (e.g. a rendered file's exact content)."""
    return _SHA256_PREFIX + hashlib.sha256(data).hexdigest()


def is_sha256_digest(value: object) -> bool:
    """True if ``value`` is a well-formed ``sha256:<64 lowercase hex>`` digest string."""
    if not isinstance(value, str) or not value.startswith(_SHA256_PREFIX):
        return False
    hexpart = value[len(_SHA256_PREFIX) :]
    return len(hexpart) == 64 and all(c in "0123456789abcdef" for c in hexpart)
