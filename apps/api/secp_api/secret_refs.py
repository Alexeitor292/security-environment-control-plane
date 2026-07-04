"""Secret-reference SYNTAX validation (API-side) — ADR-007.

A ``secret_ref`` is an opaque ``<scheme>:<locator>`` pointer to where a provider
secret lives. The API may validate its **syntax** but MUST NEVER resolve it
(resolution is worker-only). This module contains no resolution logic and reads no
secrets — only syntax.
"""

from __future__ import annotations

import re

SECRET_REF_PATTERN = re.compile(r"^(?P<scheme>[a-z][a-z0-9-]*):(?P<locator>\S.*)$")

# Schemes the platform understands. SECP-002A ships the dev 'env' scheme; SECP-B2-4 adds the
# opaque 'vault:' scheme for a future worker-only OpenBao/Vault-style backend. The API validates
# ONLY the syntax of a reference — it NEVER resolves, inspects, renders, logs, or routes it, and
# resolution stays worker-only (ADR-007). A future 'aws-sm:' etc. is a compatible addition.
SUPPORTED_SCHEMES = {"env", "vault"}

# The dev 'env' scheme may ONLY point at a namespaced provider-secret env var, so a
# secret_ref can never be used to read arbitrary environment variables.
ENV_LOCATOR_PATTERN = re.compile(r"^SECP_PROVIDER_SECRET__[A-Za-z0-9_]+$")

# The 'vault' scheme locator is an OPAQUE, structural logical path only: slash-delimited segments
# of safe characters, no leading slash, no dot-segment traversal, no host/scheme/port/query, no
# whitespace. It names *where* a secret lives, never a secret, endpoint, host, port, or token, and
# is resolved only in the worker behind the out-of-band-granted OpenBao adapter.
VAULT_LOCATOR_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9._-]+)*$")


class InvalidSecretRefError(ValueError):
    """Raised when a secret reference is syntactically invalid."""


def parse_secret_ref(secret_ref: str) -> tuple[str, str]:
    """Return ``(scheme, locator)`` or raise :class:`InvalidSecretRefError`.

    Performs SYNTAX checks only — never resolves or reads a secret.
    """
    if not isinstance(secret_ref, str) or not secret_ref.strip():
        raise InvalidSecretRefError("secret reference must be a non-empty string")
    match = SECRET_REF_PATTERN.match(secret_ref)
    if not match:
        raise InvalidSecretRefError("secret reference must be of the form '<scheme>:<locator>'")
    scheme = match.group("scheme")
    locator = match.group("locator")
    if scheme not in SUPPORTED_SCHEMES:
        raise InvalidSecretRefError(
            f"unsupported secret-reference scheme '{scheme}'; "
            f"supported: {sorted(SUPPORTED_SCHEMES)}"
        )
    if scheme == "env" and not ENV_LOCATOR_PATTERN.match(locator):
        raise InvalidSecretRefError(
            "the 'env' scheme requires a namespaced locator matching SECP_PROVIDER_SECRET__<NAME>"
        )
    if scheme == "vault" and not VAULT_LOCATOR_PATTERN.match(locator):
        raise InvalidSecretRefError(
            "the 'vault' scheme requires an opaque slash-delimited logical path "
            "(no leading slash, host, scheme, port, query, whitespace, or dot-segment traversal)"
        )
    return scheme, locator


def validate_secret_ref_syntax(secret_ref: str) -> None:
    """Validate syntax; raise :class:`InvalidSecretRefError` if invalid."""
    parse_secret_ref(secret_ref)


def looks_like_plaintext_secret(value: str) -> bool:
    """Heuristic guard: does this look like a raw secret rather than a reference?

    Used to refuse obvious plaintext credentials submitted where a reference is
    expected. A valid ``<scheme>:<locator>`` with a supported scheme is NOT
    plaintext.
    """
    try:
        parse_secret_ref(value)
        return False
    except InvalidSecretRefError:
        return True
