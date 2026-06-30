"""Secret-reference SYNTAX validation (API-side) — ADR-007.

A ``secret_ref`` is an opaque ``<scheme>:<locator>`` pointer to where a provider
secret lives. The API may validate its **syntax** but MUST NEVER resolve it
(resolution is worker-only). This module contains no resolution logic and reads no
secrets — only syntax.
"""

from __future__ import annotations

import re

SECRET_REF_PATTERN = re.compile(r"^(?P<scheme>[a-z][a-z0-9-]*):(?P<locator>\S.*)$")

# Schemes the platform understands. SECP-002A ships the dev 'env' scheme only; a
# production secret manager (e.g. 'vault', 'aws-sm') is a future, compatible addition.
SUPPORTED_SCHEMES = {"env"}

# The dev 'env' scheme may ONLY point at a namespaced provider-secret env var, so a
# secret_ref can never be used to read arbitrary environment variables.
ENV_LOCATOR_PATTERN = re.compile(r"^SECP_PROVIDER_SECRET__[A-Za-z0-9_]+$")


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
