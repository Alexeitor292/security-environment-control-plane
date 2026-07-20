"""Pure deployment foundation for production B8 discovery activation.

This package owns only fixed production layout, strict deployment-local identity validation,
in-memory TLS preparation, and deterministic artifact rendering.  Importing it, parsing a profile,
preparing TLS material, or rendering artifacts performs no filesystem mutation, subprocess
execution, or network contact.
"""

from __future__ import annotations

PACKAGE_CONTRACT_VERSION = "secp.discovery-activation/v1alpha1"
PACKAGE_VERSION = "0.1.0"
PACKAGE_IMPLEMENTATION_ID = "secp-pr5f/discovery-activation/v1"


class DiscoveryActivationError(Exception):
    """A fail-closed error carrying only a bounded, non-sensitive reason code."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)

    def __repr__(self) -> str:
        return f"DiscoveryActivationError({self.reason_code!r})"


__all__ = [
    "PACKAGE_CONTRACT_VERSION",
    "PACKAGE_VERSION",
    "PACKAGE_IMPLEMENTATION_ID",
    "DiscoveryActivationError",
]
