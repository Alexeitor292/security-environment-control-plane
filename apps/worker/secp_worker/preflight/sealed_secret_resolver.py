"""Sealed worker-side secret resolver for read-only staging preflight (SECP-B2-0).

No production secret manager resolver exists yet. This sealed resolver satisfies the worker
``SecretResolver`` boundary but ALWAYS fails closed — it resolves nothing, reads no environment,
contacts no secret backend, and never returns a credential. It exists so a read-only preflight
terminates as ``credential_unavailable`` instead of weakening the credential model with an
insecure API-side store or resolver.

Activation dependency: a future, separately reviewed PR must inject a real production-safe,
worker-only resolver in its place before a deliberate live preflight can proceed.
"""

from __future__ import annotations

from secp_worker.secrets import SecretResolutionError


class SealedSecretResolutionError(SecretResolutionError):
    """Raised by the sealed resolver: no production secret resolver is configured."""


class SealedSecretResolver:
    """A worker ``SecretResolver`` that always fails closed (never resolves a secret)."""

    def resolve(self, secret_ref: str):  # noqa: ANN201 - matches SecretResolver protocol
        # Redacted: never echoes the reference locator or any value (there is none).
        raise SealedSecretResolutionError(
            "no production secret resolver is configured for read-only preflight"
        )
