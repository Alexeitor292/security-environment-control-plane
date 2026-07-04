"""Sealed worker-side secret resolver for read-only staging preflight (SECP-B2-0, sealed SECP-B2-1).

No production secret manager resolver exists yet. This sealed resolver implements the worker-only
:class:`WorkerSecretResolver` contract (SECP-B2-1) but ALWAYS fails closed — it resolves nothing,
reads no environment, contacts no secret backend, and never returns :class:`SecretMaterial`. It
exists so a read-only preflight terminates as ``credential_unavailable`` instead of weakening the
credential model with an insecure API-side store or resolver.

Activation dependency: a future, separately reviewed PR must inject a real production-safe,
worker-only resolver (implementing the same contract) in its place before a deliberate live
preflight can proceed.
"""

from __future__ import annotations

from secp_worker.preflight.secret_resolution import (
    SealedUnavailableResolver,
    SecretResolutionUnavailable,
)


class SealedSecretResolutionError(SecretResolutionUnavailable):
    """Raised by the sealed resolver: no production secret resolver is configured."""


class SealedSecretResolver(SealedUnavailableResolver):
    """A worker :class:`WorkerSecretResolver` that always fails closed (never resolves a secret)."""
