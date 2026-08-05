"""Worker-owned range provider implementations and their registry.

This is where range execution lives, and it lives here because it is privileged: the local Docker
provider drives a Docker socket, which is root-equivalent on the host. Charter Invariants 6/7 and
ADR-005 place that in the worker. The API holds only the contract types
(:mod:`secp_api.range_providers`) and dispatches; it never constructs a provider and never runs one.

The provider is additionally SEALED BY DEFAULT (``SECP_RANGE_LOCAL_DOCKER``, impossible in
production). Moving execution to the worker answers *where* the capability may run; the seal
answers *whether it is switched on at all*. Both apply.
"""

from __future__ import annotations

from secp_api.range_providers.base import RangeProvider

from secp_worker.range.local_docker import LocalDockerProvider

#: Providers by the name persisted on ``RangeInstance.provider``.
_PROVIDERS: dict[str, RangeProvider] = {}


class RangeProviderSealedError(RuntimeError):
    """The requested provider exists but is not permitted to run in this deployment."""


def get_provider(name: str) -> RangeProvider:
    """Return the provider registered under ``name``.

    Constructed lazily and cached, so importing this package never touches a Docker socket. A test
    that installs its own provider via :func:`set_provider` bypasses the seal, because such a
    provider touches nothing.
    """
    provider = _PROVIDERS.get(name)
    if provider is None:
        if name != LocalDockerProvider.name:
            raise KeyError(f"unknown range provider '{name}'")
        from secp_api.config import get_settings

        if not get_settings().range_local_docker_enabled:
            raise RangeProviderSealedError(
                "the local Docker range provider is sealed; it is development/demo only and must "
                "be enabled explicitly with SECP_RANGE_LOCAL_DOCKER=true (never in production)"
            )
        provider = LocalDockerProvider()
        _PROVIDERS[name] = provider
    return provider


def set_provider(name: str, provider: RangeProvider) -> None:
    """Register/override a provider. Used by tests to install a deterministic fake."""
    _PROVIDERS[name] = provider


def reset_providers() -> None:
    _PROVIDERS.clear()


__all__ = [
    "LocalDockerProvider",
    "RangeProviderSealedError",
    "get_provider",
    "reset_providers",
    "set_provider",
]
