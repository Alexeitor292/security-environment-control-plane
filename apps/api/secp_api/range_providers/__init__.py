"""Range provider implementations behind one provider-neutral boundary.

The lifecycle service knows only :mod:`secp_api.range_providers.base`. Nothing above this package
imports Docker, and no provider touches the database — providers receive a spec and an observation
sink, and return observations. That is what keeps the lifecycle model portable to a second provider
without rewriting the service.
"""

from __future__ import annotations

from secp_api.range_providers.base import (
    OperationContext,
    ProviderHealth,
    RangeProvider,
    ResourceObservation,
    TeardownObservation,
    TeardownResourceOutcome,
)
from secp_api.range_providers.local_docker import LocalDockerProvider

#: The provider registry, keyed by the name persisted on ``RangeInstance.provider``.
_PROVIDERS: dict[str, RangeProvider] = {}


class RangeProviderSealedError(RuntimeError):
    """The requested provider exists but is not permitted to run in this deployment."""


def get_provider(name: str) -> RangeProvider:
    """Return the provider registered under ``name``.

    Constructed lazily and cached so a process holds one provider per name, and so importing this
    package never touches a Docker socket.

    The local Docker provider is SEALED BY DEFAULT. A Docker socket is root-equivalent on the host,
    so constructing this provider is privileged execution and must be opted into explicitly
    (``SECP_RANGE_LOCAL_DOCKER=true``, never available in production). A test that installs its own
    provider via :func:`set_provider` bypasses this, because such a provider touches nothing.
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
    "OperationContext",
    "ProviderHealth",
    "RangeProvider",
    "ResourceObservation",
    "TeardownObservation",
    "TeardownResourceOutcome",
    "get_provider",
    "reset_providers",
    "set_provider",
]
