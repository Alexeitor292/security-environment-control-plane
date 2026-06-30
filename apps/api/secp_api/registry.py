"""Plugin registry.

Holds the in-process set of available plugins keyed by name. Validates that a
registered plugin actually exposes the capability methods it advertises
(ADR-003: runtime backstop for the structural Protocol).
"""

from __future__ import annotations

from secp_plugin_api.v1 import Capability, HealthReport, PluginProtocol

_REQUIRED_METHODS = (
    "health",
    "validate",
    "plan",
    "apply",
    "status",
    "reset",
    "destroy",
)


class PluginRegistryError(RuntimeError):
    pass


class PluginRegistry:
    def __init__(self) -> None:
        self._plugins: dict[str, PluginProtocol] = {}

    def register(self, plugin: PluginProtocol) -> None:
        for method in _REQUIRED_METHODS:
            if not callable(getattr(plugin, method, None)):
                raise PluginRegistryError(
                    f"plugin '{getattr(plugin, 'name', '?')}' missing method '{method}'"
                )
        # Cross-check advertised capabilities against implemented methods.
        report = plugin.health()
        for cap in report.capabilities:
            try:
                Capability(cap)
            except ValueError as exc:
                raise PluginRegistryError(
                    f"plugin '{plugin.name}' advertises unknown capability '{cap}'"
                ) from exc
        self._plugins[plugin.name] = plugin

    def unregister(self, name: str) -> None:
        """Remove a plugin (primarily for test isolation)."""
        self._plugins.pop(name, None)

    def get(self, name: str) -> PluginProtocol:
        if name not in self._plugins:
            raise PluginRegistryError(f"plugin '{name}' is not registered")
        return self._plugins[name]

    def has(self, name: str) -> bool:
        return name in self._plugins

    def names(self) -> list[str]:
        return sorted(self._plugins)

    def health_all(self) -> list[HealthReport]:
        return [p.health() for p in self._plugins.values()]


_registry: PluginRegistry | None = None


def get_registry() -> PluginRegistry:
    """Return the process-wide registry, registering built-in plugins once."""
    global _registry
    if _registry is None:
        _registry = PluginRegistry()
        from secp_plugin_simulator import SimulatorPlugin

        _registry.register(SimulatorPlugin())
    return _registry
