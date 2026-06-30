"""Plugin registry.

Holds the in-process set of available plugins keyed by name. Validates that a
registered plugin actually exposes the capability methods it advertises
(ADR-003: runtime backstop for the structural Protocol).

Closed-world inline-execution allowlist
---------------------------------------
Whether a plugin may run inline (in-process) via the InlineDispatcher is a
trust decision owned by THIS registry, not by the plugin itself.  A plugin
cannot grant its own inline-execution permission by setting
``health().simulated = True``; only an explicit ``inline_safe=True`` argument
at registration time (used exclusively for the built-in SimulatorPlugin)
counts.  Future real-provider plugins default to ``inline_safe=False``, and no
combination of plugin-provided metadata can override that.
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
        # Closed-world set of plugin names explicitly approved for inline execution.
        # Only the built-in Simulator is in this set; it is populated at
        # registration time, never derived from plugin-provided metadata.
        self._inline_safe: set[str] = set()

    def register(self, plugin: PluginProtocol, *, inline_safe: bool = False) -> None:
        """Register *plugin*.

        ``inline_safe=True`` must only be passed for the built-in Simulator.
        All other plugins default to ``inline_safe=False`` and will be refused
        by the InlineDispatcher guard regardless of what their ``health()``
        method returns.
        """
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
        if inline_safe:
            self._inline_safe.add(plugin.name)

    def unregister(self, name: str) -> None:
        """Remove a plugin (primarily for test isolation)."""
        self._plugins.pop(name, None)
        self._inline_safe.discard(name)

    def is_inline_safe(self, name: str) -> bool:
        """Return True only if the registry explicitly granted inline-execution to *name*.

        This is the authoritative check.  Plugin self-reported metadata
        (``health().simulated``) is never consulted for this decision.
        """
        return name in self._inline_safe

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
    """Return the process-wide registry, registering built-in plugins once.

    The SimulatorPlugin is the ONLY plugin registered with ``inline_safe=True``.
    All future real-provider plugins must call ``register(plugin)`` (the default
    ``inline_safe=False``) and will therefore be refused by the InlineDispatcher
    guard without any code change required.
    """
    global _registry
    if _registry is None:
        _registry = PluginRegistry()
        from secp_plugin_simulator import SimulatorPlugin

        # inline_safe=True: the Simulator is the closed-world set of one.
        _registry.register(SimulatorPlugin(), inline_safe=True)
    return _registry
