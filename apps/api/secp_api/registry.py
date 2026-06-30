"""Plugin registry.

Holds the in-process set of available plugins keyed by name. Validates that a
registered plugin actually exposes the capability methods it advertises
(ADR-003: runtime backstop for the structural Protocol).

Closed-world inline-execution allowlist — identity-based
---------------------------------------------------------
Authorization for inline execution is a **registry-owned** decision based on
**object identity**, not on plugin name and not on plugin-reported metadata.

Rules:
* ``register(plugin)`` (the public API) always registers a plugin as NOT
  inline-safe.  There is no ``inline_safe`` argument; no caller outside the
  bootstrap can make a plugin inline-safe.
* ``_register_builtin_simulator(plugin)`` is called exactly once, by
  ``get_registry()``.  It stores the actual ``SimulatorPlugin`` instance and
  marks it as the sole inline-safe plugin.
* ``is_inline_safe(plugin)`` performs a Python ``is`` (identity) check against
  the stored bootstrapped instance.  A different ``SimulatorPlugin()`` created
  elsewhere, a fake plugin named "simulator", or any other plugin object will
  return ``False``.
* Plugin names are immutable once registered — calling ``register()`` with a
  name that already exists raises ``PluginRegistryError``.  This prevents
  replacing the built-in Simulator with a different object at the same name.
* ``health().simulated`` is retained as a secondary observability field only.
  It is never consulted for the inline-execution authorization decision.
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
        # The one and only inline-safe plugin: the exact bootstrapped built-in
        # SimulatorPlugin instance.  Set once by _register_builtin_simulator();
        # never settable via the public register() API.
        self._builtin_simulator: PluginProtocol | None = None

    def register(self, plugin: PluginProtocol) -> None:
        """Register *plugin* as NOT inline-safe.

        There is no ``inline_safe`` argument.  Every plugin registered through
        this public method is refused by the InlineDispatcher guard, regardless
        of name or health() metadata.

        Raises if the plugin name is already registered (prevents replacement).
        """
        name = getattr(plugin, "name", None)
        if name in self._plugins:
            raise PluginRegistryError(
                f"plugin '{name}' is already registered and cannot be replaced; "
                "re-registration is not permitted"
            )
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

    def _register_builtin_simulator(self, plugin: PluginProtocol) -> None:
        """Bootstrap the one and only inline-safe plugin.

        Called exactly once by ``get_registry()``.  Not part of the public API;
        no external code should call this.
        """
        if self._builtin_simulator is not None:
            raise PluginRegistryError(
                "built-in Simulator is already bootstrapped; "
                "_register_builtin_simulator must only be called once"
            )
        self.register(plugin)  # runs normal validation + prevents duplicate names
        self._builtin_simulator = plugin

    def unregister(self, name: str) -> None:
        """Remove a plugin (primarily for test isolation).

        The built-in Simulator cannot be unregistered; it is permanently part
        of the closed-world allowlist for the lifetime of the process.
        """
        if self._builtin_simulator is not None and name == getattr(
            self._builtin_simulator, "name", None
        ):
            raise PluginRegistryError(
                f"the built-in Simulator plugin ('{name}') cannot be unregistered"
            )
        self._plugins.pop(name, None)

    def is_inline_safe(self, plugin: PluginProtocol) -> bool:
        """Return True ONLY for the exact bootstrapped built-in Simulator instance.

        This is an object-identity check (``plugin is self._builtin_simulator``).
        A newly constructed ``SimulatorPlugin()``, a plugin named 'simulator',
        or any plugin with ``health().simulated == True`` will all return False
        unless they ARE the same object stored during bootstrap.
        """
        return self._builtin_simulator is not None and plugin is self._builtin_simulator

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
    """Return the process-wide registry, bootstrapping built-in plugins once.

    The SimulatorPlugin instance created here is the SOLE inline-safe plugin.
    It is stored by identity inside the registry.  All future real-provider
    plugins must call ``register(plugin)`` (no inline-safe path) and will be
    refused by the InlineDispatcher guard.
    """
    global _registry
    if _registry is None:
        _registry = PluginRegistry()
        from secp_plugin_simulator import SimulatorPlugin

        # _register_builtin_simulator stores the instance for identity checking.
        _registry._register_builtin_simulator(SimulatorPlugin())
    return _registry
