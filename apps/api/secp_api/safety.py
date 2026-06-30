"""Runtime safety guards for the control-plane execution boundary.

The ``InlineDispatcher`` (ADR-005) is a *development/test convenience* that runs
orchestration in-process. It is safe ONLY because the Simulator's side effects are
simulated database rows.

Closed-world inline-execution allowlist — identity-based
---------------------------------------------------------
Authorization for inline execution is a **registry-owned, identity-based**
decision.

* A plugin cannot self-authorize by setting ``health().simulated = True``.
* The public ``register()`` API never grants inline-execution permission — there
  is no ``inline_safe`` argument for external callers.
* ``PluginRegistry.is_inline_safe(plugin)`` performs a Python ``is`` identity
  check against the exact ``SimulatorPlugin`` instance created during registry
  bootstrap.  A newly constructed ``SimulatorPlugin()``, a plugin named
  'simulator', or any plugin reporting ``simulated=True`` all fail unless they
  ARE the bootstrapped instance.

This makes it impossible for a future developer to accidentally or intentionally
drive a real provider plugin (Proxmox, OpenTofu, Ansible, …) inline:
no public API path grants the permission; only the bootstrap does.

``health().simulated`` is retained as a secondary observability / consistency
field; it is never the authorization control.

Refusals are explicit, logged, and (at the service layer) audited.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from secp_api.config import Settings, get_settings
from secp_api.errors import DomainError

if TYPE_CHECKING:  # avoid importing the contract at runtime here
    from secp_plugin_api.v1 import PluginProtocol

logger = logging.getLogger("secp.safety")


class InlineExecutionForbidden(DomainError):
    """Raised when inline execution is attempted in a prohibited situation."""

    http_status = 403
    code = "inline_execution_forbidden"


def assert_inline_execution_allowed(
    plugin: PluginProtocol, *, settings: Settings | None = None
) -> None:
    """Guard the inline execution path.  Raises :class:`InlineExecutionForbidden`.

    Call this immediately before any inline (in-process) plugin side effect,
    passing the plugin instance exactly as retrieved from the registry (so the
    identity check is meaningful).

    Authorization logic (in order):

    1. Refuse if ``APP_ENV=production`` — inline execution is never permitted in
       production regardless of the plugin.
    2. Refuse unless the plugin IS the registry's bootstrapped built-in Simulator
       instance (identity check via ``registry.is_inline_safe(plugin)``).
       Name matching and ``health().simulated`` are both ignored here.
    3. (Secondary consistency) Warn if the approved plugin reports
       ``simulated=false`` — should never happen for the Simulator, but would
       indicate a misconfiguration.
    """
    settings = settings or get_settings()
    plugin_name = getattr(plugin, "name", "<unknown>")

    # Guard 1: production is always refused.
    if settings.is_production:
        message = (
            "inline dispatcher is forbidden when APP_ENV=production; "
            "use the worker/Temporal execution path"
        )
        logger.error("REFUSED inline execution (plugin=%s): %s", plugin_name, message)
        raise InlineExecutionForbidden(message)

    # Guard 2: identity-based registry check — authoritative.
    from secp_api.registry import get_registry

    if not get_registry().is_inline_safe(plugin):
        message = (
            f"plugin '{plugin_name}' is not the built-in Simulator; "
            "inline execution is only permitted for the exact bootstrapped "
            "SimulatorPlugin instance held by the registry. "
            "Real provider plugins must use the worker/Temporal execution path."
        )
        logger.error("REFUSED inline execution (plugin=%s): %s", plugin_name, message)
        raise InlineExecutionForbidden(message)

    # Secondary consistency check (non-blocking, but worth logging).
    health = plugin.health()
    if not getattr(health, "simulated", False):
        logger.warning(
            "plugin '%s' is the bootstrapped inline-safe Simulator but reports "
            "simulated=false — this is a configuration inconsistency",
            plugin_name,
        )
