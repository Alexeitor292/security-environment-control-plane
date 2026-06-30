"""Runtime safety guards for the control-plane execution boundary.

The ``InlineDispatcher`` (ADR-005) is a *development/test convenience* that runs
orchestration in-process. It is safe ONLY because the Simulator's side effects are
simulated database rows.

Closed-world inline-execution allowlist
----------------------------------------
Authorization for inline execution is a **registry-owned** decision, not a
plugin-owned one.  A plugin cannot grant its own inline-execution permission by
setting ``health().simulated = True``.  Only a plugin that was explicitly
registered with ``inline_safe=True`` by the trusted ``PluginRegistry`` (currently
only the built-in ``SimulatorPlugin``) may run inline.

``health().simulated`` is retained as a secondary **consistency check** and
observability field, but it is never the authorization control.

This makes it impossible for a future developer to accidentally drive a real
provider plugin (Proxmox, OpenTofu, Ansible, …) inline even if they copy the
Simulator's ``health()`` signature.

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

    Call this immediately before any inline (in-process) plugin side effect, with
    the plugin that is about to run.

    Authorization logic (in order):

    1. Refuse if ``APP_ENV=production`` — inline execution is never permitted in
       production regardless of the plugin.
    2. Refuse if the plugin is NOT in the registry's closed-world inline-safe
       allowlist — self-reported ``health().simulated`` is ignored for this check.
    3. (Secondary consistency) Warn if a registry-approved plugin unexpectedly
       reports ``simulated=false`` (should never happen for the Simulator, but
       would indicate a mis-configuration worth logging).
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

    # Guard 2: closed-world registry allowlist — authoritative check.
    from secp_api.registry import get_registry

    if not get_registry().is_inline_safe(plugin_name):
        message = (
            f"plugin '{plugin_name}' is not in the inline-execution allowlist; "
            "only the built-in Simulator Plugin may run inline. "
            "Real provider plugins must use the worker/Temporal execution path. "
            "Plugin self-reported health().simulated is not authoritative for this decision."
        )
        logger.error("REFUSED inline execution (plugin=%s): %s", plugin_name, message)
        raise InlineExecutionForbidden(message)

    # Secondary consistency check (non-blocking, but worth logging).
    health = plugin.health()
    if not getattr(health, "simulated", False):
        logger.warning(
            "plugin '%s' is registry-approved for inline execution but reports "
            "simulated=false — this is a configuration inconsistency",
            plugin_name,
        )
