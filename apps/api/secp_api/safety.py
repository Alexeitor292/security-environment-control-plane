"""Runtime safety guards for the control-plane execution boundary.

The ``InlineDispatcher`` (ADR-005) is a *development/test convenience* that runs
orchestration in-process. It is safe ONLY because the Simulator's side effects are
simulated database rows. These guards make it impossible for a future developer to
accidentally drive a real provider plugin (Proxmox, OpenTofu, Ansible, …) inline:

* inline execution is forbidden when ``APP_ENV=production``; and
* inline execution is forbidden for any plugin whose ``health().simulated`` is not
  ``True`` — real plugins MUST run through the worker / Temporal path.

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
    """Guard the inline execution path. Raises :class:`InlineExecutionForbidden`.

    Call this immediately before any inline (in-process) plugin side effect, with
    the plugin that is about to run.
    """
    settings = settings or get_settings()
    plugin_name = getattr(plugin, "name", "<unknown>")

    if settings.is_production:
        message = (
            "inline dispatcher is forbidden when APP_ENV=production; "
            "use the worker/Temporal execution path"
        )
        logger.error("REFUSED inline execution (plugin=%s): %s", plugin_name, message)
        raise InlineExecutionForbidden(message)

    health = plugin.health()
    if not getattr(health, "simulated", False):
        message = (
            f"plugin '{plugin_name}' does not declare simulated=true; inline "
            "execution is permitted only for the Simulator. Real provider plugins "
            "must run through the worker/Temporal path."
        )
        logger.error("REFUSED inline execution (plugin=%s): %s", plugin_name, message)
        raise InlineExecutionForbidden(message)
