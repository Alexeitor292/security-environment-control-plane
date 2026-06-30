"""Worker-side provider discovery execution (ADR-007, ADR-010).

This runs ONLY in the worker. It resolves the target's secret reference
just-in-time, invokes the provider plugin's read-only discovery, and persists an
immutable snapshot. Secrets are never persisted, logged, or echoed; errors are
redacted. No real endpoint is contacted in SECP-002A (tests inject fakes).
"""

from __future__ import annotations

import uuid

from secp_api import audit
from secp_api.enums import AuditAction
from secp_api.errors import NotFoundError
from secp_api.models import ExecutionTarget, ProviderInventorySnapshot
from secp_api.services import inventory
from secp_plugin_api.v1 import DiscoveryRequest

from secp_worker.secrets import SecretResolutionError, SecretResolver


def build_provider_plugin(plugin_name: str):
    """Construct a discovery-capable provider plugin (worker-only import).

    When ``SECP_PROVIDER_MOCK=1`` the Proxmox plugin uses a mock transport that
    returns canned inventory and contacts no network — for verifying the Temporal
    discovery path without any real endpoint. Never enabled in production.
    """
    import os

    if plugin_name == "proxmox":
        from secp_plugin_proxmox import ProxmoxPlugin

        if os.environ.get("SECP_PROVIDER_MOCK") == "1":
            from secp_plugin_proxmox.mock import mock_transport_factory

            return ProxmoxPlugin(transport_factory=mock_transport_factory)
        return ProxmoxPlugin()
    raise ValueError(f"no discovery provider plugin for '{plugin_name}'")


def run_discovery(
    session,
    snapshot_id: uuid.UUID,
    *,
    plugin,
    resolver: SecretResolver,
) -> ProviderInventorySnapshot:
    """Execute a queued discovery snapshot. Returns the finalized snapshot."""
    snap = session.get(ProviderInventorySnapshot, snapshot_id)
    if snap is None:
        raise NotFoundError(f"snapshot {snapshot_id} not found")
    target = session.get(ExecutionTarget, snap.execution_target_id)
    if target is None:
        raise NotFoundError("execution target not found for snapshot")

    inventory.mark_running(session, snap.id)

    try:
        if not target.secret_ref:
            raise SecretResolutionError("target has no secret reference configured")
        credential = resolver.resolve(target.secret_ref)  # worker-only, just-in-time
        request = DiscoveryRequest(
            target_id=str(target.id),
            plugin_name=target.plugin_name,
            config=dict(target.config),
            scope=dict(target.scope_policy) if target.scope_policy else None,
            correlation_id=str(snap.id),
        )
        result = plugin.discover(request, credential)
        if not result.ok:
            raise RuntimeError("provider discovery returned validation errors")
        inventory.complete_snapshot(
            session,
            snap.id,
            resources=[r.model_dump() for r in result.resources],
            summary=result.summary,
            plugin_version=getattr(plugin, "version", ""),
        )
    except SecretResolutionError:
        # Redacted: record the failure without any secret detail.
        audit.record(
            session,
            action=AuditAction.secret_resolution_failed,
            resource_type="execution_target",
            resource_id=target.id,
            organization_id=snap.organization_id,
            actor="worker",
            outcome="failed",
            data={"reason": "secret reference could not be resolved"},
        )
        inventory.fail_snapshot(session, snap.id, error="secret resolution failed (redacted)")
    except Exception as exc:  # provider/normalization error — redacted
        inventory.fail_snapshot(session, snap.id, error=f"discovery failed: {type(exc).__name__}")
    return snap
