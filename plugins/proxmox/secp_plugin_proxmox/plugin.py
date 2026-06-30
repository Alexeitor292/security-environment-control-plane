"""Read-only Proxmox plugin implementation (SECP-002A).

Capabilities advertised: validate, health, discover, status. The mutating
capabilities (plan/apply/reset/destroy) exist only to satisfy the structural
``PluginProtocol`` and immediately raise ``UnsupportedCapabilityError`` — no
provider request is ever attempted for them.
"""

from __future__ import annotations

from collections.abc import Callable

from secp_plugin_api.v1 import (
    ApplyResult,
    Capability,
    DestroyResult,
    DiscoveredResource,
    DiscoveryRequest,
    DiscoveryResult,
    HealthReport,
    ObservedState,
    PluginContext,
    PluginPlan,
    ProviderCredential,
    ResetResult,
    TargetValidationResult,
    UnsupportedCapabilityError,
    ValidationResult,
)

from secp_plugin_proxmox.transport import HttpxReadOnlyTransport, ReadOnlyHttpTransport

PLUGIN_NAME = "proxmox"
PLUGIN_VERSION = "0.1.0"
CONTRACT_VERSION = "1"

# Transport factory: (config, token) -> ReadOnlyHttpTransport.
TransportFactory = Callable[[dict, str], ReadOnlyHttpTransport]


def _default_transport_factory(config: dict, token: str) -> ReadOnlyHttpTransport:
    return HttpxReadOnlyTransport(
        base_url=str(config["base_url"]),
        token=token,
        verify_tls=bool(config.get("verify_tls", True)),
    )


class ProxmoxPlugin:
    """Read-only Proxmox provider plugin (worker/plugin code only)."""

    name = PLUGIN_NAME
    version = PLUGIN_VERSION
    simulated = False

    def __init__(self, transport_factory: TransportFactory | None = None) -> None:
        self._transport_factory = transport_factory or _default_transport_factory

    # --- read-only capabilities ----------------------------------------------

    def health(self) -> HealthReport:
        return HealthReport(
            name=PLUGIN_NAME,
            version=PLUGIN_VERSION,
            contract_version=CONTRACT_VERSION,
            healthy=True,
            simulated=False,
            capabilities=[
                Capability.validate.value,
                Capability.health.value,
                Capability.discover.value,
                Capability.status.value,
            ],
            detail="Read-only Proxmox discovery. No provisioning in SECP-002A.",
        )

    def validate(self, spec: dict) -> ValidationResult:
        # SECP-002A: the Proxmox plugin only performs read-only discovery; there is
        # no provisioning spec to validate. Always ok (no provider request).
        return ValidationResult(ok=True)

    def validate_target(self, config: dict) -> TargetValidationResult:
        errors: list[str] = []
        base_url = config.get("base_url")
        if not isinstance(base_url, str) or not base_url.startswith(("http://", "https://")):
            errors.append("config.base_url must be an http(s) URL")
        if "verify_tls" in config and not isinstance(config["verify_tls"], bool):
            errors.append("config.verify_tls must be a boolean")
        return TargetValidationResult(
            ok=not errors,
            errors=errors,
            detail={"base_url": base_url} if isinstance(base_url, str) else {},
        )

    def status(self, instance_id: str, context: PluginContext) -> ObservedState:
        # Reads only from persisted data via the ResourcePort (no provider call).
        topo = context.resources.read_instance_topology(instance_id)
        return ObservedState(
            instance_id=instance_id,
            lifecycle_state="running" if topo.nodes else "unknown",
            nodes_total=len(topo.nodes),
            networks_total=len(topo.networks),
            topology=topo,
        )

    # --- discovery (read-only) -----------------------------------------------

    def discover(
        self, request: DiscoveryRequest, credential: ProviderCredential
    ) -> DiscoveryResult:
        transport = self._transport_factory(request.config, credential.secret)
        scope = request.scope or {}
        resources: list[DiscoveredResource] = []

        nodes = _as_list(transport.get("/nodes"))
        for node in nodes:
            node_name = str(node.get("node", ""))
            resources.append(
                DiscoveredResource(
                    resource_type="node",
                    provider_external_id=node_name,
                    display_name=node_name,
                    parent_ref="cluster",
                    status=str(node.get("status", "unknown")),
                    attributes=_safe_attrs(node, ("maxcpu", "maxmem", "level")),
                )
            )
            for kind, rtype in (("qemu", "vm"), ("lxc", "container")):
                for guest in _as_list(transport.get(f"/nodes/{node_name}/{kind}")):
                    vmid = str(guest.get("vmid", ""))
                    resources.append(
                        DiscoveredResource(
                            resource_type=rtype,
                            provider_external_id=f"{node_name}/{vmid}",
                            display_name=str(guest.get("name", vmid)),
                            parent_ref=node_name,
                            status=str(guest.get("status", "unknown")),
                            attributes=_safe_attrs(guest, ("cores", "maxmem", "template")),
                        )
                    )
            for store in _as_list(transport.get(f"/nodes/{node_name}/storage")):
                sid = str(store.get("storage", ""))
                resources.append(
                    DiscoveredResource(
                        resource_type="storage",
                        provider_external_id=f"{node_name}/{sid}",
                        display_name=sid,
                        parent_ref=node_name,
                        status=str(store.get("active", "unknown")),
                        attributes=_safe_attrs(store, ("type", "content", "total")),
                    )
                )

        resources = _apply_scope(resources, scope)
        summary = _summarize(resources)
        return DiscoveryResult(ok=True, resources=resources, summary=summary)

    # --- unsupported (mutating) capabilities — hard-fail before any request ---

    def plan(self, spec: dict, targets: list) -> PluginPlan:
        raise UnsupportedCapabilityError(PLUGIN_NAME, "plan")

    def apply(self, plan: PluginPlan, context: PluginContext) -> ApplyResult:
        raise UnsupportedCapabilityError(PLUGIN_NAME, "apply")

    def reset(self, plan: PluginPlan, instance_id: str, context: PluginContext) -> ResetResult:
        raise UnsupportedCapabilityError(PLUGIN_NAME, "reset")

    def destroy(self, instance_ids: list[str], context: PluginContext) -> DestroyResult:
        raise UnsupportedCapabilityError(PLUGIN_NAME, "destroy")


def _as_list(value: object) -> list[dict]:
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    return []


def _safe_attrs(row: dict, keys: tuple[str, ...]) -> dict:
    # Copy only a small, explicit set of non-sensitive fields.
    return {k: row[k] for k in keys if k in row}


def _apply_scope(resources: list[DiscoveredResource], scope: dict) -> list[DiscoveredResource]:
    allowed_types = set(scope.get("resource_types") or [])
    allowed_nodes = set(scope.get("nodes") or [])

    def keep(r: DiscoveredResource) -> bool:
        if allowed_types and r.resource_type not in allowed_types:
            return False
        if allowed_nodes:
            node = (
                r.provider_external_id.split("/")[0]
                if r.resource_type != "node"
                else r.provider_external_id
            )
            if node not in allowed_nodes:
                return False
        return True

    return [r for r in resources if keep(r)]


def _summarize(resources: list[DiscoveredResource]) -> dict:
    counts: dict[str, int] = {}
    for r in resources:
        counts[r.resource_type] = counts.get(r.resource_type, 0) + 1
    return {"total": len(resources), "by_type": counts}
