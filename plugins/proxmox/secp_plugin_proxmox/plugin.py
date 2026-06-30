"""Read-only Proxmox plugin implementation (SECP-002A).

Capabilities advertised: validate, health, discover, status. The mutating
capabilities (plan/apply/reset/destroy) exist only to satisfy the structural
``PluginProtocol`` and immediately raise ``UnsupportedCapabilityError`` before
any provider request can be attempted.
"""

from __future__ import annotations

from collections.abc import Callable
from urllib.parse import urlparse

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

TransportFactory = Callable[[dict, str], ReadOnlyHttpTransport]
CONFIG_KEYS = frozenset({"base_url", "verify_tls"})
SCOPE_KEYS = frozenset({"resource_types", "nodes"})
RESOURCE_TYPES = frozenset({"node", "vm", "container", "storage", "network"})


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
        return ValidationResult(ok=True)

    def validate_target(
        self, config: dict, scope_policy: dict | None = None
    ) -> TargetValidationResult:
        return _validate_target_config(config, scope_policy)

    def status(self, instance_id: str, context: PluginContext) -> ObservedState:
        topo = context.resources.read_instance_topology(instance_id)
        return ObservedState(
            instance_id=instance_id,
            lifecycle_state="running" if topo.nodes else "unknown",
            nodes_total=len(topo.nodes),
            networks_total=len(topo.networks),
            topology=topo,
        )

    def discover(
        self, request: DiscoveryRequest, credential: ProviderCredential
    ) -> DiscoveryResult:
        validation = self.validate_target(request.config, request.scope)
        if not validation.ok:
            return DiscoveryResult(ok=False, errors=validation.errors)

        transport = self._transport_factory(request.config, credential.reveal_secret())
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
        return DiscoveryResult(ok=True, resources=resources, summary=_summarize(resources))

    def plan(self, spec: dict, targets: list) -> PluginPlan:
        raise UnsupportedCapabilityError(PLUGIN_NAME, "plan")

    def apply(self, plan: PluginPlan, context: PluginContext) -> ApplyResult:
        raise UnsupportedCapabilityError(PLUGIN_NAME, "apply")

    def reset(self, plan: PluginPlan, instance_id: str, context: PluginContext) -> ResetResult:
        raise UnsupportedCapabilityError(PLUGIN_NAME, "reset")

    def destroy(self, instance_ids: list[str], context: PluginContext) -> DestroyResult:
        raise UnsupportedCapabilityError(PLUGIN_NAME, "destroy")


def _validate_target_config(
    config: dict, scope_policy: dict | None = None
) -> TargetValidationResult:
    if not isinstance(config, dict):
        return TargetValidationResult(ok=False, errors=["config must be an object"])

    errors: list[str] = []
    unsupported = sorted(set(config) - CONFIG_KEYS)
    if unsupported:
        errors.append(f"unsupported Proxmox config keys: {', '.join(unsupported)}")

    base_url = config.get("base_url")
    if not isinstance(base_url, str):
        errors.append("config.base_url must be an https:// URL")
    else:
        parsed = urlparse(base_url)
        if parsed.scheme != "https" or not parsed.netloc:
            errors.append("config.base_url must use https:// and include a host")

    verify_tls = config.get("verify_tls", True)
    if not isinstance(verify_tls, bool):
        errors.append("config.verify_tls must be a boolean")
    elif verify_tls is not True:
        errors.append("config.verify_tls=false is not allowed for Proxmox targets")

    errors.extend(_validate_scope_policy(scope_policy))
    return TargetValidationResult(
        ok=not errors,
        errors=errors,
        detail={"base_url": base_url} if isinstance(base_url, str) else {},
    )


def _validate_scope_policy(scope_policy: dict | None) -> list[str]:
    if scope_policy in (None, {}):
        return []
    if not isinstance(scope_policy, dict):
        return ["scope_policy must be an object"]

    errors: list[str] = []
    unsupported = sorted(set(scope_policy) - SCOPE_KEYS)
    if unsupported:
        errors.append(f"unsupported Proxmox scope_policy keys: {', '.join(unsupported)}")

    resource_types = scope_policy.get("resource_types")
    if resource_types is not None:
        if not isinstance(resource_types, list) or not all(
            isinstance(v, str) for v in resource_types
        ):
            errors.append("scope_policy.resource_types must be a list of strings")
        else:
            unknown = sorted(set(resource_types) - RESOURCE_TYPES)
            if unknown:
                errors.append(
                    "scope_policy.resource_types contains unsupported values: " + ", ".join(unknown)
                )

    nodes = scope_policy.get("nodes")
    if nodes is not None and (
        not isinstance(nodes, list) or not all(isinstance(v, str) and v for v in nodes)
    ):
        errors.append("scope_policy.nodes must be a list of non-empty strings")

    return errors


def _as_list(value: object) -> list[dict]:
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    return []


def _safe_attrs(row: dict, keys: tuple[str, ...]) -> dict:
    return {k: row[k] for k in keys if k in row}


def _apply_scope(resources: list[DiscoveredResource], scope: dict) -> list[DiscoveredResource]:
    allowed_types = set(scope.get("resource_types") or [])
    allowed_nodes = set(scope.get("nodes") or [])

    def keep(resource: DiscoveredResource) -> bool:
        if allowed_types and resource.resource_type not in allowed_types:
            return False
        if allowed_nodes:
            node = (
                resource.provider_external_id.split("/")[0]
                if resource.resource_type != "node"
                else resource.provider_external_id
            )
            if node not in allowed_nodes:
                return False
        return True

    return [resource for resource in resources if keep(resource)]


def _summarize(resources: list[DiscoveredResource]) -> dict:
    counts: dict[str, int] = {}
    for resource in resources:
        counts[resource.resource_type] = counts.get(resource.resource_type, 0) + 1
    return {"total": len(resources), "by_type": counts}
