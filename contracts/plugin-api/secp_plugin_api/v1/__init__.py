"""Plugin contract — version 1.

A plugin exposes a capability surface. The control plane invokes *read-only*
capabilities (``validate``, ``plan``, ``status``, ``health``) directly, but
*side-effecting* capabilities (``apply``, ``reset``, ``destroy``) only through the
worker boundary (see ADR-003, ADR-005, Charter Invariants 6/7).

Plugins never import control-plane internals. Persistence happens through the
``ResourcePort`` handed to the plugin inside a ``PluginContext`` — so a plugin
depends only on this contract, not on the core database models.
"""

from secp_plugin_api.v1.contract import (
    Capability,
    PluginContext,
    PluginProtocol,
    ResourcePort,
)
from secp_plugin_api.v1.models import (
    ApplyResult,
    DestroyResult,
    HealthReport,
    InstancePlan,
    InstanceTopology,
    ObservedState,
    PluginPlan,
    ResetResult,
    TargetInstance,
    TopologyEdge,
    TopologyNetwork,
    TopologyNode,
    ValidationResult,
)

CONTRACT_VERSION = "1"

__all__ = [
    "CONTRACT_VERSION",
    "Capability",
    "PluginContext",
    "PluginProtocol",
    "ResourcePort",
    "ApplyResult",
    "DestroyResult",
    "HealthReport",
    "InstancePlan",
    "InstanceTopology",
    "ObservedState",
    "PluginPlan",
    "ResetResult",
    "TargetInstance",
    "TopologyEdge",
    "TopologyNetwork",
    "TopologyNode",
    "ValidationResult",
]
