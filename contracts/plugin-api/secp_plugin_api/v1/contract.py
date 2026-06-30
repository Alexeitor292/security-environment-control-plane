"""The plugin capability contract (v1) and the persistence port plugins use.

A plugin implements :class:`PluginProtocol`. It receives a :class:`PluginContext`
on side-effecting calls; the context carries a :class:`ResourcePort` that the
plugin uses to persist/read simulated (or, for real plugins, observed) topology.
This keeps plugins decoupled from the control-plane database (Charter Invariant 9,
ADR-003).
"""

from __future__ import annotations

from enum import Enum
from typing import Protocol, runtime_checkable

from secp_plugin_api.v1.models import (
    ApplyResult,
    DestroyResult,
    HealthReport,
    InstanceTopology,
    ObservedState,
    PluginPlan,
    ResetResult,
    TargetInstance,
    ValidationResult,
)


class Capability(str, Enum):
    """Capabilities a plugin may advertise via ``health()``.

    The control plane checks capability support before dispatching an operation,
    so a partial plugin degrades gracefully (ADR-003).
    """

    validate = "validate"
    plan = "plan"
    apply = "apply"
    status = "status"
    reset = "reset"
    destroy = "destroy"
    health = "health"
    # Reserved / future (Charter §11) — declared but not required in v1.
    reconcile = "reconcile"
    discover = "discover"
    collect_artifacts = "collect-artifacts"


@runtime_checkable
class ResourcePort(Protocol):
    """Persistence port handed to a plugin for an instance's topology.

    Implemented by the worker/orchestration layer (backed by the control-plane
    database). Plugins must use only this interface to read/write resources, so
    they never import core models.
    """

    def replace_instance_topology(self, instance_id: str, topology: InstanceTopology) -> None:
        """Idempotently set an instance's full topology to ``topology``."""
        ...

    def clear_instance_topology(self, instance_id: str) -> None:
        """Remove all simulated resources for an instance (idempotent)."""
        ...

    def read_instance_topology(self, instance_id: str) -> InstanceTopology:
        """Read back the currently-persisted topology for an instance."""
        ...


class PluginContext:
    """Execution context passed to side-effecting plugin methods.

    Carries the persistence port plus opaque, secure-reference configuration
    (never plaintext secrets — Charter §11). Kept as a concrete, simple class so
    plugins and the worker share one shape.
    """

    def __init__(
        self,
        resources: ResourcePort,
        *,
        config: dict[str, str] | None = None,
        correlation_id: str | None = None,
    ) -> None:
        self.resources = resources
        self.config = config or {}
        self.correlation_id = correlation_id


@runtime_checkable
class PluginProtocol(Protocol):
    """The contract every integration implements (v1).

    Read-only capabilities (``validate``, ``plan``, ``status``, ``health``) may be
    invoked by the control-plane API. Side-effecting capabilities (``apply``,
    ``reset``, ``destroy``) must only be invoked through the worker boundary.
    """

    name: str
    version: str
    simulated: bool

    def health(self) -> HealthReport: ...

    def validate(self, spec: dict) -> ValidationResult: ...

    def plan(self, spec: dict, targets: list[TargetInstance]) -> PluginPlan: ...

    def apply(self, plan: PluginPlan, context: PluginContext) -> ApplyResult: ...

    def status(self, instance_id: str, context: PluginContext) -> ObservedState: ...

    def reset(self, plan: PluginPlan, instance_id: str, context: PluginContext) -> ResetResult: ...

    def destroy(self, instance_ids: list[str], context: PluginContext) -> DestroyResult: ...
