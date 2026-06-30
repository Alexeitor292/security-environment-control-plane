"""Provider-neutral data models exchanged across the plugin contract (v1).

These types are deliberately free of any vendor or core-database concept. They
describe *desired topology* (what a plugin should realise) and *observed state*
(what it reports back), in normalized terms that any provider can map onto.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class NodeKind(str, Enum):
    attacker = "attacker"
    target = "target"
    sensor = "sensor"
    service = "service"
    gateway = "gateway"


class EdgeKind(str, Enum):
    network = "network"  # node attached to a network
    monitors = "monitors"  # sensor observes a node/network
    reaches = "reaches"  # declared reachability (intra-instance only)


# --- Desired topology (produced by plan, realised by apply) -------------------


class TopologyNetwork(BaseModel):
    """A simulated/observed network segment within one environment instance."""

    ref: str = Field(description="Stable per-instance reference, e.g. 'team-network'.")
    name: str
    cidr: str
    team_ref: str | None = None
    isolated: bool = True


class TopologyNode(BaseModel):
    """A simulated/observed host within one environment instance."""

    ref: str
    name: str
    kind: NodeKind
    role: str
    image: str
    network_ref: str
    ip_address: str
    attributes: dict[str, str] = Field(default_factory=dict)


class TopologyEdge(BaseModel):
    """A relationship between two topology elements, scoped to one instance."""

    source_ref: str
    target_ref: str
    kind: EdgeKind


class InstanceTopology(BaseModel):
    """The full normalized topology for a single environment instance."""

    networks: list[TopologyNetwork] = Field(default_factory=list)
    nodes: list[TopologyNode] = Field(default_factory=list)
    edges: list[TopologyEdge] = Field(default_factory=list)


# --- Plan ---------------------------------------------------------------------


class TargetInstance(BaseModel):
    """A control-plane instance the plan should target (one per team)."""

    instance_id: str
    instance_ref: str
    team_ref: str
    team_index: int


class InstancePlan(BaseModel):
    instance_id: str
    instance_ref: str
    team_ref: str
    desired: InstanceTopology
    summary: dict[str, int] = Field(default_factory=dict)


class PluginPlan(BaseModel):
    """Deterministic plan: same version + targets always yields the same plan."""

    plugin: str
    contract_version: str
    instances: list[InstancePlan] = Field(default_factory=list)

    @property
    def total_nodes(self) -> int:
        return sum(len(i.desired.nodes) for i in self.instances)

    @property
    def total_networks(self) -> int:
        return sum(len(i.desired.networks) for i in self.instances)


# --- Capability results -------------------------------------------------------


class ValidationResult(BaseModel):
    ok: bool
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class ApplyResult(BaseModel):
    ok: bool
    instances_applied: list[str] = Field(default_factory=list)
    created: dict[str, int] = Field(default_factory=dict)
    message: str = ""


class ResetResult(BaseModel):
    ok: bool
    instance_id: str
    idempotent_noop: bool = False
    message: str = ""


class DestroyResult(BaseModel):
    ok: bool
    instances_destroyed: list[str] = Field(default_factory=list)
    idempotent_noop: bool = False
    message: str = ""


class ObservedState(BaseModel):
    instance_id: str
    lifecycle_state: str
    nodes_total: int = 0
    nodes_up: int = 0
    networks_total: int = 0
    topology: InstanceTopology = Field(default_factory=InstanceTopology)


class HealthReport(BaseModel):
    name: str
    version: str
    contract_version: str
    healthy: bool
    capabilities: list[str] = Field(default_factory=list)
    simulated: bool = False
    detail: str = ""
