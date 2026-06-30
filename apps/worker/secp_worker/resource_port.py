"""SQLAlchemy-backed implementation of the plugin contract's ResourcePort.

This adapter is the *only* place a plugin's topology output meets the control-
plane database. Plugins themselves never import these models (ADR-003). It writes
the provider-neutral ``environment_*`` projection tables (ADR-008).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from secp_api.models import EnvironmentNetwork, EnvironmentNode, EnvironmentTopologyEdge
from secp_plugin_api.v1 import InstanceTopology
from secp_plugin_api.v1.models import TopologyEdge, TopologyNetwork, TopologyNode
from sqlalchemy import delete, select
from sqlalchemy.orm import Session


def _as_uuid(value: str | uuid.UUID) -> uuid.UUID:
    return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))


def _utcnow() -> datetime:
    return datetime.now(UTC)


class SqlAlchemyResourcePort:
    def __init__(
        self, session: Session, provider: str = "simulator", simulated: bool = True
    ) -> None:
        self.session = session
        self.provider = provider
        # Provenance: the Simulator marks rows simulated=true. Real providers pass
        # simulated=false. Never a provider-specific column — pure provenance.
        self.simulated = simulated

    def replace_instance_topology(self, instance_id: str, topology: InstanceTopology) -> None:
        iid = _as_uuid(instance_id)
        self.clear_instance_topology(instance_id)
        now = _utcnow()
        for net in topology.networks:
            self.session.add(
                EnvironmentNetwork(
                    instance_id=iid,
                    ref=net.ref,
                    name=net.name,
                    cidr=net.cidr,
                    team_ref=net.team_ref,
                    isolated=net.isolated,
                    status="up",
                    provider=self.provider,
                    provider_resource_type="network",
                    source=self.provider,
                    simulated=self.simulated,
                    observed_at=now,
                )
            )
        for node in topology.nodes:
            self.session.add(
                EnvironmentNode(
                    instance_id=iid,
                    ref=node.ref,
                    name=node.name,
                    kind=node.kind.value,
                    role=node.role,
                    image=node.image,
                    network_ref=node.network_ref,
                    ip_address=node.ip_address,
                    status="up",
                    provider=self.provider,
                    provider_resource_type="node",
                    source=self.provider,
                    simulated=self.simulated,
                    observed_at=now,
                    attributes=dict(node.attributes),
                )
            )
        for edge in topology.edges:
            self.session.add(
                EnvironmentTopologyEdge(
                    instance_id=iid,
                    source_ref=edge.source_ref,
                    target_ref=edge.target_ref,
                    kind=edge.kind.value,
                    provider=self.provider,
                    source=self.provider,
                    simulated=self.simulated,
                )
            )
        self.session.flush()

    def clear_instance_topology(self, instance_id: str) -> None:
        iid = _as_uuid(instance_id)
        for model in (EnvironmentTopologyEdge, EnvironmentNode, EnvironmentNetwork):
            self.session.execute(delete(model).where(model.instance_id == iid))
        self.session.flush()

    def read_instance_topology(self, instance_id: str) -> InstanceTopology:
        iid = _as_uuid(instance_id)
        networks = (
            self.session.execute(
                select(EnvironmentNetwork)
                .where(EnvironmentNetwork.instance_id == iid)
                .order_by(EnvironmentNetwork.ref)
            )
            .scalars()
            .all()
        )
        nodes = (
            self.session.execute(
                select(EnvironmentNode)
                .where(EnvironmentNode.instance_id == iid)
                .order_by(EnvironmentNode.ref)
            )
            .scalars()
            .all()
        )
        edges = (
            self.session.execute(
                select(EnvironmentTopologyEdge)
                .where(EnvironmentTopologyEdge.instance_id == iid)
                .order_by(EnvironmentTopologyEdge.source_ref, EnvironmentTopologyEdge.target_ref)
            )
            .scalars()
            .all()
        )
        return InstanceTopology(
            networks=[
                TopologyNetwork(
                    ref=n.ref,
                    name=n.name,
                    cidr=n.cidr,
                    team_ref=n.team_ref,
                    isolated=n.isolated,
                )
                for n in networks
            ],
            nodes=[
                TopologyNode(
                    ref=n.ref,
                    name=n.name,
                    kind=n.kind,
                    role=n.role,
                    image=n.image,
                    network_ref=n.network_ref,
                    ip_address=n.ip_address,
                    attributes=dict(n.attributes or {}),
                )
                for n in nodes
            ],
            edges=[
                TopologyEdge(source_ref=e.source_ref, target_ref=e.target_ref, kind=e.kind)
                for e in edges
            ],
        )
