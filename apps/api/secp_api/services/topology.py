"""Topology projection and audit-log read services.

The topology is a live operational projection (Charter §8, §14), computed by
joining declared intent with simulated inventory. Output is shaped for direct
consumption by React Flow. Per-team views are filtered to a single instance, which
is the data-isolation boundary in SECP-001 (design §8).
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from secp_api.auth import Principal
from secp_api.enums import Permission
from secp_api.errors import NotFoundError
from secp_api.models import (
    AuditEvent,
    EnvironmentInstance,
    EnvironmentNetwork,
    EnvironmentNode,
    EnvironmentTopologyEdge,
)
from secp_api.services.exercises import get_exercise


def _get_instance(
    session: Session, actor: Principal, instance_id: uuid.UUID
) -> EnvironmentInstance:
    instance = session.get(EnvironmentInstance, instance_id)
    if instance is None:
        raise NotFoundError(f"instance {instance_id} not found")
    actor.require_org(instance.organization_id)
    return instance


def instance_topology(session: Session, actor: Principal, instance_id: uuid.UUID) -> dict:
    """Return a React-Flow-shaped graph for one team's instance only."""
    instance = _get_instance(session, actor, instance_id)

    networks = (
        session.execute(
            select(EnvironmentNetwork)
            .where(EnvironmentNetwork.instance_id == instance.id)
            .order_by(EnvironmentNetwork.ref)
        )
        .scalars()
        .all()
    )
    nodes = (
        session.execute(
            select(EnvironmentNode)
            .where(EnvironmentNode.instance_id == instance.id)
            .order_by(EnvironmentNode.ref)
        )
        .scalars()
        .all()
    )
    edges = (
        session.execute(
            select(EnvironmentTopologyEdge)
            .where(EnvironmentTopologyEdge.instance_id == instance.id)
            .order_by(EnvironmentTopologyEdge.source_ref)
        )
        .scalars()
        .all()
    )

    flow_nodes = []
    for net in networks:
        flow_nodes.append(
            {
                "id": f"net:{net.ref}",
                "type": "network",
                "data": {
                    "label": net.name,
                    "cidr": net.cidr,
                    "isolated": net.isolated,
                    "kind": "network",
                },
            }
        )
    for node in nodes:
        flow_nodes.append(
            {
                "id": f"node:{node.ref}",
                "type": node.kind,
                "data": {
                    "label": node.name,
                    "role": node.role,
                    "kind": node.kind,
                    "image": node.image,
                    "ip": node.ip_address,
                    "status": node.status,
                    "network": node.network_ref,
                },
            }
        )

    flow_edges = []
    for i, edge in enumerate(edges):
        src = f"node:{edge.source_ref}"
        # network edges point node -> network; monitors/reaches point node -> node.
        tgt = f"net:{edge.target_ref}" if edge.kind == "network" else f"node:{edge.target_ref}"
        flow_edges.append(
            {
                "id": f"edge:{i}:{edge.source_ref}->{edge.target_ref}",
                "source": src,
                "target": tgt,
                "label": edge.kind,
                "data": {"kind": edge.kind},
            }
        )

    return {
        "instance_id": str(instance.id),
        "team_ref": instance.team_ref,
        "team_index": instance.team_index,
        "lifecycle_state": instance.lifecycle_state.value
        if hasattr(instance.lifecycle_state, "value")
        else instance.lifecycle_state,
        "nodes": flow_nodes,
        "edges": flow_edges,
    }


def exercise_topologies(session: Session, actor: Principal, exercise_id: uuid.UUID) -> list[dict]:
    """Per-team topologies for an exercise, one isolated graph per team."""
    exercise = get_exercise(session, actor, exercise_id)
    instances = (
        session.execute(
            select(EnvironmentInstance)
            .where(EnvironmentInstance.exercise_id == exercise.id)
            .order_by(EnvironmentInstance.team_index)
        )
        .scalars()
        .all()
    )
    return [instance_topology(session, actor, inst.id) for inst in instances]


def list_audit_events(
    session: Session,
    actor: Principal,
    *,
    exercise_id: uuid.UUID | None = None,
    limit: int = 200,
) -> list[AuditEvent]:
    actor.require(Permission.audit_read)
    stmt = (
        select(AuditEvent)
        .where(AuditEvent.organization_id == actor.organization_id)
        .order_by(AuditEvent.created_at.desc())
        .limit(limit)
    )
    events = list(session.execute(stmt).scalars().all())
    if exercise_id is not None:
        # Include events directly about the exercise plus its child resources.
        child_ids = _exercise_resource_ids(session, exercise_id)
        events = [
            e
            for e in events
            if e.resource_id in child_ids or str(exercise_id) == (e.resource_id or "")
        ]
    return events


def _exercise_resource_ids(session: Session, exercise_id: uuid.UUID) -> set[str]:
    ids = {str(exercise_id)}
    instances = (
        session.execute(
            select(EnvironmentInstance.id).where(EnvironmentInstance.exercise_id == exercise_id)
        )
        .scalars()
        .all()
    )
    ids.update(str(i) for i in instances)
    from secp_api.models import DeploymentPlan, WorkflowRun

    for model in (DeploymentPlan, WorkflowRun):
        rows = (
            session.execute(select(model.id).where(model.exercise_id == exercise_id))
            .scalars()
            .all()
        )
        ids.update(str(r) for r in rows)
    return ids
