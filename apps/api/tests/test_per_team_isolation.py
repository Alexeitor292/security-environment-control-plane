"""AC6.3 — per-team isolation: each team gets its own isolated instance (design §8)."""

from __future__ import annotations

from secp_api.models import (
    EnvironmentInstance,
    SimulatedNetwork,
    SimulatedNode,
    SimulatedTopologyEdge,
)


def _instances(session, exercise_id):
    return (
        session.query(EnvironmentInstance)
        .filter(EnvironmentInstance.exercise_id == exercise_id)
        .order_by(EnvironmentInstance.team_index)
        .all()
    )


def test_each_team_has_its_own_instance(session, principal, running_exercise):
    exercise = running_exercise()
    instances = _instances(session, exercise.id)
    assert len(instances) == 2
    assert {i.team_index for i in instances} == {0, 1}


def test_team_networks_have_disjoint_cidrs(session, principal, running_exercise):
    exercise = running_exercise()
    instances = _instances(session, exercise.id)
    cidrs_per_team = []
    for inst in instances:
        cidrs = {
            n.cidr
            for n in session.query(SimulatedNetwork).filter(SimulatedNetwork.instance_id == inst.id)
        }
        cidrs_per_team.append(cidrs)
    # Strict isolation => no shared subnet between the two teams.
    assert cidrs_per_team[0].isdisjoint(cidrs_per_team[1])


def test_team_node_ips_are_disjoint(session, principal, running_exercise):
    exercise = running_exercise()
    instances = _instances(session, exercise.id)
    ips = []
    for inst in instances:
        ips.append(
            {
                n.ip_address
                for n in session.query(SimulatedNode).filter(SimulatedNode.instance_id == inst.id)
            }
        )
    assert ips[0].isdisjoint(ips[1])


def test_no_cross_instance_topology_edges(session, principal, running_exercise):
    exercise = running_exercise()
    instances = _instances(session, exercise.id)
    instance_ids = {i.id for i in instances}
    # Every edge belongs to exactly one instance; refs never cross instances
    # because each instance's topology is built and stored independently.
    for inst in instances:
        node_refs = {
            n.ref for n in session.query(SimulatedNode).filter(SimulatedNode.instance_id == inst.id)
        }
        net_refs = {
            n.ref
            for n in session.query(SimulatedNetwork).filter(SimulatedNetwork.instance_id == inst.id)
        }
        edges = session.query(SimulatedTopologyEdge).filter(
            SimulatedTopologyEdge.instance_id == inst.id
        )
        for edge in edges:
            assert edge.source_ref in (node_refs | net_refs)
            assert edge.target_ref in (node_refs | net_refs)
    assert len(instance_ids) == 2


def test_topology_projection_is_per_team(session, principal, running_exercise):
    from secp_api.services import topology

    exercise = running_exercise()
    topos = topology.exercise_topologies(session, principal, exercise.id)
    assert len(topos) == 2
    # Each projection references exactly one instance id.
    assert topos[0]["instance_id"] != topos[1]["instance_id"]
    assert topos[0]["team_ref"] != topos[1]["team_ref"]
