"""Proof #7 — generic topology migration preserves simulated-topology behavior.

Two angles:
1. Behavior: a simulator exercise still produces the same topology, now in the
   provider-neutral ``environment_*`` tables with honest provenance columns.
2. Data preservation: applying the rename migration over a database that already
   holds ``simulated_*`` rows preserves those rows under the new table names.
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine, text

from secp_api.models import EnvironmentNetwork, EnvironmentNode, EnvironmentTopologyEdge

API_DIR = Path(__file__).resolve().parents[1]


# --- behavior preserved -------------------------------------------------------

def test_simulator_writes_generic_provenance(session, principal, running_exercise):
    from secp_api.models import EnvironmentInstance

    exercise = running_exercise()
    instance = (
        session.query(EnvironmentInstance)
        .filter(EnvironmentInstance.exercise_id == exercise.id)
        .first()
    )
    nodes = (
        session.query(EnvironmentNode)
        .filter(EnvironmentNode.instance_id == instance.id)
        .all()
    )
    assert nodes, "simulator should still produce nodes"
    for n in nodes:
        assert n.provider == "simulator"
        assert n.source == "simulator"
        assert n.simulated is True
        assert n.provider_resource_type == "node"
        assert n.observed_at is not None
        assert n.provider_resource_id is None  # simulator has no external id

    nets = (
        session.query(EnvironmentNetwork)
        .filter(EnvironmentNetwork.instance_id == instance.id)
        .all()
    )
    assert nets and all(net.provider == "simulator" and net.simulated for net in nets)
    edges = (
        session.query(EnvironmentTopologyEdge)
        .filter(EnvironmentTopologyEdge.instance_id == instance.id)
        .all()
    )
    assert edges and all(e.simulated for e in edges)


def test_topology_projection_shape_unchanged(session, principal, running_exercise):
    from secp_api.services import topology

    exercise = running_exercise()
    topos = topology.exercise_topologies(session, principal, exercise.id)
    assert len(topos) == 2
    for t in topos:
        assert {"instance_id", "team_ref", "nodes", "edges"} <= set(t)
        # network + host nodes present, React-Flow node ids unchanged.
        assert any(n["type"] == "network" for n in t["nodes"])
        assert any(n["id"].startswith("node:") for n in t["nodes"])


# --- data preservation across the rename migration ----------------------------

def test_rename_migration_preserves_existing_rows(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config

    db_path = (tmp_path / "rename.db").as_posix()
    url = f"sqlite+pysqlite:///{db_path}"
    monkeypatch.setenv("SECP_DATABASE_URL", url)

    from secp_api.config import get_settings

    get_settings.cache_clear()
    cfg = Config(str(API_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(API_DIR / "migrations"))
    cfg.set_main_option("sqlalchemy.url", url)

    # 1. Upgrade only to the INITIAL revision (still simulator-named tables).
    command.upgrade(cfg, "09a75fd21cf8")

    # 2. Insert a simulated_node row (FK off on this raw engine), simulating data
    #    that exists before the rename.
    engine = create_engine(url, future=True)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO simulated_node "
                "(id, instance_id, ref, name, kind, role, image, network_ref, "
                " ip_address, status, provider, simulated, attributes, created_at) "
                "VALUES (:id, :iid, 'attacker', 'team1-attacker', 'attacker', "
                " 'attacker', 'kali-linux', 'team-network', '10.20.0.10', 'up', "
                " 'simulator', 1, '{}', :ts)"
            ),
            {
                "id": "11111111-1111-1111-1111-111111111111",
                "iid": "22222222-2222-2222-2222-222222222222",
                "ts": "2026-06-30T00:00:00+00:00",
            },
        )

    # 3. Upgrade to head (runs the rename migration).
    command.upgrade(cfg, "head")

    # 4. The row is preserved under the new table name, with generic defaults.
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT ref, provider, source, provider_resource_type "
                "FROM environment_node WHERE ref = 'attacker'"
            )
        ).all()
    engine.dispose()
    get_settings.cache_clear()

    assert len(rows) == 1
    ref, provider, source, prt = rows[0]
    assert ref == "attacker"
    assert provider == "simulator"
    assert source == "simulator"  # backfilled default
    assert prt == "node"          # backfilled default
