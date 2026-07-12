"""Migration tests for SECP-B10 / ADR-016 PR B (revision b2c9e5a1f4d7).

Proves the publication-binding migration upgrades/downgrades cleanly on SQLite, preserves
legacy v1alpha1 rows (all new columns NULL, no backfill), enforces the portable
coherent-publication CHECK and the ``(template_id, publication_fingerprint)`` uniqueness, and
that the revision chain still has exactly one head. The PostgreSQL trigger restore on
downgrade is exercised in the postgres-gated module.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError

API_DIR = Path(__file__).resolve().parents[1]

REVISION = "b2c9e5a1f4d7"
DOWN_REVISION = "a1b2c3d4e5f6"

_NEW_COLUMNS = {
    "source_topology_document_id",
    "source_topology_revision_id",
    "topology_content_hash",
    "topology_validation_result_id",
    "topology_validation_result_hash",
    "base_environment_version_id",
    "publication_contract_version",
    "publication_fingerprint",
}


@pytest.fixture(autouse=True)
def _restore_settings_cache():
    """Ensure the tmp-DB URL never leaks into later tests via the settings LRU cache."""
    yield
    from secp_api.config import get_settings

    get_settings.cache_clear()


def _config(url: str) -> Config:
    cfg = Config(str(API_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(API_DIR / "migrations"))
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


def _activate(monkeypatch, url: str) -> Config:
    """Point both alembic (via ``env.py`` -> settings) and our engine at the same DB."""
    from secp_api.config import get_settings

    monkeypatch.setenv("SECP_DATABASE_URL", url)
    get_settings.cache_clear()
    return _config(url)


def _engine(tmp_path, name="m.db"):
    url = f"sqlite+pysqlite:///{(tmp_path / name).as_posix()}"
    return url, create_engine(url, future=True)


def _seed_org_template(conn, *, org_id, tmpl_id):
    conn.execute(
        text(
            "INSERT INTO organization (id, name, slug, created_at) "
            "VALUES (:id, 'Org', :slug, CURRENT_TIMESTAMP)"
        ),
        {"id": str(org_id), "slug": f"o-{org_id.hex[:8]}"},
    )
    conn.execute(
        text(
            "INSERT INTO environment_template "
            "(id, organization_id, name, slug, display_name, description, created_at) "
            "VALUES (:id, :org, 'T', :slug, 'T', '', CURRENT_TIMESTAMP)"
        ),
        {"id": str(tmpl_id), "org": str(org_id), "slug": f"t-{tmpl_id.hex[:8]}"},
    )


def _insert_version(conn, *, org_id, tmpl_id, number, api_version, publication=None):
    cols = {
        "id": str(uuid.uuid4()),
        "organization_id": str(org_id),
        "template_id": str(tmpl_id),
        "version_number": number,
        "api_version": api_version,
        "spec": '{"a": 1}',
        "content_hash": f"sha256:{uuid.uuid4().hex}",
    }
    cols.update(publication or {})
    names = ", ".join(cols)
    binds = ", ".join(f":{k}" for k in cols)
    conn.execute(
        text(
            f"INSERT INTO environment_version ({names}, created_at) "
            f"VALUES ({binds}, CURRENT_TIMESTAMP)"
        ),
        cols,
    )
    return cols["id"]


def _published_binding(fingerprint="sha256:" + "ab" * 32):
    return {
        "source_topology_document_id": str(uuid.uuid4()),
        "source_topology_revision_id": str(uuid.uuid4()),
        "topology_content_hash": "sha256:" + "cd" * 32,
        "topology_validation_result_id": str(uuid.uuid4()),
        "topology_validation_result_hash": "sha256:" + "ef" * 32,
        "base_environment_version_id": None,
        "publication_contract_version": "secp.publication/v1",
        "publication_fingerprint": fingerprint,
    }


def test_single_head():
    scripts = ScriptDirectory.from_config(_config("sqlite://"))
    heads = scripts.get_heads()
    assert list(heads) == [REVISION], heads


def test_upgrade_adds_columns_and_preserves_legacy_rows(tmp_path, monkeypatch):
    url, engine = _engine(tmp_path)
    cfg = _activate(monkeypatch, url)
    command.upgrade(cfg, DOWN_REVISION)

    org_id, tmpl_id = uuid.uuid4(), uuid.uuid4()
    with engine.begin() as conn:
        _seed_org_template(conn, org_id=org_id, tmpl_id=tmpl_id)
        legacy_id = _insert_version(
            conn,
            org_id=org_id,
            tmpl_id=tmpl_id,
            number=1,
            api_version="controlplane.security/v1alpha1",
        )

    command.upgrade(cfg, "head")

    inspector = inspect(engine)
    cols = {c["name"] for c in inspector.get_columns("environment_version")}
    assert _NEW_COLUMNS <= cols

    # legacy row survived with every publication column NULL (no backfill)
    with engine.begin() as conn:
        row = conn.execute(
            text(
                "SELECT publication_fingerprint, source_topology_document_id, "
                "base_environment_version_id, publication_contract_version "
                "FROM environment_version WHERE id = :id"
            ),
            {"id": legacy_id},
        ).one()
    assert row == (None, None, None, None)
    engine.dispose()


def test_check_constraint_and_uniqueness_on_head(tmp_path, monkeypatch):
    url, engine = _engine(tmp_path, "check.db")
    command.upgrade(_activate(monkeypatch, url), "head")
    org_id, tmpl_id = uuid.uuid4(), uuid.uuid4()

    # Exercise CHECK/UNIQUE only — disable FK enforcement so we needn't build the
    # topology FK targets.
    with engine.begin() as conn:
        conn.connection.dbapi_connection.execute("PRAGMA foreign_keys=OFF")
        _seed_org_template(conn, org_id=org_id, tmpl_id=tmpl_id)

    # legacy row (all publication cols NULL) is accepted
    with engine.begin() as conn:
        conn.connection.dbapi_connection.execute("PRAGMA foreign_keys=OFF")
        _insert_version(
            conn,
            org_id=org_id,
            tmpl_id=tmpl_id,
            number=1,
            api_version="controlplane.security/v1alpha1",
        )

    # fully-bound published row (v1alpha2) is accepted
    fp = "sha256:" + "11" * 32
    with engine.begin() as conn:
        conn.connection.dbapi_connection.execute("PRAGMA foreign_keys=OFF")
        _insert_version(
            conn,
            org_id=org_id,
            tmpl_id=tmpl_id,
            number=2,
            api_version="controlplane.security/v1alpha2",
            publication=_published_binding(fp),
        )

    # partial binding (some publication cols set, others NULL) is rejected by the CHECK
    with pytest.raises(Exception) as exc:
        with engine.begin() as conn:
            conn.connection.dbapi_connection.execute("PRAGMA foreign_keys=OFF")
            partial = _published_binding("sha256:" + "22" * 32)
            partial["topology_content_hash"] = None
            _insert_version(
                conn,
                org_id=org_id,
                tmpl_id=tmpl_id,
                number=3,
                api_version="controlplane.security/v1alpha2",
                publication=partial,
            )
    assert "constraint" in str(exc.value).lower() or "check" in str(exc.value).lower()

    # fully-bound but wrong api_version is rejected by the CHECK
    with pytest.raises(IntegrityError):
        with engine.begin() as conn:
            conn.connection.dbapi_connection.execute("PRAGMA foreign_keys=OFF")
            _insert_version(
                conn,
                org_id=org_id,
                tmpl_id=tmpl_id,
                number=4,
                api_version="controlplane.security/v1alpha1",
                publication=_published_binding("sha256:" + "33" * 32),
            )

    # v1alpha2 with EVERY publication column NULL is rejected (no unpublished-v1alpha2 state)
    with pytest.raises(IntegrityError):
        with engine.begin() as conn:
            conn.connection.dbapi_connection.execute("PRAGMA foreign_keys=OFF")
            _insert_version(
                conn,
                org_id=org_id,
                tmpl_id=tmpl_id,
                number=6,
                api_version="controlplane.security/v1alpha2",  # no publication -> all NULL
            )

    # wrong publication_contract_version is rejected by the CHECK
    with pytest.raises(IntegrityError):
        with engine.begin() as conn:
            conn.connection.dbapi_connection.execute("PRAGMA foreign_keys=OFF")
            bad = _published_binding("sha256:" + "44" * 32)
            bad["publication_contract_version"] = "secp.publication/v2"
            _insert_version(
                conn,
                org_id=org_id,
                tmpl_id=tmpl_id,
                number=7,
                api_version="controlplane.security/v1alpha2",
                publication=bad,
            )

    # a v1alpha1 row carrying any publication column is rejected by the CHECK
    with pytest.raises(IntegrityError):
        with engine.begin() as conn:
            conn.connection.dbapi_connection.execute("PRAGMA foreign_keys=OFF")
            _insert_version(
                conn,
                org_id=org_id,
                tmpl_id=tmpl_id,
                number=8,
                api_version="controlplane.security/v1alpha1",
                publication={"publication_fingerprint": "sha256:" + "55" * 32},
            )

    # duplicate (template_id, publication_fingerprint) is rejected by the unique constraint
    with pytest.raises(Exception) as dup:
        with engine.begin() as conn:
            conn.connection.dbapi_connection.execute("PRAGMA foreign_keys=OFF")
            _insert_version(
                conn,
                org_id=org_id,
                tmpl_id=tmpl_id,
                number=5,
                api_version="controlplane.security/v1alpha2",
                publication=_published_binding(fp),  # same fp as version 2
            )
    assert "unique" in str(dup.value).lower()
    engine.dispose()


def test_downgrade_drops_columns_and_keeps_legacy_row(tmp_path, monkeypatch):
    url, engine = _engine(tmp_path, "down.db")
    cfg = _activate(monkeypatch, url)
    command.upgrade(cfg, "head")

    org_id, tmpl_id = uuid.uuid4(), uuid.uuid4()
    with engine.begin() as conn:
        _seed_org_template(conn, org_id=org_id, tmpl_id=tmpl_id)
        legacy_id = _insert_version(
            conn,
            org_id=org_id,
            tmpl_id=tmpl_id,
            number=1,
            api_version="controlplane.security/v1alpha1",
        )

    command.downgrade(cfg, DOWN_REVISION)

    inspector = inspect(engine)
    cols = {c["name"] for c in inspector.get_columns("environment_version")}
    assert not (_NEW_COLUMNS & cols)

    with engine.begin() as conn:
        surviving = conn.execute(
            text("SELECT id FROM environment_version WHERE id = :id"), {"id": legacy_id}
        ).scalar_one()
    assert surviving == legacy_id
    engine.dispose()
