"""PostgreSQL-backed publication tests (SECP-B10 / ADR-016 PR B, deliverables 11 & 12).

Proves, on a real PostgreSQL, that:
  * the ``SELECT FOR UPDATE`` template lock serialises concurrent publications so identical
    inputs collapse to one row (idempotent) and distinct inputs get monotonic version numbers
    with no duplicate;
  * a superseded (non-current) approved head cannot be published;
  * the hardened BEFORE INSERT OR UPDATE trigger blocks raw-SQL mutation of every publication
    binding column (``created_by`` included) and rejects any incoherent/fabricated INSERT, while
    staying precise (non-binding columns such as ``created_at`` remain updatable).

Skipped unless ``SECP_TEST_POSTGRES_URL`` is set, so the default suite stays hermetic.
Never claims SQLite proves ``SELECT FOR UPDATE``.
"""

from __future__ import annotations

import json
import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
import secp_api.immutability  # noqa: F401  (registers ORM immutability guards)
from secp_api.enums import TopologyRevisionStatus
from secp_api.seed import bootstrap_dev
from secp_api.services import catalog
from secp_api.services import environment_publication as pub
from secp_api.services import topology_authoring as topo
from secp_api.topology_authoring_models import TopologyRevision
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from tests.test_environment_publication_service import (  # type: ignore
    base_definition,
    base_topology,
)

PG_URL = os.environ.get("SECP_TEST_POSTGRES_URL")
DOWN_REVISION = "a1b2c3d4e5f6"

pytestmark = pytest.mark.skipif(
    not PG_URL, reason="set SECP_TEST_POSTGRES_URL to run PostgreSQL publication tests"
)


@pytest.fixture(scope="module")
def pg():
    assert PG_URL
    engine = create_engine(PG_URL, future=True)
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))

    from alembic import command
    from alembic.config import Config
    from secp_api.config import get_settings

    api_dir = __import__("pathlib").Path(__file__).resolve().parents[1]
    previous = os.environ.get("SECP_DATABASE_URL")
    os.environ["SECP_DATABASE_URL"] = PG_URL
    get_settings.cache_clear()
    cfg = Config(str(api_dir / "alembic.ini"))
    cfg.set_main_option("script_location", str(api_dir / "migrations"))
    cfg.set_main_option("sqlalchemy.url", PG_URL)
    command.upgrade(cfg, "head")

    SessionLocal = sessionmaker(bind=engine, autoflush=False, future=True)
    # one dev principal for the whole module; each test makes its own template/topology
    boot = SessionLocal()
    principal = bootstrap_dev(boot)
    boot.commit()
    boot.close()

    yield engine, SessionLocal, principal

    engine.dispose()
    if previous is None:
        os.environ.pop("SECP_DATABASE_URL", None)
    else:
        os.environ["SECP_DATABASE_URL"] = previous
    get_settings.cache_clear()


def _approve(session, principal, *, topology=None):
    doc = topo.create_draft(
        session, principal, display_name="d", document=topology or base_topology()
    )
    doc_id = doc.id
    revision = session.get(TopologyRevision, doc.current_revision_id)
    rev_id = revision.id
    ch = revision.content_hash
    validation = topo.validate_revision(
        session, principal, doc_id, rev_id, expected_content_hash=ch
    )
    val_id = validation.id
    topo.submit_revision(session, principal, doc_id, rev_id, expected_content_hash=ch)
    topo.approve_revision(session, principal, doc_id, rev_id, expected_content_hash=ch, reason="ok")
    session.commit()
    return doc_id, rev_id, ch, val_id


def _publish(session, principal, *, template_id, definition, doc_id, rev_id, ch, val_id):
    return pub.publish_version(
        session,
        principal,
        template_id=template_id,
        definition=definition,
        topology_document_id=doc_id,
        topology_revision_id=rev_id,
        expected_topology_content_hash=ch,
        validation_result_id=val_id,
        base_environment_version_id=None,
    )


# --- raw-SQL immutability of the new publication binding columns (deliverable 12) --------------


@pytest.fixture
def published(pg):
    engine, SessionLocal, principal = pg
    session = SessionLocal()
    template = catalog.create_template(
        session, principal, name="T", slug=f"imm-{uuid.uuid4().hex[:8]}"
    )
    doc_id, rev_id, ch, val_id = _approve(session, principal)
    version = _publish(
        session,
        principal,
        template_id=template.id,
        definition=base_definition(),
        doc_id=doc_id,
        rev_id=rev_id,
        ch=ch,
        val_id=val_id,
    )
    session.commit()
    vid = version.id
    session.close()
    return engine, vid


@pytest.mark.parametrize(
    "column,value",
    [
        ("publication_fingerprint", "sha256:" + "ff" * 32),
        ("source_topology_document_id", str(uuid.uuid4())),
        ("source_topology_revision_id", str(uuid.uuid4())),
        ("topology_content_hash", "sha256:" + "ff" * 32),
        ("topology_validation_result_id", str(uuid.uuid4())),
        ("topology_validation_result_hash", "sha256:" + "ff" * 32),
        ("base_environment_version_id", str(uuid.uuid4())),
        ("publication_contract_version", "secp.publication/v2"),
        ("spec", '{"tampered": true}'),
        ("content_hash", "sha256:" + "ff" * 32),
        ("api_version", "controlplane.security/v1alpha1"),
        ("organization_id", str(uuid.uuid4())),
        ("template_id", str(uuid.uuid4())),
    ],
)
def test_raw_sql_cannot_mutate_publication_binding(published, column, value):
    engine, vid = published
    with pytest.raises(Exception) as exc:
        with engine.begin() as conn:
            conn.execute(
                text(f"UPDATE environment_version SET {column} = :v WHERE id = :id"),
                {"v": value, "id": vid},
            )
    assert "immutable" in str(exc.value).lower()


def test_raw_sql_created_by_is_immutable_on_published_row(published):
    # SECP-B10 / ADR-016: created_by is now a protected binding on the published row too.
    engine, vid = published
    with pytest.raises(Exception) as exc:
        with engine.begin() as conn:
            conn.execute(
                text("UPDATE environment_version SET created_by = :c WHERE id = :id"),
                {"c": uuid.uuid4(), "id": vid},
            )
    assert "immutable" in str(exc.value).lower()


# --- raw-SQL INSERT coherence (deliverable 3/5) ------------------------------------------------
#
# The hardened BEFORE INSERT trigger makes a fabricated/partial/mismatched/unpublished-v1alpha2
# row impossible even via raw SQL that bypasses the ORM and the publication service.

_FAKE_UUID = "00000000-0000-0000-0000-0000000000ff"
_FAKE_HASH = "sha256:" + "ee" * 32
_ALL_PUBLICATION_NULL = dict.fromkeys(
    (
        "source_topology_document_id",
        "source_topology_revision_id",
        "topology_content_hash",
        "topology_validation_result_id",
        "topology_validation_result_hash",
        "base_environment_version_id",
        "publication_contract_version",
        "publication_fingerprint",
    ),
    None,
)


@pytest.fixture
def raw_ids(pg):
    engine, SessionLocal, principal = pg
    session = SessionLocal()
    template = catalog.create_template(
        session, principal, name="T", slug=f"raw-{uuid.uuid4().hex[:8]}"
    )
    doc_id, rev_id, _ch, val_id = _approve(session, principal)
    tid, org = template.id, principal.organization_id
    session.commit()
    session.close()
    return engine, (doc_id, rev_id, val_id, tid, org, "sha256:" + "1a" * 32, "sha256:" + "2b" * 32)


def _build_row(ids, *, col=None, prov=None, spec_api="controlplane.security/v1alpha2"):
    doc_id, rev_id, val_id, tid, org, tch, vrh = ids
    provenance = {
        "topology_document_id": str(doc_id),
        "topology_revision_id": str(rev_id),
        "topology_content_hash": tch,
        "topology_validation_result_id": str(val_id),
        "topology_validation_result_hash": vrh,
        "base_environment_version_id": None,
        "publication_contract_version": "secp.publication/v1",
    }
    if prov:
        provenance.update(prov)
    spec = {
        "apiVersion": spec_api,
        "kind": "Environment",
        "metadata": {"name": "x"},
        "spec": {"publicationProvenance": provenance},
    }
    cols = {
        "id": str(uuid.uuid4()),
        "organization_id": str(org),
        "template_id": str(tid),
        "version_number": 1,
        "api_version": "controlplane.security/v1alpha2",
        "content_hash": "sha256:" + "3c" * 32,
        "spec": json.dumps(spec),
        "source_topology_document_id": str(doc_id),
        "source_topology_revision_id": str(rev_id),
        "topology_content_hash": tch,
        "topology_validation_result_id": str(val_id),
        "topology_validation_result_hash": vrh,
        "base_environment_version_id": None,
        "publication_contract_version": "secp.publication/v1",
        "publication_fingerprint": "sha256:" + "4d" * 32,
    }
    if col:
        cols.update(col)
    return cols


def _raw_insert(engine, cols):
    names = ", ".join(cols)
    binds = ", ".join(f":{k}" for k in cols)
    with engine.begin() as conn:
        conn.execute(
            text(f"INSERT INTO environment_version ({names}, created_at) VALUES ({binds}, now())"),
            cols,
        )


def test_raw_sql_coherent_v1alpha2_insert_succeeds(raw_ids):
    engine, ids = raw_ids
    cols = _build_row(ids)
    _raw_insert(engine, cols)
    with engine.begin() as conn:
        got = conn.execute(
            text("SELECT publication_fingerprint FROM environment_version WHERE id = :id"),
            {"id": cols["id"]},
        ).scalar_one()
    assert got == cols["publication_fingerprint"]


_RAW_INCOHERENT = {
    "all_publication_null": {"col": _ALL_PUBLICATION_NULL},
    "partial_missing_hash": {"col": {"topology_content_hash": None}},
    "wrong_contract_version": {"col": {"publication_contract_version": "secp.publication/v2"}},
    "spec_apiversion_mismatch": {"spec_api": "controlplane.security/v1alpha1"},
    "mirror_document_id": {"col": {"source_topology_document_id": _FAKE_UUID}},
    "mirror_revision_id": {"col": {"source_topology_revision_id": _FAKE_UUID}},
    "mirror_topology_hash": {"col": {"topology_content_hash": _FAKE_HASH}},
    "mirror_validation_id": {"col": {"topology_validation_result_id": _FAKE_UUID}},
    "mirror_validation_hash": {"col": {"topology_validation_result_hash": _FAKE_HASH}},
    "mirror_base_disagreement": {"col": {"base_environment_version_id": _FAKE_UUID}},
    "mirror_contract_version": {"prov": {"publication_contract_version": "secp.publication/v2"}},
}


@pytest.mark.parametrize("name", sorted(_RAW_INCOHERENT))
def test_raw_sql_rejects_incoherent_v1alpha2_insert(raw_ids, name):
    engine, ids = raw_ids
    cols = _build_row(ids, **_RAW_INCOHERENT[name])
    with pytest.raises(Exception) as exc:
        _raw_insert(engine, cols)
    assert "environment_version" in str(exc.value).lower()
    # the row must not have been persisted
    with engine.begin() as conn:
        present = conn.execute(
            text("SELECT count(*) FROM environment_version WHERE id = :id"),
            {"id": cols["id"]},
        ).scalar_one()
    assert present == 0


# --- concurrency (deliverable 11) --------------------------------------------------------------


def _run_two(SessionLocal, principal, template_id, doc_id, rev_id, ch, val_id, definitions):
    barrier = threading.Barrier(len(definitions))
    results: list = []
    lock = threading.Lock()

    def worker(defn):
        session = SessionLocal()
        try:
            barrier.wait(timeout=20)
            version = _publish(
                session,
                principal,
                template_id=template_id,
                definition=defn,
                doc_id=doc_id,
                rev_id=rev_id,
                ch=ch,
                val_id=val_id,
            )
            session.commit()
            outcome = (str(version.id), version.version_number)
        except Exception as exc:  # pragma: no cover - surfaced via assertions
            session.rollback()
            outcome = ("ERROR", repr(exc))
        finally:
            session.close()
        with lock:
            results.append(outcome)

    with ThreadPoolExecutor(max_workers=len(definitions)) as pool:
        list(pool.map(worker, definitions))
    return results


def test_concurrent_identical_publications_collapse_to_one_row(pg):
    engine, SessionLocal, principal = pg
    session = SessionLocal()
    template = catalog.create_template(
        session, principal, name="T", slug=f"cc-a-{uuid.uuid4().hex[:8]}"
    )
    doc_id, rev_id, ch, val_id = _approve(session, principal)
    tid = template.id
    session.commit()
    session.close()

    results = _run_two(
        SessionLocal,
        principal,
        tid,
        doc_id,
        rev_id,
        ch,
        val_id,
        [base_definition(), base_definition()],
    )
    assert all(r[0] != "ERROR" for r in results), results
    ids = {r[0] for r in results}
    numbers = {r[1] for r in results}
    assert len(ids) == 1, f"identical inputs must yield one version id: {results}"
    assert numbers == {1}
    with engine.begin() as conn:
        count = conn.execute(
            text("SELECT count(*) FROM environment_version WHERE template_id = :t"),
            {"t": str(tid)},
        ).scalar_one()
    assert count == 1


def test_concurrent_distinct_publications_get_monotonic_numbers(pg):
    engine, SessionLocal, principal = pg
    session = SessionLocal()
    template = catalog.create_template(
        session, principal, name="T", slug=f"cc-b-{uuid.uuid4().hex[:8]}"
    )
    doc_id, rev_id, ch, val_id = _approve(session, principal)
    tid = template.id
    session.commit()
    session.close()

    d1 = base_definition()
    d2 = base_definition()
    d2["metadata"]["name"] = "pub-env-b"  # distinct content -> distinct fingerprint

    results = _run_two(SessionLocal, principal, tid, doc_id, rev_id, ch, val_id, [d1, d2])
    assert all(r[0] != "ERROR" for r in results), results
    ids = {r[0] for r in results}
    numbers = sorted(r[1] for r in results)
    assert len(ids) == 2, f"distinct inputs must yield two versions: {results}"
    assert numbers == [1, 2], numbers
    with engine.begin() as conn:
        count = conn.execute(
            text("SELECT count(*) FROM environment_version WHERE template_id = :t"),
            {"t": str(tid)},
        ).scalar_one()
    assert count == 2


def test_superseded_approved_head_cannot_be_published(pg):
    """A revision that is no longer the document's current approved head must not publish."""
    engine, SessionLocal, principal = pg
    session = SessionLocal()
    template = catalog.create_template(
        session, principal, name="T", slug=f"cc-c-{uuid.uuid4().hex[:8]}"
    )
    doc_id, rev_id, ch, val_id = _approve(session, principal)
    tid = template.id
    session.commit()

    # A new revision after approval clears the approved pointer (new review required),
    # so the previously-approved rev_id is no longer the current approved head.
    new_topology = base_topology()
    new_topology["nodes"].append(
        {"id": "target-2", "kind": "target", "network": "net-a", "x": 3, "y": 3}
    )
    new_topology["edges"].append(
        {"id": "e-t2", "source": "target-2", "target": "net-a", "kind": "network"}
    )
    reloaded = session.get(TopologyRevision, rev_id)
    topo.create_revision(
        session,
        principal,
        doc_id,
        base_revision_number=reloaded.revision_number,
        base_content_hash=reloaded.content_hash,
        document=new_topology,
    )
    session.commit()

    superseded = session.get(TopologyRevision, rev_id)
    assert (
        superseded.status == TopologyRevisionStatus.approved
    )  # the revision itself stays approved
    from secp_api.errors import EnvironmentPublicationError

    with pytest.raises(EnvironmentPublicationError) as exc:
        _publish(
            session,
            principal,
            template_id=tid,
            definition=base_definition(),
            doc_id=doc_id,
            rev_id=rev_id,
            ch=ch,
            val_id=val_id,
        )
    assert exc.value.code == "version_publish_topology_not_approved"
    session.close()


# --- migration up/down trigger restore on PostgreSQL (deliverable 2 & 12) ----------------------


def _trigger_body(engine) -> str:
    with engine.begin() as conn:
        return conn.execute(
            text(
                "SELECT pg_get_functiondef(oid) FROM pg_proc "
                "WHERE proname = 'secp_block_version_mutation'"
            )
        ).scalar_one()


def _trigger_events(engine) -> set[str]:
    with engine.begin() as conn:
        return set(
            conn.execute(
                text(
                    "SELECT event_manipulation FROM information_schema.triggers "
                    "WHERE event_object_table = 'environment_version' "
                    "AND trigger_name = 'secp_environment_version_immutable'"
                )
            ).scalars()
        )


def _ensure_migration_database(base_url: str, name: str) -> str:
    """Create an isolated database for the destructive up/down/up migration test if it does not
    exist (the CI Postgres service ships only the main test database), and return its URL. This
    keeps the migration test from disturbing the shared schema used by the other tests."""
    admin = create_engine(base_url, future=True, isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as conn:
            exists = conn.execute(
                text("SELECT 1 FROM pg_database WHERE datname = :n"), {"n": name}
            ).scalar()
            if not exists:
                conn.execute(text(f'CREATE DATABASE "{name}"'))
    finally:
        admin.dispose()
    return base_url.rsplit("/", 1)[0] + "/" + name


def test_downgrade_restores_prior_trigger_then_reupgrades_on_postgres():
    """On a dedicated PG database: upgrade installs the publication-aware trigger; downgrade
    restores the prior 4-column trigger BEFORE dropping the new columns; re-upgrade is clean."""
    assert PG_URL
    mig_url = _ensure_migration_database(PG_URL, "secptest_mig")
    engine = create_engine(mig_url, future=True)
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))

    from alembic import command
    from alembic.config import Config
    from secp_api.config import get_settings

    api_dir = __import__("pathlib").Path(__file__).resolve().parents[1]
    previous = os.environ.get("SECP_DATABASE_URL")
    os.environ["SECP_DATABASE_URL"] = mig_url
    get_settings.cache_clear()
    cfg = Config(str(api_dir / "alembic.ini"))
    cfg.set_main_option("script_location", str(api_dir / "migrations"))
    cfg.set_main_option("sqlalchemy.url", mig_url)

    try:
        command.upgrade(cfg, "head")
        assert "source_topology_document_id" in _trigger_body(engine)
        # hardened trigger fires on INSERT and UPDATE
        assert _trigger_events(engine) == {"INSERT", "UPDATE"}

        command.downgrade(cfg, DOWN_REVISION)
        restored = _trigger_body(engine)
        # prior body guards only spec/content_hash/version_number/api_version
        assert "source_topology_document_id" not in restored
        assert "publication_fingerprint" not in restored
        assert "content_hash" in restored
        # prior trigger fires on UPDATE only
        assert _trigger_events(engine) == {"UPDATE"}
        with engine.begin() as conn:
            cols = {
                r[0]
                for r in conn.execute(
                    text(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_name = 'environment_version'"
                    )
                )
            }
        assert "publication_fingerprint" not in cols

        command.upgrade(cfg, "head")  # clean re-upgrade
        assert "source_topology_document_id" in _trigger_body(engine)
        assert _trigger_events(engine) == {"INSERT", "UPDATE"}
    finally:
        engine.dispose()
        if previous is None:
            os.environ.pop("SECP_DATABASE_URL", None)
        else:
            os.environ["SECP_DATABASE_URL"] = previous
        get_settings.cache_clear()
