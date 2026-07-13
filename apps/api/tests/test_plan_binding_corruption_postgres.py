"""PostgreSQL-backed plan/version binding-corruption tests (ADR-016 PR E amendment, deliverable 4).

On a REAL PostgreSQL, every internal ``DeploymentPlan`` binding disagreement collapses into the SAME
closed response — HTTP 409, body exactly ``{"error":{"code":"plan_version_binding_invalid"}}`` —
with no id/hash/internal detail, and a refused corrupted binding mutates nothing. The
``deployment_plan`` and ``exercise`` tables carry NO database immutability trigger (only
``environment_version`` and
``audit_event`` do), so a raw Core UPDATE genuinely tampers with them — exactly the DB-level
corruption the app-layer verifier must still catch. We never claim database-level ``DeploymentPlan``
immutability.

Foreign-key constraints make a *truly missing* referenced Exercise/EnvironmentVersion impossible to
persist (a stronger guarantee than the app check), so those "missing" branches are proven at the
unit level against the pure ``_binding_disagreement_category`` helper; the DB-tampering-reachable
disagreements are proven end-to-end over HTTP here. The public exact-version read endpoint keeps its
normal 404/403 behavior.

Skipped unless ``SECP_TEST_POSTGRES_URL`` is set, so the default suite stays hermetic.
"""

from __future__ import annotations

import os
import re
import uuid

import pytest
from fastapi.testclient import TestClient
from secp_api.auth import Principal
from secp_api.db import get_sessionmaker, reset_engine_for_tests
from secp_api.enums import Permission
from secp_api.models import AuditEvent, DeploymentPlan, Exercise
from secp_api.seed import bootstrap_dev
from secp_api.services import catalog, exercises, planning
from secp_api.services.planning import _binding_disagreement_category
from sqlalchemy import create_engine, text
from tests.test_environment_publication_service import (  # type: ignore
    _template,
    _v1alpha1_def,
    approve_topology,
    publish,
)

PG_URL = os.environ.get("SECP_TEST_POSTGRES_URL")

pytestmark = pytest.mark.skipif(
    not PG_URL, reason="set SECP_TEST_POSTGRES_URL to run PostgreSQL binding-corruption tests"
)

_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


# --- fixtures: migrate a fresh schema, bind the GLOBAL engine to PG, bootstrap one principal ----


@pytest.fixture(scope="module")
def pg_principal():
    assert PG_URL
    admin = create_engine(PG_URL, future=True)
    with admin.begin() as conn:
        conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    admin.dispose()

    import pathlib

    from alembic import command
    from alembic.config import Config
    from secp_api.config import get_settings

    api_dir = pathlib.Path(__file__).resolve().parents[1]
    previous = os.environ.get("SECP_DATABASE_URL")
    os.environ["SECP_DATABASE_URL"] = PG_URL
    get_settings.cache_clear()
    cfg = Config(str(api_dir / "alembic.ini"))
    cfg.set_main_option("script_location", str(api_dir / "migrations"))
    cfg.set_main_option("sqlalchemy.url", PG_URL)
    command.upgrade(cfg, "head")
    # Bind the global engine/sessionmaker to PostgreSQL so BOTH the test session and the TestClient
    # app hit the same real database.
    engine = reset_engine_for_tests(PG_URL)

    boot = get_sessionmaker()()
    principal = bootstrap_dev(boot)
    boot.commit()
    boot.close()

    yield principal

    engine.dispose()
    if previous is None:
        os.environ.pop("SECP_DATABASE_URL", None)
    else:
        os.environ["SECP_DATABASE_URL"] = previous
    get_settings.cache_clear()


@pytest.fixture
def session(pg_principal):
    s = get_sessionmaker()()
    try:
        yield s
    finally:
        s.rollback()
        s.close()


@pytest.fixture
def principal(pg_principal):
    return pg_principal


@pytest.fixture
def client(pg_principal):
    from secp_api.main import create_app

    app = create_app()
    app.router.on_startup.clear()
    return TestClient(app)


# --- helpers -----------------------------------------------------------------------------------


def _published_plan(session, principal, *, name="pgbind"):
    template = _template(session, principal)
    approved = approve_topology(session, principal)
    version = publish(session, principal, template, approved)
    exercise = exercises.create_exercise(
        session, principal, template_id=template.id, version_id=version.id, name=name
    )
    exercises.validate_exercise(session, principal, exercise.id)
    plan = planning.generate_plan(session, principal, exercise.id)
    session.commit()
    return template, version, exercise, plan


def _core_update(session, table, row_id, **values) -> None:
    # Raw Core UPDATE: correct column typing, but NOT through the ORM unit-of-work, so the
    # before_flush immutability guard never sees it — the DB-level tampering the verifier catches.
    session.execute(table.update().where(table.c.id == row_id).values(**values))
    session.commit()
    session.expire_all()


def _other_org_principal(session) -> Principal:
    from secp_api.models import Organization, Role, User, UserRoleAssignment

    suffix = uuid.uuid4().hex[:8]
    org = Organization(name=f"Other PG Org {suffix}", slug=f"other-pg-{suffix}")
    session.add(org)
    session.flush()
    role = session.query(Role).filter_by(name="platform-admin").one()
    user = User(
        organization_id=org.id,
        email=f"other-{suffix}@local.test",
        display_name="Other",
        subject=f"other-{suffix}",
    )
    session.add(user)
    session.flush()
    session.add(UserRoleAssignment(organization_id=org.id, user_id=user.id, role_id=role.id))
    session.commit()
    return Principal(
        user_id=user.id,
        organization_id=org.id,
        email=user.email,
        permissions=frozenset(Permission),
    )


def _other_org_version_and_exercise(session):
    other = _other_org_principal(session)
    t = catalog.create_template(session, other, name="Other T", slug=f"ot-{uuid.uuid4().hex[:8]}")
    v = catalog.create_version(session, other, template_id=t.id, definition=_v1alpha1_def())
    ex = exercises.create_exercise(
        session, other, template_id=t.id, version_id=v.id, name="other-ex"
    )
    session.commit()
    return v, ex


def _assert_closed_409(r) -> None:
    assert r.status_code == 409, r.text
    assert r.json() == {"error": {"code": "plan_version_binding_invalid"}}
    # no id (plan/exercise/version), hash, or internal detail may leak.
    assert not _UUID_RE.search(r.text), r.text
    assert "sha256:" not in r.text
    for token in ("Traceback", "sqlalchemy", "psycopg", "IntegrityError", "spec", "template_id"):
        assert token not in r.text


_WRONG_HASH = "sha256:" + "e" * 64


# --- A. DB-tampering-reachable internal corruption -> exact closed 409 over HTTP ----------------


def test_cross_org_version_id_is_closed_409_not_403(session, principal, client):
    _t, _v, _ex, plan = _published_plan(session, principal, name="xorg-ver")
    other_v, _other_ex = _other_org_version_and_exercise(session)
    _core_update(session, DeploymentPlan.__table__, plan.id, environment_version_id=other_v.id)
    _assert_closed_409(client.post(f"/api/v1/plans/{plan.id}/submit"))


def test_same_org_wrong_version_id_is_closed_409(session, principal, client):
    _t, _v, _ex, plan = _published_plan(session, principal, name="wrong-ver")
    t2 = _template(session, principal)
    v2 = catalog.create_version(session, principal, template_id=t2.id, definition=_v1alpha1_def())
    session.commit()
    _core_update(session, DeploymentPlan.__table__, plan.id, environment_version_id=v2.id)
    _assert_closed_409(client.post(f"/api/v1/plans/{plan.id}/submit"))


def test_cross_org_exercise_binding_is_closed_409(session, principal, client):
    _t, _v, _ex, plan = _published_plan(session, principal, name="xorg-ex")
    _other_v, other_ex = _other_org_version_and_exercise(session)
    _core_update(session, DeploymentPlan.__table__, plan.id, exercise_id=other_ex.id)
    _assert_closed_409(client.post(f"/api/v1/plans/{plan.id}/submit"))


def test_exercise_version_disagreement_is_closed_409(session, principal, client):
    _t, _v, ex, plan = _published_plan(session, principal, name="ex-ver")
    t2 = _template(session, principal)
    v2 = catalog.create_version(session, principal, template_id=t2.id, definition=_v1alpha1_def())
    session.commit()
    # point the exercise at a different (real, same-org) version than the plan.
    _core_update(session, Exercise.__table__, ex.id, environment_version_id=v2.id)
    _assert_closed_409(client.post(f"/api/v1/plans/{plan.id}/submit"))


def test_exercise_template_disagreement_is_closed_409(session, principal, client):
    _t, _v, ex, plan = _published_plan(session, principal, name="ex-tmpl")
    t2 = _template(session, principal)
    session.commit()
    _core_update(session, Exercise.__table__, ex.id, template_id=t2.id)
    _assert_closed_409(client.post(f"/api/v1/plans/{plan.id}/submit"))


def test_plan_version_hash_disagreement_is_closed_409(session, principal, client):
    _t, _v, _ex, plan = _published_plan(session, principal, name="hash")
    _core_update(session, DeploymentPlan.__table__, plan.id, version_content_hash=_WRONG_HASH)
    _assert_closed_409(client.post(f"/api/v1/plans/{plan.id}/submit"))


def test_read_path_hash_disagreement_is_closed_409(session, principal, client):
    # The read serializer (_serialize on GET latest plan) folds the same corruption to a closed 409.
    _t, version, ex, plan = _published_plan(session, principal, name="hash-read")
    _core_update(session, DeploymentPlan.__table__, plan.id, version_content_hash=_WRONG_HASH)
    r = client.get(f"/api/v1/exercises/{ex.id}/plan")
    _assert_closed_409(r)
    assert version.content_hash not in r.text


# --- FK-/trigger-prevented branches: proven at the unit level on the pure category helper -------


def test_missing_reference_branches_fold_via_pure_helper(session, principal):
    # A truly-missing referenced row cannot be persisted (FK-enforced), so these branches are proven
    # directly on the pure helper: a None Exercise/EnvironmentVersion yields the closed category.
    _t, version, ex, plan = _published_plan(session, principal, name="missing")
    assert _binding_disagreement_category(principal, plan, None, version) == "exercise_missing"
    assert _binding_disagreement_category(principal, plan, ex, None) == "version_missing"
    # and a coherent binding yields no disagreement at all.
    assert _binding_disagreement_category(principal, plan, ex, version) is None


# --- B. a refused corrupted binding leaves ALL plan/exercise state unchanged --------------------


def _plan_state(session, plan_id):
    session.expire_all()
    p = session.get(DeploymentPlan, plan_id)
    ex = session.get(Exercise, p.exercise_id)
    audits = session.query(AuditEvent).filter_by(resource_id=str(plan_id)).count()
    return (
        p.status.value,
        ex.lifecycle_state.value,
        p.approved_content_hash,
        p.decided_by,
        p.decided_at,
        p.decision_reason,
        audits,
    )


def test_submit_refusal_leaves_state_unchanged(session, principal, client):
    _t, _v, _ex, plan = _published_plan(session, principal, name="no-mut-submit")
    _core_update(session, DeploymentPlan.__table__, plan.id, version_content_hash=_WRONG_HASH)
    before = _plan_state(session, plan.id)
    _assert_closed_409(client.post(f"/api/v1/plans/{plan.id}/submit"))
    assert _plan_state(session, plan.id) == before


def test_approve_refusal_leaves_state_unchanged(session, principal, client):
    _t, _v, _ex, plan = _published_plan(session, principal, name="no-mut-approve")
    assert client.post(f"/api/v1/plans/{plan.id}/submit").status_code == 200  # valid -> awaiting
    _core_update(session, DeploymentPlan.__table__, plan.id, version_content_hash=_WRONG_HASH)
    before = _plan_state(session, plan.id)
    _assert_closed_409(client.post(f"/api/v1/plans/{plan.id}/approve", json={"reason": "x"}))
    after = _plan_state(session, plan.id)
    assert after == before
    assert after[2] is None  # approved_content_hash never recorded
    assert after[3] is None and after[4] is None  # decided_by / decided_at never set


def test_reject_refusal_leaves_state_unchanged(session, principal, client):
    _t, _v, _ex, plan = _published_plan(session, principal, name="no-mut-reject")
    assert client.post(f"/api/v1/plans/{plan.id}/submit").status_code == 200
    _core_update(session, DeploymentPlan.__table__, plan.id, version_content_hash=_WRONG_HASH)
    before = _plan_state(session, plan.id)
    _assert_closed_409(client.post(f"/api/v1/plans/{plan.id}/reject", json={"reason": "x"}))
    assert _plan_state(session, plan.id) == before


# --- C. the public exact-version read route keeps its normal 404/403 (NOT converted to 409) -----


def test_public_read_nonexistent_stays_404(client):
    r = client.get(f"/api/v1/environment-versions/{uuid.uuid4()}")
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "not_found"
    assert r.json() != {"error": {"code": "plan_version_binding_invalid"}}


def test_public_read_cross_org_stays_403(session, client):
    other_v, _other_ex = _other_org_version_and_exercise(session)
    r = client.get(f"/api/v1/environment-versions/{other_v.id}")
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "forbidden"
    assert r.json() != {"error": {"code": "plan_version_binding_invalid"}}


# --- D. valid behavior is unchanged on real PostgreSQL -----------------------------------------


def test_valid_published_lifecycle_succeeds_with_provenance(session, principal, client):
    _t, version, ex, plan = _published_plan(session, principal, name="valid-pub")
    r = client.get(f"/api/v1/exercises/{ex.id}/plan")
    assert r.status_code == 200
    assert r.json()["environment_version_binding"]["publication_provenance"] is not None
    assert client.post(f"/api/v1/plans/{plan.id}/submit").status_code == 200
    ar = client.post(f"/api/v1/plans/{plan.id}/approve", json={"reason": "ok"})
    assert ar.status_code == 200
    assert ar.json()["approved_content_hash"] == version.content_hash
    assert ar.json()["environment_version_binding"]["publication_provenance"] is not None


def test_valid_legacy_lifecycle_succeeds_with_null_provenance(session, principal, client):
    template = _template(session, principal)
    version = catalog.create_version(
        session, principal, template_id=template.id, definition=_v1alpha1_def()
    )
    exercise = exercises.create_exercise(
        session, principal, template_id=template.id, version_id=version.id, name="valid-legacy"
    )
    exercises.validate_exercise(session, principal, exercise.id)
    plan = planning.generate_plan(session, principal, exercise.id)
    session.commit()
    assert client.post(f"/api/v1/plans/{plan.id}/submit").status_code == 200
    ar = client.post(f"/api/v1/plans/{plan.id}/approve", json={"reason": "ok"})
    assert ar.status_code == 200
    assert ar.json()["environment_version_binding"]["publication_provenance"] is None
    assert ar.json()["approved_content_hash"] == version.content_hash
