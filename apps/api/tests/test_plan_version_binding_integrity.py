"""Plan / EnvironmentVersion binding-integrity tests (ADR-016 PR E, deliverable 12).

A DeploymentPlan binds exactly ONE immutable EnvironmentVersion via ``environment_version_id`` +
``version_content_hash``. Its typed read binding + publication provenance are always derived from
that exact version (never plan.summary or the spec), the binding cannot change after creation, the
verifier fails closed on any disagreement — with the redacted ``plan_version_binding_invalid`` and
NO disagreement values in the HTTP response — and published/legacy provenance survives the whole
generated -> submitted -> approved lifecycle unchanged.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from secp_api.errors import ImmutableResourceError, PlanVersionBindingError
from secp_api.models import DeploymentPlan, EnvironmentVersion
from secp_api.schemas import PlanOut, VersionOut
from secp_api.services import catalog, exercises, planning
from tests.test_environment_publication_service import (  # type: ignore
    _template,
    _v1alpha1_def,
    approve_topology,
    publish,
)


@pytest.fixture
def client(engine, principal):
    from secp_api.main import create_app

    app = create_app()
    app.router.on_startup.clear()
    return TestClient(app)


def _published_plan(session, principal):
    """A generated plan bound to a freshly published v1alpha2 version. Returns (version, plan)."""
    template = _template(session, principal)
    approved = approve_topology(session, principal)
    version = publish(session, principal, template, approved)
    exercise = exercises.create_exercise(
        session, principal, template_id=template.id, version_id=version.id, name="bind"
    )
    exercises.validate_exercise(session, principal, exercise.id)
    plan = planning.generate_plan(session, principal, exercise.id)
    session.commit()
    return version, plan


def _legacy_plan(session, principal):
    template = _template(session, principal)
    version = catalog.create_version(
        session, principal, template_id=template.id, definition=_v1alpha1_def()
    )
    exercise = exercises.create_exercise(
        session, principal, template_id=template.id, version_id=version.id, name="legacy-bind"
    )
    exercises.validate_exercise(session, principal, exercise.id)
    plan = planning.generate_plan(session, principal, exercise.id)
    session.commit()
    return version, plan


# --- serialized binding is derived from exactly the bound version ------------------------------


def test_binding_matches_plan_and_version_provenance(session, principal):
    version, plan = _published_plan(session, principal)
    binding = PlanOut.from_plan(
        plan, planning.require_plan_version_binding(session, principal, plan)
    ).environment_version_binding
    assert binding is not None
    assert binding.environment_version_id == plan.environment_version_id == version.id
    assert binding.content_hash == plan.version_content_hash == version.content_hash
    assert binding.publication_provenance == VersionOut.from_version(version).publication_provenance


def test_published_provenance_survives_generated_submitted_approved(session, principal, client):
    version, plan = _published_plan(session, principal)
    expected = VersionOut.from_version(version).publication_provenance
    assert expected is not None
    exercise_id = str(plan.exercise_id)

    # generated
    r = client.get(f"/api/v1/exercises/{exercise_id}/plan")
    assert r.status_code == 200
    assert r.json()["environment_version_binding"]["publication_provenance"] == expected.model_dump(
        mode="json"
    )

    # submitted
    r = client.post(f"/api/v1/plans/{plan.id}/submit")
    assert r.status_code == 200
    assert r.json()["environment_version_binding"]["publication_provenance"] == expected.model_dump(
        mode="json"
    )

    # approved
    r = client.post(f"/api/v1/plans/{plan.id}/approve", json={"reason": "ok"})
    assert r.status_code == 200
    body = r.json()
    assert body["environment_version_binding"]["publication_provenance"] == expected.model_dump(
        mode="json"
    )
    assert body["approved_content_hash"] == version.content_hash


def test_legacy_null_provenance_through_lifecycle(session, principal, client):
    _version, plan = _legacy_plan(session, principal)
    exercise_id = str(plan.exercise_id)
    for step in (
        lambda: client.get(f"/api/v1/exercises/{exercise_id}/plan"),
        lambda: client.post(f"/api/v1/plans/{plan.id}/submit"),
        lambda: client.post(f"/api/v1/plans/{plan.id}/approve", json={"reason": "ok"}),
    ):
        r = step()
        assert r.status_code == 200, r.text
        assert r.json()["environment_version_binding"]["publication_provenance"] is None


# --- synthetic mismatch fails closed at the serializer -----------------------------------------


def test_from_plan_with_mismatched_version_fails_closed(session, principal):
    _v1, plan = _published_plan(session, principal)
    # a DIFFERENT version (different template + hash) must never serialize against this plan.
    other_template = _template(session, principal)
    other_version = catalog.create_version(
        session, principal, template_id=other_template.id, definition=_v1alpha1_def()
    )
    session.commit()
    with pytest.raises(PlanVersionBindingError):
        PlanOut.from_plan(plan, other_version)


# --- the binding cannot change after creation (ORM immutability guard) --------------------------


@pytest.mark.parametrize("field", ["environment_version_id", "version_content_hash"])
def test_plan_binding_fields_immutable_after_creation(session, principal, field):
    _version, plan = _published_plan(session, principal)
    setattr(
        plan,
        field,
        uuid.uuid4() if field == "environment_version_id" else "sha256:" + "0" * 64,
    )
    with pytest.raises(ImmutableResourceError):
        session.flush()
    session.rollback()


def test_version_provenance_is_immutable(session, principal):
    version, _plan = _published_plan(session, principal)
    version.publication_fingerprint = "sha256:" + "0" * 64
    with pytest.raises(ImmutableResourceError):
        session.flush()
    session.rollback()


# --- defense in depth: a raw-SQL-corrupted binding is caught by the verifier -------------------
#
# The ORM before_flush guard cannot see a raw UPDATE (DB-level tampering / a hypothetical bug), so
# these prove the verifier itself re-checks and fails closed BEFORE any lifecycle mutation.


_CORRUPT_HASH = "sha256:" + "e" * 64


def _corrupt_hash_raw(session, plan_id) -> None:
    # A Core UPDATE on the mapped table: it uses the column types (correct UUID binding) but does
    # NOT pass through the ORM unit-of-work, so the before_flush immutability guard never sees it —
    # exactly the DB-level tampering the verifier must still catch.
    table = DeploymentPlan.__table__
    session.execute(
        table.update().where(table.c.id == plan_id).values(version_content_hash=_CORRUPT_HASH)
    )
    session.commit()
    session.expire_all()


def test_verifier_fails_closed_on_raw_corrupted_hash(session, principal):
    _version, plan = _published_plan(session, principal)
    _corrupt_hash_raw(session, plan.id)
    reloaded = session.get(DeploymentPlan, plan.id)
    with pytest.raises(PlanVersionBindingError):
        planning.require_plan_version_binding(session, principal, reloaded)


def test_submission_refuses_corrupted_binding_without_mutating(session, principal):
    _version, plan = _published_plan(session, principal)  # status 'generated'
    _corrupt_hash_raw(session, plan.id)
    with pytest.raises(PlanVersionBindingError):
        planning.submit_plan(session, principal, plan.id)
    session.rollback()
    session.expire_all()
    # status is unchanged — the refusal happened before the transition.
    assert session.get(DeploymentPlan, plan.id).status.value == "generated"


def test_approval_refuses_corrupted_binding_before_recording_hash(session, principal):
    _version, plan = _published_plan(session, principal)
    planning.submit_plan(session, principal, plan.id)  # -> awaiting_approval
    session.commit()
    _corrupt_hash_raw(session, plan.id)
    with pytest.raises(PlanVersionBindingError):
        planning.approve_plan(session, principal, plan.id, "should refuse")
    session.rollback()
    session.expire_all()
    reloaded = session.get(DeploymentPlan, plan.id)
    assert reloaded.status.value == "awaiting_approval"
    assert reloaded.approved_content_hash is None  # nothing was recorded


def test_http_response_leaks_no_disagreement_values_on_corrupt_binding(session, principal, client):
    version, plan = _published_plan(session, principal)
    _corrupt_hash_raw(session, plan.id)
    r = client.get(f"/api/v1/exercises/{plan.exercise_id}/plan")
    assert r.status_code == 409
    assert r.json() == {"error": {"code": "plan_version_binding_invalid"}}
    # neither the version's real hash nor the corrupted expected hash appears in the response.
    assert version.content_hash not in r.text
    assert _CORRUPT_HASH not in r.text
    assert str(version.id) not in r.text


# --- content_hash(spec) recompute branch (SQLite: real PostgreSQL's version-immutability trigger
#     legitimately forbids making a version row incoherent, so this defense-in-depth branch is
#     exercised on the trigger-free backend; we never claim the DB blocks it here) ---------------


def _corrupt_version_spec_raw(session, version_id) -> None:
    # Raw Core UPDATE of the version's spec so content_hash(spec) diverges from the stored
    # content_hash while every id/hash reference still matches — isolating the recompute check.
    table = EnvironmentVersion.__table__
    session.execute(
        table.update()
        .where(table.c.id == version_id)
        .values(spec={"apiVersion": "controlplane.security/v1alpha2", "tampered": True})
    )
    session.commit()
    session.expire_all()


def test_verifier_fails_closed_on_spec_hash_recompute_mismatch(session, principal):
    version, plan = _published_plan(session, principal)
    _corrupt_version_spec_raw(session, version.id)
    reloaded = session.get(DeploymentPlan, plan.id)
    with pytest.raises(PlanVersionBindingError):
        planning.require_plan_version_binding(session, principal, reloaded)


def test_http_recompute_mismatch_is_closed_409(session, principal, client):
    version, plan = _published_plan(session, principal)
    _corrupt_version_spec_raw(session, version.id)
    r = client.get(f"/api/v1/exercises/{plan.exercise_id}/plan")
    assert r.status_code == 409
    assert r.json() == {"error": {"code": "plan_version_binding_invalid"}}
    assert str(version.id) not in r.text
    assert version.content_hash not in r.text


# --- the verifier folds a cross-org actor (plan_org) into the same closed error ----------------


def test_verifier_folds_cross_org_actor_to_binding_error(session, principal, other_org_principal):
    # Defense in depth: even if the plan's org differs from the actor's, the verifier returns the
    # closed binding error rather than a 403 (the public get_plan gate blocks this upstream in HTTP;
    # the verifier still fails closed if reached).
    _version, plan = _published_plan(session, principal)
    with pytest.raises(PlanVersionBindingError):
        planning.require_plan_version_binding(session, other_org_principal, plan)
