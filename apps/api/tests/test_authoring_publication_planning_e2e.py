"""Full authoring-convergence end-to-end regression (ADR-016 PR E, deliverable 11).

Drives the ENTIRE explicit chain — every transition is a deliberate, separate step, and nothing
auto-triggers the next:

    template
      -> topology draft -> initial revision -> validate -> submit -> approve
      -> [approval published NO version]
      -> publish (v1alpha2 EnvironmentVersion, server-owned provenance)
      -> [exactly one version + typed provenance]
      -> exact idempotent replay -> [same version, no duplicate audit]
      -> [publication created NO exercise/plan/workflow/manifest]
      -> create exercise -> [no auto-plan] -> validate exercise
      -> generate plan -> [plan binds exactly that version; provenance matches; no authoring query]
      -> submit plan -> [no approval, no execution]
      -> approve plan -> [approved_content_hash == version hash; no workflow/manifest; unchanged]

The audit chain is asserted to contain the topology lifecycle, exactly ONE version.published, the
exercise, and plan.generated/submitted/approved. A second scenario runs the legacy v1alpha1 path
(provenance null) through the same plan lifecycle to prove backward compatibility. No test depends
on timestamp or UUID ordering.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from secp_api.enums import AuditAction, LifecycleState, PlanStatus
from secp_api.models import (
    DeploymentPlan,
    EnvironmentVersion,
    Exercise,
    ProvisioningManifest,
    WorkflowRun,
)
from secp_api.schemas import PlanOut, VersionOut
from secp_api.services import catalog, exercises, planning
from secp_api.topology_authoring_models import TopologyRevision
from tests.test_environment_publication_service import (  # type: ignore
    _template,
    _v1alpha1_def,
    approve_topology,
    base_definition,
    publish,
)

PUBLISH_URL = "/api/v1/environment-versions/publish"


@pytest.fixture
def client(engine, principal):
    """Real ASGI app on the per-test engine — used to publish through the ONE audited route so the
    version.published audit is exercised exactly as in production."""
    from secp_api.main import create_app

    app = create_app()
    app.router.on_startup.clear()
    return TestClient(app)


def _publish_body(template, approved) -> dict:
    return {
        "template_id": str(template.id),
        "definition": base_definition(),
        "topology_document_id": str(approved.document_id),
        "topology_revision_id": str(approved.revision_id),
        "expected_topology_content_hash": approved.content_hash,
        "validation_result_id": str(approved.validation_id),
        "base_environment_version_id": None,
    }


# --- helpers ------------------------------------------------------------------------------------


def _actions(session, org_id) -> list[str]:
    session.expire_all()
    from secp_api.models import AuditEvent

    return [e.action for e in session.query(AuditEvent).filter_by(organization_id=org_id).all()]


def _count(session, model) -> int:
    session.expire_all()
    return session.query(model).count()


def _assert_no_execution_side_effects(session) -> None:
    assert _count(session, WorkflowRun) == 0
    assert _count(session, ProvisioningManifest) == 0


# --- scenario 1: published v1alpha2 all the way to plan approval -------------------------------


def test_full_authoring_to_plan_approval_binds_one_published_version(session, principal, client):
    org = principal.organization_id
    template = _template(session, principal)
    session.commit()

    # -- authoring: draft -> initial revision -> validate -> submit -> approve --
    approved = approve_topology(session, principal)
    session.commit()
    # topology approval alone publishes NOTHING: no environment version exists yet.
    assert _count(session, EnvironmentVersion) == 0
    revision = session.get(TopologyRevision, approved.revision_id)
    approved_status_before = revision.status

    # -- publish via the ONE audited route: exactly one immutable v1alpha2 version + provenance --
    body = _publish_body(template, approved)
    r = client.post(PUBLISH_URL, json=body)
    assert r.status_code == 201, r.text
    session.expire_all()
    version = session.get(EnvironmentVersion, uuid.UUID(r.json()["id"]))
    assert _count(session, EnvironmentVersion) == 1
    assert version.api_version == "controlplane.security/v1alpha2"
    assert version.publication_fingerprint is not None
    version_out = VersionOut.from_version(version)
    assert version_out.publication_provenance is not None
    assert _actions(session, org).count(AuditAction.version_published.value) == 1

    # -- exact idempotent replay: same version, no duplicate row or audit --
    replay = client.post(PUBLISH_URL, json=body)
    assert replay.status_code == 200, replay.text
    assert replay.json()["id"] == str(version.id)
    assert _count(session, EnvironmentVersion) == 1
    assert _actions(session, org).count(AuditAction.version_published.value) == 1

    # -- publication created NO downstream planning/execution objects --
    assert _count(session, Exercise) == 0
    assert _count(session, DeploymentPlan) == 0
    _assert_no_execution_side_effects(session)
    # the approved topology revision is untouched by publication + replay.
    session.expire_all()
    assert session.get(TopologyRevision, approved.revision_id).status == approved_status_before

    # -- create exercise from the published version: NO auto-plan --
    exercise = exercises.create_exercise(
        session, principal, template_id=template.id, version_id=version.id, name="e2e"
    )
    session.commit()
    assert exercise.environment_version_id == version.id
    assert _count(session, DeploymentPlan) == 0  # creating an exercise generates no plan

    exercises.validate_exercise(session, principal, exercise.id)
    session.commit()

    # -- generate plan: binds EXACTLY the published version; provenance matches --
    plan = planning.generate_plan(session, principal, exercise.id)
    session.commit()
    assert plan.environment_version_id == version.id
    assert plan.version_content_hash == version.content_hash
    assert plan.status == PlanStatus.generated

    bound = planning.require_plan_version_binding(session, principal, plan)
    assert bound.id == version.id
    plan_out = PlanOut.from_plan(plan, bound)
    binding = plan_out.environment_version_binding
    assert binding is not None
    assert binding.environment_version_id == version.id
    assert binding.template_id == version.template_id
    assert binding.content_hash == version.content_hash
    # the plan's surfaced provenance IS the version's server-owned provenance (never plan.summary).
    assert binding.publication_provenance == version_out.publication_provenance

    # -- submit plan: no approval recorded, no execution --
    planning.submit_plan(session, principal, plan.id)
    session.commit()
    session.expire_all()
    plan = session.get(DeploymentPlan, plan.id)
    assert plan.status == PlanStatus.awaiting_approval
    assert plan.approved_content_hash is None
    _assert_no_execution_side_effects(session)

    # -- approve plan: records the verified immutable hash; still nothing deployed --
    planning.approve_plan(session, principal, plan.id, "approved e2e")
    session.commit()
    session.expire_all()
    plan = session.get(DeploymentPlan, plan.id)
    assert plan.status == PlanStatus.approved
    assert plan.approved_content_hash == version.content_hash
    _assert_no_execution_side_effects(session)
    # exercise stopped at 'approved' — approval deployed nothing.
    assert session.get(Exercise, exercise.id).lifecycle_state == LifecycleState.approved
    # the version + topology remain immutable/unchanged through the whole plan lifecycle.
    session.expire_all()
    assert session.get(EnvironmentVersion, version.id).content_hash == version.content_hash
    assert session.get(TopologyRevision, approved.revision_id).status == approved_status_before

    # -- the audit chain is the full explicit lineage, version.published exactly once --
    actions = _actions(session, org)
    for required in (
        AuditAction.topology_draft_created.value,
        AuditAction.topology_validation_recorded.value,
        AuditAction.topology_submitted.value,
        AuditAction.topology_approved.value,
        AuditAction.exercise_created.value,
        AuditAction.plan_generated.value,
        AuditAction.plan_submitted.value,
        AuditAction.plan_approved.value,
    ):
        assert required in actions, required
    assert actions.count(AuditAction.version_published.value) == 1
    # no deployment/dispatch action ever fired.
    for forbidden in (
        AuditAction.deploy_started.value,
        AuditAction.provisioning_apply_started.value,
        AuditAction.manifest_generated.value,
    ):
        assert forbidden not in actions, forbidden


def test_plan_generated_audit_carries_published_lineage_not_spec(session, principal):
    from secp_api.models import AuditEvent

    org = principal.organization_id
    template = _template(session, principal)
    approved = approve_topology(session, principal)
    version = publish(session, principal, template, approved)
    exercise = exercises.create_exercise(
        session, principal, template_id=template.id, version_id=version.id, name="e2e-audit"
    )
    exercises.validate_exercise(session, principal, exercise.id)
    planning.generate_plan(session, principal, exercise.id)
    session.commit()

    session.expire_all()
    ev = (
        session.query(AuditEvent)
        .filter_by(organization_id=org, action=AuditAction.plan_generated.value)
        .one()
    )
    # published lineage is present as visibility metadata...
    assert ev.data["version_origin"] == "published"
    assert ev.data["environment_version_id"] == str(version.id)
    assert ev.data["publication_fingerprint"] == version.publication_fingerprint
    assert ev.data["topology_revision_id"] == str(approved.revision_id)
    # ...but NO spec/topology/role/network/name content leaks into the audit.
    blob = str(ev.data)
    for banned in (
        "apiVersion",
        "roles",
        "attacker-1",
        "net-a",
        "img-a",
        "Environment",
        'topology":',
    ):
        assert banned not in blob


# --- scenario 2: legacy v1alpha1 stays fully plannable, provenance null ------------------------


def test_legacy_v1alpha1_version_plans_and_approves_with_null_provenance(session, principal):
    template = _template(session, principal)
    version = catalog.create_version(
        session, principal, template_id=template.id, definition=_v1alpha1_def()
    )
    session.commit()
    assert version.api_version == "controlplane.security/v1alpha1"
    assert version.publication_fingerprint is None

    exercise = exercises.create_exercise(
        session, principal, template_id=template.id, version_id=version.id, name="legacy"
    )
    exercises.validate_exercise(session, principal, exercise.id)
    plan = planning.generate_plan(session, principal, exercise.id)
    session.commit()

    bound = planning.require_plan_version_binding(session, principal, plan)
    binding = PlanOut.from_plan(plan, bound).environment_version_binding
    assert binding is not None
    assert binding.api_version == "controlplane.security/v1alpha1"
    # legacy version surfaces NO publication provenance.
    assert binding.publication_provenance is None

    # the full lifecycle still works and stays null-provenance throughout.
    planning.submit_plan(session, principal, plan.id)
    planning.approve_plan(session, principal, plan.id, "legacy approve")
    session.commit()
    session.expire_all()
    plan = session.get(DeploymentPlan, plan.id)
    assert plan.status == PlanStatus.approved
    assert plan.approved_content_hash == version.content_hash
    final_binding = PlanOut.from_plan(
        plan, planning.require_plan_version_binding(session, principal, plan)
    ).environment_version_binding
    assert final_binding is not None
    assert final_binding.publication_provenance is None

    # legacy planning triggered no auto-execution.
    _assert_no_execution_side_effects(session)


def test_legacy_plan_generated_audit_marks_legacy_manual_origin(session, principal):
    from secp_api.models import AuditEvent

    org = principal.organization_id
    template = _template(session, principal)
    version = catalog.create_version(
        session, principal, template_id=template.id, definition=_v1alpha1_def()
    )
    exercise = exercises.create_exercise(
        session, principal, template_id=template.id, version_id=version.id, name="legacy-audit"
    )
    exercises.validate_exercise(session, principal, exercise.id)
    planning.generate_plan(session, principal, exercise.id)
    session.commit()

    session.expire_all()
    ev = (
        session.query(AuditEvent)
        .filter_by(organization_id=org, action=AuditAction.plan_generated.value)
        .one()
    )
    assert ev.data["version_origin"] == "legacy_manual"
    # legacy lineage carries NO publication provenance ids/hashes.
    for absent in (
        "publication_fingerprint",
        "topology_document_id",
        "topology_revision_id",
        "base_environment_version_id",
    ):
        assert absent not in ev.data, absent
