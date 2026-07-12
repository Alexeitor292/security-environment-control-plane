"""Audited EnvironmentVersion publication API tests (ADR-016 PR C).

Drives the real ASGI app end to end: truthful 201-vs-200 idempotency, the typed publication
provenance read model, closed per-code HTTP mapping, request-validation redaction, atomic success
auditing, durable refusal auditing that survives rollback, audit-failure handling, and the absence
of any downstream side effect. The publication service (SECP-B10) remains the authoritative
permission and precondition boundary.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from secp_api.deps import current_principal
from secp_api.enums import (
    AuditAction,
    EnvironmentPublicationErrorCode,
    Permission,
)
from secp_api.errors import EnvironmentPublicationError
from secp_api.models import AuditEvent, EnvironmentVersion
from secp_api.topology_authoring_models import TopologyRevision
from tests.test_environment_publication_service import (  # type: ignore
    _template,
    _v1alpha1_def,
    approve_topology,
    base_definition,
    base_topology,
)

V1ALPHA2 = "controlplane.security/v1alpha2"
PUBLISH_URL = "/api/v1/environment-versions/publish"

# Backend internals / caller values that must NEVER appear in any response body.
_FORBIDDEN = ("Traceback", "sqlalchemy", "psycopg", "IntegrityError", "pydantic", "ctx")


@pytest.fixture
def client(engine, principal):
    """Real app on the per-test engine. ``principal`` has already bootstrapped the dev admin, whom
    ``current_principal`` resolves for unauthenticated requests."""
    from secp_api.main import create_app

    app = create_app()
    app.router.on_startup.clear()
    return TestClient(app)


@pytest.fixture
def ctx(session, principal, client):
    """A template + an approved topology revision + passing validation, committed and visible to
    the API's own session."""
    template = _template(session, principal)
    approved = approve_topology(session, principal)
    session.commit()
    return SimpleNamespace(
        session=session, principal=principal, client=client, template=template, approved=approved
    )


def _body(template, approved, *, definition=None, base=None, **overrides):
    body = {
        "template_id": str(template.id),
        "definition": definition if definition is not None else base_definition(),
        "topology_document_id": str(approved.document_id),
        "topology_revision_id": str(approved.revision_id),
        "expected_topology_content_hash": approved.content_hash,
        "validation_result_id": str(approved.validation_id),
        "base_environment_version_id": str(base) if base else None,
    }
    body.update(overrides)
    return body


def _versions(session, template_id):
    session.expire_all()
    return session.query(EnvironmentVersion).filter_by(template_id=template_id).all()


def _audits(session, action: AuditAction):
    session.expire_all()
    return session.query(AuditEvent).filter_by(action=action.value).all()


def _no_leak(response) -> None:
    text = response.text
    for token in _FORBIDDEN:
        assert token not in text, f"response leaked {token!r}: {text[:300]}"


# --- success + idempotency (deliverable 4/11) --------------------------------------------------


def test_publish_creates_version_201_with_typed_provenance(ctx):
    r = ctx.client.post(PUBLISH_URL, json=_body(ctx.template, ctx.approved))
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["api_version"] == V1ALPHA2
    assert body["version_number"] == 1
    assert body["template_id"] == str(ctx.template.id)

    versions = _versions(ctx.session, ctx.template.id)
    assert len(versions) == 1
    assert body["id"] == str(versions[0].id)
    assert body["content_hash"] == versions[0].content_hash

    # typed provenance mirrors the embedded spec.publicationProvenance exactly
    prov = body["publication_provenance"]
    embedded = body["spec"]["spec"]["publicationProvenance"]
    for key in (
        "topology_document_id",
        "topology_revision_id",
        "topology_content_hash",
        "topology_validation_result_id",
        "topology_validation_result_hash",
        "base_environment_version_id",
        "publication_contract_version",
    ):
        assert prov[key] == embedded[key], key
    # server-owned fingerprint is read-only data, NOT embedded in the spec provenance
    assert prov["publication_fingerprint"] == versions[0].publication_fingerprint
    assert "publication_fingerprint" not in embedded

    # exactly one success audit, atomic with the version
    published = _audits(ctx.session, AuditAction.version_published)
    assert len(published) == 1
    assert published[0].resource_id == str(versions[0].id)
    assert published[0].outcome == "success"


def test_exact_replay_returns_200_same_version_no_duplicate(ctx):
    body = _body(ctx.template, ctx.approved)
    first = ctx.client.post(PUBLISH_URL, json=body)
    assert first.status_code == 201
    second = ctx.client.post(PUBLISH_URL, json=body)
    assert second.status_code == 200, second.text
    assert second.json()["id"] == first.json()["id"]
    assert second.json()["version_number"] == 1

    assert len(_versions(ctx.session, ctx.template.id)) == 1  # no second row
    assert len(_audits(ctx.session, AuditAction.version_published)) == 1  # no duplicate audit


def test_changed_definition_creates_second_version(ctx):
    ctx.client.post(PUBLISH_URL, json=_body(ctx.template, ctx.approved))
    d2 = base_definition()
    d2["metadata"]["name"] = "pub-env-2"
    r2 = ctx.client.post(PUBLISH_URL, json=_body(ctx.template, ctx.approved, definition=d2))
    assert r2.status_code == 201
    assert {v.version_number for v in _versions(ctx.session, ctx.template.id)} == {1, 2}
    assert len(_audits(ctx.session, AuditAction.version_published)) == 2


# --- read model (deliverable 8/11) -------------------------------------------------------------


def test_legacy_v1alpha1_version_has_null_provenance(ctx):
    version = __import__("secp_api.services.catalog", fromlist=["create_version"]).create_version(
        ctx.session, ctx.principal, template_id=ctx.template.id, definition=_v1alpha1_def()
    )
    ctx.session.commit()
    r = ctx.client.get(f"/api/v1/templates/{ctx.template.id}/versions")
    assert r.status_code == 200
    row = next(v for v in r.json() if v["id"] == str(version.id))
    assert row["api_version"] == "controlplane.security/v1alpha1"
    assert row["publication_provenance"] is None


def test_list_versions_returns_typed_provenance_for_published(ctx):
    pub = ctx.client.post(PUBLISH_URL, json=_body(ctx.template, ctx.approved)).json()
    r = ctx.client.get(f"/api/v1/templates/{ctx.template.id}/versions")
    assert r.status_code == 200
    row = next(v for v in r.json() if v["id"] == pub["id"])
    assert row["publication_provenance"] == pub["publication_provenance"]
    assert row["publication_provenance"]["publication_fingerprint"].startswith("sha256:")


# --- permission + organization (deliverable 11) ------------------------------------------------


def _override(client, principal):
    client.app.dependency_overrides[current_principal] = lambda: principal


def _restricted(principal, permissions):
    from secp_api.auth import Principal

    return Principal(
        user_id=principal.user_id,
        organization_id=principal.organization_id,
        email=principal.email,
        permissions=frozenset(permissions),
    )


def test_missing_version_publish_returns_403(ctx):
    _override(
        ctx.client, _restricted(ctx.principal, set(Permission) - {Permission.version_publish})
    )
    r = ctx.client.post(PUBLISH_URL, json=_body(ctx.template, ctx.approved))
    assert r.status_code == 403
    assert r.json() == {"error": {"code": "version_publish_permission_denied"}}
    assert len(_versions(ctx.session, ctx.template.id)) == 0


@pytest.mark.parametrize("perm", [Permission.version_create, Permission.topology_decide])
def test_other_permissions_do_not_grant_publish(ctx, perm):
    _override(ctx.client, _restricted(ctx.principal, {perm}))
    r = ctx.client.post(PUBLISH_URL, json=_body(ctx.template, ctx.approved))
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "version_publish_permission_denied"


def test_cross_org_reference_returns_403_no_detail(session, principal, other_org_principal, client):
    template = _template(session, principal)  # dev org's template
    approved = approve_topology(session, other_org_principal, name="other")  # other org topology
    session.commit()
    _override(client, other_org_principal)
    r = client.post(PUBLISH_URL, json=_body(template, approved))
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "version_publish_cross_org_forbidden"
    _no_leak(r)
    assert str(template.id) not in {  # no foreign-object detail beyond the closed code
        k for k in r.json().get("error", {})
    }


# --- HTTP status mapping (deliverable 5/11) ----------------------------------------------------


def test_every_error_code_has_explicit_http_status():
    for code in EnvironmentPublicationErrorCode:
        assert code.value in EnvironmentPublicationError._STATUS, code
        assert EnvironmentPublicationError(code).http_status in {403, 404, 409, 422, 500}


def test_status_map_has_no_extra_or_missing_members():
    enum_values = {c.value for c in EnvironmentPublicationErrorCode}
    assert set(EnvironmentPublicationError._STATUS) == enum_values


def test_404_template_not_found(ctx):
    body = _body(ctx.template, ctx.approved, template_id=str(uuid.uuid4()))
    r = ctx.client.post(PUBLISH_URL, json=body)
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "version_publish_template_not_found"


def test_409_topology_hash_mismatch(ctx):
    body = _body(ctx.template, ctx.approved, expected_topology_content_hash="sha256:" + "0" * 64)
    r = ctx.client.post(PUBLISH_URL, json=body)
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "version_publish_topology_hash_mismatch"


def test_422_topology_in_payload_forbidden(ctx):
    d = base_definition()
    d["spec"]["topology"] = base_topology()
    r = ctx.client.post(PUBLISH_URL, json=_body(ctx.template, ctx.approved, definition=d))
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "version_publish_topology_in_payload_forbidden"


def test_422_provenance_in_payload_forbidden(ctx):
    d = base_definition()
    d["spec"]["publicationProvenance"] = {"x": 1}
    r = ctx.client.post(PUBLISH_URL, json=_body(ctx.template, ctx.approved, definition=d))
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "version_publish_provenance_in_payload_forbidden"


def test_422_definition_invalid_when_v1alpha1(ctx):
    d = base_definition()
    d["apiVersion"] = "controlplane.security/v1alpha1"
    r = ctx.client.post(PUBLISH_URL, json=_body(ctx.template, ctx.approved, definition=d))
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "version_publish_definition_invalid"


def test_422_role_topology_mismatch(ctx):
    d = base_definition()
    d["spec"]["roles"][0]["kind"] = "target"  # topology node attacker-1 is 'attacker'
    r = ctx.client.post(PUBLISH_URL, json=_body(ctx.template, ctx.approved, definition=d))
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "version_publish_role_topology_mismatch"


def test_contract_error_detail_is_never_serialized(ctx, monkeypatch):
    # The contract carries an internal ``detail`` for logs/tests; it must NEVER reach the caller —
    # only the closed code does.
    from secp_api.environment_publication_contract import PublicationContractError

    def boom(*a, **k):
        raise PublicationContractError(
            "version_publish_definition_invalid", "SECRET-INTERNAL-DETAIL"
        )

    monkeypatch.setattr(
        "secp_api.services.environment_publication.compose_published_definition", boom
    )
    r = ctx.client.post(PUBLISH_URL, json=_body(ctx.template, ctx.approved))
    assert r.status_code == 422
    assert r.json() == {"error": {"code": "version_publish_definition_invalid"}}
    assert "SECRET-INTERNAL-DETAIL" not in r.text


# --- input rejection + redaction (deliverable 6/11) --------------------------------------------

_MALFORMED = {
    "malformed_uuid": {"template_id": "not-a-uuid"},
    "malformed_hash": {"expected_topology_content_hash": "deadbeef"},
    "missing_required": {"__delete__": "validation_result_id"},
    "unknown_field": {"surprise": "value-should-not-echo"},
    "caller_idempotency_key": {"idempotency_key": "idem-should-not-echo"},
    "caller_fingerprint": {"publication_fingerprint": "sha256:" + "ab" * 32},
    "wrong_definition_type": {"definition": "a-string-not-a-mapping"},
}


@pytest.mark.parametrize("name", sorted(_MALFORMED))
def test_malformed_request_is_redacted(ctx, name):
    body = _body(ctx.template, ctx.approved)
    mutation = dict(_MALFORMED[name])
    drop = mutation.pop("__delete__", None)
    if drop:
        body.pop(drop)
    body.update(mutation)
    r = ctx.client.post(PUBLISH_URL, json=body)
    assert r.status_code == 422
    assert r.json() == {"error": {"code": "invalid_environment_publication_input"}}
    # the rejected value / field name must not be reflected
    for value in mutation.values():
        assert str(value) not in r.text
    _no_leak(r)
    # a redacted request never reached the service, so no version and no service-refusal audit
    assert len(_versions(ctx.session, ctx.template.id)) == 0
    assert len(_audits(ctx.session, AuditAction.version_publish_refused)) == 0


def test_redaction_does_not_affect_unrelated_routes(ctx):
    # a malformed body on the direct-create route keeps FastAPI's default (non-redacted) behavior
    r = ctx.client.post(f"/api/v1/templates/{ctx.template.id}/versions", json={"definition": 123})
    assert r.status_code == 422
    assert r.json() != {"error": {"code": "invalid_environment_publication_input"}}


# --- durable refusal auditing (deliverable 7/11) -----------------------------------------------


def test_service_refusal_creates_exactly_one_durable_denied_audit(ctx):
    body = _body(ctx.template, ctx.approved, template_id=str(uuid.uuid4()))
    r = ctx.client.post(PUBLISH_URL, json=body)
    assert r.status_code == 404
    refusals = _audits(ctx.session, AuditAction.version_publish_refused)
    assert len(refusals) == 1
    ev = refusals[0]
    assert ev.outcome == "denied"
    assert ev.resource_type == "environment_version_publication"
    assert set(ev.data) == {
        "refusal_code",
        "template_id",
        "topology_document_id",
        "topology_revision_id",
        "expected_topology_content_hash",
        "validation_result_id",
        "base_environment_version_id",
    }
    assert ev.data["refusal_code"] == "version_publish_template_not_found"
    assert "definition" not in ev.data
    # refusal survived the rollback WITHOUT persisting a version
    assert len(_versions(ctx.session, ctx.template.id)) == 0


def test_refusal_audit_survives_when_request_rolls_back(ctx):
    # topology_in_payload is a 422 raised after preconditions; the refusal must still be durable
    d = base_definition()
    d["spec"]["topology"] = base_topology()
    r = ctx.client.post(PUBLISH_URL, json=_body(ctx.template, ctx.approved, definition=d))
    assert r.status_code == 422
    refusals = _audits(ctx.session, AuditAction.version_publish_refused)
    assert len(refusals) == 1
    assert refusals[0].data["refusal_code"] == "version_publish_topology_in_payload_forbidden"


def _raise_boom(*_a, **_k):
    raise RuntimeError("boom")


def test_success_audit_failure_returns_closed_500_no_leak(ctx, monkeypatch):
    # HTTP contract on any backend: a failing success audit yields ONLY the closed audit-failure
    # code (never a raw audit/DB exception). The transactional "no version persists" atomicity is
    # a real-transaction property verified against PostgreSQL in test_postgres_publication.py
    # (SQLite's savepoint-release semantics differ and are not authoritative here).
    monkeypatch.setattr("secp_api.audit.record", _raise_boom)
    r = ctx.client.post(PUBLISH_URL, json=_body(ctx.template, ctx.approved))
    assert r.status_code == 500
    assert r.json() == {"error": {"code": "version_publish_audit_failure"}}
    _no_leak(r)


def test_refusal_audit_failure_returns_closed_500_no_leak(ctx, monkeypatch):
    monkeypatch.setattr("secp_api.audit.record", _raise_boom)
    body = _body(ctx.template, ctx.approved, template_id=str(uuid.uuid4()))
    r = ctx.client.post(PUBLISH_URL, json=body)
    assert r.status_code == 500
    assert r.json() == {"error": {"code": "version_publish_audit_failure"}}
    _no_leak(r)
    assert len(_versions(ctx.session, ctx.template.id)) == 0


def test_success_audit_payload_is_allowlisted_and_safe(ctx):
    ctx.client.post(PUBLISH_URL, json=_body(ctx.template, ctx.approved))
    ev = _audits(ctx.session, AuditAction.version_published)[0]
    assert set(ev.data) == {
        "template_id",
        "environment_version_id",
        "version_number",
        "environment_content_hash",
        "publication_fingerprint",
        "topology_document_id",
        "topology_revision_id",
        "topology_content_hash",
        "topology_validation_result_id",
        "topology_validation_result_hash",
        "base_environment_version_id",
        "publication_contract_version",
    }
    # No definition/topology CONTENT leaks (the allowlisted keys legitimately contain "topology_").
    blob = str(ev.data)
    for banned in (
        "apiVersion",
        "roles",
        "attacker-1",
        "net-a",
        "img-a",
        "findings",
        "Environment",
    ):
        assert banned not in blob


# --- direct-create boundary + no downstream side effects (deliverable 9/10/11) -----------------


def test_direct_create_v1alpha2_still_refused(ctx):
    r = ctx.client.post(
        f"/api/v1/templates/{ctx.template.id}/versions", json={"definition": base_definition()}
    )
    assert r.status_code == 422  # ValidationFailedError: v1alpha2 not creatable directly
    assert len(_versions(ctx.session, ctx.template.id)) == 0


def test_direct_create_v1alpha1_still_succeeds(ctx):
    r = ctx.client.post(
        f"/api/v1/templates/{ctx.template.id}/versions", json={"definition": _v1alpha1_def()}
    )
    assert r.status_code == 201
    assert r.json()["api_version"] == "controlplane.security/v1alpha1"
    assert r.json()["publication_provenance"] is None


def test_publish_creates_no_downstream_objects(ctx):
    from secp_api.models import (
        DeploymentPlan,
        Exercise,
        ProvisioningManifest,
        WorkflowRun,
    )

    rev_before = ctx.session.get(TopologyRevision, ctx.approved.revision_id)
    status_before = rev_before.status

    r = ctx.client.post(PUBLISH_URL, json=_body(ctx.template, ctx.approved))
    assert r.status_code == 201

    ctx.session.expire_all()
    assert ctx.session.query(Exercise).count() == 0
    assert ctx.session.query(DeploymentPlan).count() == 0
    assert ctx.session.query(WorkflowRun).count() == 0
    assert ctx.session.query(ProvisioningManifest).count() == 0
    # the approved topology revision is unchanged
    assert ctx.session.get(TopologyRevision, ctx.approved.revision_id).status == status_before


def test_definitions_validate_still_accepts_v1alpha2_without_persisting(ctx):
    r = ctx.client.post("/api/v1/definitions/validate", json={"definition": base_definition()})
    assert r.status_code == 200
    assert len(_versions(ctx.session, ctx.template.id)) == 0
