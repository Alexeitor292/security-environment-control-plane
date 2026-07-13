"""Exact EnvironmentVersion read endpoint tests (ADR-016 PR E, deliverable 1).

``GET /api/v1/environment-versions/{version_id}`` is an exact, organization-scoped, read-only
single-version read. It replaces the frontend's list-all-then-scan for source-derived base
resolution. It performs NO mutation, writes NO audit event, does NO topology-authoring lookup,
takes NO caller template id, and never falls back to a list-all scan or a "latest" inference.
Published v1alpha2 returns typed provenance; legacy v1alpha1 returns null provenance.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from secp_api.deps import current_principal
from secp_api.models import AuditEvent, EnvironmentVersion
from secp_api.services import catalog
from tests.test_environment_publication_service import (  # type: ignore
    _template,
    _v1alpha1_def,
    approve_topology,
    publish,
)

READ_URL = "/api/v1/environment-versions/{}"
_FORBIDDEN = ("Traceback", "sqlalchemy", "psycopg", "IntegrityError", "pydantic")


@pytest.fixture
def client(engine, principal):
    from secp_api.main import create_app

    app = create_app()
    app.router.on_startup.clear()
    return TestClient(app)


def _override(client, principal) -> None:
    client.app.dependency_overrides[current_principal] = lambda: principal


def _audit_count(session) -> int:
    session.expire_all()
    return session.query(AuditEvent).count()


def _version_count(session) -> int:
    session.expire_all()
    return session.query(EnvironmentVersion).count()


# --- same-org happy path (published + legacy) --------------------------------------------------


def test_read_published_version_returns_typed_provenance(session, principal, client):
    template = _template(session, principal)
    approved = approve_topology(session, principal)
    version = publish(session, principal, template, approved)
    session.commit()

    r = client.get(READ_URL.format(version.id))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["id"] == str(version.id)
    assert body["template_id"] == str(template.id)
    assert body["api_version"] == "controlplane.security/v1alpha2"
    assert body["content_hash"] == version.content_hash

    prov = body["publication_provenance"]
    assert prov is not None
    assert prov["publication_fingerprint"] == version.publication_fingerprint
    assert prov["topology_revision_id"] == str(approved.revision_id)
    # the server-owned fingerprint is never embedded in the spec provenance
    assert "publication_fingerprint" not in body["spec"]["spec"]["publicationProvenance"]


def test_read_legacy_v1alpha1_version_returns_null_provenance(session, principal, client):
    template = _template(session, principal)
    version = catalog.create_version(
        session, principal, template_id=template.id, definition=_v1alpha1_def()
    )
    session.commit()

    r = client.get(READ_URL.format(version.id))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["api_version"] == "controlplane.security/v1alpha1"
    assert body["publication_provenance"] is None


# --- safe not-found ----------------------------------------------------------------------------


def test_read_nonexistent_version_is_safe_not_found(session, principal, client):
    r = client.get(READ_URL.format(uuid.uuid4()))
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "not_found"
    for token in _FORBIDDEN:
        assert token not in r.text


def test_read_malformed_id_is_rejected_without_leak(client):
    r = client.get(READ_URL.format("not-a-uuid"))
    assert r.status_code == 422
    for token in _FORBIDDEN:
        assert token not in r.text


# --- cross-org refusal -------------------------------------------------------------------------


def test_read_cross_org_is_refused(session, principal, other_org_principal, client):
    template = _template(session, principal)  # dev org's version
    version = catalog.create_version(
        session, principal, template_id=template.id, definition=_v1alpha1_def()
    )
    session.commit()

    _override(client, other_org_principal)
    r = client.get(READ_URL.format(version.id))
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "forbidden"
    # no foreign-object content beyond the closed code + message
    for token in _FORBIDDEN:
        assert token not in r.text


# --- read is a pure read: no mutation, no audit ------------------------------------------------


def test_read_creates_no_audit_and_no_mutation(session, principal, client):
    template = _template(session, principal)
    approved = approve_topology(session, principal)
    version = publish(session, principal, template, approved)
    session.commit()

    audits_before = _audit_count(session)
    versions_before = _version_count(session)

    for _ in range(3):
        assert client.get(READ_URL.format(version.id)).status_code == 200

    assert _audit_count(session) == audits_before
    assert _version_count(session) == versions_before
    # the version row content is untouched by reads
    session.expire_all()
    assert session.get(EnvironmentVersion, version.id).content_hash == version.content_hash
