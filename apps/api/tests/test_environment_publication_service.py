"""Transactional publish_version service tests (SECP-B10 / ADR-016 PR B).

SQLite-runnable (logic, refusals, idempotency, bypass closure, ORM immutability). PostgreSQL
concurrency + raw-SQL immutability live in the postgres-gated companion modules.
"""

from __future__ import annotations

import copy
import uuid

import pytest
from secp_api.auth import Principal
from secp_api.enums import Permission
from secp_api.errors import (
    EnvironmentPublicationError,
    ImmutableResourceError,
    ValidationFailedError,
)
from secp_api.models import EnvironmentVersion
from secp_api.services import catalog
from secp_api.services import environment_publication as pub
from secp_api.services import topology_authoring as topo
from secp_api.topology_authoring_models import TopologyRevision

V1ALPHA2 = "controlplane.security/v1alpha2"


# --- matched (definition, topology) builders ---------------------------------------------------


def base_definition() -> dict:
    return {
        "apiVersion": V1ALPHA2,
        "kind": "Environment",
        "metadata": {"name": "pub-env"},
        "spec": {
            "teams": {"count": 1, "isolationPolicy": "strict"},
            "networks": [{"name": "net-a", "cidrStrategy": "per-team", "isolated": True}],
            "roles": [
                {"name": "attacker-1", "kind": "attacker", "image": "img-a", "network": "net-a"},
                {"name": "target-1", "kind": "target", "image": "img-t", "network": "net-a"},
            ],
            "requiredPlugins": ["simulator"],
        },
    }


def base_topology() -> dict:
    return {
        "schema_version": "secp.topology/v1",
        "nodes": [
            {"id": "attacker-1", "kind": "attacker", "network": "net-a", "x": 1, "y": 1},
            {"id": "target-1", "kind": "target", "network": "net-a", "x": 2, "y": 2},
            {"id": "net-a", "kind": "network"},
        ],
        "edges": [
            {"id": "e-a", "source": "attacker-1", "target": "net-a", "kind": "network"},
            {"id": "e-t", "source": "target-1", "target": "net-a", "kind": "network"},
        ],
        "networks": [{"id": "net-a", "isolated": True}],
        "zones": [],
    }


def _template(session, principal, slug: str | None = None):
    return catalog.create_template(
        session, principal, name="Pub T", slug=slug or f"pub-{uuid.uuid4().hex[:8]}"
    )


class Approved:
    def __init__(self, doc, revision, validation, content_hash):
        self.document_id = doc.id
        self.revision_id = revision.id
        self.validation_id = validation.id
        self.content_hash = content_hash
        self.source_version_id = doc.source_environment_version_id


def approve_topology(session, principal, *, topology=None, source_version_id=None, name="doc"):
    """Drive a topology draft -> validate -> submit -> approve; return the approved binding."""
    doc = topo.create_draft(
        session,
        principal,
        display_name=name,
        source_environment_version_id=source_version_id,
        document=topology if topology is not None else base_topology(),
    )
    revision = session.get(TopologyRevision, doc.current_revision_id)
    ch = revision.content_hash
    validation = topo.validate_revision(
        session, principal, doc.id, revision.id, expected_content_hash=ch
    )
    topo.submit_revision(session, principal, doc.id, revision.id, expected_content_hash=ch)
    topo.approve_revision(
        session, principal, doc.id, revision.id, expected_content_hash=ch, reason="ok"
    )
    session.flush()
    return Approved(doc, session.get(TopologyRevision, revision.id), validation, ch)


def publish(session, principal, template, approved, *, definition=None, base=None):
    return pub.publish_version(
        session,
        principal,
        template_id=template.id,
        definition=definition if definition is not None else base_definition(),
        topology_document_id=approved.document_id,
        topology_revision_id=approved.revision_id,
        expected_topology_content_hash=approved.content_hash,
        validation_result_id=approved.validation_id,
        base_environment_version_id=base,
    )


def _without(principal, permission) -> Principal:
    return Principal(
        user_id=principal.user_id,
        organization_id=principal.organization_id,
        email=principal.email,
        permissions=frozenset(principal.permissions) - {permission},
    )


def _only(principal, permissions) -> Principal:
    return Principal(
        user_id=principal.user_id,
        organization_id=principal.organization_id,
        email=principal.email,
        permissions=frozenset(permissions),
    )


def _assert_code(code_name, fn):
    with pytest.raises(EnvironmentPublicationError) as exc:
        fn()
    assert exc.value.code == code_name


# --- happy path --------------------------------------------------------------------------------


def test_publish_creates_immutable_v1alpha2_version_with_provenance(session, principal):
    template = _template(session, principal)
    approved = approve_topology(session, principal)
    version = publish(session, principal, template, approved)
    session.commit()

    assert isinstance(version, EnvironmentVersion)
    assert version.api_version == V1ALPHA2
    assert version.version_number == 1
    assert version.organization_id == principal.organization_id
    assert version.template_id == template.id
    assert version.created_by == principal.user_id
    # provenance is server-built from fetched records
    assert version.source_topology_document_id == approved.document_id
    assert version.source_topology_revision_id == approved.revision_id
    assert version.topology_validation_result_id == approved.validation_id
    assert version.base_environment_version_id is None
    assert version.publication_contract_version == "secp.publication/v1"
    assert version.publication_fingerprint.startswith("sha256:")
    assert version.content_hash.startswith("sha256:")
    # the composed spec embeds the approved topology + provenance
    assert version.spec["apiVersion"] == V1ALPHA2
    assert version.spec["spec"]["topology"]["schema_version"] == "secp.topology/v1"
    prov = version.spec["spec"]["publicationProvenance"]
    assert prov["topology_revision_id"] == str(approved.revision_id)
    assert version.topology_content_hash == prov["topology_content_hash"]


# --- permission (deliverable 4) ----------------------------------------------------------------


def test_publish_requires_version_publish_permission(session, principal):
    template = _template(session, principal)
    approved = approve_topology(session, principal)
    _assert_code(
        "version_publish_permission_denied",
        lambda: publish(
            session, _without(principal, Permission.version_publish), template, approved
        ),
    )


@pytest.mark.parametrize(
    "perm",
    [Permission.version_create, Permission.topology_decide, Permission.plan_generate],
)
def test_other_permissions_do_not_imply_version_publish(session, principal, perm):
    template = _template(session, principal)
    approved = approve_topology(session, principal)
    _assert_code(
        "version_publish_permission_denied",
        lambda: publish(session, _only(principal, {perm}), template, approved),
    )


# --- refusals ----------------------------------------------------------------------------------


def test_refuse_template_not_found(session, principal):
    approved = approve_topology(session, principal)

    class _T:
        id = uuid.uuid4()

    _assert_code(
        "version_publish_template_not_found", lambda: publish(session, principal, _T(), approved)
    )


def test_refuse_cross_org_template(session, principal, other_org_principal):
    template = _template(session, principal)  # principal's org
    approved = approve_topology(session, other_org_principal)  # other org's topology
    # other_org actor publishing to principal's template -> cross-org on the template
    _assert_code(
        "version_publish_cross_org_forbidden",
        lambda: publish(session, other_org_principal, template, approved),
    )


def test_refuse_topology_not_approved_when_only_validated(session, principal):
    template = _template(session, principal)
    doc = topo.create_draft(session, principal, display_name="d", document=base_topology())
    revision = session.get(TopologyRevision, doc.current_revision_id)
    ch = revision.content_hash
    validation = topo.validate_revision(
        session, principal, doc.id, revision.id, expected_content_hash=ch
    )
    session.flush()
    approved = Approved(doc, session.get(TopologyRevision, revision.id), validation, ch)
    _assert_code(
        "version_publish_topology_not_approved",
        lambda: publish(session, principal, template, approved),
    )


def test_refuse_topology_hash_mismatch(session, principal):
    template = _template(session, principal)
    approved = approve_topology(session, principal)
    approved.content_hash = "sha256:" + "00" * 32
    _assert_code(
        "version_publish_topology_hash_mismatch",
        lambda: publish(session, principal, template, approved),
    )


def test_refuse_validation_missing(session, principal):
    template = _template(session, principal)
    approved = approve_topology(session, principal)
    approved.validation_id = uuid.uuid4()
    _assert_code(
        "version_publish_validation_missing",
        lambda: publish(session, principal, template, approved),
    )


def test_refuse_caller_supplied_topology_in_definition(session, principal):
    template = _template(session, principal)
    approved = approve_topology(session, principal)
    d = base_definition()
    d["spec"]["topology"] = base_topology()
    _assert_code(
        "version_publish_topology_in_payload_forbidden",
        lambda: publish(session, principal, template, approved, definition=d),
    )


def test_refuse_caller_supplied_provenance_in_definition(session, principal):
    template = _template(session, principal)
    approved = approve_topology(session, principal)
    d = base_definition()
    d["spec"]["publicationProvenance"] = {"x": 1}
    _assert_code(
        "version_publish_provenance_in_payload_forbidden",
        lambda: publish(session, principal, template, approved, definition=d),
    )


def test_refuse_role_topology_mismatch(session, principal):
    template = _template(session, principal)
    approved = approve_topology(session, principal)
    d = base_definition()
    d["spec"]["roles"][0]["kind"] = "target"  # node attacker-1 is 'attacker'
    _assert_code(
        "version_publish_role_topology_mismatch",
        lambda: publish(session, principal, template, approved, definition=d),
    )


def test_refuse_unsupported_role_kind(session, principal):
    template = _template(session, principal)
    # topology of a single service-role node would be unrepresentable; drive an approved
    # topology and then publish a definition whose role kind is 'service'.
    approved = approve_topology(session, principal)
    d = base_definition()
    d["spec"]["roles"][0]["kind"] = "service"
    _assert_code(
        "version_publish_unsupported_role_kind",
        lambda: publish(session, principal, template, approved, definition=d),
    )


def test_refuse_definition_invalid_when_v1alpha1(session, principal):
    template = _template(session, principal)
    approved = approve_topology(session, principal)
    d = base_definition()
    d["apiVersion"] = "controlplane.security/v1alpha1"
    _assert_code(
        "version_publish_definition_invalid",
        lambda: publish(session, principal, template, approved, definition=d),
    )


# --- source/base/template policy (deliverable 9) -----------------------------------------------


def test_sourceless_doc_forbids_a_base(session, principal):
    template = _template(session, principal)
    approved = approve_topology(session, principal)  # no source version
    base = _template_version_id(session, principal, template)
    _assert_code(
        "version_publish_base_version_mismatch",
        lambda: publish(session, principal, template, approved, base=base),
    )


def _template_version_id(session, principal, template):
    v1 = catalog.create_version(
        session,
        principal,
        template_id=template.id,
        definition=_v1alpha1_def(),
    )
    session.flush()
    return v1.id


def _v1alpha1_def() -> dict:
    return {
        "apiVersion": "controlplane.security/v1alpha1",
        "kind": "Environment",
        "metadata": {"name": "seed"},
        "spec": {
            "teams": {"count": 1, "isolationPolicy": "strict"},
            "networks": [{"name": "net-a", "cidrStrategy": "per-team"}],
            "roles": [{"name": "r1", "kind": "target", "image": "i", "network": "net-a"}],
            "requiredPlugins": ["simulator"],
        },
    }


def test_source_derived_doc_requires_exact_base_and_template(session, principal):
    template = _template(session, principal)
    source_version = catalog.create_version(
        session, principal, template_id=template.id, definition=_v1alpha1_def()
    )
    session.flush()
    approved = approve_topology(session, principal, source_version_id=source_version.id)
    # (a) missing base -> required
    _assert_code(
        "version_publish_base_version_required",
        lambda: publish(session, principal, template, approved, base=None),
    )
    # (b) wrong base id -> mismatch
    _assert_code(
        "version_publish_base_version_mismatch",
        lambda: publish(session, principal, template, approved, base=uuid.uuid4()),
    )
    # (c) correct base but a different destination template -> template_mismatch
    other_template = _template(session, principal, slug="other-t")
    _assert_code(
        "version_publish_template_mismatch",
        lambda: publish(session, principal, other_template, approved, base=source_version.id),
    )
    # (d) correct base + correct template -> success
    version = publish(session, principal, template, approved, base=source_version.id)
    assert version.base_environment_version_id == source_version.id


# --- idempotency (deliverable 10) --------------------------------------------------------------


def test_exact_repeat_is_idempotent(session, principal):
    template = _template(session, principal)
    approved = approve_topology(session, principal)
    v1 = publish(session, principal, template, approved)
    session.commit()
    v2 = publish(session, principal, template, approved)
    session.commit()
    assert v1.id == v2.id
    assert v1.version_number == 1
    count = session.query(EnvironmentVersion).filter_by(template_id=template.id).count()
    assert count == 1


def test_changing_definition_creates_a_new_version(session, principal):
    template = _template(session, principal)
    approved = approve_topology(session, principal)
    v1 = publish(session, principal, template, approved)
    session.commit()
    d2 = base_definition()
    d2["metadata"]["displayName"] = "changed"
    v2 = publish(session, principal, template, approved, definition=d2)
    session.commit()
    assert v1.id != v2.id
    assert {v1.version_number, v2.version_number} == {1, 2}


def test_changing_destination_template_publishes_in_that_template(session, principal):
    approved = approve_topology(session, principal)  # sourceless
    ta = _template(session, principal, slug="ta")
    tb = _template(session, principal, slug="tb")
    va = publish(session, principal, ta, approved)
    session.commit()
    vb = publish(session, principal, tb, approved)
    session.commit()
    assert va.id != vb.id
    assert va.template_id == ta.id and vb.template_id == tb.id
    # same composed content, different server fingerprint (template_id is in the fingerprint)
    assert va.content_hash == vb.content_hash
    assert va.publication_fingerprint != vb.publication_fingerprint


def test_no_publication_input_row_is_mutated(session, principal):
    template = _template(session, principal)
    approved = approve_topology(session, principal)
    rev_before = session.get(TopologyRevision, approved.revision_id)
    status_before = rev_before.status
    publish(session, principal, template, approved)
    session.commit()
    rev_after = session.get(TopologyRevision, approved.revision_id)
    assert rev_after.status == status_before  # approved revision is never marked consumed


# --- bypass closure (deliverable 9) ------------------------------------------------------------


def test_direct_create_version_still_works_for_v1alpha1(session, principal):
    template = _template(session, principal)
    version = catalog.create_version(
        session, principal, template_id=template.id, definition=_v1alpha1_def()
    )
    assert version.api_version == "controlplane.security/v1alpha1"


def test_direct_create_version_refuses_v1alpha2(session, principal):
    template = _template(session, principal)
    d = base_definition()  # v1alpha2, no publication blocks
    with pytest.raises(ValidationFailedError):
        catalog.create_version(session, principal, template_id=template.id, definition=d)


def test_direct_create_version_refuses_fabricated_publication_envelope(session, principal):
    template = _template(session, principal)
    # A fully-shaped caller-fabricated v1alpha2 publication envelope must not persist directly.
    d = base_definition()
    d["spec"]["topology"] = base_topology()
    d["spec"]["publicationProvenance"] = {
        "topology_document_id": str(uuid.uuid4()),
        "topology_revision_id": str(uuid.uuid4()),
        "topology_content_hash": "sha256:" + "ab" * 32,
        "topology_validation_result_id": str(uuid.uuid4()),
        "topology_validation_result_hash": "sha256:" + "cd" * 32,
        "base_environment_version_id": None,
        "publication_contract_version": "secp.publication/v1",
    }
    with pytest.raises(ValidationFailedError):
        catalog.create_version(session, principal, template_id=template.id, definition=d)


# --- ORM immutability of the published row (deliverable 12) -------------------------------------


@pytest.mark.parametrize(
    "field,value",
    [
        ("publication_fingerprint", "sha256:" + "ff" * 32),
        ("source_topology_document_id", uuid.uuid4()),
        ("source_topology_revision_id", uuid.uuid4()),
        ("topology_content_hash", "sha256:" + "ff" * 32),
        ("topology_validation_result_id", uuid.uuid4()),
        ("topology_validation_result_hash", "sha256:" + "ff" * 32),
        ("base_environment_version_id", uuid.uuid4()),
        ("publication_contract_version", "secp.publication/v2"),
        ("organization_id", uuid.uuid4()),
        ("template_id", uuid.uuid4()),
        ("created_by", uuid.uuid4()),
        ("api_version", "controlplane.security/v1alpha1"),
    ],
)
def test_published_row_columns_are_immutable(session, principal, field, value):
    template = _template(session, principal)
    approved = approve_topology(session, principal)
    version = publish(session, principal, template, approved)
    session.commit()
    setattr(version, field, value)
    with pytest.raises(ImmutableResourceError):
        session.flush()


def test_published_spec_is_immutable(session, principal):
    template = _template(session, principal)
    approved = approve_topology(session, principal)
    version = publish(session, principal, template, approved)
    session.commit()
    new_spec = copy.deepcopy(version.spec)
    new_spec["metadata"]["name"] = "tampered"
    version.spec = new_spec
    with pytest.raises(ImmutableResourceError):
        session.flush()


def test_legacy_v1alpha1_row_still_works_and_is_immutable(session, principal):
    template = _template(session, principal)
    version = catalog.create_version(
        session, principal, template_id=template.id, definition=_v1alpha1_def()
    )
    session.commit()
    assert version.publication_fingerprint is None
    version.content_hash = "sha256:" + "ee" * 32
    with pytest.raises(ImmutableResourceError):
        session.flush()


# --- ORM insertion-coherence guard (deliverable 2/5) -------------------------------------------
#
# Direct ORM construction must not be able to persist a fabricated, partial, mismatched, or
# unpublished-v1alpha2 row (the publication service is the only legitimate v1alpha2 producer).
# Coherence negatives raise in before_flush, before any INSERT/FK evaluation, so arbitrary UUIDs
# in the binding columns are fine.


def _coherent_v1alpha2_kwargs(template, principal) -> dict:
    doc, rev, val = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    tch = "sha256:" + "a1" * 32
    vrh = "sha256:" + "b2" * 32
    fp = "sha256:" + "c3" * 32
    prov = {
        "topology_document_id": str(doc),
        "topology_revision_id": str(rev),
        "topology_content_hash": tch,
        "topology_validation_result_id": str(val),
        "topology_validation_result_hash": vrh,
        "base_environment_version_id": None,
        "publication_contract_version": "secp.publication/v1",
    }
    spec = {
        "apiVersion": V1ALPHA2,
        "kind": "Environment",
        "metadata": {"name": "pub"},
        "spec": {"publicationProvenance": prov},
    }
    return {
        "organization_id": template.organization_id,
        "template_id": template.id,
        "version_number": 1,
        "api_version": V1ALPHA2,
        "content_hash": "sha256:" + "d4" * 32,
        "spec": spec,
        "source_topology_document_id": doc,
        "source_topology_revision_id": rev,
        "topology_content_hash": tch,
        "topology_validation_result_id": val,
        "topology_validation_result_hash": vrh,
        "base_environment_version_id": None,
        "publication_contract_version": "secp.publication/v1",
        "publication_fingerprint": fp,
        "created_by": principal.user_id,
    }


def _null_all_publication(kw):
    for c in (
        "source_topology_document_id",
        "source_topology_revision_id",
        "topology_content_hash",
        "topology_validation_result_id",
        "topology_validation_result_hash",
        "base_environment_version_id",
        "publication_contract_version",
        "publication_fingerprint",
    ):
        kw[c] = None


def _spec_api(kw, value):
    kw["spec"] = copy.deepcopy(kw["spec"])
    kw["spec"]["apiVersion"] = value


def _spec_prov(kw, key, value):
    kw["spec"] = copy.deepcopy(kw["spec"])
    kw["spec"]["spec"]["publicationProvenance"][key] = value


_COHERENCE_MUTATORS = {
    "v1alpha2_all_publication_null": _null_all_publication,
    "partial_missing_topology_hash": lambda kw: kw.update(topology_content_hash=None),
    "wrong_contract_version": lambda kw: kw.update(
        publication_contract_version="secp.publication/v2"
    ),
    "spec_apiversion_mismatch": lambda kw: _spec_api(kw, "controlplane.security/v1alpha1"),
    "mirror_document_id": lambda kw: kw.update(source_topology_document_id=uuid.uuid4()),
    "mirror_revision_id": lambda kw: kw.update(source_topology_revision_id=uuid.uuid4()),
    "mirror_topology_hash": lambda kw: kw.update(topology_content_hash="sha256:" + "ee" * 32),
    "mirror_validation_id": lambda kw: kw.update(topology_validation_result_id=uuid.uuid4()),
    "mirror_validation_hash": lambda kw: kw.update(
        topology_validation_result_hash="sha256:" + "ee" * 32
    ),
    "mirror_base_disagreement": lambda kw: kw.update(base_environment_version_id=uuid.uuid4()),
    "mirror_contract_version": lambda kw: _spec_prov(
        kw, "publication_contract_version", "secp.publication/v2"
    ),
}


@pytest.mark.parametrize("name", sorted(_COHERENCE_MUTATORS))
def test_orm_insert_rejects_incoherent_v1alpha2_row(session, principal, name):
    template = _template(session, principal)
    kwargs = _coherent_v1alpha2_kwargs(template, principal)
    _COHERENCE_MUTATORS[name](kwargs)
    session.add(EnvironmentVersion(**kwargs))
    with pytest.raises(ImmutableResourceError):
        session.flush()


def test_orm_insert_rejects_spec_apiversion_not_matching_column(session, principal):
    # A v1alpha1 api_version whose spec claims v1alpha2 (or vice versa) is incoherent.
    template = _template(session, principal)
    version = EnvironmentVersion(
        organization_id=template.organization_id,
        template_id=template.id,
        version_number=1,
        api_version="controlplane.security/v1alpha1",
        content_hash="sha256:" + "d4" * 32,
        spec={"apiVersion": V1ALPHA2, "kind": "Environment", "metadata": {"name": "x"}},
        created_by=principal.user_id,
    )
    session.add(version)
    with pytest.raises(ImmutableResourceError):
        session.flush()


def test_orm_insert_rejects_v1alpha1_carrying_publication_column(session, principal):
    template = _template(session, principal)
    version = EnvironmentVersion(
        organization_id=template.organization_id,
        template_id=template.id,
        version_number=1,
        api_version="controlplane.security/v1alpha1",
        content_hash="sha256:" + "d4" * 32,
        spec={
            "apiVersion": "controlplane.security/v1alpha1",
            "kind": "Environment",
            "metadata": {"name": "x"},
        },
        publication_fingerprint="sha256:" + "c3" * 32,  # illegal on a v1alpha1 row
        created_by=principal.user_id,
    )
    session.add(version)
    with pytest.raises(ImmutableResourceError):
        session.flush()


def test_orm_insert_allows_coherent_v1alpha1_row(session, principal):
    template = _template(session, principal)
    version = EnvironmentVersion(
        organization_id=template.organization_id,
        template_id=template.id,
        version_number=1,
        api_version="controlplane.security/v1alpha1",
        content_hash="sha256:" + "d4" * 32,
        spec={
            "apiVersion": "controlplane.security/v1alpha1",
            "kind": "Environment",
            "metadata": {"name": "x"},
        },
        created_by=principal.user_id,
    )
    session.add(version)
    session.flush()  # coherent legacy row inserts cleanly
    assert version.id is not None
    assert version.publication_fingerprint is None
