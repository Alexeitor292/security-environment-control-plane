"""Service + workflow + permission + audit tests for topology authoring (SECP-B9)."""

from __future__ import annotations

import pytest
from secp_api.auth import Principal
from secp_api.enums import (
    AuditAction,
    Permission,
    TopologyAuthoringStatus,
    TopologyRevisionStatus,
    TopologyValidationStatus,
)
from secp_api.errors import ImmutableResourceError, TopologyAuthoringError
from secp_api.models import AuditEvent
from secp_api.services import topology_authoring as svc

SCHEMA = "secp.topology/v1"


def _valid_doc():
    return {
        "schema_version": SCHEMA,
        "nodes": [
            {"id": "atk", "kind": "attacker", "label": "attacker", "x": 40, "y": 40},
            {"id": "web", "kind": "target", "label": "web", "x": 260, "y": 40},
            {"id": "sen", "kind": "sensor", "label": "sensor", "x": 480, "y": 40},
            {"id": "net", "kind": "network", "label": "team-net", "x": 160, "y": 260},
        ],
        "edges": [
            {"id": "e-atk", "source": "atk", "target": "net", "kind": "network"},
            {"id": "e-web", "source": "web", "target": "net", "kind": "network"},
            {"id": "e-sen", "source": "sen", "target": "net", "kind": "network"},
            {"id": "e-mon", "source": "sen", "target": "web", "kind": "monitors"},
        ],
        "networks": [{"id": "net", "label": "team-net", "cidr": "10.20.0.0/24"}],
        "zones": [],
    }


def _restricted(principal: Principal, *perms: Permission) -> Principal:
    return Principal(
        user_id=principal.user_id,
        organization_id=principal.organization_id,
        email=principal.email,
        permissions=frozenset(perms),
    )


def _audit_actions(session, organization_id=None) -> list[str]:
    q = session.query(AuditEvent)
    rows = q.all()
    return [r.action for r in rows]


# --------------------------------------------------------------- lifecycle


def _drive_to_submitted(session, principal):
    doc = svc.create_draft(session, principal, display_name="Web Breach", document=_valid_doc())
    session.flush()
    rev = svc._current_revision(session, doc)
    result = svc.validate_revision(
        session, principal, doc.id, rev.id, expected_content_hash=rev.content_hash
    )
    assert result.status == TopologyValidationStatus.valid
    svc.submit_revision(session, principal, doc.id, rev.id, expected_content_hash=rev.content_hash)
    return doc, rev


class TestDraftAndRevisions:
    def test_create_draft_makes_revision_one(self, session, principal):
        doc = svc.create_draft(session, principal, display_name="D", document=_valid_doc())
        session.flush()
        assert doc.revision_count == 1
        rev = svc._current_revision(session, doc)
        assert rev.revision_number == 1
        assert rev.status == TopologyRevisionStatus.draft
        assert rev.content_hash.startswith("sha256:")
        assert doc.status == TopologyAuthoringStatus.draft

    def test_create_draft_from_version_derives_topology(
        self, session, principal, template_and_version
    ):
        _, version = template_and_version
        doc = svc.create_draft(
            session,
            principal,
            display_name="From version",
            source_environment_version_id=version.id,
        )
        session.flush()
        rev = svc._current_revision(session, doc)
        # The valid definition has roles + a network, so nodes were derived.
        assert len(rev.document_content["nodes"]) > 0
        assert doc.source_environment_version_id == version.id

    def test_create_draft_from_foreign_version_fails_closed(
        self, session, principal, other_org_principal, template_and_version
    ):
        _, version = template_and_version  # in principal's org
        with pytest.raises(TopologyAuthoringError) as e:
            svc.create_draft(
                session,
                other_org_principal,
                display_name="x",
                source_environment_version_id=version.id,
            )
        assert e.value.code == "topology_cross_org_forbidden"

    def test_revision_monotonicity_and_parent(self, session, principal):
        doc = svc.create_draft(session, principal, display_name="D", document=_valid_doc())
        session.flush()
        r1 = svc._current_revision(session, doc)
        doc2 = _valid_doc()
        doc2["nodes"][0]["x"] = 999
        r2 = svc.create_revision(
            session,
            principal,
            doc.id,
            base_revision_number=1,
            base_content_hash=r1.content_hash,
            document=doc2,
        )
        assert r2.revision_number == 2
        assert r2.parent_revision_id == r1.id
        assert r2.content_hash != r1.content_hash

    def test_stale_base_revision_fails_closed(self, session, principal):
        doc = svc.create_draft(session, principal, display_name="D", document=_valid_doc())
        session.flush()
        with pytest.raises(TopologyAuthoringError) as e:
            svc.create_revision(
                session,
                principal,
                doc.id,
                base_revision_number=99,
                base_content_hash="sha256:x",
                document=_valid_doc(),
            )
        assert e.value.code == "topology_revision_stale"

    def test_stale_base_hash_fails_closed(self, session, principal):
        doc = svc.create_draft(session, principal, display_name="D", document=_valid_doc())
        session.flush()
        with pytest.raises(TopologyAuthoringError) as e:
            svc.create_revision(
                session,
                principal,
                doc.id,
                base_revision_number=1,
                base_content_hash="sha256:wrong",
                document=_valid_doc(),
            )
        assert e.value.code == "topology_hash_mismatch"

    def test_revision_content_is_immutable(self, session, principal):
        doc = svc.create_draft(session, principal, display_name="D", document=_valid_doc())
        session.commit()
        rev = svc._current_revision(session, doc)
        rev.content_hash = "sha256:tampered"
        with pytest.raises(ImmutableResourceError):
            session.flush()
        session.rollback()

    def test_revision_cannot_be_deleted(self, session, principal):
        doc = svc.create_draft(session, principal, display_name="D", document=_valid_doc())
        session.commit()
        rev = svc._current_revision(session, doc)
        session.delete(rev)
        with pytest.raises(ImmutableResourceError):
            session.flush()
        session.rollback()

    def test_cross_org_read_fails_closed(self, session, principal, other_org_principal):
        doc = svc.create_draft(session, principal, display_name="D", document=_valid_doc())
        session.commit()
        with pytest.raises(TopologyAuthoringError) as e:
            svc.get_document(session, other_org_principal, doc.id)
        assert e.value.code == "topology_cross_org_forbidden"


class TestValidationWorkflow:
    def test_validation_pins_to_hash_and_never_mutates_content(self, session, principal):
        doc = svc.create_draft(session, principal, display_name="D", document=_valid_doc())
        session.flush()
        rev = svc._current_revision(session, doc)
        before = rev.content_hash
        result = svc.validate_revision(
            session, principal, doc.id, rev.id, expected_content_hash=rev.content_hash
        )
        assert result.content_hash == before
        assert rev.content_hash == before  # unchanged
        assert result.status == TopologyValidationStatus.valid
        assert rev.status == TopologyRevisionStatus.validated

    def test_validation_hash_mismatch_fails_closed(self, session, principal):
        doc = svc.create_draft(session, principal, display_name="D", document=_valid_doc())
        session.flush()
        rev = svc._current_revision(session, doc)
        with pytest.raises(TopologyAuthoringError) as e:
            svc.validate_revision(
                session, principal, doc.id, rev.id, expected_content_hash="sha256:no"
            )
        assert e.value.code == "topology_hash_mismatch"

    def test_invalid_document_stays_draft(self, session, principal):
        bad = _valid_doc()
        bad["edges"].append({"id": "bad", "source": "net", "target": "net", "kind": "network"})
        doc = svc.create_draft(session, principal, display_name="D", document=bad)
        session.flush()
        rev = svc._current_revision(session, doc)
        result = svc.validate_revision(
            session, principal, doc.id, rev.id, expected_content_hash=rev.content_hash
        )
        assert result.status == TopologyValidationStatus.invalid
        assert rev.status == TopologyRevisionStatus.draft  # not advanced

    def test_new_revision_makes_validation_stale(self, session, principal):
        doc = svc.create_draft(session, principal, display_name="D", document=_valid_doc())
        session.flush()
        r1 = svc._current_revision(session, doc)
        svc.validate_revision(
            session, principal, doc.id, r1.id, expected_content_hash=r1.content_hash
        )
        assert svc.validation_status_for_current(session, doc) == TopologyValidationStatus.valid
        moved = _valid_doc()
        moved["nodes"][0]["x"] = 12345
        svc.create_revision(
            session,
            principal,
            doc.id,
            base_revision_number=1,
            base_content_hash=r1.content_hash,
            document=moved,
        )
        # the new current revision has no validation → unverifiable, and the
        # aggregate is back to draft.
        assert doc.status == TopologyAuthoringStatus.draft
        assert (
            svc.validation_status_for_current(session, doc) == TopologyValidationStatus.unverifiable
        )


class TestSubmitApproveSeparation:
    def test_cannot_submit_unvalidated_revision(self, session, principal):
        doc = svc.create_draft(session, principal, display_name="D", document=_valid_doc())
        session.flush()
        rev = svc._current_revision(session, doc)
        with pytest.raises(TopologyAuthoringError) as e:
            svc.submit_revision(
                session, principal, doc.id, rev.id, expected_content_hash=rev.content_hash
            )
        assert e.value.code == "topology_validation_required"

    def test_submit_then_approve_records_decision_only(self, session, principal):
        doc, rev = _drive_to_submitted(session, principal)
        assert doc.status == TopologyAuthoringStatus.submitted
        approved = svc.approve_revision(
            session,
            principal,
            doc.id,
            rev.id,
            expected_content_hash=rev.content_hash,
            reason="looks good",
        )
        assert approved.status == TopologyRevisionStatus.approved
        assert approved.decided_by == principal.user_id
        assert doc.status == TopologyAuthoringStatus.approved
        assert doc.approved_revision_id == rev.id
        # Approval generated NO plan and NO deployment: there is no plan record
        # and the aggregate exposes no plan pointer.
        assert not hasattr(doc, "generated_plan_id")

    def test_cannot_approve_unsubmitted_revision(self, session, principal):
        doc = svc.create_draft(session, principal, display_name="D", document=_valid_doc())
        session.flush()
        rev = svc._current_revision(session, doc)
        with pytest.raises(TopologyAuthoringError) as e:
            svc.approve_revision(
                session, principal, doc.id, rev.id, expected_content_hash=rev.content_hash
            )
        assert e.value.code == "topology_not_submitted"

    def test_approve_hash_mismatch_fails_closed(self, session, principal):
        doc, rev = _drive_to_submitted(session, principal)
        with pytest.raises(TopologyAuthoringError) as e:
            svc.approve_revision(
                session, principal, doc.id, rev.id, expected_content_hash="sha256:stale"
            )
        assert e.value.code == "topology_hash_mismatch"

    def test_new_revision_after_approval_requires_new_review(self, session, principal):
        doc, rev = _drive_to_submitted(session, principal)
        svc.approve_revision(
            session, principal, doc.id, rev.id, expected_content_hash=rev.content_hash
        )
        assert doc.status == TopologyAuthoringStatus.approved
        moved = _valid_doc()
        moved["nodes"][1]["x"] = 777
        svc.create_revision(
            session,
            principal,
            doc.id,
            base_revision_number=1,
            base_content_hash=rev.content_hash,
            document=moved,
        )
        # the aggregate reopens to draft; the previously approved revision stays
        # frozen as a historical record.
        assert doc.status == TopologyAuthoringStatus.draft
        assert doc.submitted_revision_id is None
        session.refresh(rev)
        assert rev.status == TopologyRevisionStatus.approved

    def test_reject_records_decision(self, session, principal):
        doc, rev = _drive_to_submitted(session, principal)
        rejected = svc.reject_revision(
            session,
            principal,
            doc.id,
            rev.id,
            expected_content_hash=rev.content_hash,
            reason="boundary too wide",
        )
        assert rejected.status == TopologyRevisionStatus.rejected
        assert doc.status == TopologyAuthoringStatus.rejected


class TestPermissionSeparation:
    def test_drafter_cannot_validate_submit_or_decide(self, session, principal):
        drafter = _restricted(principal, Permission.topology_draft, Permission.topology_read)
        doc = svc.create_draft(session, drafter, display_name="D", document=_valid_doc())
        session.flush()
        rev = svc._current_revision(session, doc)
        for call in (
            lambda: svc.validate_revision(
                session, drafter, doc.id, rev.id, expected_content_hash=rev.content_hash
            ),
            lambda: svc.submit_revision(
                session, drafter, doc.id, rev.id, expected_content_hash=rev.content_hash
            ),
            lambda: svc.approve_revision(
                session, drafter, doc.id, rev.id, expected_content_hash=rev.content_hash
            ),
        ):
            with pytest.raises(TopologyAuthoringError) as e:
                call()
            assert e.value.code == "topology_permission_denied"

    def test_validator_cannot_approve(self, session, principal):
        doc, rev = _drive_to_submitted(session, principal)
        validator = _restricted(principal, Permission.topology_validate, Permission.topology_read)
        with pytest.raises(TopologyAuthoringError) as e:
            svc.approve_revision(
                session, validator, doc.id, rev.id, expected_content_hash=rev.content_hash
            )
        assert e.value.code == "topology_permission_denied"

    def test_reader_cannot_draft(self, session, principal):
        reader = _restricted(principal, Permission.topology_read)
        with pytest.raises(TopologyAuthoringError) as e:
            svc.create_draft(session, reader, display_name="D", document=_valid_doc())
        assert e.value.code == "topology_permission_denied"


class TestAudit:
    def test_accepted_mutations_are_audited_safely(self, session, principal):
        doc, rev = _drive_to_submitted(session, principal)
        svc.approve_revision(
            session, principal, doc.id, rev.id, expected_content_hash=rev.content_hash
        )
        session.flush()
        actions = _audit_actions(session)
        for expected in (
            AuditAction.topology_draft_created.value,
            AuditAction.topology_validation_recorded.value,
            AuditAction.topology_submitted.value,
            AuditAction.topology_approved.value,
        ):
            assert expected in actions
        # audit payloads carry ids/hashes/counts only — never the document body.
        for ev in session.query(AuditEvent).all():
            assert "document_content" not in ev.data
            assert "nodes" not in ev.data

    def test_refused_mutation_is_audited(self, session, principal):
        doc = svc.create_draft(session, principal, display_name="D", document=_valid_doc())
        session.flush()
        try:
            svc.create_revision(
                session,
                principal,
                doc.id,
                base_revision_number=1,
                base_content_hash="sha256:wrong",
                document=_valid_doc(),
            )
        except TopologyAuthoringError:
            pass
        session.flush()
        refused = [e for e in session.query(AuditEvent).all() if e.outcome == "refused"]
        assert any(e.action == AuditAction.topology_revision_refused.value for e in refused)
        assert all("code" in e.data for e in refused)


class TestReviewInvariants:
    def test_revalidating_an_approved_revision_does_not_downgrade_the_aggregate(
        self, session, principal
    ):
        doc, rev = _drive_to_submitted(session, principal)
        svc.approve_revision(
            session, principal, doc.id, rev.id, expected_content_hash=rev.content_hash
        )
        assert doc.status == TopologyAuthoringStatus.approved
        svc.validate_revision(
            session, principal, doc.id, rev.id, expected_content_hash=rev.content_hash
        )
        assert doc.status == TopologyAuthoringStatus.approved
        session.refresh(rev)
        assert rev.status == TopologyRevisionStatus.approved

    def test_new_revision_after_approval_clears_approved_pointer(self, session, principal):
        doc, rev = _drive_to_submitted(session, principal)
        svc.approve_revision(
            session, principal, doc.id, rev.id, expected_content_hash=rev.content_hash
        )
        moved = _valid_doc()
        moved["nodes"][0]["x"] = 4321
        svc.create_revision(
            session,
            principal,
            doc.id,
            base_revision_number=1,
            base_content_hash=rev.content_hash,
            document=moved,
        )
        assert doc.approved_revision_id is None

    def test_secret_shaped_decision_reason_is_refused(self, session, principal):
        doc, rev = _drive_to_submitted(session, principal)
        with pytest.raises(TopologyAuthoringError) as e:
            svc.approve_revision(
                session,
                principal,
                doc.id,
                rev.id,
                expected_content_hash=rev.content_hash,
                reason="approved; token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload",
            )
        assert e.value.code == "topology_secret_field_forbidden"

    def test_content_validation_refusal_is_audited(self, session, principal):
        bad = _valid_doc()
        bad["nodes"][0]["kind"] = "rootkit"
        with pytest.raises(TopologyAuthoringError):
            svc.create_draft(session, principal, display_name="D", document=bad)
        session.flush()
        refused = [e for e in session.query(AuditEvent).all() if e.outcome == "refused"]
        assert any(e.data.get("code") == "topology_unknown_object_kind" for e in refused)

    def test_permission_denied_mutation_is_audited(self, session, principal):
        reader = _restricted(principal, Permission.topology_read)
        with pytest.raises(TopologyAuthoringError):
            svc.create_draft(session, reader, display_name="D", document=_valid_doc())
        session.flush()
        refused = [e for e in session.query(AuditEvent).all() if e.outcome == "refused"]
        assert any(e.data.get("code") == "topology_permission_denied" for e in refused)

    def test_cross_org_mutation_refusal_uses_stage_action(
        self, session, principal, other_org_principal
    ):
        doc = svc.create_draft(session, principal, display_name="D", document=_valid_doc())
        session.commit()
        rev = svc._current_revision(session, doc)
        with pytest.raises(TopologyAuthoringError) as e:
            svc.create_revision(
                session,
                other_org_principal,
                doc.id,
                base_revision_number=1,
                base_content_hash=rev.content_hash,
                document=_valid_doc(),
            )
        assert e.value.code == "topology_cross_org_forbidden"
        session.flush()
        refused = [x for x in session.query(AuditEvent).all() if x.outcome == "refused"]
        # bucketed under the revision stage, NOT decision — so audit filters cleanly
        assert any(
            x.action == AuditAction.topology_revision_refused.value
            and x.data.get("code") == "topology_cross_org_forbidden"
            for x in refused
        )

    def test_illegal_revision_status_transition_is_blocked(self, session, principal):
        doc, rev = _drive_to_submitted(session, principal)
        svc.approve_revision(
            session, principal, doc.id, rev.id, expected_content_hash=rev.content_hash
        )
        session.commit()
        session.refresh(rev)  # load the prior status so the guard can compare
        rev.status = TopologyRevisionStatus.draft  # approved -> draft is illegal
        with pytest.raises(ImmutableResourceError):
            session.flush()
        session.rollback()


class TestValidationResultImmutable:
    def test_validation_result_is_append_only(self, session, principal):
        doc = svc.create_draft(session, principal, display_name="D", document=_valid_doc())
        session.flush()
        rev = svc._current_revision(session, doc)
        result = svc.validate_revision(
            session, principal, doc.id, rev.id, expected_content_hash=rev.content_hash
        )
        session.commit()
        result.status = TopologyValidationStatus.invalid
        with pytest.raises(ImmutableResourceError):
            session.flush()
        session.rollback()
