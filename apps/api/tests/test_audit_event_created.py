"""AC2.2 — every mutation creates an immutable AuditEvent (Charter Invariant 10)."""

from __future__ import annotations

import pytest
from secp_api.enums import AuditAction
from secp_api.errors import ImmutableResourceError
from secp_api.models import AuditEvent


def _actions(session) -> list[str]:
    return [e.action for e in session.query(AuditEvent).all()]


def test_template_and_version_creation_are_audited(session, principal, valid_definition):
    from secp_api.services import catalog

    template = catalog.create_template(session, principal, name="T", slug="t-audit")
    catalog.create_version(session, principal, template_id=template.id, definition=valid_definition)
    session.commit()
    actions = _actions(session)
    assert AuditAction.template_created.value in actions
    assert AuditAction.version_created.value in actions


def test_full_flow_produces_expected_audit_chain(session, principal, running_exercise):
    running_exercise()
    actions = set(_actions(session))
    for expected in (
        AuditAction.exercise_created,
        AuditAction.exercise_validated,
        AuditAction.plan_generated,
        AuditAction.plan_submitted,
        AuditAction.plan_approved,
        AuditAction.deploy_started,
        AuditAction.deploy_completed,
        AuditAction.instance_created,
    ):
        assert expected.value in actions, f"missing audit action {expected.value}"


def test_audit_events_are_immutable(session, principal, valid_definition):
    from secp_api.services import catalog

    catalog.create_template(session, principal, name="T", slug="t-immut-audit")
    session.commit()
    event = session.query(AuditEvent).first()
    assert event is not None
    event.outcome = "tampered"
    with pytest.raises(ImmutableResourceError):
        session.flush()


def test_audit_events_cannot_be_deleted(session, principal, valid_definition):
    from secp_api.services import catalog

    catalog.create_template(session, principal, name="T", slug="t-del-audit")
    session.commit()
    event = session.query(AuditEvent).first()
    session.delete(event)
    with pytest.raises(ImmutableResourceError):
        session.flush()
