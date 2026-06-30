"""AC2.3 — organization-scoped authorization boundaries (assignment Phase 2 rule 7)."""

from __future__ import annotations

import pytest
from secp_api.errors import AuthorizationError


def test_cross_org_template_access_denied(
    session, principal, other_org_principal, template_and_version
):
    from secp_api.services import catalog

    template, _ = template_and_version
    # A principal from another org must not read this org's template.
    with pytest.raises(AuthorizationError):
        catalog.get_template(session, other_org_principal, template.id)


def test_cross_org_version_access_denied(
    session, principal, other_org_principal, template_and_version
):
    from secp_api.services import catalog

    _, version = template_and_version
    with pytest.raises(AuthorizationError):
        catalog.get_version(session, other_org_principal, version.id)


def test_listing_is_scoped_to_own_org(
    session, principal, other_org_principal, template_and_version
):
    from secp_api.services import catalog

    # The other org sees none of this org's templates.
    assert catalog.list_templates(session, other_org_principal) == []
    # This org sees its own.
    assert len(catalog.list_templates(session, principal)) >= 1


def test_missing_permission_denied(session, principal, valid_definition):
    """A principal lacking plan:approve cannot approve, even within its org."""
    from secp_api.auth import Principal
    from secp_api.enums import Permission
    from secp_api.services import catalog, exercises, planning

    template = catalog.create_template(session, principal, name="T", slug="t-perm")
    version = catalog.create_version(
        session, principal, template_id=template.id, definition=valid_definition
    )
    exercise = exercises.create_exercise(
        session, principal, template_id=template.id, version_id=version.id, name="x"
    )
    exercises.validate_exercise(session, principal, exercise.id)
    plan = planning.generate_plan(session, principal, exercise.id)
    planning.submit_plan(session, principal, plan.id)
    session.commit()

    weak = Principal(
        user_id=principal.user_id,
        organization_id=principal.organization_id,
        email=principal.email,
        permissions=frozenset({Permission.plan_generate}),  # no plan:approve
    )
    with pytest.raises(AuthorizationError):
        planning.approve_plan(session, weak, plan.id, "nope")
