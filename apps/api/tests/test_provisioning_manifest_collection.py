"""``GET /api/v1/manifests`` — the collection route that made manifests reachable at all.

WHY THIS EXISTS
----------------
Every manifest route was parameterised on an id: ``/manifests/{id}``,
``/manifests/{id}/operations``, ``/manifests/{id}/change-sets``. Nothing enumerated them, and no
other route returned a manifest id. So a manifest was reachable ONLY by a caller that had just
created it in the same session, and change-set approvals — which hang off
``/manifests/{id}/change-sets`` — were not reachable at all.

That is a distinct category from a route that merely needs a parent id a screen can obtain. The id
here had no producer a client could call, so the surface was not "one selection step away", it was
unbuildable. A collection route is the only thing that closes it.
"""

from __future__ import annotations

import uuid

import pytest
from secp_api.auth import Principal
from secp_api.enums import Permission
from secp_api.errors import AuthorizationError
from secp_api.services import manifests


def _generate(session, principal, provisioning_env):
    env = provisioning_env()
    manifest = manifests.generate_manifest(session, principal, env.plan.id)
    session.commit()
    return env, manifest


def test_a_generated_manifest_is_enumerable(session, principal, provisioning_env):
    """The property the whole route exists for: reachable without already holding the id."""
    _, manifest = _generate(session, principal, provisioning_env)
    listed = manifests.list_manifests(session, principal)
    assert [row.id for row in listed] == [manifest.id]


def test_an_empty_organization_lists_nothing_rather_than_failing(session, principal):
    """An organization with no manifests gets an empty list, not an error.

    Stated because the distinction matters to a client: an empty collection means "none exist",
    and that is only a truthful answer while the route exists. A 404 would mean "not built".
    """
    assert manifests.list_manifests(session, principal) == []


def test_the_listing_is_organization_scoped_and_the_scope_is_not_a_filter(
    session, principal, other_org_principal, provisioning_env
):
    """The other organization's principal sees none of it.

    Scope comes from the PRINCIPAL, so there is no argument a caller can pass to widen it. This is
    the assertion that would fail if someone later added an ``organization_id`` query parameter as
    a convenience.
    """
    _, manifest = _generate(session, principal, provisioning_env)
    assert [row.id for row in manifests.list_manifests(session, principal)] == [manifest.id]
    assert manifests.list_manifests(session, other_org_principal) == []


def test_listing_requires_the_provisioning_read_permission(session, principal, provisioning_env):
    """Same permission as reading one. A collection must not be an easier door than an item."""
    _generate(session, principal, provisioning_env)
    unprivileged = Principal(
        user_id=principal.user_id,
        organization_id=principal.organization_id,
        email=principal.email,
        permissions=frozenset(p for p in Permission if p is not Permission.provisioning_read),
    )
    with pytest.raises(AuthorizationError):
        manifests.list_manifests(session, unprivileged)


def test_the_plan_filter_narrows_within_scope_and_never_escapes_it(
    session, principal, other_org_principal, provisioning_env
):
    """A filter argument must not become a way to reach another organization's row.

    The filter is applied ON TOP of the principal's scope, so naming the other organization's plan
    id returns nothing rather than that organization's manifest.
    """
    env, manifest = _generate(session, principal, provisioning_env)
    assert [row.id for row in manifests.list_manifests(session, principal)] == [manifest.id]

    matched = manifests.list_manifests(session, principal, deployment_plan_id=env.plan.id)
    assert [row.id for row in matched] == [manifest.id]

    missed = manifests.list_manifests(session, principal, deployment_plan_id=uuid.uuid4())
    assert missed == []

    # The other organization cannot reach it by naming the right plan id either.
    assert (
        manifests.list_manifests(session, other_org_principal, deployment_plan_id=env.plan.id) == []
    )


def test_the_target_filter_narrows_within_scope(session, principal, provisioning_env):
    env, manifest = _generate(session, principal, provisioning_env)
    matched = manifests.list_manifests(session, principal, execution_target_id=env.target.id)
    assert [row.id for row in matched] == [manifest.id]
    assert manifests.list_manifests(session, principal, execution_target_id=uuid.uuid4()) == []


def test_both_filters_must_agree(session, principal, provisioning_env):
    """Two filters are an AND, not an OR — a mistake that reads as working on one-row data."""
    env, manifest = _generate(session, principal, provisioning_env)
    assert [
        row.id
        for row in manifests.list_manifests(
            session,
            principal,
            deployment_plan_id=env.plan.id,
            execution_target_id=env.target.id,
        )
    ] == [manifest.id]
    assert (
        manifests.list_manifests(
            session,
            principal,
            deployment_plan_id=env.plan.id,
            execution_target_id=uuid.uuid4(),
        )
        == []
    )


def test_the_collection_route_is_registered_and_precedes_its_parameterised_sibling() -> None:
    """FastAPI matches in declaration order.

    ``/manifests`` after ``/manifests/{manifest_id}`` is reachable only because the parameter is
    typed as a UUID; a later change to ``str`` would silently capture every list request and answer
    404. Asserting the ORDER removes the dependence on that coincidence, and asserting it here
    means the guard does not rely on anyone remembering why the lines are arranged that way.
    """
    from secp_api.main import app

    # Read the OPENAPI document, not ``app.routes``. Every router here is mounted as an
    # ``_IncludedRouter``, so a walk over ``app.routes`` sees four documentation endpoints and none
    # of the API at all -- it would have found an empty list and this assertion would have been the
    # only thing standing between that and a green run. The document is also what a client and the
    # generated TypeScript actually see, which is the property being claimed.
    paths = list(app.openapi()["paths"])
    assert "/api/v1/manifests" in paths, (
        "the manifest collection route is not in the published contract; every manifest surface is "
        "then reachable only by a caller that already holds an id, which is the defect this route "
        "closes"
    )
    # A positive control: if the filter above ever stops matching real routes, this fails rather
    # than the emptiness passing as "nothing to check".
    assert "/api/v1/manifests/{manifest_id}" in paths
    assert paths.index("/api/v1/manifests") < paths.index("/api/v1/manifests/{manifest_id}")
