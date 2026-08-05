"""The permission each route requires, resolved by call graph and pinned against hand checks.

A frontend that renders "you need X to see this" is making a claim about the server. If the claim
is wrong in the permissive direction it offers a control the server will refuse; if it is wrong in
the restrictive direction it hides a surface the operator is entitled to. Neither is discoverable
from the route path — `GET /api/v1/targets` and `GET /api/v1/ranges` look alike and are not.

So the answers come from the call graph, and the ones that matter are ALSO checked by hand here.
Three of the four pins below were wrong at some point while the resolver was written, each from a
different bug, and each is kept as a regression:

  * ``routers/ranges.py`` and ``services/ranges.py`` both define ``list_ranges``. Keeping one body
    per name resolved the route handler's call to ITSELF, and 213 of 243 routes reported no
    permission — the reassuring direction.
  * ``seen`` keyed on the bare NAME meant the service function was skipped as already visited,
    because the router function of the same name had already been recorded. Two functions sharing
    a name are not a cycle.
  * `GET /api/v1/targets` resolving to nothing is NOT a resolver gap: ``services.targets
    .list_targets`` calls no ``principal.require`` at all and scopes by organization only. That
    was confirmed by reading it, which is the only way to tell an unguarded route from a walk that
    lost the thread — and it is why an unresolved route is never reported as "needs nothing".
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from resolve_route_permissions import ARTIFACT, route_permissions, serialize  # noqa: E402

#: Routes whose permission was read out of the source by hand. The resolver must agree.
HAND_CHECKED: dict[str, list[str]] = {
    # services/ranges.py: `principal.require(Permission.exercise_operate)` — two hops from the
    # handler, and nothing in the path suggests "exercise".
    "GET /api/v1/ranges": ["exercise_operate"],
    # The worker-node list is gated on managing DISCOVERY, not on anything worker-shaped.
    "GET /api/v1/target-discovery/read-only-bootstrap/worker-nodes": ["target_discovery_manage"],
    "GET /api/v1/enrollment": ["enrollment_read"],
    "GET /api/v1/audit": ["audit_read"],
    # THE DEEPEST CHAIN, and the case a one-hop resolver was warned about. Three hops:
    #   routers/competitions.list_range_teams
    #     -> services/competitions.get_competition_for_range
    #       -> services/ranges.get_range   <- principal.require(Permission.exercise_operate)
    # Nothing in the route path, the handler, or even the function it calls mentions a
    # permission; the gate is two functions below the one the handler names. A resolver that
    # inspected the route's immediate dependency would report this unguarded.
    "GET /api/v1/ranges/{range_id}/teams": ["exercise_operate"],
    "GET /api/v1/ranges/{range_id}/scoreboard": ["exercise_operate"],
}

#: Routes verified BY HAND to enforce no permission beyond authentication. Not "unresolved" —
#: read, and found to have no `require` anywhere in the chain. Listed explicitly so the difference
#: between "checked, and there is no gate" and "the walk found nothing" stays visible.
VERIFIED_UNGUARDED: set[str] = {
    # services/targets.py:269 — scopes by `actor.organization_id` and requires no permission.
    "GET /api/v1/targets",
    # routers/system.py:33 — reads the plugin registry's health; no service call, no `require`.
    "GET /api/v1/plugins",
    # routers/ranges.py:126 — the handler DELETES the principal with a comment saying why:
    # "authentication only; the shipped catalog is not tenant data". The only open route in the
    # contract that states its own reason.
    "GET /api/v1/range-templates",
    "GET /api/v1/range-templates/{slug}",
}


@pytest.fixture(scope="module")
def resolved() -> dict[str, dict[str, object]]:
    return route_permissions()


def test_the_artifact_is_in_step_with_the_call_graph() -> None:
    assert ARTIFACT.exists(), "contracts/openapi/route-permissions.json is missing"
    assert ARTIFACT.read_text(encoding="utf-8") == serialize(route_permissions()), (
        "route-permissions.json is stale. Run: python scripts/resolve_route_permissions.py"
    )


@pytest.mark.parametrize(("route", "expected"), sorted(HAND_CHECKED.items()))
def test_the_resolver_agrees_with_the_hand_check(
    resolved: dict[str, dict[str, object]], route: str, expected: list[str]
) -> None:
    assert route in resolved, f"{route} is not a registered route"
    assert resolved[route]["permissions"] == expected


def test_an_unguarded_route_is_recorded_as_verified_rather_than_unresolved(
    resolved: dict[str, dict[str, object]],
) -> None:
    """The distinction a client cannot afford to lose.

    An empty result means one of two things — the walk found no gate, or there is no gate — and
    they are opposite instructions to a UI. Anything in ``VERIFIED_UNGUARDED`` has been read; the
    rest stay unresolved, and a surface must not claim they need nothing.
    """
    for route in VERIFIED_UNGUARDED:
        assert route in resolved, f"{route} is not a registered route"
        assert resolved[route]["permissions"] == []
        assert resolved[route]["state"] == "open", (
            f"{route} was read by hand and found open, but the artifact says "
            f"{resolved[route]['state']!r}. `open` and `unknown` are different instructions to a "
            "client and must not collapse."
        )


def test_an_unresolved_route_is_never_reported_as_open(
    resolved: dict[str, dict[str, object]],
) -> None:
    """The pair that must not merge.

    `unknown` means the walk found no gate. `open` means somebody read the code and there is no
    gate. A client rendering the first as the second shows every control to everyone — which is
    exactly what a broken walk produces, so the two states carry the failure apart.
    """
    for route, entry in resolved.items():
        if entry["state"] == "open":
            assert route in VERIFIED_UNGUARDED, f"{route} claims `open` without a hand check"
        if entry["state"] == "unknown":
            assert route not in VERIFIED_UNGUARDED


def test_the_resolver_resolves_most_routes(resolved: dict[str, dict[str, object]]) -> None:
    """A smoke check on the resolver itself, not a target to tune toward.

    If a future change breaks the walk, the failure mode is silent: every route reports no
    permission and every screen decides it needs nothing. A floor makes that loud. It is
    deliberately far below the current figure — this asserts the walk still works, not that any
    particular number of routes is gated.
    """
    resolvable = sum(1 for entry in resolved.values() if entry["permissions"])
    assert resolvable > len(resolved) // 2, (
        f"only {resolvable} of {len(resolved)} routes resolved to a permission. The call-graph "
        "walk has probably stopped following a hop rather than the API having become open."
    )


def test_no_route_claims_a_permission_that_is_not_a_real_member() -> None:
    """A typo in the enum member would render as a requirement nobody can hold."""
    from secp_api.enums import Permission

    members = {member.name for member in Permission}
    for route, entry in route_permissions().items():
        for name in entry["permissions"]:
            assert name in members, f"{route} resolves to unknown permission {name!r}"
