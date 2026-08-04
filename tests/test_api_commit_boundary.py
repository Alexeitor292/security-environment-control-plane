"""The commit boundary is enforced here, on the trees the server actually serves.

The defect
----------
``secp_api.db.get_db`` commits the request transaction in its own teardown. FastAPI decides WHEN
that teardown runs from the ``scope`` on the ``Depends`` marker in the endpoint signature
(``fastapi/dependencies/utils.py``: ``use_astack = request_astack``, and only
``if sub_dependant.scope == "function": use_astack = function_astack``). A generator dependency
defaults to ``computed_scope="request"`` (``fastapi/dependencies/models.py``), and ``routing.py``
closes the request stack AFTER ``await response(scope, receive, send)``. So with the default the
commit lands after the client already holds its 2xx — and a commit that then FAILS cannot be
reported. Measured on the pinned fastapi 0.138.2: teardown failure at request scope returns ``200``
with a complete body; the same failure at function scope returns ``500``.

``secp_api.deps.DB_SESSION`` carries ``scope="function"``, which is the fix.

Why this guard walks TWO trees and requires them to AGREE
--------------------------------------------------------
This is the whole reason the module exists in this shape, and it must not be simplified away.

An earlier candidate fix rewrote the composed app's dependant tree at composition time — one seam,
zero call-site edits, and it set **all 349 resolutions to "function"**. A guard that inspected only
those route objects reported GREEN. Driven over a real socket, the response STILL preceded the
commit: nothing had changed.

The reason is that ``_populate_api_route_state`` rebuilds
``route.dependant = get_dependant(path=..., call=route.endpoint, ...)`` for every served operation
via ``_EffectiveRouteContext.from_api_route``. Measured on this app: **0 of the served operations
use the dependant object reachable from the route objects** — every one is a fresh tree rebuilt
from the endpoint SIGNATURE. Only the ``Depends(...)`` marker in that signature survives.

So a guard that walks only the declared tree can certify a tree the server never consults. This one
walks both and fails on disagreement, which is exactly the shape of that mirage.

Non-vacuity
-----------
Every count is checked for a population before any verdict is issued. "No offenders" and "nothing
to look at" must never be reported the same way — that is the failure mode this whole stream exists
to catch.
"""

from __future__ import annotations

import pytest
import secp_api.db as secp_db
import secp_api.deps as secp_deps
import secp_api.immutability  # noqa: F401  (registers ORM immutability guards)
from fastapi.routing import APIRoute, _EffectiveRouteContext, _IncludedRouter
from secp_api.main import create_app

# Identity on the loaded objects, never a name or a source string: a rename, a copy, or a
# same-named helper in another module cannot satisfy these.
SESSION_CALLABLES = (secp_deps.db_session, secp_db.get_db)

REQUIRED_SCOPE = "function"

# Floors, not exact counts: this guard must not need editing every time a route is added. They exist
# only so an empty or collapsed walk cannot pass as "no offenders found".
MIN_ROUTES = 50
MIN_SESSION_RESOLUTIONS = 50


@pytest.fixture(scope="module")
def app():
    return create_app()


def _walk(root):
    """Every dependant in a resolved tree, once each (sub-dependants are shared)."""
    out, seen, stack = [], set(), [root]
    while stack:
        current = stack.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        out.append(current)
        stack.extend(current.dependencies)
    return out


def _declared_routes(container, seen=None, out=None):
    """The ``APIRoute`` objects the routers declared — what a naive guard would inspect."""
    seen = set() if seen is None else seen
    out = [] if out is None else out
    if id(container) in seen:
        return out
    seen.add(id(container))
    routes = getattr(container, "routes", None)
    if routes is None:
        original = getattr(container, "original_router", None)
        if original is not None:
            _declared_routes(original, seen, out)
        return out
    for route in routes:
        if isinstance(route, APIRoute):
            out.append(route)
        else:
            original = getattr(route, "original_router", None)
            _declared_routes(original if original is not None else route, seen, out)
    return out


def _served_contexts(router, out=None, seen=None):
    """The trees the app's OWN matcher will consult.

    Built by asking FastAPI's ``effective_candidates()`` rather than by reimplementing routing, so
    this cannot drift into inspecting something the server does not use.
    """
    out = [] if out is None else out
    seen = set() if seen is None else seen
    if id(router) in seen:
        return out
    seen.add(id(router))
    for route in getattr(router, "routes", []):
        if isinstance(route, _IncludedRouter):
            for candidate in route.effective_candidates():
                if isinstance(candidate, _EffectiveRouteContext):
                    out.append(candidate)
                else:
                    _served_contexts(candidate, out, seen)
    return out


def _session_resolutions(dependant):
    return [d for d in _walk(dependant) if d.call in SESSION_CALLABLES]


# --------------------------------------------------------------------------- non-vacuity first


def test_the_guard_has_a_population_to_judge(app):
    """Before any zero is believed: are there routes, and do any resolve a session at all?"""
    declared = _declared_routes(app)
    served = _served_contexts(app.router)
    assert len(declared) >= MIN_ROUTES, f"only {len(declared)} declared APIRoute(s) reached"
    assert len(served) >= MIN_ROUTES, f"only {len(served)} served route context(s) reached"

    declared_res = [d for r in declared for d in _session_resolutions(r.dependant)]
    served_res = [
        d for c in served if c.dependant is not None for d in _session_resolutions(c.dependant)
    ]
    assert len(declared_res) >= MIN_SESSION_RESOLUTIONS, (
        f"only {len(declared_res)} declared session resolution(s); the identity check against "
        f"{[c.__name__ for c in SESSION_CALLABLES]} is not engaging, so its silence means nothing"
    )
    assert len(served_res) >= MIN_SESSION_RESOLUTIONS, (
        f"only {len(served_res)} SERVED session resolution(s); the served-tree walk is not "
        "engaging, so this module would pass whatever the application did"
    )


def test_the_served_tree_is_not_the_declared_tree(app):
    """The premise of the dual walk, re-derived rather than trusted from the docstring.

    If FastAPI ever stopped rebuilding the dependant per served operation, the two walks would
    become the same walk and the agreement check below would silently stop testing anything. This
    asserts the rebuild is still happening, so the guard's own shape stays justified.
    """
    declared = {
        (method, route.path): route
        for route in _declared_routes(app)
        for method in route.methods or ()
    }
    served = _served_contexts(app.router)
    assert served, "no served route contexts were reached"

    shared = different = 0
    for context in served:
        for method in context.methods or ():
            route = declared.get((method, context.path))
            if route is None:
                continue
            if context.dependant is route.dependant:
                shared += 1
            else:
                different += 1
    assert different > 0, (
        "every served context reuses the declared dependant object. FastAPI no longer rebuilds the "
        "tree per served operation, so a composition-time mutation would now take effect and this "
        "module's dual walk no longer proves what it claims — re-derive it before relaxing it."
    )
    assert shared == 0, (
        f"{shared} served context(s) share the declared dependant object while {different} do not; "
        "the rebuild is now inconsistent and the guard's assumptions need re-deriving"
    )


# --------------------------------------------------------------------------- the boundary itself


def test_every_served_session_resolution_commits_before_the_response(app):
    """THE GATE. A session resolved at request scope commits after the client holds its response."""
    offenders = []
    for context in _served_contexts(app.router):
        if context.dependant is None:
            continue
        for dependant in _session_resolutions(context.dependant):
            if dependant.scope != REQUIRED_SCOPE:
                offenders.append(
                    f"{sorted(context.methods or ())} {context.path} "
                    f"(scope={dependant.scope!r}, computed={dependant.computed_scope!r})"
                )
    assert not offenders, (
        f"{len(offenders)} SERVED session resolution(s) do not declare scope={REQUIRED_SCOPE!r}, "
        f"so their commit runs after the response is written to the socket. Use "
        f"secp_api.deps.DB_SESSION, never a bare Depends(db_session). First 10: {offenders[:10]}"
    )


def test_the_declared_and_served_trees_agree_about_scope(app):
    """Catches a "fix" that does not survive ``get_dependant``'s rebuild.

    This is the check that would have failed the composition-time seam described in the module
    docstring, which set every DECLARED resolution to "function" while every SERVED one stayed at
    the default. Without it, that mirage passes.
    """
    declared_scopes = {
        d.scope for r in _declared_routes(app) for d in _session_resolutions(r.dependant)
    }
    served_scopes = {
        d.scope
        for c in _served_contexts(app.router)
        if c.dependant is not None
        for d in _session_resolutions(c.dependant)
    }
    assert declared_scopes == served_scopes, (
        f"declared trees say {declared_scopes} but SERVED trees say {served_scopes}. A dependency "
        "scope is being set somewhere that does not survive FastAPI's per-operation rebuild of "
        "route.dependant — the served behaviour is NOT what the declared tree claims."
    )


def test_the_single_seam_is_the_only_way_a_route_gets_a_session(app):
    """The seam is load-bearing, so prove it is really what every route resolved.

    Identity on ``secp_api.deps.DB_SESSION`` itself. A second marker declaring the same scope would
    still pass the scope checks above but would reintroduce the per-site decision this design
    exists to remove — and, because ``Dependant.cache_key`` includes the computed scope, a marker
    at a DIFFERENT scope would hand one request two distinct sessions.
    """
    assert secp_deps.DB_SESSION.dependency is secp_deps.db_session
    assert secp_deps.DB_SESSION.scope == REQUIRED_SCOPE

    import ast
    import pathlib

    package = pathlib.Path(secp_deps.__file__).parent
    bare = []
    for path in sorted(package.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = getattr(func, "id", None) or getattr(func, "attr", None)
            if name != "Depends":
                continue
            first = node.args[0] if node.args else None
            # BOTH spellings. ``Depends(db_session)`` is an ``ast.Name``;
            # ``Depends(deps.db_session)`` is an ``ast.Attribute`` and was MISSED by an earlier
            # version of this check — measured, not hypothesised: a new registered route written
            # that way failed only the served-tree test, leaving this one green. The served-tree
            # walk caught it, so nothing shipped unprotected, but a source check that misses a
            # legal spelling of the thing it forbids will eventually be believed about a case it
            # never examined.
            target = None
            if isinstance(first, ast.Name):
                target = first.id
            elif isinstance(first, ast.Attribute):
                target = first.attr
            if target in {"db_session", "get_db"}:
                # The seam's own definition is the one legitimate site.
                if path.name == "deps.py" and any(kw.arg == "scope" for kw in node.keywords):
                    continue
                bare.append(f"{path.relative_to(package.parent)}:{node.lineno}")
    assert not bare, (
        f"{len(bare)} site(s) build their own session Depends instead of using "
        f"secp_api.deps.DB_SESSION: {bare}. One seam means a new route cannot opt back into the "
        "defect by writing the obvious thing."
    )
