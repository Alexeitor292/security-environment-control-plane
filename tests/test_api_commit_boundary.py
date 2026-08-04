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
#
# This set answers "is this THE session dependency?". It deliberately does NOT answer "could this
# hand a route a Session?" — see ``_generator_dependants`` below for why that distinction is the
# whole point.
SESSION_CALLABLES = (secp_deps.db_session, secp_db.get_db)

REQUIRED_SCOPE = "function"

# Generator dependencies permitted to exist that are NOT the session seam.
#
# EMPTY, and adding to it is a reviewed decision, not a formality. Every entry must be a callable
# that provably hands out no Session, because anything on this list is exempt from the single-seam
# rule below (it is NEVER exempt from the scope rule — that one has no escape hatch).
#
# Measured on this application: ``db_session`` is the ONLY generator dependency in any served tree,
# 349 of 349 resolutions. So this list being empty costs nothing today and forces a decision the
# first time that stops being true.
ALLOWED_NON_SESSION_GENERATORS: frozenset = frozenset()

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

    BOTH shapes are collected, and the second was missed by the first version of this module:

    * routes reached through ``include_router`` become ``_EffectiveRouteContext`` objects with a
      REBUILT dependant — the ordinary case here;
    * a route registered directly with ``@app.get(...)`` is a plain ``APIRoute`` sitting on
      ``app.router.routes``, with no effective context at all. Descending only ``_IncludedRouter``
      made such a route INVISIBLE to every check below. Latent today because every router in
      ``create_app`` is included, but a decorator on the app object is a more likely thing for
      someone to write than any of the exotic cases this module guards against.
    """
    out = [] if out is None else out
    seen = [] if seen is None else seen
    if any(node is router for node in seen):
        return out
    # Held by strong reference, NOT by id(): the nested ``_IncludedRouter`` objects below are
    # constructed fresh by ``effective_candidates()``, so an id()-keyed set could match a recycled
    # address and skip a subtree that was never visited.
    seen.append(router)

    # An ``_IncludedRouter`` is expanded through its OWN ``effective_candidates()``. It does not
    # have a ``.routes`` attribute at all, so the earlier code — which recursed into this function
    # and fell through to ``getattr(router, "routes", [])`` — silently dropped the ENTIRE subtree
    # for any router included into another router.
    #
    # That was not theoretical. A route under a nested router carrying a router-level
    # ``dependencies=[Depends(...)]`` was served (present in the OpenAPI schema, answering 200 over
    # a real socket, its dependency demonstrably running) while this walk reported the corpus
    # completely unchanged — 182 contexts, 349 generator dependencies — and every check passed.
    # ``dependencies=[...]`` on a router is a mainstream FastAPI idiom for auth, and nesting
    # routers is ordinary, so this was a live hole rather than an exotic one.
    #
    # The ``getattr(..., [])`` that caused it is precisely the absence-of-input/absence-of-match
    # confusion this whole module exists to prevent: the walk answered "nothing here" for a subtree
    # it had failed to open.
    if isinstance(router, _IncludedRouter):
        for candidate in router.effective_candidates():
            if isinstance(candidate, _EffectiveRouteContext):
                out.append(candidate)
            else:
                _served_contexts(candidate, out, seen)
        return out

    for route in getattr(router, "routes", []):
        if isinstance(route, _IncludedRouter):
            _served_contexts(route, out, seen)
        elif isinstance(route, APIRoute):
            # Serves directly off its own ``dependant``; there is no rebuilt context to consult.
            out.append(route)
    return out


def _session_resolutions(dependant):
    """Resolutions of the KNOWN session dependency. Not the safety check — see below."""
    return [d for d in _walk(dependant) if d.call in SESSION_CALLABLES]


def _generator_dependants(dependant):
    """Every ``yield``-style dependency in a tree, by SHAPE rather than by identity.

    This is the exhaustive enumeration, and the reason it exists is a real defeat of the earlier
    design. ``_session_resolutions`` asks "is this ``db_session``?" — which a wrapper simply is not:

        def tenant_session():        # .call is tenant_session, not db_session
            yield from get_db()      # ...but it hands the route the very same Session

    A route depending on that wrapper produced ZERO session resolutions, so every check keyed on
    ``SESSION_CALLABLES`` passed it, and the route committed after its response was on the wire —
    demonstrated on the real composed app over a real socket, not argued. Identity over a closed
    set answers "is this the thing I know about"; it cannot answer "is this something that hands a
    route a Session", because that set is open.

    What is NOT open is the shape. Only a generator dependency can hold a transaction across the
    response boundary, because only a generator has teardown that FastAPI schedules. So the checks
    below enumerate generator dependencies and require each one to be accounted for, which is
    closed over the property that actually matters rather than over a list of names.
    """
    return [d for d in _walk(dependant) if d.is_gen_callable or d.is_async_gen_callable]


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

    # The SHAPE enumeration needs its own floor. It is what the gate now runs on, and an
    # ``is_gen_callable`` that stopped reporting True would make the gate silently vacuous while
    # every identity-based count above stayed healthy.
    served_gens = [
        d for c in served if c.dependant is not None for d in _generator_dependants(c.dependant)
    ]
    assert len(served_gens) >= MIN_SESSION_RESOLUTIONS, (
        f"only {len(served_gens)} SERVED generator dependency(ies) found; "
        "Dependant.is_gen_callable is not engaging, so the gate that enumerates by shape would "
        "pass whatever the application did"
    )
    # ...and the shape enumeration must be a SUPERSET of the identity one. If it ever is not, the
    # shape predicate has stopped seeing the session dependency itself.
    missing = [d for d in served_res if d not in served_gens]
    assert not missing, (
        f"{len(missing)} session resolution(s) were NOT reported as generator dependencies; the "
        "shape predicate no longer covers the very dependency it was written to generalise"
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

    # Only INCLUDED routes are rebuilt. A route registered directly with ``@app.get(...)`` is its
    # own served object, so it legitimately shares its dependant — counting that as a broken premise
    # would fail a perfectly correct route. Measured: injecting one such route made ``shared`` 1
    # against 187 rebuilt, and an unconditional ``shared == 0`` flagged it.
    shared = different = 0
    for context in served:
        if isinstance(context, APIRoute):
            continue  # serves off its own dependant by design; nothing to rebuild
        for method in context.methods or ():
            route = declared.get((method, context.path))
            if route is None:
                continue
            if context.dependant is route.dependant:
                shared += 1
            else:
                different += 1
    assert different > 0, (
        "every included route reuses the declared dependant object. FastAPI no longer rebuilds the "
        "tree per served operation, so a composition-time mutation would now take effect and this "
        "module's dual walk no longer proves what it claims — re-derive it before relaxing it."
    )
    assert shared == 0, (
        f"{shared} INCLUDED route context(s) share the declared dependant object while {different} "
        "do not; the rebuild is now inconsistent and the guard's assumptions need re-deriving"
    )


# --------------------------------------------------------------------------- the boundary itself


def test_every_served_generator_dependency_commits_before_the_response(app):
    """THE GATE, and it has NO escape hatch.

    Enumerated by shape, not by identity: EVERY generator dependency in EVERY served tree must
    declare ``scope="function"``, whatever it is called and whatever it hands out. A dependency at
    request scope has its teardown run after the response reaches the socket, and that is true of a
    wrapper around ``db_session`` exactly as it is true of ``db_session`` itself.

    ``ALLOWED_NON_SESSION_GENERATORS`` does not exempt anything here. A generator dependency that
    hands out no Session still holds teardown across the boundary, and "it does not touch the
    database" is a claim about today's implementation rather than about the shape.
    """
    offenders = []
    for context in _served_contexts(app.router):
        if context.dependant is None:
            continue
        for dependant in _generator_dependants(context.dependant):
            if dependant.scope != REQUIRED_SCOPE:
                offenders.append(
                    f"{sorted(context.methods or ())} {context.path} -> "
                    f"{getattr(dependant.call, '__qualname__', dependant.call)} "
                    f"(scope={dependant.scope!r}, computed={dependant.computed_scope!r})"
                )
    assert not offenders, (
        f"{len(offenders)} SERVED generator dependency(ies) do not declare "
        f"scope={REQUIRED_SCOPE!r}, so their teardown runs after the response is written to the "
        f"socket. If it hands out a Session, use secp_api.deps.DB_SESSION. If it does not, it "
        f"still must declare the scope. First 10: {offenders[:10]}"
    )


def test_the_session_seam_is_the_only_generator_dependency_served(app):
    """The single-seam property, enforced over the OPEN set rather than a known list.

    The gate above stops a wrapper from committing late. This stops a wrapper from existing quietly
    at all — because a second path to a Session reintroduces exactly the per-site decision the seam
    exists to remove, and because ``Dependant.cache_key`` includes the computed scope, so two
    session providers in one request can hand out two distinct Sessions.

    Anything genuinely session-free goes in ``ALLOWED_NON_SESSION_GENERATORS`` with a reason. That
    is a reviewed edit in a file called out for review, not a silent default.
    """
    unknown = []
    for context in _served_contexts(app.router):
        if context.dependant is None:
            continue
        for dependant in _generator_dependants(context.dependant):
            call = dependant.call
            if call in SESSION_CALLABLES or call in ALLOWED_NON_SESSION_GENERATORS:
                continue
            unknown.append(
                f"{sorted(context.methods or ())} {context.path} -> "
                f"{getattr(call, '__module__', '?')}."
                f"{getattr(call, '__qualname__', call)}"
            )
    assert not unknown, (
        f"{len(unknown)} served generator dependency(ies) are neither the session seam nor "
        f"allow-listed. A wrapper such as `def tenant_session(): yield from get_db()` hands out "
        f"the SAME Session while satisfying no identity check, which is how the earlier version of "
        f"this guard was defeated. Route it through secp_api.deps.DB_SESSION, or add it to "
        f"ALLOWED_NON_SESSION_GENERATORS with a reason. First 10: {unknown[:10]}"
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
    import sys

    package = pathlib.Path(secp_deps.__file__).parent

    # HOW THE ONE LEGITIMATE SITE IS RECOGNISED, and why it is not keyed on a location.
    #
    # v1 tested ``path.name == "deps.py"`` — defeated by a second ``routers/deps.py``.
    # v2 tested the resolved path of ``secp_api.deps`` — which fixes that, but only by swapping one
    # N=1 assumption ("the seam lives in a file with this basename") for another ("the seam lives at
    # this path"). Moving the seam to ``secp_api/session.py`` would then fail a correct refactor,
    # and the check would be asserting a filesystem fact rather than the property it cares about.
    #
    # So the exemption is keyed on OBJECT IDENTITY: a site is legitimate exactly when it is the
    # module-level assignment whose bound name IS ``secp_deps.DB_SESSION`` — the one canonical seam
    # object, wherever it happens to live. A second seam is a different object and is never ``is``
    # the canonical one, so it is still caught; and relocating the real seam needs no edit here.
    modules_by_file = {}
    for module in list(sys.modules.values()):
        file = getattr(module, "__file__", None)
        if file:
            try:
                modules_by_file[pathlib.Path(file).resolve()] = module
            except (OSError, ValueError):  # pragma: no cover - defensive
                continue

    def _is_the_canonical_seam_assignment(path, node, tree):
        """True only for the module-level statement that binds the canonical seam object.

        The bound names are read by DUCK TYPING the AST's own naming convention — ``targets``
        (plural, ``X = ...``) or ``target`` (singular, ``X: T = ...``) — rather than by listing
        node types. That is deliberate, and it is the third time this predicate has been narrowed
        by an assumption it did not know it was making:

            v1  keyed on a BASENAME   — "the seam lives in a file called deps.py"
            v2  keyed on a PATH       — "the seam lives at this resolved location"
            v3  keyed on a NODE TYPE  — "the seam is a bare Assign, not an AnnAssign"

        v3's cost was the worse direction: the perfectly idiomatic
        ``DB_SESSION: Depends = Depends(db_session, scope="function")`` made the guard flag the
        seam's OWN definition. A false green gets re-checked by the next person to touch it; a
        false red gets acted on — someone sees the guard reject correct code and edits the seam to
        appease it.

        Duck typing on ``value``/``target(s)`` removes the node-type list, so any binding statement
        that follows the AST's convention is handled without this predicate being told about it.
        The residual assumption, stated rather than hidden: the seam is bound by a module-level
        statement whose ``value`` is the ``Depends(...)`` call itself. A seam built indirectly —
        through a helper call, a comprehension, or a conditional — would not be recognised, and
        should not be: that is no longer one obvious construction site.
        """
        module = modules_by_file.get(path.resolve())
        if module is None:
            return False  # not imported: cannot be the seam the application actually uses
        for stmt in tree.body:  # module level only, deliberately
            if getattr(stmt, "value", None) is not node:
                continue
            targets = getattr(stmt, "targets", None)
            if targets is None:
                single = getattr(stmt, "target", None)
                targets = [single] if single is not None else []
            for target in targets:
                if isinstance(target, ast.Name):
                    if getattr(module, target.id, None) is secp_deps.DB_SESSION:
                        return True
        return False

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
                # The one legitimate site: the assignment that binds the canonical seam object.
                if _is_the_canonical_seam_assignment(path, node, tree):
                    continue
                bare.append(f"{path.relative_to(package.parent)}:{node.lineno}")
    assert not bare, (
        f"{len(bare)} site(s) build their own session Depends instead of using "
        f"secp_api.deps.DB_SESSION: {bare}. One seam means a new route cannot opt back into the "
        "defect by writing the obvious thing."
    )
