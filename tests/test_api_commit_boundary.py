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

import functools
import inspect
import sys

import fastapi
import fastapi.dependencies.utils as fastapi_dependency_utils
import pytest
import secp_api.db as secp_db
import secp_api.deps as secp_deps
import secp_api.immutability  # noqa: F401  (registers ORM immutability guards)
from fastapi.dependencies.models import Dependant
from fastapi.routing import APIRoute, _EffectiveRouteContext, _IncludedRouter
from secp_api.main import create_app

# --------------------------------------------------------------------------- the shape predicate
#
# WHERE FastAPI KEEPS "does this dependency have teardown", and why this is BOUND rather than
# reimplemented.
#
# The gate in this module enumerates generator dependencies by SHAPE, and that is only sound while
# the shape it enumerates is the same one FastAPI consults when it decides which exit stack a
# dependency's teardown goes on. That decision is one disjunction, in
# ``fastapi/dependencies/utils.py``:
#
#     elif <is generator> or <is async generator>:
#         use_astack = request_astack
#         if <computed scope> == "function":
#             use_astack = function_astack
#
# The disjunction itself has not changed. WHERE IT LIVES has, and that broke this module once:
#
#   <= 0.138  ``Dependant.is_gen_callable`` / ``.is_async_gen_callable`` / ``.computed_scope``,
#             as ``functools.cached_property`` on the dataclass.
#   >= 0.141  ``Dependant`` became ``@dataclass(slots=True)``. A slotted class has no ``__dict__``
#             for a ``cached_property`` to cache into, so every one of them moved OUT to
#             module-level ``lru_cache``d functions in ``fastapi.dependencies.models``:
#             ``_is_gen_callable(call)``, ``_is_async_gen_callable(call)``,
#             ``_get_computed_scope(dependant=...)`` — re-exported into
#             ``fastapi.dependencies.utils``, which is the module that schedules the teardown.
#             The bodies are the same logic; only the binding site moved.
#
# On 0.141.1 the attribute spelling raises ``AttributeError`` and this module failed 4 of its 7
# nodes. That was the right OUTCOME — the gate refused rather than reporting a green it had not
# earned — but it left the gate unrunnable, which is why the binding below exists.
#
# IT IS A BINDING, NEVER A REIMPLEMENTATION, and that is the load-bearing decision here. It would
# be one line to write ``inspect.isgeneratorfunction(call) or inspect.isasyncgenfunction(call)``
# and have both versions pass. That line is wrong in the dangerous direction: it UNDER-reports, so a
# dependency of a shape it misses would be INVISIBLE to the gate while FastAPI still scheduled its
# teardown after the response — a silent green, which is the exact failure this module exists to
# catch.
#
# WHICH shapes it misses is deliberately NOT written here as prose.
#
# It was, and that is why this paragraph is shaped like this. The count lived in two places — a
# table in this comment and a sentence in the discrimination test's docstring — and one of them was
# already wrong: it claimed the substitute misses ``functools.partial``, which the stdlib has
# unwrapped itself since 3.8. The measurement it sat next to was correct; the summarising clause was
# a fresh unmeasured claim wearing the clothes of a restatement, and by the time its own author
# caught it, it had reached a review and a public PR description.
#
# So the answer is COMPUTED instead. ``_naive_substitute`` below is that exact one-line substitute,
# ``TEARDOWN_SHAPE_CORPUS`` is the single corpus both tests consume, and
# ``NAIVE_SUBSTITUTE_UNDER_REPORTS`` names the shapes it misses ONCE, as data that a test checks
# against a live measurement. Adding or removing a shape cannot leave a stale number behind,
# because there is no number to leave.
#
# So the lookup resolves FastAPI's own object and RAISES if it can find neither spelling. A future
# version that genuinely removed the concept must STOP this gate and force a decision, not be
# papered over by a local approximation of it.

_BINDING_MODULE_LEVEL = "fastapi.dependencies.utils module-level functions (>= 0.141)"
_BINDING_DEPENDANT_ATTRIBUTE = "Dependant cached properties (<= 0.138)"

_MODULE_LEVEL_NAMES = ("_is_gen_callable", "_is_async_gen_callable", "_get_computed_scope")
_ATTRIBUTE_NAMES = ("is_gen_callable", "is_async_gen_callable", "computed_scope")


def _bind_to_fastapis_teardown_disjunction():
    """Resolve the predicate out of FastAPI itself, preferring the module that schedules teardown.

    Returns ``(is_generator_dependency, computed_scope, binding_label, bound_fastapi_objects)``.
    The last element exists so the provenance can be ASSERTED below rather than assumed: a binding
    that silently fell back to something not owned by FastAPI is the one failure this indirection
    could introduce, so it is pinned.
    """
    module_level = [getattr(fastapi_dependency_utils, name, None) for name in _MODULE_LEVEL_NAMES]
    if all(callable(obj) for obj in module_level):
        is_gen, is_async_gen, get_scope = module_level

        def _module_level_is_generator(dependant):
            return is_gen(dependant.call) or is_async_gen(dependant.call)

        def _module_level_scope(dependant):
            return get_scope(dependant=dependant)

        return (
            _module_level_is_generator,
            _module_level_scope,
            _BINDING_MODULE_LEVEL,
            (is_gen, is_async_gen, get_scope),
        )

    attributes = [getattr(Dependant, name, None) for name in _ATTRIBUTE_NAMES]
    if all(obj is not None for obj in attributes):

        def _attribute_is_generator(dependant):
            return dependant.is_gen_callable or dependant.is_async_gen_callable

        def _attribute_scope(dependant):
            return dependant.computed_scope

        # ``cached_property`` wraps the real function in ``.func``; unwrap so the provenance pin
        # below sees a ``__module__`` in both spellings.
        return (
            _attribute_is_generator,
            _attribute_scope,
            _BINDING_DEPENDANT_ATTRIBUTE,
            tuple(getattr(obj, "func", obj) for obj in attributes),
        )

    raise RuntimeError(
        f"fastapi {fastapi.__version__} exposes NEITHER spelling of the generator-dependency "
        f"predicate: no {_MODULE_LEVEL_NAMES} on fastapi.dependencies.utils and no "
        f"{_ATTRIBUTE_NAMES} on Dependant. This gate enumerates teardown-carrying dependencies by "
        "shape, and it is only sound while it asks FastAPI the same question FastAPI's scheduler "
        "asks. Re-derive the disjunction in fastapi/dependencies/utils.py and bind to it; do NOT "
        "substitute a local inspect.isgeneratorfunction check, which misses partials, wrapped "
        "callables and generator __call__ and would make this gate silently vacuous."
    )


(
    _is_generator_dependency,
    _computed_scope,
    SHAPE_PREDICATE_BINDING,
    _BOUND_FASTAPI_OBJECTS,
) = _bind_to_fastapis_teardown_disjunction()


def _build_teardown_shape_corpus():
    """``(label, call, carries_teardown)`` for each shape FastAPI's predicate classifies.

    ONE corpus, consumed by both tests below. Two tests with two private copies of "the shapes" is
    the same duplication as two prose copies of a count, and decays the same way.
    """

    def plain():  # pragma: no cover - never executed, only classified
        return None

    async def coroutine():  # pragma: no cover
        return None

    def sync_generator():  # pragma: no cover
        yield None

    async def async_generator():  # pragma: no cover
        yield None

    @functools.wraps(sync_generator)
    def wrapped_generator(*args, **kwargs):  # pragma: no cover
        return sync_generator(*args, **kwargs)

    class GeneratorCall:
        def __call__(self):  # pragma: no cover
            yield None

    class AsyncGeneratorCall:
        async def __call__(self):  # pragma: no cover
            yield None

    class PlainClass:
        def __init__(self):  # pragma: no cover
            pass

    return (
        ("plain function", plain, False),
        ("coroutine function", coroutine, False),
        ("class (constructed, never torn down)", PlainClass, False),
        ("sync generator", sync_generator, True),
        ("async generator", async_generator, True),
        ("functools.partial of a sync generator", functools.partial(sync_generator), True),
        ("@wraps-wrapped sync generator", wrapped_generator, True),
        ("instance with generator __call__", GeneratorCall(), True),
        ("instance with async generator __call__", AsyncGeneratorCall(), True),
    )


TEARDOWN_SHAPE_CORPUS = _build_teardown_shape_corpus()


def _naive_substitute(call):
    """The one-line reimplementation this module REFUSES, kept only so its failures are measured.

    Nothing in the gate calls this. It exists so the argument for binding is a live measurement
    rather than a sentence — see ``NAIVE_SUBSTITUTE_UNDER_REPORTS``.
    """
    return inspect.isgeneratorfunction(call) or inspect.isasyncgenfunction(call)


# The shapes ``_naive_substitute`` misses, named ONCE, as data.
#
# This is the single copy. There is no count anywhere in this module — not in a comment, not in a
# docstring — because the count is ``len()`` of this set and the test below re-measures it against
# the live predicates on every run. Adding a shape to the corpus that the substitute also misses
# fails that test until this set is updated, which is the point: the edit cannot be half-done.
NAIVE_SUBSTITUTE_UNDER_REPORTS = frozenset(
    {
        "@wraps-wrapped sync generator",
        "instance with generator __call__",
        "instance with async generator __call__",
    }
)

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
    # Held by strong reference rather than by ``id()``. DEFENSIVE HARDENING, NOT A FIX FOR A
    # DEMONSTRATED DEFECT — an earlier version of this comment claimed the nested
    # ``_IncludedRouter`` objects are "constructed fresh by ``effective_candidates()``", so an
    # id()-keyed set could match a recycled address. That is wider than what is true.
    #
    # Measured in fastapi 0.138.2: ``effective_candidates()`` MEMOISES. It caches into
    # ``self._effective_candidates``, keyed on ``_effective_candidates_version``, and returns the
    # same list object while the routes version is unchanged. So the children are built once and
    # then retained by a strong reference on the parent for the lifetime of the app — there is no
    # window in which an address could be freed and reused mid-walk, and the ``id()`` guard was not
    # exploitable here.
    #
    # Strong references are kept anyway: they cost nothing, and they are belt-and-braces against a
    # future FastAPI that stops memoising. Stated this way because a comment claiming a hazard
    # wider than the one measured is the same failure this module exists to catch — including when
    # it is a comment about one's own defensive change.
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

    The predicate is FastAPI's own — see ``_bind_to_fastapis_teardown_disjunction`` for which
    spelling of it is in use and why it is never reimplemented here.
    """
    return [d for d in _walk(dependant) if _is_generator_dependency(d)]


# --------------------------------------------------------------------------- non-vacuity first


def test_the_shape_predicate_is_bound_to_fastapis_own_definition():
    """The indirection above must resolve to FASTAPI's object, never to a local stand-in.

    Every other check in this module inherits its meaning from that one predicate. The floors below
    would catch a predicate that answered False for everything, and the single-seam rule would catch
    one that answered True for everything — but neither would catch a predicate that was a
    *plausible local approximation*, which is the failure the binding exists to prevent. So the
    provenance is asserted rather than trusted: the bound objects must come out of the ``fastapi``
    package, and where the module-level spelling exists they must be the very objects
    ``fastapi.dependencies.utils`` consults when it chooses the exit stack.
    """
    assert SHAPE_PREDICATE_BINDING in (_BINDING_MODULE_LEVEL, _BINDING_DEPENDANT_ATTRIBUTE), (
        f"unrecognised binding {SHAPE_PREDICATE_BINDING!r}"
    )
    assert len(_BOUND_FASTAPI_OBJECTS) == 3, _BOUND_FASTAPI_OBJECTS

    # NON-VACUITY ON THE PIN ITSELF, asserted here rather than inferred from elsewhere.
    #
    # This is not hypothetical. A probe written to verify this very relocation compared
    # ``getattr(utils, "_is_gen_callable", None) is getattr(models, "_is_gen_callable", None)`` on
    # a 0.138.2 environment and reported True — because BOTH were ``None``, and ``None is None``.
    # An identity assertion passes vacuously in exactly the case where the thing it pins has
    # ceased to exist, which is the failure mode this program has now met repeatedly.
    #
    # The binding cannot actually reach that state: the module-level branch is gated on
    # ``callable(obj)``, which ``None`` fails, and the ownership check below would reject ``None``
    # anyway. But a property that holds only because of two other places is weaker than one stated
    # where the identity comparison is, so it is stated here.
    for bound in _BOUND_FASTAPI_OBJECTS:
        assert bound is not None, (
            "a bound object is None, so the identity comparison below would be comparing two "
            "absences and would pass while pinning nothing at all"
        )
        assert callable(bound), f"{bound!r} is not callable and so cannot be the predicate"

    for bound in _BOUND_FASTAPI_OBJECTS:
        owner = getattr(bound, "__module__", "") or ""
        assert owner.split(".")[0] == "fastapi", (
            f"{bound!r} is owned by {owner!r}, not by fastapi. The shape predicate has fallen back "
            "to a local reimplementation, which cannot stay in step with FastAPI's scheduler and "
            "would miss partials, wrapped callables and generator __call__."
        )

    if SHAPE_PREDICATE_BINDING == _BINDING_MODULE_LEVEL:
        assert _BOUND_FASTAPI_OBJECTS == (
            fastapi_dependency_utils._is_gen_callable,
            fastapi_dependency_utils._is_async_gen_callable,
            fastapi_dependency_utils._get_computed_scope,
        ), (
            "the bound objects are not the ones fastapi.dependencies.utils itself calls, so this "
            "gate and FastAPI's teardown scheduling could disagree"
        )
    else:
        assert not any(hasattr(fastapi_dependency_utils, name) for name in _MODULE_LEVEL_NAMES), (
            "the module-level spelling IS available but the attribute spelling was bound; the "
            "binding order no longer prefers the module that schedules teardown"
        )


def test_the_shape_predicate_still_discriminates_across_every_teardown_shape():
    """A constant, or a predicate bound to the wrong concept, must not survive this.

    Every shape in ``TEARDOWN_SHAPE_CORPUS``, which is also what
    ``test_the_naive_substitute_this_module_refuses_really_does_under_report`` consumes — one
    corpus, so the two tests cannot drift apart.

    Each shape is then cross-checked against FastAPI's ``computed_scope``, which derives "request"
    from the same disjunction through a DIFFERENT bound object. That is not independent of
    FastAPI's logic — nothing here could be — but it is independent of which object this module
    bound, which is the mistake the indirection could actually make.
    """
    assert TEARDOWN_SHAPE_CORPUS, "the corpus is empty; this test would assert nothing"

    wrong = []
    for label, call, expected in TEARDOWN_SHAPE_CORPUS:
        observed = _is_generator_dependency(Dependant(call=call))
        if observed is not expected:
            wrong.append(f"{label}: predicate said {observed!r}, expected {expected!r}")
        # ``scope`` is left unset, so FastAPI computes "request" for exactly the shapes that carry
        # teardown and None for the rest.
        scope_says = _computed_scope(Dependant(call=call)) == "request"
        if scope_says is not expected:
            wrong.append(f"{label}: computed_scope implied {scope_says!r}, expected {expected!r}")
    assert not wrong, (
        f"the shape predicate ({SHAPE_PREDICATE_BINDING}) no longer classifies teardown-carrying "
        f"dependencies correctly, so every verdict in this module is unsound: {wrong}"
    )


def test_the_naive_substitute_this_module_refuses_really_does_under_report():
    """The reason for binding rather than reimplementing, MEASURED on every run.

    The module comment above argues that a one-line ``inspect`` check would make this gate
    silently vacuous. That argument used to be prose carrying a count, in two places, and one copy
    was already wrong — it claimed ``functools.partial`` was missed, which the stdlib has unwrapped
    itself since 3.8. So the claim is now computed here instead, and three things are checked:

    * the substitute really does disagree with FastAPI on a NON-EMPTY set — otherwise the whole
      argument for the binding is vacuous and the indirection buys nothing;
    * every disagreement is in the UNDER-reporting direction — the substitute says False where
      FastAPI says True. That is the direction that matters: an over-report would be noisy and
      safe, an under-report hides a dependency whose teardown runs after the response;
    * the set is exactly ``NAIVE_SUBSTITUTE_UNDER_REPORTS``, so adding a corpus shape that the
      substitute also misses fails here until that one declaration is updated.

    There is no number to keep in step, in this docstring or anywhere else in the module. The count
    is ``len(NAIVE_SUBSTITUTE_UNDER_REPORTS)`` and nothing restates it.
    """
    assert TEARDOWN_SHAPE_CORPUS, "the corpus is empty; this test would assert nothing"

    under = set()
    over = set()
    for label, call, expected in TEARDOWN_SHAPE_CORPUS:
        # Compared against ``expected`` rather than against the bound predicate, so a defect in the
        # binding surfaces in the discrimination test above rather than being masked here by both
        # sides moving together.
        assert _is_generator_dependency(Dependant(call=call)) is expected, (
            f"{label}: FastAPI's own predicate disagrees with the corpus, so this comparison "
            "cannot say anything about the substitute"
        )
        if _naive_substitute(call) is expected:
            continue
        (under if expected else over).add(label)

    assert under, (
        "the naive inspect substitute now agrees with FastAPI on every shape in the corpus. Either "
        "the corpus no longer contains a shape that distinguishes them — in which case this test, "
        "and the argument for binding rather than reimplementing, are both vacuous — or the "
        "stdlib has absorbed the cases FastAPI handles. Re-derive before believing the second."
    )
    assert not over, (
        f"the substitute OVER-reports on {sorted(over)}, which is not the failure this module "
        "documents; re-derive the argument rather than adjusting the expectation"
    )
    assert under == NAIVE_SUBSTITUTE_UNDER_REPORTS, (
        f"measured under-reported shapes {sorted(under)} != declared "
        f"{sorted(NAIVE_SUBSTITUTE_UNDER_REPORTS)}. Update the declaration — it is the ONLY place "
        "this is written down, which is why this test can catch it."
    )


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

    # The SHAPE enumeration needs its own floor. It is what the gate now runs on, and a shape
    # predicate that stopped reporting True would make the gate silently vacuous while every
    # identity-based count above stayed healthy.
    served_gens = [
        d for c in served if c.dependant is not None for d in _generator_dependants(c.dependant)
    ]
    assert len(served_gens) >= MIN_SESSION_RESOLUTIONS, (
        f"only {len(served_gens)} SERVED generator dependency(ies) found; FastAPI's "
        f"generator-dependency predicate ({SHAPE_PREDICATE_BINDING}) is not engaging, so the gate "
        "that enumerates by shape would pass whatever the application did"
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


def _scope_rule_offenders(contexts):
    """THE SCOPE RULE. Deliberately does not consult ``ALLOWED_NON_SESSION_GENERATORS``.

    Extracted so the rule and its allow-list independence can be exercised against a purpose-built
    app, not only against the real one — see the regression pin below.
    """
    offenders = []
    for context in contexts:
        if getattr(context, "dependant", None) is None:
            continue
        for dependant in _generator_dependants(context.dependant):
            if dependant.scope != REQUIRED_SCOPE:
                offenders.append(
                    f"{sorted(context.methods or ())} {context.path} -> "
                    f"{getattr(dependant.call, '__qualname__', dependant.call)} "
                    f"(scope={dependant.scope!r}, computed={_computed_scope(dependant)!r})"
                )
    return offenders


def _single_seam_rule_offenders(contexts):
    """THE SINGLE-SEAM RULE. This one DOES honour the allow-list — that is its whole difference."""
    unknown = []
    for context in contexts:
        if getattr(context, "dependant", None) is None:
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
    return unknown


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
    offenders = _scope_rule_offenders(_served_contexts(app.router))
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
    unknown = _single_seam_rule_offenders(_served_contexts(app.router))
    assert not unknown, (
        f"{len(unknown)} served generator dependency(ies) are neither the session seam nor "
        f"allow-listed. A wrapper such as `def tenant_session(): yield from get_db()` hands out "
        f"the SAME Session while satisfying no identity check, which is how the earlier version of "
        f"this guard was defeated. Route it through secp_api.deps.DB_SESSION, or add it to "
        f"ALLOWED_NON_SESSION_GENERATORS with a reason. First 10: {unknown[:10]}"
    )


def test_the_allow_list_never_exempts_anything_from_the_scope_rule(monkeypatch):
    """Pin the no-escape-hatch split against a real allow-list ENTRY, not against the comment.

    The two rules differ in exactly one way, and it is load-bearing: the single-seam rule honours
    ``ALLOWED_NON_SESSION_GENERATORS``, the scope rule never does. Read as prose that is a claim;
    the only way to know it is a fact is to put something in the list and check both rules.

    Driven here against a purpose-built app because the real application has an EMPTY allow-list —
    so nothing in the corpus can exercise this path, and a future edit that quietly made the
    allow-list safety-relevant would leave every other test in this module green.
    """
    from fastapi import Depends, FastAPI

    def allowed_generator():
        """Stands in for something genuinely session-free that a future change allow-lists."""
        yield object()

    probe = FastAPI()

    @probe.get("/at-request-scope")
    def _request_scoped(_dep=Depends(allowed_generator)) -> dict:  # no scope -> "request"
        return {}

    @probe.get("/at-function-scope")
    def _function_scoped(_dep=Depends(allowed_generator, scope=REQUIRED_SCOPE)) -> dict:
        return {}

    monkeypatch.setattr(
        sys.modules[__name__],
        "ALLOWED_NON_SESSION_GENERATORS",
        frozenset({allowed_generator}),
    )
    contexts = _served_contexts(probe.router)
    assert len(contexts) == 2, f"the probe app was not walked: {contexts}"

    # The allow-list DOES exempt it from the single-seam rule — otherwise this pin proves nothing
    # about the allow-list, only that an unknown generator is rejected.
    assert not _single_seam_rule_offenders(contexts), (
        "the allow-list entry was not honoured by the single-seam rule, so the two rules are no "
        "longer distinguishable and this pin cannot demonstrate the difference between them"
    )

    # ...and it does NOT exempt it from the scope rule. Exactly one of the two routes offends.
    offenders = _scope_rule_offenders(contexts)
    assert len(offenders) == 1, f"expected exactly the request-scoped route to offend: {offenders}"
    assert "/at-request-scope" in offenders[0], offenders
    assert "allowed_generator" in offenders[0], offenders


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
