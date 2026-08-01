"""Static census: the API's dependency surface and its commit call sites.

Two questions are answered here, both from the **loaded objects** rather than from grepping source
text for route decorators:

1. Which routes resolve a database session through ``secp_api.deps.db_session``, and with what
   dependency ``scope``? Taken from each route's resolved ``Dependant`` tree — the same structure
   FastAPI itself walks at request time — so a route registered by any means is counted, and a
   decorator this module never heard of cannot hide one.
2. Where does anything under ``secp_api`` commit, and is that commit on a **success** path or only
   inside an ``except`` handler? Taken from the AST of each loaded module's own source, so the
   answer describes the code that is actually imported.

Question 2 exists because the naive form of question 1 gives the wrong answer. Five routers contain
an explicit ``session.commit()``, which looks like "these five are already safe" — but four of them
commit only while handling an exception, to persist a durable refusal audit before re-raising. Those
endpoints are exposed on their success path regardless. Distinguishing the two is structural, not a
matter of reading the code carefully, so it is done mechanically here.

Nothing in this module executes a request or touches a database.
"""

from __future__ import annotations

import ast
import inspect
import sys
from dataclasses import dataclass, field
from types import ModuleType

import secp_api.db as secp_db
import secp_api.deps as secp_deps
from fastapi import FastAPI
from fastapi.dependencies.models import Dependant
from fastapi.routing import APIRoute

READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# The loaded objects themselves. Identity comparison against these means a rename, a copy, or a
# same-named helper in another module cannot be mistaken for the real session dependency.
DB_SESSION_DEPENDENCY = secp_deps.db_session
GET_DB_GENERATOR = secp_db.get_db


class CensusError(RuntimeError):
    """The census could not be taken over a population it can vouch for.

    Raised rather than returning an empty result: "nothing found" and "nothing to look at" must
    never be reported the same way.
    """


# --------------------------------------------------------------------------- routes


@dataclass(frozen=True)
class RouteFact:
    method: str
    path: str
    endpoint_module: str
    endpoint_name: str
    db_session_scopes: tuple[object, ...]
    uses_db_session: bool

    @property
    def is_write(self) -> bool:
        return self.method in WRITE_METHODS

    @property
    def key(self) -> str:
        return f"{self.method} {self.path}"


def iter_api_routes(app: FastAPI) -> list[APIRoute]:
    """Every ``APIRoute`` the app will actually serve, including nested included routers.

    FastAPI 0.138 keeps an included router as a single ``_IncludedRouter`` entry in ``app.routes``
    rather than flattening its routes into it, so the obvious ``[r for r in app.routes if
    isinstance(r, APIRoute)]`` yields **zero** routes on this application. That empty list is a
    perfectly plausible-looking answer, which is exactly why it is dangerous; this function
    descends, and ``verify_route_census`` refuses an empty or implausible result.
    """
    found: list[APIRoute] = []
    seen: set[int] = set()

    def descend(container: object) -> None:
        if id(container) in seen:
            return
        seen.add(id(container))
        routes = getattr(container, "routes", None)
        if routes is None:
            original = getattr(container, "original_router", None)
            if original is not None:
                descend(original)
            return
        for route in routes:
            if isinstance(route, APIRoute):
                found.append(route)
            else:
                original = getattr(route, "original_router", None)
                descend(original if original is not None else route)

    descend(app)
    return found


def walk_dependants(root: Dependant) -> list[Dependant]:
    """Every dependant in the resolved tree, once each (the graph may share sub-dependants)."""
    out: list[Dependant] = []
    seen: set[int] = set()
    stack = [root]
    while stack:
        current = stack.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        out.append(current)
        stack.extend(current.dependencies)
    return out


def census_routes(app: FastAPI) -> list[RouteFact]:
    """One ``RouteFact`` per (method, path), with the session dependency's scope as resolved."""
    facts: list[RouteFact] = []
    for route in iter_api_routes(app):
        scopes = tuple(
            dependant.scope
            for dependant in walk_dependants(route.dependant)
            if dependant.call is DB_SESSION_DEPENDENCY or dependant.call is GET_DB_GENERATOR
        )
        endpoint = route.endpoint
        for method in sorted(route.methods or ()):
            facts.append(
                RouteFact(
                    method=method,
                    path=route.path,
                    endpoint_module=getattr(endpoint, "__module__", "?"),
                    endpoint_name=getattr(endpoint, "__qualname__", repr(endpoint)),
                    db_session_scopes=scopes,
                    uses_db_session=bool(scopes),
                )
            )
    return sorted(facts, key=lambda f: (f.path, f.method))


def verify_route_census(facts: list[RouteFact], app: FastAPI) -> list[str]:
    """Prove the census had a population to count before any of its zeros are believed.

    Returns a list of problems; empty means the census is trustworthy. Every check here exists
    because its failure mode produces a *clean-looking* result: no routes, no session dependencies,
    or a route table that disagrees with the app's own matcher.
    """
    problems: list[str] = []
    if not facts:
        problems.append("the route census is empty: no APIRoute was reached at all")
        return problems

    if not any(fact.uses_db_session for fact in facts):
        problems.append(
            "no route resolves secp_api.deps.db_session; either the identity check is broken or "
            "the dependency graph is not being walked"
        )

    # Independent cross-check via a genuinely different code path: the OpenAPI schema, which
    # FastAPI builds by its own traversal. Compared as SETS of (method, path), not as counts, and
    # restricted to schema-visible routes because internal routes set include_in_schema=False.
    schema = app.openapi()
    documented = {
        (method.upper(), path)
        for path, operations in schema.get("paths", {}).items()
        for method in operations
        if method.upper() in READ_METHODS | WRITE_METHODS
    }
    visible = {
        (fact.method, fact.path)
        for fact, route in (
            (fact, route)
            for route in iter_api_routes(app)
            if route.include_in_schema
            for fact in facts
            if fact.path == route.path and fact.method in (route.methods or ())
        )
    }
    missing_from_walk = documented - visible
    if missing_from_walk:
        problems.append(
            f"{len(missing_from_walk)} operation(s) in the OpenAPI schema were not reached by the "
            f"route walk, e.g. {sorted(missing_from_walk)[:3]}"
        )
    if not documented:
        problems.append("the OpenAPI cross-check produced no operations, so it verified nothing")

    # A route this survey is known to reach must be present, or the enumeration silently narrowed.
    if not any(f.key == "POST /api/v1/templates" for f in facts):
        problems.append("the known route 'POST /api/v1/templates' is absent from the census")
    return problems


# --------------------------------------------------------------------------- commit sites


@dataclass(frozen=True)
class CommitSite:
    module: str
    lineno: int
    receiver: str
    in_except_handler: bool
    enclosing: str
    savepoint_release: bool

    @property
    def protects_success_path(self) -> bool:
        """True only for a real transaction commit reached without raising.

        A savepoint release is excluded deliberately. ``session.begin_nested().commit()`` RELEASEs a
        SAVEPOINT inside the enclosing transaction; it makes nothing durable and nothing visible to
        another connection. Counting it as protection is the single easiest way to understate this
        survey's exposure, and ``secp_api.services.provisioning`` contains exactly that shape.
        """
        return not self.in_except_handler and not self.savepoint_release


@dataclass
class CommitCensus:
    sites: list[CommitSite] = field(default_factory=list)
    modules_scanned: int = 0
    modules_unreadable: list[str] = field(default_factory=list)

    def success_path_sites(self) -> list[CommitSite]:
        """Real transaction commits reachable without an exception — the only protective ones."""
        return [site for site in self.sites if site.protects_success_path]

    def error_path_sites(self) -> list[CommitSite]:
        return [site for site in self.sites if site.in_except_handler]

    def savepoint_sites(self) -> list[CommitSite]:
        return [site for site in self.sites if site.savepoint_release]

    def modules_with_success_path_commit(self) -> set[str]:
        return {site.module for site in self.success_path_sites()}


def _enclosing_name(parents: dict[int, ast.AST], node: ast.AST) -> str:
    current: ast.AST | None = node
    while current is not None:
        if isinstance(current, ast.FunctionDef | ast.AsyncFunctionDef):
            return current.name
        current = parents.get(id(current))
    return "<module>"


def _in_except_handler(parents: dict[int, ast.AST], node: ast.AST) -> bool:
    current: ast.AST | None = node
    while current is not None:
        if isinstance(current, ast.ExceptHandler):
            return True
        current = parents.get(id(current))
    return False


def census_commit_sites(package_prefix: str = "secp_api") -> CommitCensus:
    """Every ``<something>.commit()`` under the loaded package, classified by code path.

    Keyed on the AST of the module object that is actually imported, so it describes running code.
    The receiver name is recorded but never matched on — ``session``, ``s`` and ``sp`` all count.
    """
    census = CommitCensus()
    modules: list[tuple[str, ModuleType]] = sorted(
        (name, module)
        for name, module in list(sys.modules.items())
        if module is not None and (name == package_prefix or name.startswith(package_prefix + "."))
    )
    for name, module in modules:
        try:
            source = inspect.getsource(module)
        except (OSError, TypeError):
            census.modules_unreadable.append(name)
            continue
        try:
            tree = ast.parse(source)
        except SyntaxError:
            census.modules_unreadable.append(name)
            continue
        census.modules_scanned += 1
        parents: dict[int, ast.AST] = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parents[id(child)] = parent
        savepoint_names = _savepoint_bindings(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not isinstance(func, ast.Attribute) or func.attr != "commit":
                continue
            receiver = getattr(func.value, "id", None) or ast.unparse(func.value)
            census.sites.append(
                CommitSite(
                    module=name,
                    lineno=node.lineno,
                    receiver=str(receiver),
                    in_except_handler=_in_except_handler(parents, node),
                    enclosing=_enclosing_name(parents, node),
                    savepoint_release=str(receiver) in savepoint_names,
                )
            )
    return census


def _savepoint_bindings(tree: ast.AST) -> set[str]:
    """Names bound to a ``…begin_nested()`` result anywhere in the module.

    Module-wide rather than per-scope on purpose: over-attributing "this is only a savepoint"
    would understate exposure, so the rule is kept blunt and then cross-checked at runtime, where
    SQLAlchemy's ``after_commit`` does not fire for a savepoint release at all.
    """
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        value = node.value
        if not isinstance(value, ast.Call):
            continue
        func = value.func
        if isinstance(func, ast.Attribute) and func.attr == "begin_nested":
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
    return names


def verify_commit_census(census: CommitCensus) -> list[str]:
    """Prove the AST scanner can see a commit before any module's zero is believed.

    ``secp_api.db`` contains exactly two commits — ``session_scope`` and ``get_db`` — and neither is
    inside an ``except`` handler. If the scanner cannot find those, its silence about every other
    module means nothing.
    """
    problems: list[str] = []
    if census.modules_scanned < 10:
        problems.append(
            f"only {census.modules_scanned} secp_api modules were scanned; the package does not "
            "appear to be imported, so an empty result would be meaningless"
        )
    db_sites = [site for site in census.sites if site.module == "secp_api.db"]
    if len(db_sites) != 2:
        problems.append(
            f"expected exactly 2 commit sites in secp_api.db (session_scope, get_db), found "
            f"{len(db_sites)}: the AST matcher is not finding known commits"
        )
    if any(site.in_except_handler for site in db_sites):
        problems.append(
            "a secp_api.db commit was classified as being inside an except handler; the code-path "
            "classifier is wrong in the direction that would make endpoints look safe"
        )
    if not census.error_path_sites():
        problems.append(
            "no commit anywhere was classified as error-path-only; the classifier is not "
            "discriminating, which is the direction that overstates exposure"
        )
    if not census.savepoint_sites():
        problems.append(
            "no commit was classified as a savepoint release; secp_api.services.provisioning "
            "contains a session.begin_nested() release, so the savepoint rule is not engaging and "
            "a non-protective commit would be counted as protection"
        )
    if census.modules_unreadable:
        problems.append(f"unreadable modules: {sorted(census.modules_unreadable)}")
    return problems
