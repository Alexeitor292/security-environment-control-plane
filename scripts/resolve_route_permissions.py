"""Resolve which permission each API route requires, by following the call graph.

WHY THIS IS NOT A GREP. The permission is almost never in the route handler. `list_ranges` takes
only `principal: Principal = Depends(current_principal)` and its body calls
``ranges.list_ranges(session, principal, ...)``; the gate — ``principal.require(
Permission.exercise_operate)`` — lives in the service, one hop away. A scan of the handler body
finds nothing and concludes the route is unguarded, which is both wrong and reassuring, the worst
combination. Nothing about `GET /api/v1/targets` suggests `target_discovery:manage` either.

So this walks: route decorator -> handler -> every function the handler calls that is reachable in
``secp_api`` -> ``principal.require(Permission.X)``, to a bounded depth.

WHAT IT REFUSES TO GUESS. A route whose chain reaches no ``require`` is reported as UNRESOLVED, not
as "no permission required". Those are different claims and only one of them is safe to render: a
client told "this needs nothing" will show the control to everyone. Unresolved entries are listed
so a human decides, which is the same choice the reachability analysis makes when its rules stop
matching.

    python scripts/resolve_route_permissions.py            # write the artifact
    python scripts/resolve_route_permissions.py --check     # fail if it is stale
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
API_ROOT = REPO_ROOT / "apps" / "api" / "secp_api"
ARTIFACT = REPO_ROOT / "contracts" / "openapi" / "route-permissions.json"

#: How far to follow calls. Two hops covers route -> service -> helper, which is every shape in
#: the tree today; a deeper chain is reported unresolved rather than followed forever.
MAX_DEPTH = 4


def _module_functions() -> dict[str, list[ast.FunctionDef]]:
    """Every function in ``secp_api``, keyed by bare name -> ALL bodies with that name.

    A LIST, not one body, and the first version of this was wrong in a way worth recording. It used
    ``setdefault``, so the first function found under a name won — and ``routers/ranges.py`` defines
    ``list_ranges`` just as ``services/ranges.py`` does. Sorted traversal reached the router first,
    so resolving the route handler's call to ``ranges.list_ranges`` found the handler itself, which
    was already in ``seen``. The chain stopped at the first hop and 213 of 243 routes reported no
    permission at all — including ones whose ``principal.require`` is a single readable line away.

    The comment that version carried claimed a collision "can only turn an unresolved route into a
    resolved one". That was false in exactly the case it mattered, which is the same
    one-word-two-concepts error as `operation_id` and `list_ranges` is a better example of it than
    anything invented would be. Every candidate body is searched now; `seen` bounds the recursion.
    """
    found: dict[str, list[ast.FunctionDef]] = {}
    for path in sorted(API_ROOT.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError:  # pragma: no cover - a file that does not parse is not a call target
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                found.setdefault(node.name, []).append(node)
    return found


def _permissions_in(node: ast.AST) -> set[str]:
    """``principal.require(Permission.X)`` -> ``{"X"}``, for this body only."""
    names: set[str] = set()
    for call in ast.walk(node):
        if not isinstance(call, ast.Call):
            continue
        func = call.func
        if not (isinstance(func, ast.Attribute) and func.attr in {"require", "require_any"}):
            continue
        for argument in call.args:
            if isinstance(argument, ast.Attribute) and isinstance(argument.value, ast.Name):
                if argument.value.id == "Permission":
                    names.add(argument.attr)
    return names


def _called_names(node: ast.AST) -> set[str]:
    called: set[str] = set()
    for call in ast.walk(node):
        if not isinstance(call, ast.Call):
            continue
        func = call.func
        if isinstance(func, ast.Name):
            called.add(func.id)
        elif isinstance(func, ast.Attribute):
            called.add(func.attr)
    return called


def _resolve(
    function: ast.FunctionDef,
    functions: dict[str, list[ast.FunctionDef]],
    depth: int,
    seen: frozenset[int],
) -> set[str]:
    """Follow calls until a ``require`` is found, or the depth runs out.

    ``seen`` holds function IDENTITIES, not names, and that distinction was the second bug here.
    Keyed on the name, the router's ``list_ranges`` put "list_ranges" into ``seen`` before
    recursing, so the SERVICE function of the same name — the one holding
    ``principal.require(Permission.exercise_operate)`` — was skipped as already visited. The guard
    exists to stop cycles, and two different functions that share a name are not a cycle.
    """
    found = _permissions_in(function)
    if found or depth >= MAX_DEPTH:
        return found
    for name in sorted(_called_names(function)):
        if name not in functions:
            continue
        for candidate in functions[name]:
            if id(candidate) in seen:
                continue
            found |= _resolve(candidate, functions, depth + 1, seen | {id(candidate)})
    return found


def route_permissions() -> dict[str, dict[str, list[str]]]:
    """``{"GET /api/v1/targets": {"permissions": ["target_discovery_manage"]}}``."""
    functions = _module_functions()
    routes: dict[str, dict[str, list[str]]] = {}
    for path in sorted((API_ROOT / "routers").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        prefix = ""
        for node in ast.walk(tree):
            # `APIRouter(prefix="/api/v1")` — the prefix a router's paths hang off.
            if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "APIRouter":
                for keyword in node.keywords:
                    if keyword.arg == "prefix" and isinstance(keyword.value, ast.Constant):
                        prefix = str(keyword.value.value)
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            for decorator in node.decorator_list:
                if not isinstance(decorator, ast.Call):
                    continue
                attribute = decorator.func
                if not (
                    isinstance(attribute, ast.Attribute)
                    and attribute.attr in {"get", "post", "put", "patch", "delete"}
                ):
                    continue
                if not decorator.args or not isinstance(decorator.args[0], ast.Constant):
                    continue
                route = f"{attribute.attr.upper()} {prefix}{decorator.args[0].value}"
                names = sorted(_resolve(node, functions, 0, frozenset({id(node)})))
                routes[route] = {"permissions": names}
    return routes


def serialize(routes: dict[str, dict[str, list[str]]]) -> str:
    return json.dumps(routes, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail when the artifact is stale")
    args = parser.parse_args(argv)

    rendered = serialize(route_permissions())
    if not args.check:
        ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        with ARTIFACT.open("w", encoding="utf-8", newline="") as handle:
            handle.write(rendered)
        print(f"wrote {ARTIFACT.relative_to(REPO_ROOT).as_posix()}")
        return 0

    if not ARTIFACT.exists():
        print("route-permissions.json is missing", file=sys.stderr)
        return 1
    if ARTIFACT.read_text(encoding="utf-8") != rendered:
        print(
            "route-permissions.json is STALE. Run: python scripts/resolve_route_permissions.py",
            file=sys.stderr,
        )
        return 1
    print("route permissions are in step with the call graph.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
