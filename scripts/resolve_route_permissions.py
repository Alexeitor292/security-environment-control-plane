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

#: Routes READ BY HAND and found to enforce no permission beyond authentication.
#:
#: This list is the difference between "we checked, and there is no gate" and "the walk found
#: nothing", which are opposite instructions to a client and are otherwise the same empty result.
#: A route only joins this set when somebody has read the service function and seen the absence.
VERIFIED_OPEN: frozenset[str] = frozenset(
    {
        # services/targets.py:269 — scopes by `actor.organization_id`, with no
        # `principal.require` anywhere in the chain. Confirmed independently by two
        # people, by two methods, on 2026-08-05.
        "GET /api/v1/targets",
        # routers/system.py:33 — the handler takes `_: Principal` and calls `get_registry()
        # .health_all()`. No service, no `require`. Found because the resolver had wrongly given it
        # `worker_identity_manage` from an unrelated function of a matching name, which would have
        # HIDDEN the integrations surface from operators entitled to see it.
        "GET /api/v1/plugins",
    }
)


def _module_functions() -> dict[str, list[tuple[str, ast.FunctionDef]]]:
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
    found: dict[str, list[tuple[str, ast.FunctionDef]]] = {}
    for path in sorted(API_ROOT.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError:  # pragma: no cover - a file that does not parse is not a call target
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                found.setdefault(node.name, []).append((path.stem, node))
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


def _alias_map(tree: ast.Module) -> dict[str, str]:
    """Import aliases in one file -> the module they name.

    `routers/worker_nodes.py` does `from ... import worker_nodes as svc`, so its calls read
    `svc.list_worker_nodes(...)`. Matching the alias against file stems finds nothing and the
    route reports unguarded — the reassuring direction again. The alias has to be resolved.
    """
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for name in node.names:
                aliases[name.asname or name.name] = name.name
        elif isinstance(node, ast.Import):
            for name in node.names:
                aliases[name.asname or name.name.split(".")[0]] = name.name.split(".")[-1]
    return aliases


def _called_names(node: ast.AST) -> set[tuple[str | None, str]]:
    """Calls in this body as ``(module_alias, name)``.

    The alias matters. ``ranges.list_ranges(...)`` names the module it means, and resolving it to
    every function called ``list_ranges`` anywhere in ``secp_api`` is how
    ``GET /api/v1/plugins`` — a handler that calls ``get_registry().health_all()`` and enforces
    nothing — acquired ``worker_identity_manage`` from an unrelated function of a matching name.
    That is the RESTRICTIVE error: it hides a surface from operators entitled to see it, and it
    looks exactly like diligence.
    """
    called: set[tuple[str | None, str]] = set()
    for call in ast.walk(node):
        if not isinstance(call, ast.Call):
            continue
        func = call.func
        if isinstance(func, ast.Name):
            called.add((None, func.id))
        elif isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name):
                called.add((func.value.id, func.attr))
            # A receiver that is not a plain name — `get_registry().health_all()` — is a VALUE of
            # unknown type, not a module. Following it by method name alone is what gave
            # `GET /api/v1/plugins` a `worker_identity_manage` it does not enforce. Unattributable
            # calls are not followed; the route stays `unknown`, which is the safe state.
    return called


def _resolve(
    function: ast.FunctionDef,
    functions: dict[str, list[tuple[str, ast.FunctionDef]]],
    depth: int,
    seen: frozenset[int],
    aliases: dict[str, str],
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
    for module, name in sorted(_called_names(function), key=lambda pair: (pair[1], pair[0] or "")):
        if name not in functions:
            continue
        candidates = functions[name]
        resolved = aliases.get(module or "", module)
        # A qualified call names its module: follow only that one. An unqualified call could be a
        # local helper or an import, so every body is still considered — but a WRONG module can no
        # longer contribute a permission to a route that calls something else of the same name.
        if module is not None:
            candidates = [pair for pair in candidates if pair[0] in {module, resolved}]
        for _, candidate in candidates:
            if id(candidate) in seen:
                continue
            found |= _resolve(candidate, functions, depth + 1, seen | {id(candidate)}, aliases)
    return found


def route_permissions() -> dict[str, dict[str, object]]:
    """``{"GET /api/v1/ranges": {"state": "requires", "permissions": ["exercise_operate"]}}``."""
    functions = _module_functions()
    routes: dict[str, dict[str, object]] = {}
    for path in sorted((API_ROOT / "routers").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        aliases = _alias_map(tree)
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
                names = sorted(_resolve(node, functions, 0, frozenset({id(node)}), aliases))
                # Three states, never two. `open` is a verified absence of a gate; `unknown` is
                # the walk finding nothing, which a client must not render as "needs nothing".
                if names:
                    state = "requires"
                elif route in VERIFIED_OPEN:
                    state = "open"
                else:
                    state = "unknown"
                routes[route] = {"state": state, "permissions": names}
    return routes


def serialize(routes: dict[str, dict[str, object]]) -> str:
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
