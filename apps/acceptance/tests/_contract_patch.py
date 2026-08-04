"""Patch a contract constant in EVERY module that binds it, discovered rather than enumerated.

THE HALF-PATCHED WORLD
----------------------
``from secp_acceptance.reasons import PASSING_OUTCOMES`` binds the name at import time, so each
importing module holds its own reference. Patching one module leaves every other answering from the
real contract — and the result reads as a pass, because the unpatched values are the correct ones
and most assertions still hold.

That is not hypothetical. Patching only ``recorder`` while testing the allowlist produced a run
whose verdict said ``failed`` while the document's own ``not_passing()`` said nothing was failing —
inside the test named for exactly that disagreement.

WHY DISCOVERED AND NOT ENUMERATED
---------------------------------
The first fix was ``monkeypatch.setattr`` on the two modules known to bind it, by name. That is
correct until a third binder appears, at which point the test is silently half-patched again and
nothing says so. acc-B-enrollment hit precisely that when its module became the third.

So the binders are discovered from the import graph. A new binder is covered the day it is written,
by a test nobody remembered to update.

WHY THE PRODUCTION MODULES WERE NOT CHANGED INSTEAD
---------------------------------------------------
Late binding (``reasons.PASSING_OUTCOMES`` at each use site) would remove the hazard at the root.
It was declined deliberately: the hazard does not exist in production, where these constants never
change at runtime. It is an artefact of monkeypatching. Reshaping shipped modules to make a test
technique safer is the wrong trade, and doing it to only SOME of the binders is strictly worse than
not doing it at all.
"""

from __future__ import annotations

import ast
import importlib
import pathlib

import pytest

_PACKAGE = "secp_acceptance"


def _package_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[1] / _PACKAGE


def binders_of(name: str) -> tuple[str, ...]:
    """Every module in the package that imports ``name`` from the contract, by import graph.

    Read over the AST rather than by importing and inspecting: a module that has not been imported
    yet still binds the name the moment it is, and a sweep that only saw loaded modules would give a
    different answer depending on test ordering.
    """
    found: list[str] = []
    for path in sorted(_package_root().rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom):
                continue
            if node.module and node.module.startswith(_PACKAGE):
                if any(alias.name == name for alias in node.names):
                    found.append(f"{_PACKAGE}.{path.stem}")
                    break
    return tuple(found)


def patch_contract_constant(
    monkeypatch: pytest.MonkeyPatch, name: str, value: object
) -> tuple[str, ...]:
    """Patch ``name`` to ``value`` in every module that binds it. Returns the modules patched.

    Refuses when the sweep finds nothing. That guard is the load-bearing half: this mechanism
    succeeds by FINDING a set, so a sweep that silently matched nothing would leave every caller
    running against a completely unpatched world — and passing, because the unpatched values are the
    real ones. A negative-form mechanism is worth exactly the corpus it was evaluated over.
    """
    modules = binders_of(name)
    if not modules:
        raise AssertionError(
            f"no module was found binding {name!r}. Either the constant was renamed, or the "
            f"import-graph sweep is broken — in both cases patching nothing would leave this test "
            f"running against the real contract while reading as a pass."
        )
    for module_name in modules:
        monkeypatch.setattr(importlib.import_module(module_name), name, value, raising=True)
    return modules


__all__ = ["binders_of", "patch_contract_constant"]
