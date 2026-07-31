"""The ordinary/operator task-queue names must agree across every plane that hardcodes them.

WHY THIS GUARD EXISTS
---------------------
``"secp-orchestration"`` is written as a literal in SIX independent production sites spanning five
packages, with nothing keeping them equal. They agree today, which is exactly what makes the risk
invisible: a future change to one is silent, not loud.

The consequence is cross-stream and specifically bad. ``secp_operator_deployment`` hardcodes the
name NOWHERE — it reads queue names as DATA from the root-controlled deployment profile and matches
them against an independent pins file. So its operator-facing isolation check would keep reporting
green, *correctly*, while the worker had drifted onto a different queue. The check cannot detect the
drift, because it never reads any of these literals. Detecting it has to happen here.

WHY A GUARD RATHER THAN A SINGLE CONSTANT
-----------------------------------------
Consolidating to one shared symbol is the better end state, but it would mean editing packages this
stream does not own — ``apps/deployment/secp_discovery_activation`` in particular. A guard is
owner-neutral, catches a NEW seventh site (which consolidation alone would not), and can be
tightened into the consolidation later without losing coverage in between.

The inline comparison in ``adapters.py`` is the most dangerous of the six: a bare literal inside a
conditional is the least likely to be found by anyone changing the constant, and it fails silently
rather than loudly. It is therefore scanned from the AST rather than imported.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

#: Every site that hardcodes the ORDINARY queue name, as (path, how-to-read-it).
#: Adding a seventh site without adding it here does not weaken the guard — the sweep below
#: independently fails on any unregistered occurrence of the literal.
_ORDINARY_SYMBOL_SITES = (
    ("apps/deployment/secp_discovery_activation/layout.py", "ORDINARY_TASK_QUEUE"),
    ("apps/management/secp_management/topology.py", "ORDINARY_TASK_QUEUE"),
    ("apps/worker/secp_worker/activation_probe.py", "ORDINARY_TASK_QUEUE"),
    ("apps/commissioning/secp_commissioning/cli.py", "DEFAULT_ORDINARY_QUEUE"),
)

#: Sites where the name is not a module-level constant and must be read differently.
_ORDINARY_OTHER_SITES = (
    "apps/api/secp_api/config.py",  # the Settings default
    "apps/deployment/secp_discovery_activation/adapters.py",  # an INLINE comparison
)

_PRODUCTION_ROOTS = ("apps", "contracts", "plugins")


def _module_constant(rel_path: str, name: str) -> str:
    """Read a module-level string constant by AST, without importing the module.

    Importing would drag in each package's dependencies and couple this guard to import order; the
    assignment is what we are asserting about, so read exactly that.
    """
    tree = ast.parse((REPO / rel_path).read_text(encoding="utf-8"), filename=rel_path)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if (
                    isinstance(target, ast.Name)
                    and target.id == name
                    and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)
                ):
                    return node.value.value
        if (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == name
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            return node.value.value
    raise AssertionError(f"{rel_path} no longer defines {name} as a string constant")


def _string_literals(rel_path: str) -> list[str]:
    tree = ast.parse((REPO / rel_path).read_text(encoding="utf-8"), filename=rel_path)
    return [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]


def test_every_symbolic_ordinary_queue_site_agrees() -> None:
    values = {rel: _module_constant(rel, name) for rel, name in _ORDINARY_SYMBOL_SITES}
    distinct = set(values.values())
    assert len(distinct) == 1, f"the ordinary task queue name has drifted across planes: {values}"
    assert distinct == {"secp-orchestration"}, distinct


def test_the_settings_default_and_the_inline_comparison_agree_with_the_constants() -> None:
    """The two sites that are not module constants must still carry the same name.

    ``config.py`` is the value the shipped worker actually polls, and ``adapters.py`` is the bare
    literal inside a conditional — the one most likely to drift unnoticed.
    """
    expected = _module_constant(_ORDINARY_SYMBOL_SITES[0][0], _ORDINARY_SYMBOL_SITES[0][1])
    for rel in _ORDINARY_OTHER_SITES:
        assert expected in _string_literals(rel), (
            f"{rel} no longer carries the ordinary queue name {expected!r} — "
            "it has drifted from the other planes"
        )


def test_no_unregistered_site_hardcodes_the_ordinary_queue() -> None:
    """A SEVENTH site is the failure mode consolidation alone would not catch.

    Any new production occurrence of the literal must be added to the lists above (and thereby be
    checked for agreement), or removed in favour of importing an existing constant.
    """
    known = {rel for rel, _ in _ORDINARY_SYMBOL_SITES} | set(_ORDINARY_OTHER_SITES)
    offenders: list[str] = []
    for root in _PRODUCTION_ROOTS:
        for path in sorted((REPO / root).rglob("*.py")):
            if "__pycache__" in path.parts or "tests" in path.parts:
                continue
            rel = str(path.relative_to(REPO)).replace("\\", "/")
            if rel in known:
                continue
            if "secp-orchestration" in _string_literals(rel):
                offenders.append(rel)
    assert not offenders, (
        "new site(s) hardcode the ordinary task queue without being covered by this guard: "
        f"{offenders}"
    )


def test_the_operator_queue_is_distinct_from_the_ordinary_queue() -> None:
    """A shared queue would let the sealed worker pick up controlled-live work (ADR-022 §12)."""
    topology = "apps/management/secp_management/topology.py"
    ordinary = _module_constant(topology, "ORDINARY_TASK_QUEUE")
    operator = _module_constant(topology, "OPERATOR_TASK_QUEUE")
    assert ordinary != operator
    assert operator == "secp-controlled-live-v1"


def test_the_guard_is_not_vacuous() -> None:
    """Every registered site must really carry the literal — an empty sweep would pass silently."""
    for rel, name in _ORDINARY_SYMBOL_SITES:
        assert _module_constant(rel, name) == "secp-orchestration", rel
    for rel in _ORDINARY_OTHER_SITES:
        assert "secp-orchestration" in _string_literals(rel), rel
