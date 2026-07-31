"""The adapters cannot mutate the host — checked structurally, not textually (WS-E).

Two pre-existing guards assert this by substring: ``assert f'"{verb}," not in text``. They see a
double-quoted verb followed immediately by a comma, and nothing else. That covers the accidental
regression — someone typing ``("enable", self.operator_service)`` is caught — but it is blind to a
constructed verb, and the property is load-bearing for a SAFETY claim rather than a style one.

The hole, demonstrated: a genuine ``enable_operator_unit()`` building ``verb = "en" + "able"`` and
calling ``self.runner.run(self.service_inspector, [verb, self.operator_service], ...)`` passes a
substring scan. A live ``systemctl enable <operator-service>`` path would sit in the shipped adapter
with every textual guard green.

Three independent structural checks close it, each proven to fire against synthetic mutated source
rather than assumed to:

* :func:`test_every_runner_call_passes_a_literal_read_only_verb` — the ARGV POSITION that decides
  mutation is position 0, and it must be a string LITERAL from a read-only allowlist. A computed
  verb is not a ``Constant`` and is refused on that basis alone, whatever it evaluates to. This is
  the check the substring scan could not express.
* :func:`test_no_mutation_verb_appears_as_a_string_literal_anywhere` — the natural shape, but over
  every string constant in the AST rather than one punctuation-sensitive spelling.
* :func:`test_the_concrete_adapters_expose_no_method_beyond_their_protocols` — the protocols are
  single-method (``ContainerRuntime.image_present``, ``ServiceStateAdapter.snapshot``), which is
  genuinely strong; what the mutation exploited is that a CONCRETE adapter may carry extra methods
  and call them itself. Pinned as an exact set.

Stated limit: a private method (``_enable``) called from an existing public one would evade the
third check, and a verb assembled at runtime from data would evade the first two. The first check is
the backstop for that case — it refuses any non-literal in the verb position, so a runtime-assembled
verb cannot reach ``runner.run`` through this module at all. What none of them cover is a verb
reaching the runner from OUTSIDE this module; the runner is only ever constructed with pinned
executables, which is a separate property tested elsewhere.

Nothing here executes an adapter method or runs a command; the module is parsed and its classes
introspected.
"""

from __future__ import annotations

import ast
import inspect
import pathlib

import pytest
from secp_operator_deployment.host_adapters import (
    LocalContainerRuntimeAdapter,
    LocalServiceStateAdapter,
)

_ADAPTERS = pathlib.Path(inspect.getfile(LocalServiceStateAdapter))

# Verbs that MUTATE a unit or container. Neither systemd nor the container runtime may receive one.
MUTATION_VERBS = frozenset(
    {
        "start",
        "stop",
        "restart",
        "enable",
        "disable",
        "reload",
        "mask",
        "unmask",
        "kill",
        "rm",
        "remove",
        "create",
        "run",
        "pull",
        "push",
        "prune",
        "update",
        "daemon-reload",
    }
)

# The read-only subcommands this module is permitted to invoke, in argv position 0.
READ_ONLY_VERBS = frozenset({"image", "inspect", "show", "exec"})


def _module_ast(source: str | None = None) -> ast.Module:
    return ast.parse(source if source is not None else _ADAPTERS.read_text(encoding="utf-8"))


def _runner_call_argvs(tree: ast.Module) -> list[ast.expr]:
    """The second positional argument of every ``<x>.runner.run(...)`` call."""
    found: list[ast.expr] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "run":
            continue
        target = node.func.value
        if isinstance(target, ast.Attribute) and target.attr == "runner":
            assert len(node.args) >= 2, "runner.run called without an argv argument"
            found.append(node.args[1])
    return found


def _verb_of(argv: ast.expr) -> tuple[bool, str | None]:
    """``(is_literal, value)`` for argv position 0."""
    if not isinstance(argv, ast.Tuple | ast.List) or not argv.elts:
        return False, None
    first = argv.elts[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        return True, first.value
    return False, None


# --------------------------------------------------------------------------- the three checks


def test_every_runner_call_passes_a_literal_read_only_verb():
    argvs = _runner_call_argvs(_module_ast())
    assert len(argvs) == 4, f"expected 4 runner.run sites, found {len(argvs)}"

    for argv in argvs:
        is_literal, verb = _verb_of(argv)
        assert is_literal, (
            "a runner.run argv does not begin with a string LITERAL. A computed verb is refused "
            "here regardless of what it evaluates to — that is the point of this check."
        )
        assert verb in READ_ONLY_VERBS, f"non-read-only verb {verb!r}"
        assert verb not in MUTATION_VERBS, verb


def test_no_mutation_verb_appears_as_a_string_literal_anywhere():
    """The natural shape, over every string constant rather than one spelling of it."""
    offenders = sorted(
        {
            node.value
            for node in ast.walk(_module_ast())
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value in MUTATION_VERBS
        }
    )
    assert not offenders, f"mutation verb literal(s) in the adapters: {offenders}"


def test_the_concrete_adapters_expose_no_method_beyond_their_protocols():
    """The mutation added a public ``enable_operator_unit``. An exact set catches that; a
    ``>=`` style check would not."""
    for cls, allowed in (
        (LocalContainerRuntimeAdapter, {"image_present"}),
        (LocalServiceStateAdapter, {"snapshot", "observe", "observe_generation"}),
    ):
        public = {
            name
            for name, value in vars(cls).items()
            if not name.startswith("_") and callable(value)
        }
        assert public == allowed, f"{cls.__name__} public surface moved: {sorted(public)}"


# --------------------------------------------------------------------------- guard the guards
#
# Each check is shown to FIRE on the shape it claims to catch. A structural check that silently
# stopped matching would be exactly as green as one that holds.


_CONSTRUCTED_VERB = """
class LocalServiceStateAdapter:
    def enable_operator_unit(self):
        verb = "en" + "able"
        return self.runner.run(
            self.service_inspector, [verb, self.operator_service],
            timeout_seconds=1, max_output_bytes=1,
        )
"""

_LITERAL_VERB = """
class LocalServiceStateAdapter:
    def enable_operator_unit(self):
        return self.runner.run(
            self.service_inspector, ("enable", self.operator_service),
            timeout_seconds=1, max_output_bytes=1,
        )
"""


def test_the_literal_verb_check_catches_a_constructed_verb():
    """The exact mutation a substring scan cannot see."""
    argvs = _runner_call_argvs(_module_ast(_CONSTRUCTED_VERB))
    assert len(argvs) == 1
    is_literal, _ = _verb_of(argvs[0])
    assert is_literal is False, "a constructed verb was accepted as a literal"


def test_the_literal_verb_check_also_catches_the_natural_shape():
    argvs = _runner_call_argvs(_module_ast(_LITERAL_VERB))
    is_literal, verb = _verb_of(argvs[0])
    assert is_literal and verb == "enable" and verb in MUTATION_VERBS


def test_the_literal_scan_catches_a_mutation_verb_the_substring_form_would_miss():
    """``assert '"enable",' not in text`` misses this: no comma follows the literal."""
    missed_by_substring = 'x = ("enable")\n'
    assert '"enable",' not in missed_by_substring  # the old guard would pass
    offenders = {
        n.value
        for n in ast.walk(_module_ast(missed_by_substring))
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value in MUTATION_VERBS
    }
    assert offenders == {"enable"}  # the AST scan does not


def test_the_runner_call_finder_is_not_vacuous():
    """If the finder stopped matching, every check above would pass over an empty list."""
    assert _runner_call_argvs(_module_ast()), "no runner.run calls found — the checks are vacuous"
    assert not _runner_call_argvs(_module_ast("x = 1\n"))


@pytest.mark.parametrize("extra", ["enable_operator_unit", "start"])
def test_the_public_surface_check_catches_an_added_method(extra):
    class _Mutated(LocalServiceStateAdapter):  # type: ignore[misc]
        pass

    setattr(_Mutated, extra, lambda self: None)
    public = {n for n, v in vars(_Mutated).items() if not n.startswith("_") and callable(v)}
    assert extra in public
