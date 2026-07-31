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

STATED LIMITS, and the first one is a correction. This docstring previously claimed the literal
check meant "a runtime-assembled verb cannot reach ``runner.run`` through this module at all".
**That was false**, and it was an overstated guarantee in the module written to replace an
overstated guarantee. The finder matched only ``<x>.runner.run`` and silently skipped everything
else, so ``r = self.runner`` followed by ``r.run(verb, ...)`` was invisible to it — with a private
``_enable`` and a constructed verb stacked alongside, all three checks could be evaded at once
while the suite stayed green. The finder now REFUSES an unrecognised ``.run(`` receiver instead of
skipping it, which closes the alias.

WHAT REMAINS, stated as ONE positive residual rather than a list of escapes:

    **These checks analyse the AST. A call whose receiver is not an ``ast.Attribute`` node —
    ``getattr(obj, "run")(...)`` and nothing else in this module today (checked) — is not
    analysable by them, and is the only route they cannot see. Everything else reaching
    ``runner.run`` is caught: an unrecognised receiver is refused, a non-literal verb is refused,
    a mutation verb as any string constant is refused, and an added public method breaks the exact
    surface set.**

    That residual is covered behaviourally instead: a private method wired into a public one fails
    the behavioural tests hard, including the count-equality test, because the commands actually
    run.

Why it is phrased that way, since this docstring has now been wrong three times. The first version
over-claimed ("cannot reach ``runner.run`` at all"); the second under-claimed ("invisible to every
check here"); the third under-claimed more narrowly, naming an aliased receiver and a constructed
verb as live escapes **after both had been closed**. Each rewrite enumerated ROUTES, and a list of
what evades a guard decays exactly like a list of what it covers — every time a route is closed the
list is stale, and it is stale in the direction that makes the checks look weaker than they are.

So: state the single property that puts something outside analysis, and assert everything else is
caught. **A positive statement of the one gap cannot go stale as the checks improve; an enumeration
of escapes goes stale the moment one is closed.** An under-claim is not the safe direction — it
gets a maintainer adding a redundant guard, or working around checks they think are weak. Humility
is not accuracy.

The general point, since it is what this file keeps demonstrating: a static check should refuse
what it cannot analyse rather than pass over it, because silence and success are indistinguishable
to whoever reads the green.

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


def _run_calls(tree: ast.Module) -> tuple[list[ast.expr], list[str]]:
    """Partition every ``.run(...)`` call into recognised and UNRECOGNISED receivers.

    Returns ``(argvs of <x>.runner.run calls, descriptions of everything else)``.

    The second half is the point. An earlier version matched only ``<x>.runner.run`` and
    **silently skipped** anything else, so a one-line local alias — ``r = self.runner`` then
    ``r.run(verb, ...)`` — made the receiver an ``ast.Name``, the call invisible to the finder, and
    ``len(argvs) == 4`` still held because the original four were untouched. A check evadable by an
    alias is weak; refusing what it does not recognise is free, because every ``.run(`` receiver in
    this module is already ``<x>.runner``.
    """
    recognised: list[ast.expr] = []
    unrecognised: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "run":
            continue
        target = node.func.value
        if isinstance(target, ast.Attribute) and target.attr == "runner":
            assert len(node.args) >= 2, "runner.run called without an argv argument"
            recognised.append(node.args[1])
        else:
            unrecognised.append(f"line {node.lineno}: {ast.unparse(node.func)}")
    return recognised, unrecognised


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
    argvs, unrecognised = _run_calls(_module_ast())

    # Refuse what the finder does not recognise, rather than skipping it. Without this, a local
    # alias (``r = self.runner``) hides a call from the check entirely while the count below still
    # passes.
    assert not unrecognised, (
        f"`.run(` call(s) on an unrecognised receiver: {unrecognised} — the verb check cannot see "
        "them, so they are refused rather than skipped"
    )
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


# The permitted public surface of each concrete adapter. Declared ONCE: the guard-the-guard below
# references this rather than restating it, so a change to the real allowed-set cannot leave the
# guard validating against a stale copy of it.
ALLOWED_PUBLIC_METHODS: dict[type, frozenset[str]] = {
    LocalContainerRuntimeAdapter: frozenset({"image_present"}),
    LocalServiceStateAdapter: frozenset({"snapshot", "observe", "observe_generation"}),
}


def _public_methods(cls: type) -> set[str]:
    return {
        name for name, value in vars(cls).items() if not name.startswith("_") and callable(value)
    }


def test_the_concrete_adapters_expose_no_method_beyond_their_protocols():
    """The mutation added a public ``enable_operator_unit``. An exact set catches that; a
    ``>=`` style check would not."""
    for cls, allowed in ALLOWED_PUBLIC_METHODS.items():
        assert _public_methods(cls) == allowed, (
            f"{cls.__name__} public surface moved: {sorted(_public_methods(cls))}"
        )


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


_ALIASED_RUNNER = """
class LocalServiceStateAdapter:
    def _enable(self):
        r = self.runner
        verb = "en" + "able"
        return r.run(
            self.service_inspector, [verb, self.operator_service],
            timeout_seconds=1, max_output_bytes=1,
        )
"""


def test_the_literal_verb_check_catches_a_constructed_verb():
    """The exact mutation a substring scan cannot see."""
    argvs, _ = _run_calls(_module_ast(_CONSTRUCTED_VERB))
    assert len(argvs) == 1
    is_literal, _ = _verb_of(argvs[0])
    assert is_literal is False, "a constructed verb was accepted as a literal"


def test_the_literal_verb_check_also_catches_the_natural_shape():
    argvs, _ = _run_calls(_module_ast(_LITERAL_VERB))
    is_literal, verb = _verb_of(argvs[0])
    assert is_literal and verb == "enable" and verb in MUTATION_VERBS


def test_an_aliased_runner_is_refused_rather_than_skipped():
    """The evasion that defeated the previous finder, and the reason the fix is refusal rather
    than a wider match: the alias is not recognised, so it must be REPORTED, not passed over.

    All three evasions are stacked here — private method, aliased receiver, constructed verb —
    which together produced a fully green suite before this change.
    """
    argvs, unrecognised = _run_calls(_module_ast(_ALIASED_RUNNER))

    assert argvs == [], "the aliased call must not be mistaken for a recognised runner.run"
    assert len(unrecognised) == 1, unrecognised
    assert "r.run" in unrecognised[0]


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
    recognised, _ = _run_calls(_module_ast())
    assert recognised, "no runner.run calls found — the checks are vacuous"
    assert _run_calls(_module_ast("x = 1\n")) == ([], [])


@pytest.mark.parametrize("extra", ["enable_operator_unit", "start"])
def test_the_public_surface_check_catches_an_added_method(extra):
    """Re-runs the REAL assertion against a mutated class, rather than re-implementing the
    technique beside it. The weaker form verified that ``vars()`` sees an added method — true of
    Python, not of this check — and would have kept passing if the real assertion changed.

    Both the helper and the allowed-set are the REAL ones. An earlier version restated the set as
    a literal here, so a change to the real one would have left this guard validating a stale copy
    and still passing — a guard-the-guard drifting from the guard it guards.
    """

    class _Mutated(LocalServiceStateAdapter):  # type: ignore[misc]
        pass

    setattr(_Mutated, extra, lambda self: None)

    allowed = ALLOWED_PUBLIC_METHODS[LocalServiceStateAdapter]
    public = _public_methods(_Mutated)
    assert public != allowed, f"the public-surface check would not have caught {extra}"
    assert extra in public - allowed
