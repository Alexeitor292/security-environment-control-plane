"""The simulator execution surface (secp_plugin_simulator.reconciliation).

Execution exists only here, and the claim this file has to earn is that the module is
*structurally* incapable of reaching a provider — not configured not to, not policed at runtime.
Three independent properties carry it, each checked mechanically:

1. **Nothing that could reach anything can be passed in.** The exact set of types appearing in the
   module's public signatures is pinned, and every one of them is a builtin scalar, an enum, or a
   frozen dataclass. There is no protocol, no callable, no context and no port among them, so no
   caller — and no configuration — can hand this module a connection.
2. **Its compiled code names no escape.** Checked on compiled code objects, never on source text,
   so a sentinel that merely appears in a comment proves nothing here. Two walks contribute: one
   compiles each package source file and recurses it, which is complete over the file *by
   construction*; the other walks what the interpreter actually loaded. The first exists because
   the second alone reaches only callables bound in module globals or a class body, and so missed
   a callable held in a module-level container -- the exact shape an escape would take, and one
   every other guard in this file also misses.
3. **Its import closure is pure computation.** Asserted over both packages in
   ``tests/test_reconciliation_boundary_guards.py``; this file checks the loaded module's own
   globals as well.

The remaining tests are ordinary behaviour: a plan applied to an in-memory world converges it, is
idempotent, and refuses when it is not the plan for that state.
"""

from __future__ import annotations

import dataclasses
import inspect
import types
import typing
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path

import pytest
import secp_reconciliation
from reconciliation_support import (
    COLLECTOR_DIGEST,
    NOW,
    desired,
    network,
    node,
    observed,
    scope,
)
from secp_plugin_simulator import reconciliation as simulator
from secp_reconciliation.v1 import (
    ActionKind,
    ElementKind,
    ObservationFidelity,
    ObservedState,
    PlannedAction,
    ReconciliationRefused,
    RefusalCode,
    ResetScope,
    StateElement,
    build_reset_intent,
    plan_from_states,
)

# --- Property 1: the input surface admits nothing that could reach anything --------------------

# Every type appearing anywhere in the module's public signatures, as ``(module, qualname)``. Exact,
# not a floor: a new parameter of a new type fails here rather than slipping in under a subset test.
EXPECTED_SURFACE_TYPES = {
    ("builtins", "str"),
    ("builtins", "tuple"),
    # `now` is a parameter precisely so no ambient clock decides anything -- see INERT_VALUE_TYPES
    ("datetime", "datetime"),
    ("secp_plugin_simulator.reconciliation", "SimulatedElement"),
    ("secp_plugin_simulator.reconciliation", "SimulatedWorld"),
    ("secp_reconciliation.v1.codes", "ElementKind"),
    ("secp_reconciliation.v1.codes", "FacetName"),
    ("secp_reconciliation.v1.codes", "ObservationFidelity"),
    ("secp_reconciliation.v1.execution", "ExecutionReport"),
    ("secp_reconciliation.v1.planner", "ReconciliationPlan"),
    ("secp_reconciliation.v1.reset", "ResetIntent"),
    ("secp_reconciliation.v1.state", "DesiredState"),
    ("secp_reconciliation.v1.state", "ObservedState"),
    ("secp_reconciliation.v1.state", "ReconciliationScope"),
}

# The same set closed under dataclass fields: everything reachable at any depth from anything the
# module can be handed. Also exact.
EXPECTED_CLOSURE_TYPES = EXPECTED_SURFACE_TYPES | {
    # reached through ReconciliationScope's max_actions / observation_max_age_seconds
    ("builtins", "int"),
    ("secp_reconciliation.v1.codes", "ActionKind"),
    ("secp_reconciliation.v1.codes", "DriftReason"),
    ("secp_reconciliation.v1.codes", "ExecutionOutcome"),
    ("secp_reconciliation.v1.codes", "OperatorNextStep"),
    ("secp_reconciliation.v1.codes", "PlanDisposition"),
    ("secp_reconciliation.v1.codes", "ResetScope"),
    ("secp_reconciliation.v1.codes", "StepFailureReason"),
    ("secp_reconciliation.v1.codes", "StepStatus"),
    ("secp_reconciliation.v1.execution", "StepOutcome"),
    ("secp_reconciliation.v1.planner", "DeferredElement"),
    ("secp_reconciliation.v1.planner", "PlannedAction"),
    ("secp_reconciliation.v1.state", "StateElement"),
}


# Value types that are neither enums nor frozen dataclasses but are still inert: immutable, and
# carrying no capability the module does not already have. `datetime` is admitted deliberately --
# the module already may import `datetime` (it is on the pure-computation allow-list), so being
# handed an instance grants nothing new. The one thing an instance *could* offer is a clock, which
# would break this module's determinism claim, so the clock-reading method names are on
# FORBIDDEN_CODE_NAMES below and that is checked on compiled code rather than assumed here.
INERT_VALUE_TYPES = (str, bool, int, tuple, datetime)

_UNION_ORIGINS = (typing.Union, types.UnionType)


def _public_callables():
    """Every public function and class the execution module exposes, discovered rather than
    listed, so a new public entry point is covered the moment it is added."""
    found = []
    for name, value in vars(simulator).items():
        if name.startswith("_"):
            continue
        if not (inspect.isfunction(value) or inspect.isclass(value)):
            continue
        if value.__module__ != simulator.__name__:
            continue
        found.append((name, value))
    return sorted(found)


def _flatten_annotation(annotation, into: set) -> None:
    if annotation is None or annotation is type(None) or annotation is Ellipsis:
        return
    origin = typing.get_origin(annotation)
    if origin in _UNION_ORIGINS:
        # `X | None` is not a type a caller can pass -- X and None are. Recording the union
        # machinery itself would put `types.UnionType` in the surface, which says nothing about
        # what this module can be handed.
        for argument in typing.get_args(annotation):
            _flatten_annotation(argument, into)
        return
    if origin is not None:
        into.add(origin)
        for argument in typing.get_args(annotation):
            _flatten_annotation(argument, into)
        return
    into.add(annotation)


def _surface_types() -> set:
    types_found: set = set()
    for _, value in _public_callables():
        target = value.__init__ if inspect.isclass(value) else value
        hints = typing.get_type_hints(target)
        for annotation in hints.values():
            _flatten_annotation(annotation, types_found)
    return types_found


def _public_parameters():
    """Every declared parameter of every public callable, as ``(callable, name, Parameter)``.

    Read off :func:`inspect.signature`, which sees *declarations*. Everything else in this section
    reads :func:`typing.get_type_hints`, which sees *annotations* — and those two disagree exactly
    when a parameter is unannotated. That disagreement is the hole the next two tests close.
    """
    found = []
    for name, value in _public_callables():
        target = value.__init__ if inspect.isclass(value) else value
        for parameter_name, parameter in inspect.signature(target).parameters.items():
            if parameter_name in ("self", "cls"):
                continue
            found.append((name, parameter_name, parameter))
    return found


def test_every_public_parameter_is_annotated() -> None:
    """The precondition the whole input-surface property rests on, and which nothing else checks.

    ``_surface_types()`` collects through ``typing.get_type_hints()``, which returns only
    *annotated* parameters. An unannotated one contributes nothing to that set and is therefore
    invisible to all four guards built on it — the exact pin, the inert-value-type check, the
    transitive closure, and the no-``Callable`` check. It is invisible to the escape scan too,
    because a parameter name lands in ``co_varnames`` rather than ``co_names``.

    Demonstrated rather than theorised: a single ``progress_sink=None`` added to ``execute`` and
    called in its action loop left all 50 isolation and leak guards green while a caller-supplied
    lambda received the real ``socket.socket`` class. Written *with* an annotation the same
    parameter fails five guards, so the boundary was precisely annotated-caught /
    unannotated-invisible. mypy does not cover the gap either: this repo sets
    ``check_untyped_defs`` but not ``disallow_incomplete_defs``.
    """
    unannotated = [
        (owner, parameter_name)
        for owner, parameter_name, parameter in _public_parameters()
        if parameter.annotation is inspect.Parameter.empty
    ]
    assert unannotated == []


def test_no_public_callable_accepts_varargs_or_keyword_args() -> None:
    """The residual route the annotation check alone leaves open, closed rather than disclosed.

    ``*args`` / ``**kwargs`` have nothing to annotate per-argument, so a public callable accepting
    them takes values no pinned type set describes — a second way in, differing from the first only
    in spelling. No public callable here needs them, so this is closed at zero cost rather than
    written down as a caveat. If one ever genuinely needs a variadic, this test is where that
    decision has to be argued.
    """
    variadic = [
        (owner, parameter_name)
        for owner, parameter_name, parameter in _public_parameters()
        if parameter.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)
    ]
    assert variadic == []


def test_the_annotation_and_declaration_views_agree_on_the_public_surface() -> None:
    """Ties the two views together, so neither can drift into covering less than the other.

    Without this, `_public_parameters` and `_surface_types` could diverge silently — the first
    walking declarations, the second annotations — and the tests above would still pass while
    guarding a different set of parameters than the pins actually read.
    """
    for name, value in _public_callables():
        target = value.__init__ if inspect.isclass(value) else value
        annotated = set(typing.get_type_hints(target)) - {"return"}
        declared = {
            parameter_name for owner, parameter_name, _ in _public_parameters() if owner == name
        }
        assert declared == annotated, (name, declared ^ annotated)


def test_the_public_surface_is_the_one_that_was_reviewed() -> None:
    assert [name for name, _ in _public_callables()] == [
        "SimulatedElement",
        "SimulatedWorld",
        "execute",
        "observe",
        "world_digest",
    ]


def test_the_signature_surface_is_exactly_the_reviewed_set_of_types() -> None:
    actual = {(found.__module__, found.__qualname__) for found in _surface_types()}
    assert actual == EXPECTED_SURFACE_TYPES


def test_every_type_in_the_surface_is_an_inert_value_type() -> None:
    """The pinned set above says *which* types; this says *what they are*, so replacing one of
    them with a protocol, an ABC, a callable or a mutable object fails here even if someone
    updated the pin to match."""
    for found in _surface_types():
        if found in INERT_VALUE_TYPES:
            continue
        assert isinstance(found, type), found
        assert not found._is_protocol if hasattr(found, "_is_protocol") else True, found
        if issubclass(found, Enum):
            continue
        assert dataclasses.is_dataclass(found), found
        assert found.__dataclass_params__.frozen, found


def _transitive_value_types() -> set:
    """Fixed point of the surface under dataclass fields — everything the module can be handed,
    including at a second hop."""
    closure = set(_surface_types())
    pending = list(closure)
    while pending:
        found = pending.pop()
        if not dataclasses.is_dataclass(found):
            continue
        reached: set = set()
        for annotation in typing.get_type_hints(found).values():
            _flatten_annotation(annotation, reached)
        for candidate in reached - closure:
            closure.add(candidate)
            pending.append(candidate)
    return closure


def test_the_transitive_value_closure_is_exactly_the_reviewed_set() -> None:
    actual = {(found.__module__, found.__qualname__) for found in _transitive_value_types()}
    assert actual == EXPECTED_CLOSURE_TYPES


def test_everything_reachable_through_a_field_is_also_an_inert_value_type() -> None:
    """A connection cannot be smuggled in as a field of an otherwise-inert parameter: the whole
    transitive closure, not just the top-level signature, is builtin scalars, enums and frozen
    dataclasses."""
    for found in _transitive_value_types():
        if found in INERT_VALUE_TYPES:
            continue
        assert isinstance(found, type), found
        if issubclass(found, Enum):
            continue
        assert dataclasses.is_dataclass(found) and found.__dataclass_params__.frozen, found


def test_no_public_annotation_is_a_callable_type() -> None:
    for _, value in _public_callables():
        target = value.__init__ if inspect.isclass(value) else value
        for annotation in typing.get_type_hints(target).values():
            assert typing.get_origin(annotation) is not typing.Callable
            assert annotation is not typing.Callable


# --- Property 2: the compiled code names no escape ----------------------------------------------

# Capability names that must appear nowhere in the packages' compiled code. Checked against
# ``co_names`` on the loaded code objects — the gap a purely static import scan leaves open, since
# ``getattr(__import__("socket"), "create_connection")`` imports nothing statically visible.
FORBIDDEN_CODE_NAMES = frozenset(
    {
        "__import__",
        "call",
        "check_call",
        "check_output",
        "compile",
        "connect",
        "create_connection",
        "delattr",
        "eval",
        "exec",
        # clock readers: `now` is a parameter so execution is deterministic, and being handed a
        # datetime instance must not become a way to read the time off it
        "monotonic",
        "now",
        "perf_counter",
        "today",
        "utcnow",
        "getattr",
        "globals",
        "import_module",
        "open",
        "popen",
        "Popen",
        "read_bytes",
        "read_text",
        "recv",
        "request",
        "run",
        "send",
        "sendall",
        "setattr",
        "socket",
        "spawn",
        "system",
        "urlopen",
        "urlretrieve",
        "vars",
        "write_bytes",
        "write_text",
    }
)


def _package_source_files() -> set[str]:
    import secp_plugin_simulator

    files: set[str] = set()
    for package in (secp_reconciliation, secp_plugin_simulator):
        root = Path(package.__file__).resolve().parent
        for path in root.rglob("*.py"):
            files.add(str(path.resolve()))
    return files


def _nested_code(code: types.CodeType, seen: set[int], found: list[types.CodeType]) -> None:
    if id(code) in seen:
        return
    seen.add(id(code))
    found.append(code)
    for constant in code.co_consts:
        if isinstance(constant, types.CodeType):
            _nested_code(constant, seen, found)


def _source_code_objects() -> list[types.CodeType]:
    """Every code object *lexically defined in* a package source file, reached by compiling the
    file and recursing through ``co_consts``.

    This is the walk the escape scan relies on, because it is complete over the file **by
    construction**: a code object is reached because of where it is written, not because of what
    happens to hold it at runtime. The loaded-object walk below reaches only callables bound in a
    module's globals or in a class body, so a callable held in a module-level container --
    ``_TABLE = {"probe": lambda: open(path)}`` -- was invisible to it. That is precisely the shape
    an escape would take, and every other isolation guard in this file misses it too: it imports
    nothing (``open`` is a builtin), it binds no module, and it appears in no signature.
    """
    seen: set[int] = set()
    found: list[types.CodeType] = []
    for path in sorted(_package_source_files()):
        source = Path(path).read_text(encoding="utf-8")
        _nested_code(compile(source, path, "exec"), seen, found)
    return found


def _code_objects():
    """Every code object *defined in* a package source file, reached from the loaded modules.

    Keyed on ``co_filename`` rather than on a name, so compiler-generated code (a frozen
    dataclass's ``__init__``, built by ``exec`` inside the stdlib) is correctly out of scope while
    every function actually written in these packages is in scope.

    Kept alongside :func:`_source_code_objects` rather than replaced by it: this one observes what
    the interpreter actually loaded, so a module whose loaded content diverges from its source is
    still scanned.
    """
    import importlib

    sources = _package_source_files()
    seen: set[int] = set()
    found: list[types.CodeType] = []

    def visit(code: types.CodeType) -> None:
        if code.co_filename not in sources:
            return
        _nested_code(code, seen, found)

    for package in (secp_reconciliation, "secp_plugin_simulator"):
        name = package if isinstance(package, str) else package.__name__
        root = Path(importlib.import_module(name).__file__).resolve().parent
        for path in sorted(root.rglob("*.py")):
            relative = path.relative_to(root).with_suffix("")
            parts = [part for part in relative.parts if part != "__init__"]
            module = importlib.import_module(".".join([name, *parts]))
            for value in vars(module).values():
                if inspect.isfunction(value):
                    visit(value.__code__)
                elif inspect.isclass(value):
                    for member in vars(value).values():
                        if inspect.isfunction(member):
                            visit(member.__code__)
    return found


def _scanned_code_objects() -> list[types.CodeType]:
    """The union both walks contribute. The escape scan reads exactly this."""
    return _source_code_objects() + _code_objects()


def test_the_code_object_scan_actually_reaches_the_packages_functions() -> None:
    """Without this the forbidden-name assertion below could pass by scanning nothing."""
    names = {code.co_name for code in _scanned_code_objects()}
    assert "execute" in names
    assert "verify_inputs" in names
    assert "classify_drift" in names
    assert "plan_reconciliation" in names


def test_the_source_walk_covers_every_package_file_exactly() -> None:
    """Exact, not a floor: the set of files the escape scan compiled is the set of files in the
    two packages, so a module added later cannot sit outside the scan."""
    compiled = {code.co_filename for code in _source_code_objects()}
    assert compiled == _package_source_files()


def test_the_source_walk_reaches_a_callable_a_container_would_hide() -> None:
    """Positive control for the gap the source walk exists to close, proven on a synthetic module
    rather than by planting an escape in product code.

    The container-held lambda's ``open`` is reached by recursing the compiled module, and the
    loaded-object walk's discipline -- visit functions and classes bound in ``vars(module)`` -- is
    shown to bind neither, so it could never have reached it.
    """
    source = '_TABLE = {"probe": lambda: open("x").read()}\n'
    module_code = compile(source, "<container-probe>", "exec")

    reached: list[types.CodeType] = []
    _nested_code(module_code, set(), reached)
    assert "open" in {name for code in reached for name in code.co_names}

    namespace: dict = {}
    exec(module_code, namespace)  # noqa: S102 - a synthetic probe, not product code
    bound = {
        name
        for name, value in namespace.items()
        if not name.startswith("__") and (inspect.isfunction(value) or inspect.isclass(value))
    }
    assert bound == set(), bound


def test_the_adrs_account_of_the_escape_vocabulary_matches_it() -> None:
    """ADR-029 names six capabilities and gives a count for the rest. Both are countable claims
    about this set, so both are counted here — the ADR's own wording is what a reader trusts when
    deciding how much the escape scan proves, and an uncounted number goes stale silently.

    Note what this does *not* establish: the list's completeness. A capability reached under a name
    nobody enumerated passes the scan, which is why the ADR says so in the same breath.
    """
    named = ("open", "getattr", "__import__", "socket", "connect", "Popen")
    assert set(named) <= FORBIDDEN_CODE_NAMES
    remaining = len(FORBIDDEN_CODE_NAMES) - len(named)

    adr = (
        Path(__file__).resolve().parents[1]
        / "docs"
        / "adr"
        / "ADR-029-reconciliation-and-drift-foundation.md"
    )
    body = " ".join(adr.read_text(encoding="utf-8").replace("`", "").split())
    assert f"{', '.join(named)} and {remaining} others" in body
    assert "a capability reached under a name nobody put on it would pass" in body


def test_no_code_in_the_reconciliation_packages_names_an_escape() -> None:
    violations = []
    for code in _scanned_code_objects():
        for name in code.co_names:
            if name in FORBIDDEN_CODE_NAMES:
                violations.append((code.co_name, name))
    assert violations == []


def test_the_execution_modules_globals_hold_no_module_object_at_all() -> None:
    """Property 3, locally: the execution module binds no module, so there is nothing in its
    namespace to reach through even dynamically."""
    bound = {name for name, value in vars(simulator).items() if isinstance(value, types.ModuleType)}
    assert bound == set()


# --- Refusal boundaries, re-applied on the execution side ---------------------------------------
#
# Execution *behaviour* -- convergence, idempotence, partial failure, reset-intent authorization --
# lives in tests/test_reconciliation_execution.py. What stays here is the set of refusals the
# executor must make itself rather than inherit from the planner, kept beside the isolation
# properties above because they are the same claim: this module cannot be talked into acting.


def _observed_from_world(world: simulator.SimulatedWorld, **overrides) -> ObservedState:
    elements = tuple(
        StateElement(kind=element.kind, ref=element.ref, facets=element.facets)
        for element in world.elements
    )
    return observed(*elements, **overrides)


def _authorized(plan):
    return build_reset_intent(
        plan=plan,
        reset_scope=ResetScope.element_set,
        issued_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )


def _plan_for(wanted, reconciliation_scope=None, seen=None):
    return plan_from_states(
        scope=reconciliation_scope or scope(),
        desired=wanted,
        observed=seen if seen is not None else _observed_from_world(simulator.SimulatedWorld()),
        now=NOW,
    )[2]


def test_a_plan_renamed_onto_another_surface_is_caught_as_tampering_before_anything_runs() -> None:
    """Editing the surface on a built plan no longer reaches the surface seal, because the plan no
    longer matches its own digest. The refusal is earlier and stricter than it used to be, so the
    code asserted here changed deliberately: `plan_integrity_invalid`, not
    `execution_surface_sealed`."""
    wanted = desired(network())
    plan = _plan_for(wanted)
    for surface in ("proxmox", "vmware", "aws", ""):
        with pytest.raises(ReconciliationRefused) as raised:
            simulator.execute(
                scope=scope(),
                plan=dataclasses.replace(plan, execution_surface=surface),
                desired=wanted,
                world=simulator.SimulatedWorld(),
                intent=_authorized(plan),
                now=NOW,
            )
        assert raised.value.code is RefusalCode.plan_integrity_invalid


def test_a_self_consistent_plan_for_another_surface_cannot_be_built_at_all() -> None:
    """The stronger half of the same property, and the one that carries the claim.

    The test above shows a *tampered* surface is caught. It does not show the surface is
    unreachable -- a plan that named another surface and had a matching digest would pass
    integrity. This shows no such plan can be produced through the contract: the gate refuses a
    non-simulator surface before a pair is ever verified, so planning never runs and there is
    nothing to digest.
    """
    for surface in ("proxmox", "vmware", "aws", ""):
        with pytest.raises(ReconciliationRefused) as raised:
            plan_from_states(
                scope=scope(execution_surface=surface),
                desired=desired(network()),
                observed=_observed_from_world(simulator.SimulatedWorld()),
                now=NOW,
            )
        assert raised.value.code is RefusalCode.execution_surface_sealed


def test_execution_re_applies_the_change_budget_rather_than_trusting_the_planner() -> None:
    """The defect this branch opened with. `plan_reconciliation` refuses a plan exceeding the
    scope's `max_actions`, but that refusal used to live only in the planner: a plan edited
    afterwards to carry more actions kept its original digest, executed every one of them, and
    emitted a record attesting to the *original* `plan_digest`. Forged work with legitimate-looking
    evidence.
    """
    wanted = desired(network(), node())
    tight = scope(max_actions=1)
    plan = _plan_for(wanted, tight, seen=observed(network()))
    assert len(plan.actions) == 1

    over_budget = dataclasses.replace(
        plan,
        actions=plan.actions
        + (
            PlannedAction(
                kind=ActionKind.create,
                element_kind=ElementKind.network,
                element_ref="team-network",
                reasons=(),
            ),
        ),
    )
    # the tamper is invisible to the digest the plan carries, which is exactly why it worked
    assert over_budget.plan_digest == plan.plan_digest
    with pytest.raises(ReconciliationRefused) as raised:
        simulator.execute(
            scope=tight,
            plan=over_budget,
            desired=wanted,
            world=simulator.SimulatedWorld(),
            intent=_authorized(plan),
            now=NOW,
        )
    assert raised.value.code is RefusalCode.plan_integrity_invalid


def test_execution_refuses_a_plan_presented_under_a_different_scope() -> None:
    """Integrity alone would still allow a laxer scope to be substituted at execution time. The
    plan binds the digest of the scope that authorized it, so the substitution is refused."""
    wanted = desired(network(), node())
    plan = _plan_for(wanted, scope(max_actions=2))
    with pytest.raises(ReconciliationRefused) as raised:
        simulator.execute(
            scope=scope(max_actions=99),
            plan=plan,
            desired=wanted,
            world=simulator.SimulatedWorld(),
            intent=_authorized(plan),
            now=NOW,
        )
    assert raised.value.code is RefusalCode.scope_mismatch


def test_execution_refuses_a_desired_state_that_is_not_the_one_the_plan_came_from() -> None:
    wanted = desired(network())
    plan = _plan_for(wanted)
    with pytest.raises(ReconciliationRefused) as raised:
        simulator.execute(
            scope=scope(),
            plan=plan,
            desired=desired(network(address_space="10.99.0.0/24")),
            world=simulator.SimulatedWorld(),
            intent=_authorized(plan),
            now=NOW,
        )
    assert raised.value.code is RefusalCode.verification_token_invalid


def test_the_observation_a_simulated_world_produces_carries_its_own_provenance() -> None:
    # The simulator does not manufacture a collector attestation; the caller supplies it, exactly
    # as a real collector would, and the contract checks it.
    with pytest.raises(ReconciliationRefused) as raised:
        plan_from_states(
            scope=scope(),
            desired=desired(network()),
            observed=_observed_from_world(
                simulator.SimulatedWorld(), collector_digest="not-a-digest"
            ),
            now=NOW,
        )
    assert raised.value.code is RefusalCode.observation_unverified
    assert COLLECTOR_DIGEST.startswith("sha256:")
    assert ObservationFidelity.complete.value == "complete"
