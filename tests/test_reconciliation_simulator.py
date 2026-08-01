"""The simulator execution surface (secp_plugin_simulator.reconciliation).

Execution exists only here, and the claim this file has to earn is that the module is
*structurally* incapable of reaching a provider — not configured not to, not policed at runtime.
Three independent properties carry it, each checked mechanically:

1. **Nothing that could reach anything can be passed in.** The exact set of types appearing in the
   module's public signatures is pinned, and every one of them is a builtin scalar, an enum, or a
   frozen dataclass. There is no protocol, no callable, no context and no port among them, so no
   caller — and no configuration — can hand this module a connection.
2. **Its compiled code names no escape.** Checked on the loaded code objects, so a sentinel that
   merely appears in a comment proves nothing here.
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
from enum import Enum
from pathlib import Path

import pytest
import secp_reconciliation
from reconciliation_support import (
    COLLECTOR_DIGEST,
    NOW,
    desired,
    edge,
    network,
    node,
    observed,
    scope,
)
from secp_plugin_simulator import reconciliation as simulator
from secp_reconciliation.v1 import (
    ObservationFidelity,
    ObservedState,
    PlanDisposition,
    ReconciliationRefused,
    RefusalCode,
    StateElement,
    plan_from_states,
)

# --- Property 1: the input surface admits nothing that could reach anything --------------------

# Every type appearing anywhere in the module's public signatures, as ``(module, qualname)``. Exact,
# not a floor: a new parameter of a new type fails here rather than slipping in under a subset test.
EXPECTED_SURFACE_TYPES = {
    ("builtins", "bool"),
    ("builtins", "str"),
    ("builtins", "tuple"),
    ("secp_plugin_simulator.reconciliation", "AppliedAction"),
    ("secp_plugin_simulator.reconciliation", "SimulatedElement"),
    ("secp_plugin_simulator.reconciliation", "SimulatedExecutionRecord"),
    ("secp_plugin_simulator.reconciliation", "SimulatedWorld"),
    ("secp_reconciliation.v1.codes", "ActionKind"),
    ("secp_reconciliation.v1.codes", "ElementKind"),
    ("secp_reconciliation.v1.codes", "FacetName"),
    ("secp_reconciliation.v1.planner", "ReconciliationPlan"),
    ("secp_reconciliation.v1.state", "DesiredState"),
}

# The same set closed under dataclass fields: everything reachable at any depth from anything the
# module can be handed. Also exact.
EXPECTED_CLOSURE_TYPES = EXPECTED_SURFACE_TYPES | {
    ("secp_reconciliation.v1.codes", "DriftReason"),
    ("secp_reconciliation.v1.codes", "PlanDisposition"),
    ("secp_reconciliation.v1.planner", "DeferredElement"),
    ("secp_reconciliation.v1.planner", "PlannedAction"),
    ("secp_reconciliation.v1.state", "StateElement"),
}


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


def test_the_public_surface_is_the_one_that_was_reviewed() -> None:
    assert [name for name, _ in _public_callables()] == [
        "AppliedAction",
        "SimulatedElement",
        "SimulatedExecutionRecord",
        "SimulatedWorld",
        "execute",
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
        if found in (str, bool, int, tuple):
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
        if found in (str, bool, int, tuple):
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


def _code_objects():
    """Every code object *defined in* a package source file, reached from the loaded modules.

    Keyed on ``co_filename`` rather than on a name, so compiler-generated code (a frozen
    dataclass's ``__init__``, built by ``exec`` inside the stdlib) is correctly out of scope while
    every function actually written in these packages is in scope.
    """
    import importlib

    sources = _package_source_files()
    seen: set[int] = set()
    found: list[types.CodeType] = []

    def visit(code: types.CodeType) -> None:
        if id(code) in seen or code.co_filename not in sources:
            return
        seen.add(id(code))
        found.append(code)
        for constant in code.co_consts:
            if isinstance(constant, types.CodeType):
                visit(constant)

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


def test_the_code_object_scan_actually_reaches_the_packages_functions() -> None:
    """Without this the forbidden-name assertion below could pass by scanning nothing."""
    found = _code_objects()
    names = {code.co_name for code in found}
    assert "execute" in names
    assert "verify_inputs" in names
    assert "classify_drift" in names
    assert "plan_reconciliation" in names
    assert len(found) > 30


def test_no_code_in_the_reconciliation_packages_names_an_escape() -> None:
    violations = []
    for code in _code_objects():
        for name in code.co_names:
            if name in FORBIDDEN_CODE_NAMES:
                violations.append((code.co_name, name))
    assert violations == []


def test_the_execution_modules_globals_hold_no_module_object_at_all() -> None:
    """Property 3, locally: the execution module binds no module, so there is nothing in its
    namespace to reach through even dynamically."""
    bound = {name for name, value in vars(simulator).items() if isinstance(value, types.ModuleType)}
    assert bound == set()


# --- Behaviour ----------------------------------------------------------------------------------


def _observed_from_world(world: simulator.SimulatedWorld, **overrides) -> ObservedState:
    elements = tuple(
        StateElement(kind=element.kind, ref=element.ref, facets=element.facets)
        for element in world.elements
    )
    return observed(*elements, **overrides)


def test_executing_a_plan_converges_an_empty_world_onto_the_desired_state() -> None:
    wanted = desired(network(), node(), edge())
    empty = simulator.SimulatedWorld()
    _, _, plan = plan_from_states(
        scope=scope(), desired=wanted, observed=_observed_from_world(empty), now=NOW
    )
    assert plan.disposition is PlanDisposition.actionable

    world, record = simulator.execute(plan=plan, desired=wanted, world=empty)
    assert {element.ref for element in world.elements} == {
        element.ref for element in wanted.elements
    }
    assert record.execution_surface == "simulator"
    assert record.converged is True
    assert record.world_digest_before != record.world_digest_after
    assert len(record.applied) == len(plan.actions)


def test_reconciling_the_converged_world_again_plans_and_changes_nothing() -> None:
    wanted = desired(network(), node())
    world, _ = simulator.execute(
        plan=plan_from_states(
            scope=scope(),
            desired=wanted,
            observed=_observed_from_world(simulator.SimulatedWorld()),
            now=NOW,
        )[2],
        desired=wanted,
        world=simulator.SimulatedWorld(),
    )
    _, report, plan = plan_from_states(
        scope=scope(), desired=wanted, observed=_observed_from_world(world), now=NOW
    )
    assert report.findings == ()
    assert plan.disposition is PlanDisposition.converged

    again, record = simulator.execute(plan=plan, desired=wanted, world=world)
    assert simulator.world_digest(again) == simulator.world_digest(world)
    assert record.applied == ()


def test_a_drifted_facet_is_repaired_by_executing_the_update() -> None:
    wanted = desired(network(), node())
    drifted = simulator.SimulatedWorld(
        elements=tuple(
            simulator.SimulatedElement(kind=e.kind, ref=e.ref, facets=e.facets)
            for e in desired(network(), node(image="kali:2025.4")).elements
        )
    )
    _, _, plan = plan_from_states(
        scope=scope(), desired=wanted, observed=_observed_from_world(drifted), now=NOW
    )
    assert [action.element_ref for action in plan.actions] == ["attacker-1"]
    repaired, record = simulator.execute(plan=plan, desired=wanted, world=drifted)
    assert simulator.world_digest(repaired) == simulator.world_digest(
        simulator.SimulatedWorld(
            elements=tuple(
                simulator.SimulatedElement(kind=e.kind, ref=e.ref, facets=e.facets)
                for e in sorted(wanted.elements, key=lambda element: element.ref)
            )
        )
    )
    assert record.converged is True


def test_an_unmanaged_element_is_left_untouched_and_the_record_says_it_did_not_converge() -> None:
    wanted = desired(network())
    world = simulator.SimulatedWorld(
        elements=(
            simulator.SimulatedElement(
                kind=network().kind, ref="stranger", facets=network().facets
            ),
        )
    )
    _, _, plan = plan_from_states(
        scope=scope(), desired=wanted, observed=_observed_from_world(world), now=NOW
    )
    assert plan.disposition is PlanDisposition.operator_decision_required
    after, record = simulator.execute(plan=plan, desired=wanted, world=world)
    assert [element.ref for element in after.elements] == ["stranger", "team-network"]
    assert record.converged is False


def test_execution_refuses_a_plan_that_names_any_other_surface() -> None:
    wanted = desired(network())
    _, _, plan = plan_from_states(
        scope=scope(),
        desired=wanted,
        observed=_observed_from_world(simulator.SimulatedWorld()),
        now=NOW,
    )
    for surface in ("proxmox", "vmware", "aws", ""):
        with pytest.raises(ReconciliationRefused) as raised:
            simulator.execute(
                plan=dataclasses.replace(plan, execution_surface=surface),
                desired=wanted,
                world=simulator.SimulatedWorld(),
            )
        assert raised.value.code is RefusalCode.execution_surface_sealed


def test_execution_refuses_a_desired_state_that_is_not_the_one_the_plan_came_from() -> None:
    wanted = desired(network())
    _, _, plan = plan_from_states(
        scope=scope(),
        desired=wanted,
        observed=_observed_from_world(simulator.SimulatedWorld()),
        now=NOW,
    )
    with pytest.raises(ReconciliationRefused) as raised:
        simulator.execute(
            plan=plan,
            desired=desired(network(address_space="10.99.0.0/24")),
            world=simulator.SimulatedWorld(),
        )
    assert raised.value.code is RefusalCode.verification_token_invalid


def test_the_execution_record_digest_is_deterministic_and_binds_the_plan() -> None:
    wanted = desired(network(), node())
    empty = simulator.SimulatedWorld()
    _, _, plan = plan_from_states(
        scope=scope(), desired=wanted, observed=_observed_from_world(empty), now=NOW
    )
    _, first = simulator.execute(plan=plan, desired=wanted, world=empty)
    _, second = simulator.execute(plan=plan, desired=wanted, world=empty)
    assert first.record_digest == second.record_digest
    assert first.plan_digest == plan.plan_digest

    other = desired(network(), node(), edge())
    _, _, other_plan = plan_from_states(
        scope=scope(), desired=other, observed=_observed_from_world(empty), now=NOW
    )
    _, third = simulator.execute(plan=other_plan, desired=other, world=empty)
    assert third.record_digest != first.record_digest


def test_the_observation_a_simulated_world_produces_carries_its_own_provenance() -> None:
    # The simulator does not manufacture a collector attestation; the caller supplies it, exactly
    # as a real collector would, and the contract checks it.
    world = simulator.SimulatedWorld()
    with pytest.raises(ReconciliationRefused) as raised:
        plan_from_states(
            scope=scope(),
            desired=desired(network()),
            observed=_observed_from_world(world, collector_digest="not-a-digest"),
            now=NOW,
        )
    assert raised.value.code is RefusalCode.observation_unverified
    assert COLLECTOR_DIGEST.startswith("sha256:")
    assert ObservationFidelity.complete.value == "complete"
