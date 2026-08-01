"""Simulator-only execution of a reconciliation plan.

This is the *only* execution surface for a reconciliation plan in this milestone, and it is
structurally incapable of reaching a provider rather than configured not to. Three properties
carry that claim, and each is checked mechanically by ``tests/test_reconciliation_simulator.py``:

1. **Its input surface admits nothing that could reach anything.** Every parameter and return
   annotation of every public callable resolves to a frozen dataclass or an enum drawn from a
   closed set. There is no ``PluginContext``, no ``ResourcePort``, no transport, no session, no
   callable and no protocol among them — so there is no argument through which a caller could hand
   this module a connection, and no configuration that could add one.

2. **Its import closure contains nothing capable of I/O.** The module imports the standard
   library's ``dataclasses`` and the reconciliation contract, and nothing else. No socket, HTTP,
   subprocess, filesystem, provider-SDK or plugin-transport module appears anywhere in the closure.

3. **Its compiled code names no escape.** No code object compiled from this file — not just the
   functions bound in its namespace, but every lambda, comprehension and nested definition
   wherever it is held — references ``open``, ``getattr``, ``__import__``, ``eval``, ``exec``,
   ``socket``, ``connect`` or any similar capability by name, so it cannot reach one dynamically
   either — the gap that a purely static import scan leaves.

Execution is a pure function over an in-memory world: it returns a new world and an immutable,
content-addressed record. Nothing is persisted, and "applying" an action means recomputing a
value in a tuple.
"""

from __future__ import annotations

from dataclasses import dataclass

from secp_reconciliation.v1.codes import (
    ActionKind,
    ElementKind,
    ExecutionSurface,
    FacetName,
    ReconciliationRefused,
    RefusalCode,
)
from secp_reconciliation.v1.digest import document_digest
from secp_reconciliation.v1.planner import ReconciliationPlan
from secp_reconciliation.v1.state import DesiredState, desired_state_digest

SIMULATED_EXECUTION_SCHEMA_VERSION = "secp-recon/simulated-execution/v1"
SIMULATED_WORLD_SCHEMA_VERSION = "secp-recon/simulated-world/v1"

# The one surface this module will execute for. It equals the only member the contract's
# ExecutionSurface enum has, so there is no second value a caller could supply.
EXECUTION_SURFACE = ExecutionSurface.simulator.value


@dataclass(frozen=True)
class SimulatedElement:
    """One element of the in-memory world. A value, not a handle to anything."""

    kind: ElementKind
    ref: str
    facets: tuple[tuple[FacetName, str], ...] = ()


@dataclass(frozen=True)
class SimulatedWorld:
    """The complete in-memory state a simulated reconciliation acts on."""

    elements: tuple[SimulatedElement, ...] = ()


@dataclass(frozen=True)
class AppliedAction:
    """One action the simulator carried out, in the order the plan listed it."""

    kind: ActionKind
    element_kind: ElementKind
    element_ref: str


@dataclass(frozen=True)
class SimulatedExecutionRecord:
    """Immutable, content-addressed record of one simulated execution."""

    schema_version: str
    execution_surface: str
    plan_digest: str
    applied: tuple[AppliedAction, ...]
    world_digest_before: str
    world_digest_after: str
    converged: bool
    record_digest: str


def world_digest(world: SimulatedWorld) -> str:
    """Content address of an in-memory world."""
    return document_digest(
        SIMULATED_WORLD_SCHEMA_VERSION,
        {
            "elements": [
                {
                    "kind": element.kind.value,
                    "ref": element.ref,
                    "facets": [[name.value, value] for name, value in element.facets],
                }
                for element in world.elements
            ]
        },
    )


def execute(
    *,
    plan: ReconciliationPlan,
    desired: DesiredState,
    world: SimulatedWorld,
) -> tuple[SimulatedWorld, SimulatedExecutionRecord]:
    """Apply a plan to an in-memory world and return the new world plus an execution record.

    Refuses with a bounded code when the plan names a surface other than the simulator, or when the
    desired state handed in is not the one the plan was derived from — the plan carries references
    and reasons, never facet values, so executing it against a different desired state would apply
    values nobody planned.
    """
    if plan.execution_surface != EXECUTION_SURFACE:
        raise ReconciliationRefused(RefusalCode.execution_surface_sealed)
    if desired_state_digest(desired) != plan.desired_digest:
        raise ReconciliationRefused(RefusalCode.verification_token_invalid)

    desired_by_ref = {element.ref: element for element in desired.elements}
    current = {element.ref: element for element in world.elements}
    applied: list[AppliedAction] = []

    for action in plan.actions:
        source = desired_by_ref.get(action.element_ref)
        if source is None:
            raise ReconciliationRefused(RefusalCode.verification_token_invalid)
        current[action.element_ref] = SimulatedElement(
            kind=source.kind, ref=source.ref, facets=source.facets
        )
        applied.append(
            AppliedAction(
                kind=action.kind,
                element_kind=action.element_kind,
                element_ref=action.element_ref,
            )
        )

    next_world = SimulatedWorld(
        elements=tuple(current[ref] for ref in sorted(current)),
    )
    before = world_digest(world)
    after = world_digest(next_world)
    body = {
        "execution_surface": EXECUTION_SURFACE,
        "plan_digest": plan.plan_digest,
        "applied": [
            [item.kind.value, item.element_kind.value, item.element_ref] for item in applied
        ],
        "world_digest_before": before,
        "world_digest_after": after,
        "converged": not plan.deferred,
    }
    record = SimulatedExecutionRecord(
        schema_version=SIMULATED_EXECUTION_SCHEMA_VERSION,
        execution_surface=EXECUTION_SURFACE,
        plan_digest=plan.plan_digest,
        applied=tuple(applied),
        world_digest_before=before,
        world_digest_after=after,
        converged=not plan.deferred,
        record_digest=document_digest(SIMULATED_EXECUTION_SCHEMA_VERSION, body),
    )
    return (next_world, record)
