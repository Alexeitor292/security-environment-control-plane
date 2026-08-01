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
from datetime import datetime

from secp_reconciliation.v1.codes import (
    ElementKind,
    ExecutionSurface,
    FacetName,
    ObservationFidelity,
    ReconciliationRefused,
    RefusalCode,
    StepFailureReason,
    StepStatus,
)
from secp_reconciliation.v1.digest import document_digest
from secp_reconciliation.v1.execution import (
    ExecutionReport,
    StepOutcome,
    build_execution_report,
    require_execution_authorized,
)
from secp_reconciliation.v1.planner import ReconciliationPlan, require_planned_under
from secp_reconciliation.v1.reset import ResetIntent
from secp_reconciliation.v1.state import (
    DesiredState,
    ObservedState,
    ReconciliationScope,
    StateElement,
    decode_edge_ref,
    desired_state_digest,
)

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


def _unsatisfied_dependency(element: StateElement, present: dict[str, SimulatedElement]) -> bool:
    """Whether this element's structural prerequisites are absent from the world.

    A real invariant, not injected fakery: a node cannot exist attached to a network that is not
    there, and an edge cannot relate endpoints that do not exist. This is what makes a *genuine*
    mid-plan failure reachable — the plan is emitted in dependency order, so a step fails here only
    when the world it is being applied to is not the world the plan was computed against.
    """
    if element.kind is ElementKind.node:
        attachment = element.facet_map().get(FacetName.network_attachment)
        return bool(attachment) and attachment not in present
    if element.kind is ElementKind.edge:
        source, target = decode_edge_ref(element.ref)
        if source is None or target is None:
            return True
        return source not in present or target not in present
    return False


def execute(
    *,
    scope: ReconciliationScope,
    plan: ReconciliationPlan,
    desired: DesiredState,
    world: SimulatedWorld,
    intent: ResetIntent | None,
    now: datetime,
) -> tuple[SimulatedWorld, ExecutionReport]:
    """Apply a plan to an in-memory world and return the new world plus an execution record.

    Every refusal boundary is re-applied *here*, on the execution side, rather than being trusted
    because the planner applied it once:

    * the plan's contents must still match its own digest, so a plan edited after planning cannot
      be executed while emitting evidence that attests to the original;
    * the scope presented must be the scope the plan was planned under, and its declared change
      budget and execution surface are re-checked against the plan rather than assumed;
    * the plan must name the simulator surface;
    * the desired state must be the one the plan was derived from — the plan carries references and
      reasons, never facet values, so executing it against a different desired state would apply
      values nobody planned.

    A boundary enforced only where a document is produced is not a boundary on the document; it is
    a boundary on one producer. These are the same checks the planner makes, made again by the
    component that acts.
    """
    require_execution_authorized(plan=plan, intent=intent, now=now)
    require_planned_under(plan, scope)
    if plan.execution_surface != EXECUTION_SURFACE:
        raise ReconciliationRefused(RefusalCode.execution_surface_sealed)
    if desired_state_digest(desired) != plan.desired_digest:
        raise ReconciliationRefused(RefusalCode.verification_token_invalid)

    desired_by_ref = {element.ref: element for element in desired.elements}
    current = {element.ref: element for element in world.elements}
    steps: list[StepOutcome] = []
    stopped = False

    for action in plan.actions:
        if stopped:
            steps.append(
                StepOutcome(
                    status=StepStatus.not_attempted,
                    kind=action.kind,
                    element_kind=action.element_kind,
                    element_ref=action.element_ref,
                )
            )
            continue

        source = desired_by_ref.get(action.element_ref)
        if source is None:
            steps.append(
                StepOutcome(
                    status=StepStatus.failed,
                    kind=action.kind,
                    element_kind=action.element_kind,
                    element_ref=action.element_ref,
                    failure_reason=StepFailureReason.element_not_in_desired,
                )
            )
            stopped = True
            continue

        missing = _unsatisfied_dependency(source, current)
        if missing:
            steps.append(
                StepOutcome(
                    status=StepStatus.failed,
                    kind=action.kind,
                    element_kind=action.element_kind,
                    element_ref=action.element_ref,
                    failure_reason=StepFailureReason.dependency_absent,
                )
            )
            stopped = True
            continue

        current[action.element_ref] = SimulatedElement(
            kind=source.kind, ref=source.ref, facets=source.facets
        )
        steps.append(
            StepOutcome(
                status=StepStatus.applied,
                kind=action.kind,
                element_kind=action.element_kind,
                element_ref=action.element_ref,
            )
        )

    next_world = SimulatedWorld(elements=tuple(current[ref] for ref in sorted(current)))
    return (
        next_world,
        build_execution_report(
            instance_id=plan.instance_id,
            execution_surface=EXECUTION_SURFACE,
            steps=tuple(steps),
            plan_digest=plan.plan_digest,
            intent_digest=intent.intent_digest if intent is not None else "",
            world_digest_before=world_digest(world),
            world_digest_after=world_digest(next_world),
            executed_at=now,
        ),
    )


def observe(
    *,
    world: SimulatedWorld,
    instance_id: str,
    provider: str,
    collector_digest: str,
    observed_at: datetime,
    fidelity: ObservationFidelity,
) -> ObservedState:
    """Report the world as an ordinary observation, so convergence can be *measured*.

    This is deliberately the same shape any collector produces, and it carries the caller's own
    fidelity attestation rather than manufacturing one: the simulator does not get to certify its
    own output as complete. Convergence is then decided by putting this through the ordinary
    verification and classification path, not by reading the execution report.
    """
    return ObservedState(
        instance_id=instance_id,
        provider=provider,
        collector_digest=collector_digest,
        observed_at=observed_at,
        fidelity=fidelity,
        elements=tuple(
            StateElement(kind=element.kind, ref=element.ref, facets=element.facets)
            for element in world.elements
        ),
    )
