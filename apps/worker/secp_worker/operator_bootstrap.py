"""Reviewed operator worker bootstrap factory (B1B-PR5B, ADR-022 §5/§11) — worker-only.

The SHIPPED worker registers the module-level, always-sealed activities from
:mod:`secp_worker.temporal_app`, so ordinary production refuses at the composition gate before any
I/O. A SEPARATELY REVIEWED, deployment-local operator worker — a root-controlled entrypoint
maintained OUTSIDE this repository — instead builds its activity set here, from fully-constructed,
typed, controlled-live compositions, and registers those bound methods under the SAME stable
activity names.

This factory is the safe seam the repository exposes; it does NOT contain and MUST NOT be committed
with any deployment value (endpoint, backend address, secret reference, credential, VM-ID, node,
storage, bridge, filesystem path, or secret-manager path/token). It accepts only fully-constructed
typed dependencies (never a raw dict of arbitrary objects), refuses a missing / shipped-sealed /
test-only / wrong-classification composition, and performs NO network, filesystem, database, or
secret contact at construction. Merely being able to import or call it activates nothing: no live
plan can occur without an explicitly constructed controlled-live object graph AND every
authoritative database gate passing at request time.

Mirrors the explicit-injection precedent of :mod:`secp_worker.staging_live.composition`.
"""

from __future__ import annotations

from dataclasses import dataclass

from secp_worker.onboarding.eligibility_preflight import EligibilityPreflightComposition
from secp_worker.onboarding.eligibility_provider import (
    ControlledLiveEligibilityCompositionProvider,
)
from secp_worker.plan_gen.composition import PlanExecutionComposition
from secp_worker.plan_gen.composition_provider import (
    ControlledLivePlanExecutionCompositionProvider,
)
from secp_worker.readiness.composition import ReadinessComposition
from secp_worker.readiness.composition_provider import (
    ControlledLiveReadinessCompositionProvider,
)
from secp_worker.temporal_app import (
    EligibilityPreflightActivity,
    PlanSecretReadinessActivity,
    RealPlanGenerationActivity,
    RemoteStateReadinessActivity,
    ToolchainAttestationActivity,
)


class OperatorBootstrapError(Exception):
    """The operator activity set could not be built (bounded reason code; never a value)."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True)
class OperatorActivitySet:
    """The class-based activity instances a reviewed operator worker registers.

    Each carries a constructor-injected controlled-live provider. Register the bound ``.run``
    methods (see :meth:`registerable_activities`) with the Temporal worker under the SAME stable
    names the workflows dispatch by. Deploy/reset/destroy/discover activities are unchanged and come
    from the shipped module directly.
    """

    real_plan_generation: RealPlanGenerationActivity
    eligibility_preflight: EligibilityPreflightActivity
    toolchain_attestation: ToolchainAttestationActivity
    remote_state_readiness: RemoteStateReadinessActivity
    plan_secret_readiness: PlanSecretReadinessActivity

    def registerable_activities(self) -> tuple:
        """The bound-method activities to pass to the Temporal ``Worker(activities=[...])`` list."""
        return (
            self.eligibility_preflight.run,
            self.toolchain_attestation.run,
            self.remote_state_readiness.run,
            self.plan_secret_readiness.run,
            self.real_plan_generation.run,
        )


def build_operator_activity_set(
    *,
    plan_execution_composition: PlanExecutionComposition,
    readiness_composition: ReadinessComposition,
    eligibility_composition: EligibilityPreflightComposition,
) -> OperatorActivitySet:
    """Build the reviewed operator activity set from fully-constructed, typed, controlled-live
    compositions.

    Every argument is REQUIRED and must be an EXACT composition type carrying its OWN reviewed
    worker identity, resolvers, adapters, and activations. Each ``ControlledLive*Provider``
    constructor fails closed on a ``None`` / shipped-sealed / ``test_only`` / wrong-classification
    composition — a self-declared classification is never sufficient — and performs NO I/O. Each
    readiness activity
    keeps its SEPARATE authority: the single ``readiness_composition`` carries independent
    per-operation seams/activations (toolchain layout; state adapter + state activation; resolver
    self-test + plan-secret activation) and each activity uses only its own; their capabilities and
    activations are never combined, and every activity remains independently request-driven.

    Building the set does NOT dispatch anything, contact anything, or bypass any authoritative
    database gate; those are re-derived per request inside each activity body.
    """
    if plan_execution_composition is None:
        raise OperatorBootstrapError("missing_plan_execution_composition")
    if readiness_composition is None:
        raise OperatorBootstrapError("missing_readiness_composition")
    if eligibility_composition is None:
        raise OperatorBootstrapError("missing_eligibility_composition")

    # Each provider constructor verifies its composition (enabled, non-sealed, exact classification/
    # registration bound) and fails closed; a sealed/test/wrong composition can never reach here.
    plan_provider = ControlledLivePlanExecutionCompositionProvider(plan_execution_composition)
    readiness_provider = ControlledLiveReadinessCompositionProvider(readiness_composition)
    eligibility_provider = ControlledLiveEligibilityCompositionProvider(eligibility_composition)

    return OperatorActivitySet(
        real_plan_generation=RealPlanGenerationActivity(plan_provider),
        eligibility_preflight=EligibilityPreflightActivity(eligibility_provider),
        toolchain_attestation=ToolchainAttestationActivity(readiness_provider),
        remote_state_readiness=RemoteStateReadinessActivity(readiness_provider),
        plan_secret_readiness=PlanSecretReadinessActivity(readiness_provider),
    )


def operator_task_queue(settings) -> str:  # noqa: ANN001 - duck-typed Settings
    """The DISTINCT Temporal task queue the controlled-live operator worker must poll (ADR-022 §12).

    Delegates to :func:`secp_api.workflow_routing.resolve_operator_task_queue`, which fails closed
    (``OperatorTaskQueueUnavailable``) unless a queue distinct from the shipped
    ``temporal_task_queue`` is configured. The reviewed deployment-local operator entrypoint calls
    this to register :meth:`OperatorActivitySet.registerable_activities` on the operator queue —
    NEVER on the shipped queue — so controlled-live work is never picked up by the sealed worker.
    Obtaining the queue contacts nothing and activates nothing.
    """
    from secp_api.workflow_routing import resolve_operator_task_queue

    return resolve_operator_task_queue(settings)


@dataclass(frozen=True)
class OperatorWorkerRegistration:
    """The ONE immutable object a reviewed operator entrypoint registers with its Temporal worker.

    It couples the exact deterministic operator task queue with EXACTLY the five controlled-live
    workflow classes and their five corresponding controlled-live bound activity callables, so the
    entrypoint registers them ATOMICALLY (``Worker(task_queue=reg.task_queue,
    workflows=reg.workflows,
    activities=reg.activities)``) rather than assembling queue / workflows / activities
    independently
    and risking a mismatch. All three fields are immutable tuples; ``activity_names`` are the stable
    Temporal names the workflows dispatch by, aligned by index with ``activities``.

    There is deliberately NO deploy / reset / destroy / discovery workflow or activity here — those
    remain on the shipped queue. Constructing this contacts nothing and activates nothing.
    """

    task_queue: str
    workflows: tuple
    activities: tuple
    activity_names: tuple[str, ...]


# The exact deploy/reset/destroy/discovery workflow names that must NEVER appear on the operator
# queue.
_SHIPPED_ONLY_WORKFLOWS = frozenset(
    {"DeployWorkflow", "ResetWorkflow", "DestroyWorkflow", "DiscoverWorkflow"}
)


def build_operator_worker_registration(
    *,
    settings,  # noqa: ANN001 - duck-typed Settings
    plan_execution_composition: PlanExecutionComposition,
    readiness_composition: ReadinessComposition,
    eligibility_composition: EligibilityPreflightComposition,
) -> OperatorWorkerRegistration:
    """Build the atomic operator worker registration (queue + 5 workflows + 5 activities).

    The task queue is resolved via :func:`operator_task_queue` (fails closed unless a DISTINCT
    operator queue is configured — never the shipped queue and never a caller-supplied queue). The
    five controlled-live activities come from :func:`build_operator_activity_set` (which refuses a
    missing / shipped-sealed / test-only / wrong-classification composition and, for
    controlled-live,
    the exact reviewed concrete resolver/adapter chains). This then verifies exact 5/5/5 counts,
    stable + unique + complete activity names, and that no deploy/reset/destroy/discovery workflow
    is
    present, before returning ONE immutable object. It contacts nothing.
    """
    from secp_api.workflow_routing import (
        CONTROLLED_LIVE_OPERATOR_WORKFLOW_KINDS,
        resolve_operator_task_queue,
    )

    from secp_worker.temporal_app import (
        ELIGIBILITY_PREFLIGHT_ACTIVITY_NAME,
        PLAN_SECRET_READINESS_ACTIVITY_NAME,
        REAL_PLAN_GENERATION_ACTIVITY_NAME,
        REMOTE_STATE_READINESS_ACTIVITY_NAME,
        TOOLCHAIN_ATTESTATION_ACTIVITY_NAME,
        EligibilityPreflightWorkflow,
        PlanSecretReadinessWorkflow,
        RealPlanGenerationWorkflow,
        RemoteStateReadinessWorkflow,
        ToolchainAttestationWorkflow,
    )

    task_queue = resolve_operator_task_queue(settings)

    activity_set = build_operator_activity_set(
        plan_execution_composition=plan_execution_composition,
        readiness_composition=readiness_composition,
        eligibility_composition=eligibility_composition,
    )
    # Aligned by index: workflow[i] dispatches activity[i] under activity_names[i].
    workflows = (
        EligibilityPreflightWorkflow,
        ToolchainAttestationWorkflow,
        RemoteStateReadinessWorkflow,
        PlanSecretReadinessWorkflow,
        RealPlanGenerationWorkflow,
    )
    activities = activity_set.registerable_activities()
    activity_names = (
        ELIGIBILITY_PREFLIGHT_ACTIVITY_NAME,
        TOOLCHAIN_ATTESTATION_ACTIVITY_NAME,
        REMOTE_STATE_READINESS_ACTIVITY_NAME,
        PLAN_SECRET_READINESS_ACTIVITY_NAME,
        REAL_PLAN_GENERATION_ACTIVITY_NAME,
    )

    # Exactly one workflow + one activity + one stable name per controlled-live operator-owned kind
    # (so a future 6th controlled-live kind that is not wired here is caught).
    expected = len(CONTROLLED_LIVE_OPERATOR_WORKFLOW_KINDS)
    if not (len(workflows) == len(activities) == len(activity_names) == expected):
        raise OperatorBootstrapError("registration_count_mismatch")
    if len(set(activity_names)) != expected:
        raise OperatorBootstrapError("duplicate_activity_name")
    if any(not (isinstance(name, str) and name) for name in activity_names):
        raise OperatorBootstrapError("activity_name_missing")
    if {getattr(w, "__name__", "") for w in workflows} & _SHIPPED_ONLY_WORKFLOWS:
        raise OperatorBootstrapError("shipped_only_workflow_present")

    return OperatorWorkerRegistration(
        task_queue=task_queue,
        workflows=workflows,
        activities=activities,
        activity_names=activity_names,
    )
