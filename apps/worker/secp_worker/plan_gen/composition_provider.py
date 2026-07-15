"""Worker-bootstrap composition-provider seam for plan-only execution (B1B-PR5B, ADR-022 §5/§11).

The durable ``real_plan_generation`` Temporal activity obtains its :class:`PlanExecutionComposition`
EXCLUSIVELY from an injected provider, never from a module-global, an environment flag, a settings
value, a database row, or a Temporal argument. The shipped worker injects
:class:`SealedPlanExecutionCompositionProvider`, which ALWAYS returns the disabled shipped
composition, so ordinary production still refuses at the composition gate before any I/O.

A separately reviewed operator worker bootstrap constructs a
:class:`ControlledLivePlanExecutionCompositionProvider` around ONE already-constructed, verified,
controlled-live composition and injects it instead. A
:class:`TestOnlyPlanExecutionCompositionProvider`
is explicitly separate and can only carry a ``test_only`` composition — it can never produce
controlled-live evidence. Providers are non-serializable: a provider (and the worker-only
composition it holds) can never be pickled into a Temporal argument.
"""

from __future__ import annotations

from typing import NoReturn, Protocol, SupportsIndex, runtime_checkable

from secp_worker.plan_gen.composition import (
    CONTROLLED_LIVE_CLASSIFICATION,
    TEST_ONLY_CLASSIFICATION,
    PlanExecutionComposition,
    PlanExecutionCompositionError,
    sealed_plan_execution_composition,
    verify_plan_execution_composition,
)

# Provider classifications — a provider is either the shipped sealed default, a reviewed
# controlled-live provider, or an explicitly-separate test-only provider.
SEALED_DEFAULT_PROVIDER = "sealed_default"
CONTROLLED_LIVE_PROVIDER = "controlled_live"
TEST_ONLY_PROVIDER = "test_only"


@runtime_checkable
class PlanExecutionCompositionProvider(Protocol):
    """Returns an already-constructed, non-serializable :class:`PlanExecutionComposition`.

    ``classification`` is one of :data:`SEALED_DEFAULT_PROVIDER` / :data:`CONTROLLED_LIVE_PROVIDER`
    /
    :data:`TEST_ONLY_PROVIDER`. ``get`` performs no I/O and returns the exact composition the worker
    bootstrap constructed — no fallback, no lazy live construction.
    """

    classification: str

    def get(self) -> PlanExecutionComposition: ...


class _NonSerializable:
    """Mixin: a bootstrap-owned provider can never be pickled into a Temporal argument."""

    def __getstate__(self) -> NoReturn:
        raise TypeError(f"{type(self).__name__} cannot be serialized")

    def __reduce__(self) -> NoReturn:
        raise TypeError(f"{type(self).__name__} cannot be pickled")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError(f"{type(self).__name__} cannot be pickled")


class SealedPlanExecutionCompositionProvider(_NonSerializable):
    """The shipped default provider: ALWAYS returns the disabled, sealed composition."""

    classification = SEALED_DEFAULT_PROVIDER

    def get(self) -> PlanExecutionComposition:
        return sealed_plan_execution_composition()


class ControlledLivePlanExecutionCompositionProvider(_NonSerializable):
    """A reviewed provider carrying ONE already-constructed controlled-live composition.

    Constructed only at operator worker bootstrap. Verifies (fail-closed, no I/O) that the injected
    composition is an enabled, fully-bound, ``controlled_live`` :class:`PlanExecutionComposition`
    whose classification is bound to the sealed production issuer — a shipped/sealed default or a
    ``test_only`` composition is refused, so this provider can never masquerade as anything else.
    """

    classification = CONTROLLED_LIVE_PROVIDER

    def __init__(self, composition: PlanExecutionComposition) -> None:
        if not isinstance(composition, PlanExecutionComposition):
            raise PlanExecutionCompositionError("provider_composition_invalid")
        # verify_plan_execution_composition raises composition_sealed for the disabled default and
        # composition_*_requires_sealed_issuer / composition_classification_invalid for a mismatch.
        verify_plan_execution_composition(composition)
        if composition.classification != CONTROLLED_LIVE_CLASSIFICATION:
            raise PlanExecutionCompositionError("provider_composition_not_controlled_live")
        self._composition = composition

    def get(self) -> PlanExecutionComposition:
        return self._composition


class TestOnlyPlanExecutionCompositionProvider(_NonSerializable):
    """An explicitly-separate provider carrying ONE ``test_only`` composition.

    A ``test_only`` composition uses an injected (test-only) executor factory and its capability is
    ``test_only``, so it can never produce a controlled-live durable result or a real pending
    approval. A ``controlled_live`` or sealed composition is refused here.
    """

    classification = TEST_ONLY_PROVIDER

    def __init__(self, composition: PlanExecutionComposition) -> None:
        if not isinstance(composition, PlanExecutionComposition):
            raise PlanExecutionCompositionError("provider_composition_invalid")
        verify_plan_execution_composition(composition)
        if composition.classification != TEST_ONLY_CLASSIFICATION:
            raise PlanExecutionCompositionError("provider_composition_not_test_only")
        self._composition = composition

    def get(self) -> PlanExecutionComposition:
        return self._composition
