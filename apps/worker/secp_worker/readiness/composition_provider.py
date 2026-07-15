"""Worker-bootstrap composition-provider seam for readiness activities (B1B-PR4/PR5B, ADR-021 §5).

The durable toolchain-attestation, remote-state-readiness, and plan-secret-readiness Temporal
activities obtain their :class:`ReadinessComposition` EXCLUSIVELY from an injected provider — never
from a module-global, an environment flag, a settings value, a database row, or a Temporal argument.
The shipped worker injects :class:`SealedReadinessCompositionProvider`, which ALWAYS returns the
disabled shipped composition, so ordinary production refuses at the seal before any disk read, state
backend, or secret manager is touched.

Each activity keeps its SEPARATE authority: the composition carries independent per-operation seams
(``toolchain_layout``; ``state_adapter`` + ``state_adapter_activation``; ``resolver_self_test`` +
``plan_secret_adapter_activation``), and each activity uses only its own — the provider never
combines their capabilities or activations. A separately reviewed operator bootstrap injects a
:class:`ControlledLiveReadinessCompositionProvider` around one already-constructed, enabled,
non-``test_only`` composition. Providers are non-serializable.
"""

from __future__ import annotations

from typing import NoReturn, Protocol, SupportsIndex, runtime_checkable

from secp_worker.readiness.composition import (
    ReadinessComposition,
    sealed_readiness_composition,
)

SEALED_DEFAULT_PROVIDER = "sealed_default"
CONTROLLED_LIVE_PROVIDER = "controlled_live"
TEST_ONLY_PROVIDER = "test_only"


class ReadinessCompositionProviderError(Exception):
    """A readiness composition provider was constructed with a sealed/invalid composition."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@runtime_checkable
class ReadinessCompositionProvider(Protocol):
    """Returns an already-constructed, non-serializable :class:`ReadinessComposition` (no I/O)."""

    classification: str

    def get(self) -> ReadinessComposition: ...


class _NonSerializable:
    def __getstate__(self) -> NoReturn:
        raise TypeError(f"{type(self).__name__} cannot be serialized")

    def __reduce__(self) -> NoReturn:
        raise TypeError(f"{type(self).__name__} cannot be pickled")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError(f"{type(self).__name__} cannot be pickled")


class SealedReadinessCompositionProvider(_NonSerializable):
    """The shipped default provider: ALWAYS returns the disabled, sealed readiness composition."""

    classification = SEALED_DEFAULT_PROVIDER

    def get(self) -> ReadinessComposition:
        return sealed_readiness_composition()


class ControlledLiveReadinessCompositionProvider(_NonSerializable):
    """A reviewed provider carrying ONE already-constructed, enabled controlled-live composition.

    Refuses the shipped sealed default (a disabled gate) and any ``test_only`` composition. The
    per-operation seams/activations are validated deep inside each readiness seam; this provider
    only
    guarantees the composition is enabled and not the sealed/test default.
    """

    classification = CONTROLLED_LIVE_PROVIDER

    def __init__(self, composition: ReadinessComposition) -> None:
        if not isinstance(composition, ReadinessComposition):
            raise ReadinessCompositionProviderError("provider_composition_invalid")
        if not composition.gate.enabled:
            raise ReadinessCompositionProviderError("provider_composition_is_sealed_default")
        if composition.test_only_capability:
            raise ReadinessCompositionProviderError("provider_composition_is_test_only")
        # If a remote-state adapter is present, it MUST be the EXACT reviewed concrete HTTP adapter,
        # production-bound to the concrete probe over the concrete HTTP state-control transport
        # (§10).
        # A sealed/fake/foreign adapter — or one over a sealed/fake transport — in a controlled-live
        # composition is refused. A ``None`` adapter is allowed: a controlled-live composition that
        # does not provision state readiness (e.g. toolchain-only) simply refuses state readiness at
        # the seal; it can never silently pass with a non-concrete adapter.
        if composition.state_adapter is not None:
            from secp_worker.readiness.http_state_adapter import assert_concrete_state_adapter
            from secp_worker.reviewed_identity import ReviewedIdentityError

            try:
                assert_concrete_state_adapter(composition.state_adapter)
            except ReviewedIdentityError as exc:
                raise ReadinessCompositionProviderError(exc.reason_code) from exc
        self._composition = composition

    def get(self) -> ReadinessComposition:
        return self._composition


class TestOnlyReadinessCompositionProvider(_NonSerializable):
    """An explicitly-separate provider carrying ONE ``test_only`` readiness composition.

    Its records are permanently marked ``test_only`` (they can never make combined readiness
    current); it can never produce controlled-live evidence.
    """

    classification = TEST_ONLY_PROVIDER

    def __init__(self, composition: ReadinessComposition) -> None:
        if not isinstance(composition, ReadinessComposition):
            raise ReadinessCompositionProviderError("provider_composition_invalid")
        if not composition.test_only_capability:
            raise ReadinessCompositionProviderError("provider_composition_not_test_only")
        self._composition = composition

    def get(self) -> ReadinessComposition:
        return self._composition
