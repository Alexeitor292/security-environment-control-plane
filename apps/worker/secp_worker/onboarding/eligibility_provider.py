"""Worker-bootstrap composition-provider seam for the eligibility preflight activity (B1B-PR3/PR5B).

The durable controlled-live eligibility-preflight Temporal activity obtains its
:class:`EligibilityPreflightComposition` EXCLUSIVELY from an injected provider — never from a
module-global, an environment flag, a settings value, a database row, or a Temporal argument. The
shipped worker injects :class:`SealedEligibilityCompositionProvider`, which ALWAYS returns the
disabled shipped composition (gate off; no transport/resolver/collector/verifier), so ordinary
production refuses at the seal before any target contact.

A separately reviewed operator bootstrap injects a
:class:`ControlledLiveEligibilityCompositionProvider` around one already-constructed, enabled
composition when the supervised sequence needs FRESH controlled-live eligibility evidence. This
activity retains its own SEPARATE authority (its own approved authorization + worker identity); it
is independently request-driven and never triggers plan generation. Providers are non-serializable.
"""

from __future__ import annotations

from typing import NoReturn, Protocol, SupportsIndex, runtime_checkable

from secp_worker.onboarding.eligibility_preflight import (
    EligibilityPreflightComposition,
    sealed_eligibility_composition,
)

SEALED_DEFAULT_PROVIDER = "sealed_default"
CONTROLLED_LIVE_PROVIDER = "controlled_live"


class EligibilityCompositionProviderError(Exception):
    """An eligibility composition provider was constructed with a sealed/invalid composition."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@runtime_checkable
class EligibilityCompositionProvider(Protocol):
    """Returns an already-constructed :class:`EligibilityPreflightComposition` (no I/O)."""

    classification: str

    def get(self) -> EligibilityPreflightComposition: ...


class _NonSerializable:
    def __getstate__(self) -> NoReturn:
        raise TypeError(f"{type(self).__name__} cannot be serialized")

    def __reduce__(self) -> NoReturn:
        raise TypeError(f"{type(self).__name__} cannot be pickled")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError(f"{type(self).__name__} cannot be pickled")


class SealedEligibilityCompositionProvider(_NonSerializable):
    """The shipped default provider: ALWAYS returns the disabled, sealed eligibility composition."""

    classification = SEALED_DEFAULT_PROVIDER

    def get(self) -> EligibilityPreflightComposition:
        return sealed_eligibility_composition()


class ControlledLiveEligibilityCompositionProvider(_NonSerializable):
    """A reviewed provider carrying ONE already-constructed, enabled controlled-live composition.

    Refuses the shipped sealed default (a disabled gate). The transport/resolver/collector/verifier
    seams are validated deep inside the eligibility seam behind its own gates.
    """

    classification = CONTROLLED_LIVE_PROVIDER

    def __init__(self, composition: EligibilityPreflightComposition) -> None:
        if not isinstance(composition, EligibilityPreflightComposition):
            raise EligibilityCompositionProviderError("provider_composition_invalid")
        if not composition.gate.enabled:
            raise EligibilityCompositionProviderError("provider_composition_is_sealed_default")
        self._composition = composition

    def get(self) -> EligibilityPreflightComposition:
        return self._composition
