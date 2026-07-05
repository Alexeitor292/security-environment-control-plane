"""Explicit staging-live runtime composition factory (SECP-B2-5-pre).

Assembles the production-grade-but-unwired staging-live dependency set. EVERY dependency must be
explicitly injected; there is no fallback to a live dependency, no enable flag read from
environment/config/database, and no network call at construction or startup. Incomplete composition
— or any shipped sealed/deny default passed in place of a real dependency — fails closed. It may
target ONLY the existing governed readonly-preflight orchestration; legacy discovery / Temporal /
``EnvSecretResolver`` / the dormant legacy ``live_readonly`` runner are excluded. Normal
consumer/runtime/main must never construct or import this factory.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from secp_worker.preflight.activation_gate import ResolutionActivationGate, SealedActivationGate
from secp_worker.preflight.backends.openbao_resolver import OpenBaoWorkerSecretResolver
from secp_worker.preflight.identity import DenyingWorkerIdentityVerifier
from secp_worker.preflight.live_evidence_writer import (
    LivePreflightEvidenceWriter,
    SealedLivePreflightEvidenceWriter,
)
from secp_worker.preflight.sealed_secret_resolver import SealedSecretResolver
from secp_worker.preflight.worker_identity_attestation import RegisteredWorkerIdentityVerifier


@runtime_checkable
class HardenedTransportFactory(Protocol):
    """Builds a hardened, GET-only read-only transport from the re-verified authorization + the
    just-resolved opaque credential. A real implementation returns a ``HttpxReadOnlyTransport``
    (TLS-verified, ``trust_env=False``, no redirects, bounded timeout, ``/api2/json`` base only)."""

    def __call__(self, verified: object, secret: str) -> object: ...


@runtime_checkable
class ReadOnlyCollector(Protocol):
    """Runs the governed GET-only collection and returns ONLY safe observed inventory (never a
    raw response). A real implementation is the existing ``LiveReadOnlyProxmoxCollector``."""

    def collect(self, transport: object, *, declared_boundary: dict) -> dict: ...


class StagingLiveCompositionError(Exception):
    """Fail-closed composition error. Closed reason only — never a value or endpoint."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(f"staging-live composition refused: {reason_code}")
        self.reason_code = reason_code


@dataclass(frozen=True)
class StagingLiveComposition:
    """A fully-injected, non-default staging-live dependency set. Constructed ONLY via
    :func:`build_staging_live_composition`, which fails closed on missing/sealed/deny dependency.
    """

    identity_verifier: RegisteredWorkerIdentityVerifier
    activation_gate: ResolutionActivationGate
    secret_resolver: OpenBaoWorkerSecretResolver
    transport_factory: HardenedTransportFactory
    collector: ReadOnlyCollector
    evidence_writer: LivePreflightEvidenceWriter


def build_staging_live_composition(
    *,
    identity_verifier: RegisteredWorkerIdentityVerifier,
    activation_gate: ResolutionActivationGate,
    secret_resolver: OpenBaoWorkerSecretResolver,
    transport_factory: HardenedTransportFactory,
    collector: ReadOnlyCollector,
    evidence_writer: LivePreflightEvidenceWriter,
) -> StagingLiveComposition:
    """Build the composition. Every argument is REQUIRED; a missing (``None``) or shipped
    sealed/deny default fails closed. No environment/config/database flag is read; nothing is
    contacted.
    """
    required = {
        "identity_verifier": identity_verifier,
        "activation_gate": activation_gate,
        "secret_resolver": secret_resolver,
        "transport_factory": transport_factory,
        "collector": collector,
        "evidence_writer": evidence_writer,
    }
    for name, dep in required.items():
        if dep is None:
            raise StagingLiveCompositionError(f"missing_dependency:{name}")

    # The composition must use EXPLICIT non-default dependencies — never a shipped sealed/deny one.
    if isinstance(identity_verifier, DenyingWorkerIdentityVerifier):
        raise StagingLiveCompositionError("identity_verifier_is_deny_default")
    if not isinstance(identity_verifier, RegisteredWorkerIdentityVerifier):
        raise StagingLiveCompositionError("identity_verifier_not_registered")
    if isinstance(activation_gate, SealedActivationGate):
        raise StagingLiveCompositionError("activation_gate_is_sealed_default")
    if isinstance(secret_resolver, SealedSecretResolver):
        raise StagingLiveCompositionError("secret_resolver_is_sealed_default")
    if isinstance(evidence_writer, SealedLivePreflightEvidenceWriter):
        raise StagingLiveCompositionError("evidence_writer_is_sealed_default")

    return StagingLiveComposition(
        identity_verifier=identity_verifier,
        activation_gate=activation_gate,
        secret_resolver=secret_resolver,
        transport_factory=transport_factory,
        collector=collector,
        evidence_writer=evidence_writer,
    )
