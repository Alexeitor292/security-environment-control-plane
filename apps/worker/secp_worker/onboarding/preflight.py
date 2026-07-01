"""Onboarding preflight collector seam (SECP-002B-1B-0, ADR-014) — worker-only.

A ``PreflightCollector`` produces redacted, structured evidence attesting that a target
satisfies its declared boundary and the platform prerequisites. In B1-B-0 the only
implementation is ``FakePreflightCollector``: it **does not connect to, inspect, or query
any real target** — it derives *simulated* evidence from the (already validated) declared
boundary via the shared ``simulate_boundary_checks``. Its evidence is always
``verification_level=simulated`` and can never unlock live real provisioning.

B1-B will add a ``provider_worker`` collector that gathers real, redacted, hash-bound
``live_verified`` evidence from a reviewed disposable lab and records it via
``secp_api.services.onboarding.record_preflight_result`` behind this seam.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from secp_api.enums import CollectorKind, IsolationModel, VerificationLevel
from secp_api.onboarding import simulate_boundary_checks


@runtime_checkable
class PreflightCollector(Protocol):
    """Produce redacted onboarding preflight evidence for a declared boundary."""

    name: str
    collector_kind: str
    verification_level: str

    def collect(self, *, declared_boundary: dict, isolation_model: str) -> list[dict]: ...


class FakePreflightCollector:
    """Fake collector. Inspects NOTHING real; derives simulated evidence from the boundary.

    ``fail`` / ``omit`` let a test simulate a specific failing/omitted check (e.g. to prove
    a logical-isolation target cannot activate without ``no_route_to_protected``).
    """

    name = "fake_declared_boundary"
    collector_kind = CollectorKind.fake_declared_boundary.value
    verification_level = VerificationLevel.simulated.value

    def __init__(self, *, fail: set[str] | None = None, omit: set[str] | None = None) -> None:
        self._fail = set(fail or ())
        self._omit = set(omit or ())

    def collect(self, *, declared_boundary: dict, isolation_model: str) -> list[dict]:
        iso = (
            IsolationModel.logical
            if isolation_model == IsolationModel.logical.value
            else IsolationModel.physical
        )
        return simulate_boundary_checks(declared_boundary, iso, fail=self._fail, omit=self._omit)
