"""Worker-owned read-only target evidence collector seam (SECP-002B-1B-1).

The only implementation in this release is deterministic and simulated. It does not
connect to, inspect, or query any real target. Live provider evidence remains sealed.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from secp_api.enums import CollectorKind, VerificationLevel
from secp_api.errors import LiveEvidenceSealedError
from secp_api.target_evidence import SIMULATED_EVIDENCE_SOURCE, build_simulated_evidence_payload


@runtime_checkable
class TargetEvidenceCollector(Protocol):
    """Produce provider-neutral read-only observed-target evidence."""

    evidence_source: str
    collector_kind: str
    verification_level: str

    def collect(self, *, declared_boundary: dict) -> dict: ...


class SimulatedTargetEvidenceCollector:
    """Deterministic fake collector. It derives evidence from declared boundary data only."""

    evidence_source = SIMULATED_EVIDENCE_SOURCE
    collector_kind = CollectorKind.fake_declared_boundary.value
    verification_level = VerificationLevel.simulated.value

    def collect(self, *, declared_boundary: dict) -> dict:
        return build_simulated_evidence_payload(declared_boundary)


class SealedProviderTargetEvidenceCollector:
    """Unavailable placeholder for a future live provider collector."""

    evidence_source = "provider_worker"
    collector_kind = CollectorKind.provider_worker.value
    verification_level = VerificationLevel.live_verified.value

    def collect(self, *, declared_boundary: dict) -> dict:
        raise LiveEvidenceSealedError(
            "provider_worker target evidence collection is sealed in SECP-002B-1B-1; "
            "only simulated evidence is available"
        )
