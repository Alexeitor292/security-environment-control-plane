"""Worker-owned read-only target evidence collector seam (SECP-002B-1B-1).

The only implementation in this release is deterministic and simulated. It does not
connect to, inspect, or query any real target. Live provider evidence remains sealed.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from secp_api.enums import CollectorKind, VerificationLevel
from secp_api.errors import LiveEvidenceSealedError
from secp_api.onboarding import OnboardingBoundarySpec
from secp_api.target_evidence import SIMULATED_EVIDENCE_SOURCE, TARGET_EVIDENCE_SCHEMA_VERSION


@runtime_checkable
class TargetEvidenceCollector(Protocol):
    """Produce provider-neutral read-only observed-target evidence."""

    evidence_source: str
    collector_kind: str
    verification_level: str

    def collect(self, *, declared_boundary: dict) -> dict: ...


def _simulated_evidence_payload_from_boundary(boundary: dict) -> dict:
    """Build deterministic fake observed-target evidence without contacting a provider."""
    spec = OnboardingBoundarySpec.model_validate(boundary)
    return {
        "schema_version": TARGET_EVIDENCE_SCHEMA_VERSION,
        "evidence_source": SIMULATED_EVIDENCE_SOURCE,
        "verification_level": VerificationLevel.simulated.value,
        "observed": {
            "nodes": sorted(spec.nodes),
            "storage": sorted(spec.storage),
            "network_segments": sorted(spec.network_segments),
            "cidr_reservations": sorted(spec.cidrs),
            "vmid_range": spec.vmid_range.model_dump(mode="json"),
            "quotas": spec.quotas.model_dump(mode="json"),
            "isolation": {
                "profile": spec.isolation_profile.value,
                "external_connectivity_policy": spec.external_connectivity.policy,
                "route_to_protected": False,
            },
        },
    }


class SimulatedTargetEvidenceCollector:
    """Deterministic fake collector. It derives evidence from declared boundary data only."""

    evidence_source = SIMULATED_EVIDENCE_SOURCE
    collector_kind = CollectorKind.fake_declared_boundary.value
    verification_level = VerificationLevel.simulated.value

    def collect(self, *, declared_boundary: dict) -> dict:
        return _simulated_evidence_payload_from_boundary(declared_boundary)


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
