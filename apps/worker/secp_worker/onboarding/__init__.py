"""Worker-only onboarding evidence collector seams (SECP-002B-1B, ADR-014).

Never imported by ``apps/api``. Current implementations are deterministic fakes that
inspect no real target. Live provider collectors remain sealed future capabilities.
"""

from secp_worker.onboarding.preflight import FakePreflightCollector, PreflightCollector
from secp_worker.onboarding.target_evidence import (
    SimulatedTargetEvidenceCollector,
    TargetEvidenceCollector,
)

__all__ = [
    "FakePreflightCollector",
    "PreflightCollector",
    "SimulatedTargetEvidenceCollector",
    "TargetEvidenceCollector",
]
