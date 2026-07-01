"""Worker-only onboarding preflight seam (SECP-002B-1B-0, ADR-014).

NEVER imported by ``apps/api``. In B1-B-0 only a ``FakePreflightCollector`` exists — it
inspects **no** real target and produces redacted, structured evidence from the declared
boundary. B1-B fills this seam with a real collector that gathers real (still redacted)
evidence from a reviewed disposable lab.
"""

from secp_worker.onboarding.preflight import (
    FakePreflightCollector,
    PreflightCollector,
)

__all__ = ["FakePreflightCollector", "PreflightCollector"]
