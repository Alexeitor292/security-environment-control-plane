"""Provider-neutral reconciliation and drift contracts for the control plane.

The control plane reconciles *capabilities*, never a vendor. Desired state, observed state, drift
classification, reconciliation planning and the reset/evidence documents are expressed in the same
neutral projection every provider populates (ADR-008, Charter Invariant 9), so no provider-shaped
concept enters the core types.

The current contract version is ``v1``.
"""

from secp_reconciliation import v1

__all__ = ["v1"]
