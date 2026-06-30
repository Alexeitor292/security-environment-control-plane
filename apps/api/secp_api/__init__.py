"""Security Environment Control Platform — control-plane API package.

This package is the core control plane (Charter Layer 2). It owns desired state,
RBAC, the immutable-version model, the approval gate, audit, and the topology
projection. It never executes privileged infrastructure actions; side-effecting
work is dispatched to the worker boundary (ADR-005).
"""

__version__ = "0.1.0"
