"""The provider-neutral range CONTRACT — types only, no implementation.

Everything importable from here is pure data: protocols, dataclasses and enums describing what a
range provider is asked to do and what it reports back. There is no provider implementation in this
package and there must never be one.

WHY THE IMPLEMENTATION IS NOT HERE
-----------------------------------
A range provider performs privileged infrastructure execution — the local Docker provider talks to
a Docker socket, which is root-equivalent on the host. Charter Invariants 6/7 and ADR-005 put that
work in the worker, not the API, and ``tests/test_architecture_boundary.py`` enforces it by
refusing ``subprocess`` anywhere under ``secp_api`` and refusing direct ``reset``/``destroy`` calls.

The provider implementations therefore live in :mod:`secp_worker.range`, and the API reaches them
only by dispatching through :mod:`secp_api.dispatch` — the single declared seam permitted to import
the worker.

The API still owns these TYPES, because it owns the lifecycle state machine and the system of
record: it builds the :class:`~secp_api.range_providers.base.RangeSpec` from the template row and
interprets the observations the worker sends back. It just never runs one.
"""

from __future__ import annotations

from secp_api.range_providers.base import (
    ComponentSpec,
    DeployResult,
    OperationContext,
    ProviderHealth,
    RangeProvider,
    RangeSpec,
    RecordedStep,
    ResourceObservation,
    TeardownObservation,
    TeardownResourceOutcome,
    TeardownResult,
)

__all__ = [
    "ComponentSpec",
    "DeployResult",
    "OperationContext",
    "ProviderHealth",
    "RangeProvider",
    "RangeSpec",
    "RecordedStep",
    "ResourceObservation",
    "TeardownObservation",
    "TeardownResourceOutcome",
    "TeardownResult",
]
