"""Worker-only sealed activation-gate seam for read-only-preflight resolution (SECP-B2-3).

The **shipped default is disabled** and returns the closed internal refusal
``resolution_activation_disabled``. It cannot be enabled through the API, UI, settings, environment
variables, Compose values, a database-editing route, feature flags, or Git-tracked configuration —
there is no code path in production runtime that selects an approved gate. It exists so the worker
fails closed before any durable lease is acquired.

A test-only approved gate may be injected to exercise the durable lease transitions, but the flow
still ends at the sealed unavailable resolver: it never produces secret material, a transport, a
collector, or any target contact. This PR does NOT satisfy the B2-2 out-of-band activation
evidence; it only creates the local fail-closed foundation.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from secp_api.enums import ResolutionLeaseReason


class ResolutionActivationDisabled(Exception):
    """Raised by the sealed gate: live resolution activation is disabled. Fail closed."""

    reason = ResolutionLeaseReason.resolution_activation_disabled


@runtime_checkable
class ResolutionActivationGate(Protocol):
    """Narrow worker-only seam. ``check`` returns ``None`` if activated, else fails closed."""

    def check(self) -> None: ...


class SealedActivationGate:
    """The shipped default: DISABLED. Always fails closed.

    No configuration, setting, environment variable, Compose value, feature flag, database row, or
    Git-tracked value can enable it. It reads nothing and depends on nothing external.
    """

    def check(self) -> None:
        raise ResolutionActivationDisabled("read-only-preflight resolution activation is disabled")
