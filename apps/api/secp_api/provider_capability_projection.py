"""Capability report -> published schema.

The three rollup lists are computed HERE, from the projected operations, so the summary and the
detail are the same data folded once. A client folding it separately would eventually fold it
differently, and a rollup that disagrees with the list it summarises is worse than no rollup.
"""

from __future__ import annotations

from secp_api.provider_capabilities import CapabilityReport, CapabilityState
from secp_api.schemas_provider_capabilities import (
    OperationCapabilityOut,
    ProviderCapabilitiesOut,
    ProviderCapabilityOut,
)


def capabilities_out(report: CapabilityReport) -> ProviderCapabilitiesOut:
    operations = [
        OperationCapabilityOut(
            operation=item.operation,
            state=item.state,
            required_permission=item.required_permission,
            detail=item.detail,
        )
        for item in report.operations
    ]
    return ProviderCapabilitiesOut(
        operations=operations,
        providers=[
            ProviderCapabilityOut(
                provider=item.provider,
                deployable=item.deployable,
                lifecycle_operations=list(item.lifecycle_operations),
                detail=item.detail,
            )
            for item in report.providers
        ],
        discovery=report.discovery,
        discovery_detail=report.discovery_detail,
        authorized_operations=_by_state(operations, CapabilityState.supported_authorized),
        unauthorized_operations=_by_state(operations, CapabilityState.supported_unauthorized),
        unsupported_operations=_by_state(operations, CapabilityState.not_supported),
    )


def _by_state(operations: list[OperationCapabilityOut], state: CapabilityState) -> list[str]:
    return [item.operation for item in operations if item.state is state]
