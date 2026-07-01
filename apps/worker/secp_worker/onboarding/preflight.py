"""Onboarding preflight collector seam (SECP-002B-1B-0, ADR-014) — worker-only.

A ``PreflightCollector`` produces redacted, structured evidence attesting that a target
satisfies its declared boundary and the platform prerequisites. In B1-B-0 the only
implementation is ``FakePreflightCollector``: it **does not connect to, inspect, or query
any real target** — it derives passing evidence from the (already validated) declared
boundary. Its ``detail`` strings are generic and carry no real values or secrets.

B1-B will add a real collector that gathers real evidence from a reviewed disposable lab,
still redacted and hash-bound, behind the same seam.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from secp_api.enums import IsolationModel, PreflightCheckStatus
from secp_api.onboarding import (
    BASE_REQUIRED_CHECKS,
    CHECK_NO_ROUTE_TO_PROTECTED,
    LOGICAL_REQUIRED_CHECKS,
)

# Generic, redacted, review-safe descriptions. No real hostnames/IPs/nodes/etc.
_DETAILS = {
    "nodes_in_allowlist": "all selected nodes are within the declared node allowlist",
    "storage_in_allowlist": "all selected storage is within the declared storage allowlist",
    "network_in_boundary": "requested network segments are within the declared boundary",
    "cidr_non_overlapping": "declared CIDR ranges are non-overlapping",
    "vmid_non_overlapping": "declared VM-ID range is non-overlapping",
    "capacity_within_quota": "requested capacity is within the declared quotas",
    "external_connectivity_deny": "external connectivity policy is deny by default",
    "no_route_to_protected": "no route to management/home/corporate/public network classes",
    "tls_posture_acceptable": "TLS posture is acceptable (trusted CA / pinning)",
    "credential_least_privilege": "credential scope is least privilege (opaque reference)",
    "remote_state_present": "remote state backend prerequisite is present",
    "pinned_toolchain_present": "pinned toolchain prerequisite is present",
}


@runtime_checkable
class PreflightCollector(Protocol):
    """Produce redacted onboarding preflight evidence for a declared boundary."""

    name: str

    def collect(self, *, declared_boundary: dict, isolation_model: str) -> list[dict]: ...


class FakePreflightCollector:
    """Fake collector. Inspects NOTHING real; derives evidence from the declared boundary.

    ``fail`` lets a test simulate a specific failing/omitted check (e.g. to prove a
    logical-isolation target cannot activate without ``no_route_to_protected``).
    """

    name = "fake"

    def __init__(self, *, fail: set[str] | None = None, omit: set[str] | None = None) -> None:
        self._fail = set(fail or ())
        self._omit = set(omit or ())

    def collect(self, *, declared_boundary: dict, isolation_model: str) -> list[dict]:
        required = set(BASE_REQUIRED_CHECKS)
        if isolation_model == IsolationModel.logical.value:
            required |= set(LOGICAL_REQUIRED_CHECKS)
        else:
            # Physical isolation: no-route is not required but is reported as skipped.
            required |= {CHECK_NO_ROUTE_TO_PROTECTED}

        checks: list[dict] = []
        for name in sorted(required):
            if name in self._omit:
                continue
            if name in self._fail:
                status = PreflightCheckStatus.failed
            elif (
                name == CHECK_NO_ROUTE_TO_PROTECTED
                and isolation_model != IsolationModel.logical.value
            ):
                status = PreflightCheckStatus.skipped
            else:
                status = PreflightCheckStatus.passed
            checks.append(
                {
                    "check": name,
                    "status": status.value,
                    "detail": _DETAILS.get(name, "check evaluated"),
                }
            )
        return checks
