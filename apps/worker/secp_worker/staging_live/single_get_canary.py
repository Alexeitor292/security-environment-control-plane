"""Dedicated single-GET Proxmox canary collector (SECP-B3).

Closes B2-5-pre activation-review condition A. The multi-GET ``LiveReadOnlyProxmoxCollector`` issues
several allowlisted GETs (cluster + per-node), so the canary's "exactly ONE GET" claim was
inaccurate. This collector issues EXACTLY ONE canonical, allowlisted GET (``/nodes``) — re-validated
by the closed read-only policy as defense in depth — and records every request it makes so the
request count is behaviorally testable. It reuses NO multi-GET inventory logic.

It returns only a safe, provider-neutral observation (a bounded node count derives downstream); it
never persists a raw response and never issues a second request. It performs no I/O itself — it
drives an injected transport (a fake in tests; an approved hardened transport in a real activation).
"""

from __future__ import annotations

from secp_plugin_proxmox.readonly_policy import assert_request_allowed

# The single canonical allowlisted GET the canary issues. Node reachability + policy enforcement is
# all a one-GET canary proves; it deliberately does NOT enumerate storage or network segments.
CANARY_GET_METHOD = "GET"
CANARY_GET_PATH = "/nodes"


class SingleGetCanaryCollector:
    """A one-shot collector that issues EXACTLY ONE allowlisted GET and records what it requested.

    ``collect`` returns a safe observed dict shaped like ``{"observed": {"nodes": [...]}}``; only a
    bounded count is derived from it downstream. ``requests`` is the list of ``(method, path)``
    pairs issued, so a test can assert the count is exactly one and the method is GET.
    """

    name = "single_get_proxmox_canary"

    def __init__(self) -> None:
        self.requests: list[tuple[str, str]] = []

    def collect(self, transport: object, *, declared_boundary: dict) -> dict:
        # Defense in depth: re-check the closed canonical allowlist before the single call.
        assert_request_allowed(CANARY_GET_METHOD, CANARY_GET_PATH)
        self.requests.append((CANARY_GET_METHOD, CANARY_GET_PATH))
        response = transport.get(CANARY_GET_PATH)  # type: ignore[attr-defined]
        nodes = response if isinstance(response, list) else []
        # Return ONLY a provider-neutral shape; names are discarded to a count downstream.
        return {"observed": {"nodes": nodes}}

    @property
    def get_count(self) -> int:
        return sum(1 for method, _ in self.requests if method == "GET")

    @property
    def methods(self) -> set[str]:
        return {method for method, _ in self.requests}


class SingleGetCanaryCollectorFactory:
    """Produces a FRESH, empty :class:`SingleGetCanaryCollector` for each canary run.

    The composition owns this factory (validated nominally) instead of a shared collector instance,
    so every transport-canary run counts its own requests from zero — a repeated run on the same
    composition still observes exactly one GET for that run, never an accumulated total.
    """

    def __call__(self) -> SingleGetCanaryCollector:
        return SingleGetCanaryCollector()
