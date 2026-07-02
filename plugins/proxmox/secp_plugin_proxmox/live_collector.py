"""Dormant live read-only Proxmox collector (SECP-002B-1B-4).

Worker/plugin-only and **unreachable outside unit tests**: the sole way to reach it is the
worker orchestration entry ``run_live_readonly_collection``, which first refuses a
default-disabled gate and validates an immutable binding before any secret resolution or
transport construction. This collector contacts nothing real — it drives an **injected**
``ReadOnlyHttpTransport`` (a fake in tests; the policy-hardened ``HttpxReadOnlyTransport`` in a
future, separately-authorized activation), issues only closed-allowlist **canonical GET** paths
(re-checked here via :func:`assert_request_allowed` as defense-in-depth), normalizes with the
existing pure normalizer, **never infers isolation**, and returns an in-memory, provider-neutral
observed dict. It NEVER persists evidence, creates a ``TargetEvidenceRecord``, or unseals live
evidence. No HTTP client / socket / subprocess / network I/O / credential is present here.
"""

from __future__ import annotations

from typing import Any

from secp_plugin_proxmox.readonly_normalize import normalize_proxmox_observations
from secp_plugin_proxmox.readonly_policy import assert_request_allowed
from secp_plugin_proxmox.transport import ReadOnlyHttpTransport

# The label + contract version a future authorized activation would bind (validated by the
# worker binding). Present here for the binding contract only — NOT wired into any evidence
# persistence flow, and the live-evidence seal is untouched.
LIVE_READ_EVIDENCE_SOURCE = "live_readonly_proxmox"
LIVE_READ_COLLECTOR_CONTRACT_VERSION = "secp-002b-1b-4/live-readonly-proxmox-collector/v1"

# Cluster-scope canonical GET paths issued first (node list drives per-node reads).
_CLUSTER_PATHS: tuple[str, ...] = ("/nodes", "/cluster/sdn/vnets")


class LiveReadOnlyProxmoxCollector:
    """Issues only allowlisted canonical GETs through an injected transport and normalizes."""

    name = "live_readonly_proxmox"

    def collect(self, transport: ReadOnlyHttpTransport, *, declared_boundary: dict) -> dict:
        responses: dict[str, Any] = {}
        for path in _CLUSTER_PATHS:
            responses[path] = self._get(transport, path)
        # Per-node storage reads. Node names come from the observed /nodes response; each derived
        # path is re-validated by assert_request_allowed, so a hostile node name (e.g. one with an
        # encoded slash) is refused rather than smuggling a deeper path.
        for node in responses.get("/nodes", []) or []:
            if isinstance(node, dict) and node.get("node"):
                storage_path = f"/nodes/{node['node']}/storage"
                responses[storage_path] = self._get(transport, storage_path)
        # NEVER infer isolation: no dedicated isolation observation is supplied, so the observed
        # result omits isolation and fully_segregated stays unverifiable downstream.
        return normalize_proxmox_observations(responses)

    @staticmethod
    def _get(transport: ReadOnlyHttpTransport, path: str) -> Any:
        # Defense-in-depth: enforce the closed canonical policy before the transport call too.
        assert_request_allowed("GET", path)
        return transport.get(path)
