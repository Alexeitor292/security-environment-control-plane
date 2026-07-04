"""App-side live-read contract constants + provider-neutral connection identity hash (SECP-B2-0).

The control-plane API must NOT import the Proxmox plugin (architecture boundary; provider contact
is worker-only). This module mirrors the small set of secret-free contract *labels* the API needs
to bind a live-read authorization for a read-only staging preflight, plus a provider-neutral
connection-identity hash over a target's stored, secret-free connection config.

These values MUST stay equal to the worker/plugin constants; a worker-side test
(`test_readonly_preflight_contract_alignment`) asserts that equality so drift fails CI. This
module resolves no secret, contacts nothing, and imports no plugin/transport/HTTP code.
"""

from __future__ import annotations

# Must equal secp_plugin_proxmox.live_collector.LIVE_READ_EVIDENCE_SOURCE.
LIVE_READ_EVIDENCE_SOURCE = "live_readonly_proxmox"
# Must equal secp_plugin_proxmox.live_collector.LIVE_READ_COLLECTOR_CONTRACT_VERSION.
LIVE_READ_COLLECTOR_CONTRACT_VERSION = "secp-002b-1b-4/live-readonly-proxmox-collector/v1"
# Must equal secp_plugin_proxmox.readonly_policy.PROXMOX_READONLY_POLICY_VERSION.
PROXMOX_READONLY_POLICY_VERSION = "secp-002b-1b-3/proxmox-readonly-allowlist/v1"
# The only verification level a live read-only collection may claim.
LIVE_VERIFIED_LEVEL = "live_verified"

# Provider/plugin a live-read staging substrate must be.
LIVE_READ_PLUGIN_NAME = "proxmox"


def connection_identity_hash(config: dict) -> str:
    """Deterministic ``sha256:`` hash of a target's stored, secret-free connection config.

    Provider-neutral and secret-free: it hashes only the durable stored ``ExecutionTarget.config``
    (connection identity, e.g. base_url + verify_tls), never a credential/secret reference. The
    worker's connection-hash provider computes the SAME hash from the SAME authoritative record so
    an authorization is bound to the exact connection identity it was approved for (drift fails
    closed). It refuses a config that smuggles a credential reference.
    """
    from secp_scenario_schema import content_hash

    if not isinstance(config, dict):
        raise ValueError("connection config must be an object")
    if "credential_ref" in config or "secret_ref" in config:
        raise ValueError("connection config must not carry a credential/secret reference")
    return content_hash(config)
