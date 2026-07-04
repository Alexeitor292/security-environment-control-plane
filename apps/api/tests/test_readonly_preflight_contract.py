"""SECP-B2-0 — the API-side live-read contract constants must match the worker/plugin.

The control-plane API cannot import the Proxmox plugin, so it keeps its own copies of the small
contract labels + a provider-neutral connection-identity hash. This test asserts they stay equal
to the authoritative plugin/worker values so drift fails CI (it does not contact anything).
"""

from __future__ import annotations

from secp_api import live_read_contract as api_contract


def test_contract_labels_match_the_plugin():
    from secp_plugin_proxmox.live_collector import (
        LIVE_READ_COLLECTOR_CONTRACT_VERSION,
        LIVE_READ_EVIDENCE_SOURCE,
    )
    from secp_plugin_proxmox.plugin import PLUGIN_NAME
    from secp_plugin_proxmox.readonly_policy import PROXMOX_READONLY_POLICY_VERSION

    assert api_contract.LIVE_READ_EVIDENCE_SOURCE == LIVE_READ_EVIDENCE_SOURCE
    assert api_contract.LIVE_READ_COLLECTOR_CONTRACT_VERSION == LIVE_READ_COLLECTOR_CONTRACT_VERSION
    assert api_contract.PROXMOX_READONLY_POLICY_VERSION == PROXMOX_READONLY_POLICY_VERSION
    assert api_contract.LIVE_READ_PLUGIN_NAME == PLUGIN_NAME


def test_connection_identity_hash_matches_worker_provider():
    # The worker's preflight connection-hash provider must compute the SAME hash from the SAME
    # authoritative stored config, so an authorization binds to the exact connection identity.
    from secp_worker.preflight.orchestration import _ConnectionHashProvider

    class _T:
        config = {"base_url": "placeholder", "verify_tls": True}

    provider = _ConnectionHashProvider()
    assert provider.current_connection_hash(_T()) == api_contract.connection_identity_hash(
        _T.config
    )


def test_connection_identity_hash_refuses_credential_bearing_config():
    import pytest

    for bad in ({"credential_ref": "x"}, {"secret_ref": "y"}):
        with pytest.raises(ValueError):
            api_contract.connection_identity_hash(bad)


def test_live_verified_level_matches_enum():
    from secp_api.enums import VerificationLevel

    assert api_contract.LIVE_VERIFIED_LEVEL == VerificationLevel.live_verified.value
