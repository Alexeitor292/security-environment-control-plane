"""SECP-B3 — live Proxmox provider ownership boundary (§2). Fake-only; no host/API is contacted.

Proves target eligibility fails closed for unreachable / clustered / ambiguous / isolation-incapable
/ undersized / conflicting-ownership targets; that the provider mutates only provably SECP-owned
resources; and that the shipped defaults (provider / inventory reader / API transport) refuse.
"""

from __future__ import annotations

import pytest
from secp_worker.staging_live.bootstrap.ownership import ownership_namespace
from secp_worker.staging_live.live_proxmox_provider import (
    CapacityProfile,
    LiveProxmoxProvider,
    LiveProxmoxProviderError,
    SealedLiveProxmoxProvider,
    SealedProxmoxApiTransport,
    SealedProxmoxInventoryReader,
    TargetInventory,
    assess_target,
)

_NS = ownership_namespace("staging-lab-01")
_PROFILE = CapacityProfile(
    required_vmids=10, required_vcpus=8, required_memory_mb=8192, required_disk_gb=200
)


def _healthy_inventory(**over) -> TargetInventory:
    base = dict(
        node_reachable=True,
        is_clustered=False,
        node_count=1,
        isolation_capable=True,
        nested_virtualization="available",
        available_vmids=100,
        free_vcpus=32,
        free_memory_mb=65536,
        free_disk_gb=2048,
        existing_ownership_tags=(),
    )
    base.update(over)
    return TargetInventory(**base)  # type: ignore[arg-type]


class _FakeReader:
    def __init__(self, inventory: TargetInventory) -> None:
        self._inventory = inventory

    def read_inventory(self) -> TargetInventory:
        return self._inventory


def _assess(**over):
    return assess_target(_healthy_inventory(**over), profile=_PROFILE, namespace=_NS)


# --- target eligibility fails closed -------------------------------------------------------------


def test_healthy_target_is_eligible():
    assert _assess() == type(_assess())(ok=True, reason_code="eligible")


@pytest.mark.parametrize(
    "over, reason",
    [
        ({"node_reachable": False}, "target_unreachable"),
        ({"is_clustered": True}, "target_is_clustered"),
        ({"node_count": 2}, "ambiguous_node_selection"),
        ({"node_count": 0}, "ambiguous_node_selection"),
        ({"isolation_capable": False}, "isolation_policy_unsatisfiable"),
        ({"available_vmids": 1}, "insufficient_capacity"),
        ({"free_vcpus": 1}, "insufficient_capacity"),
        ({"free_memory_mb": 128}, "insufficient_capacity"),
        ({"free_disk_gb": 1}, "insufficient_capacity"),
        ({"existing_ownership_tags": ("secp-owned:deadbeef",)}, "conflicting_secp_ownership"),
    ],
)
def test_ineligible_targets_fail_closed(over, reason):
    result = _assess(**over)
    assert result.ok is False
    assert result.reason_code == reason


def test_targets_owned_by_this_lab_are_not_a_conflict():
    # An existing resource carrying THIS lab's ownership tag is a retry/recovery, not a conflict.
    result = _assess(existing_ownership_tags=(_NS.ownership_tag,))
    assert result.ok is True


# --- provider ownership boundary -----------------------------------------------------------------


def test_provider_assess_uses_injected_reader():
    provider = LiveProxmoxProvider(
        namespace=_NS,
        inventory_reader=_FakeReader(_healthy_inventory()),
        capacity_profile=_PROFILE,
    )
    assert provider.assess().ok is True


def test_provider_mutates_only_secp_owned_resources():
    provider = LiveProxmoxProvider(
        namespace=_NS,
        inventory_reader=_FakeReader(_healthy_inventory()),
        capacity_profile=_PROFILE,
    )
    # An owned resource passes the mutation gate; anything else fails closed.
    provider.assert_mutable(_NS.ownership_tag)
    for foreign in (None, "", "secp-owned:deadbeef", ownership_namespace("other").ownership_tag):
        with pytest.raises(LiveProxmoxProviderError) as exc:
            provider.assert_mutable(foreign)
        assert exc.value.reason_code == "resource_not_secp_owned"


def test_provider_generates_owned_resource_names():
    provider = LiveProxmoxProvider(
        namespace=_NS,
        inventory_reader=_FakeReader(_healthy_inventory()),
        capacity_profile=_PROFILE,
    )
    assert provider.owned_resource_name("bridge", 0) == _NS.resource_name("bridge", 0)


# --- shipped defaults refuse ---------------------------------------------------------------------


def test_sealed_defaults_refuse_offline():
    with pytest.raises(LiveProxmoxProviderError):
        SealedLiveProxmoxProvider().assess()
    with pytest.raises(LiveProxmoxProviderError):
        SealedLiveProxmoxProvider().assert_mutable(_NS.ownership_tag)
    with pytest.raises(LiveProxmoxProviderError):
        SealedProxmoxInventoryReader().read_inventory()
    with pytest.raises(LiveProxmoxProviderError):
        SealedProxmoxApiTransport().apply_owned(operation_code="x", owner_tag=_NS.ownership_tag)
