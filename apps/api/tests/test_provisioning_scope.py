"""Proof #7 — strict provisioning scope policy rejects unsafe/invalid inputs."""

from __future__ import annotations

import copy

import pytest
from secp_api.errors import ValidationFailedError
from secp_api.provisioning_scope import validate_provisioning_scope

VALID_PROVISIONING_SCOPE: dict = {
    "allowed_nodes": ["pve-node-1", "pve-node-2"],
    "allowed_storage": ["local-lvm"],
    "allowed_bridges": ["vmbr0"],
    "allowed_templates": ["kali-linux", "ubuntu-server-22.04", "wazuh-agent"],
    "vmid_range": {"start": 9000, "end": 9100},
    "max_teams": 4,
    "max_vms": 20,
    "max_containers": 10,
    "max_total_vcpu": 64,
    "max_total_memory_mb": 131072,
    "max_total_disk_gb": 2048,
    "allowed_cidr_reservations": ["10.60.0.0/16"],
    "external_connectivity": {"policy": "deny"},
    "node_sizing": {
        "kali-linux": {"vcpu": 2, "memory_mb": 4096, "disk_gb": 40},
        "ubuntu-server-22.04": {"vcpu": 1, "memory_mb": 2048, "disk_gb": 20},
        "wazuh-agent": {"vcpu": 1, "memory_mb": 1024, "disk_gb": 10},
    },
}


def _scope(**overrides):
    s = copy.deepcopy(VALID_PROVISIONING_SCOPE)
    s.update(overrides)
    return {"provisioning": s}


def test_valid_scope_accepted():
    policy = validate_provisioning_scope(_scope())
    assert policy.max_teams == 4
    assert policy.external_connectivity.policy == "deny"


def test_missing_provisioning_section_rejected():
    with pytest.raises(ValidationFailedError):
        validate_provisioning_scope({"resource_types": ["node"]})  # discovery-only scope


@pytest.mark.parametrize(
    "overrides",
    [
        {"allowed_nodes": []},  # empty allowlist
        {"allowed_nodes": ["*"]},  # wildcard
        {"allowed_storage": ["any"]},
        {"allowed_bridges": ["all"]},
        {"allowed_templates": []},
        {"vmid_range": {"start": 9000, "end": 9000}},  # end not > start
        {"vmid_range": {"start": 9000, "end": 5000}},  # end < start
        {"vmid_range": {"start": 9000, "end": 9000000}},  # unbounded width
        {"max_teams": 0},
        {"max_vms": 0},
        {"max_total_vcpu": 0},
        {"allowed_cidr_reservations": []},
        {"allowed_cidr_reservations": ["0.0.0.0/0"]},  # unrestricted
        {"allowed_cidr_reservations": ["not-a-cidr"]},
        {"external_connectivity": {"policy": "allow"}},  # permissive refused
    ],
)
def test_invalid_scope_rejected(overrides):
    with pytest.raises(ValidationFailedError):
        validate_provisioning_scope(_scope(**overrides))


def test_unsupported_keys_rejected():
    with pytest.raises(ValidationFailedError):
        validate_provisioning_scope(_scope(unexpected_key=True))


def test_missing_required_limit_rejected():
    scope = copy.deepcopy(VALID_PROVISIONING_SCOPE)
    del scope["max_total_memory_mb"]
    with pytest.raises(ValidationFailedError):
        validate_provisioning_scope({"provisioning": scope})
