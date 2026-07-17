"""Trusted locations — no arbitrary root writes, protected roots (defect #1, #9)."""

from __future__ import annotations

import pytest
from secp_commissioning.locations import CommissioningLocations, LocationError


def test_defaults_are_generic_and_consistent():
    loc = CommissioningLocations()
    assert loc.operator_root.startswith("/opt/secp/operator")
    # evidence + descriptor are distinct from the operator write root.
    assert not loc.evidence_path.startswith(loc.operator_root + "/")


def test_resolve_operator_file_stays_under_operator_root():
    loc = CommissioningLocations()
    path = loc.resolve_operator_file("entrypoint.py")
    assert path == loc.operator_root + "/entrypoint.py"


@pytest.mark.parametrize(
    "basename", ["../etc/passwd", "a/b", "..", "/abs", "with\x00nul", "back\\slash", ""]
)
def test_resolve_operator_file_refuses_traversal_and_unsafe(basename):
    with pytest.raises(LocationError):
        CommissioningLocations().resolve_operator_file(basename)


@pytest.mark.parametrize(
    "target",
    [
        "/opt/secp/worker/config",  # ordinary worker
        "/opt/secp/api/main.py",  # control plane
        "/etc/passwd",
        "/etc/systemd/system/x.service",
        "/root/.ssh/authorized_keys",
        "/var/lib/docker/x",
        "/usr/bin/python3",
        "/opt/secp",  # parent of operator root, not under it
        "/opt/other/x",  # outside operator root
    ],
)
def test_assert_writable_target_refuses_protected_and_outside(target):
    with pytest.raises(LocationError):
        CommissioningLocations().assert_writable_target(target)


def test_assert_writable_target_accepts_under_operator_root():
    loc = CommissioningLocations()
    loc.assert_writable_target(loc.operator_root + "/entrypoint.py")  # no raise


def test_operator_root_may_not_be_a_protected_root():
    with pytest.raises(LocationError):
        CommissioningLocations(operator_root="/etc/secp")


def test_evidence_may_not_live_under_operator_root():
    with pytest.raises(LocationError):
        CommissioningLocations(
            operator_root="/opt/secp/operator",
            evidence_path="/opt/secp/operator/evidence.json",
        )
