"""Proofs #8, #9 — FakeOpenTofuRunner determinism and idempotency (no I/O)."""

from __future__ import annotations

import pytest
from secp_worker.provisioning import FakeOpenTofuRunner
from secp_worker.provisioning.runner import RunnerError

MANIFEST = {
    "manifest_version": "secp-002b-0/v1",
    "resource_limits": {"max_vms": 20},
    "reservations": [
        {"team_ref": "team1", "cidr": "10.60.0.0/24"},
        {"team_ref": "team2", "cidr": "10.60.1.0/24"},
    ],
    "topology": [
        {
            "team_ref": "team1",
            "networks": [{"name": "team-network", "cidr": "10.60.0.0/24", "bridge": "vmbr0"}],
            "nodes": [
                {
                    "ref": "attacker",
                    "guest_kind": "vm",
                    "image": "kali-linux",
                    "node": "pve-node-1",
                    "storage": "local-lvm",
                },
                {
                    "ref": "wazuh",
                    "guest_kind": "container",
                    "image": "wazuh-agent",
                    "node": "pve-node-2",
                    "storage": "local-lvm",
                },
            ],
        },
        {
            "team_ref": "team2",
            "networks": [{"name": "team-network", "cidr": "10.60.1.0/24", "bridge": "vmbr0"}],
            "nodes": [
                {
                    "ref": "attacker",
                    "guest_kind": "vm",
                    "image": "kali-linux",
                    "node": "pve-node-1",
                    "storage": "local-lvm",
                },
            ],
        },
    ],
}


def test_validate():
    assert FakeOpenTofuRunner().validate(MANIFEST).ok is True
    bad = FakeOpenTofuRunner().validate({"manifest_version": "x"})
    assert bad.ok is False and bad.errors


def test_dry_run_is_deterministic():
    a = FakeOpenTofuRunner().dry_run(MANIFEST, operation_id="op-dry")
    b = FakeOpenTofuRunner().dry_run(MANIFEST, operation_id="op-dry")
    assert a.model_dump() == b.model_dump()
    # 2 networks + 3 nodes across the two teams.
    assert a.summary["create"] == 5
    assert a.summary["by_type"] == {"network": 2, "vm": 2, "container": 1}


def test_resource_ids_are_deterministic_across_runners():
    a = FakeOpenTofuRunner().apply(MANIFEST, operation_id="op-a")
    b = FakeOpenTofuRunner().apply(MANIFEST, operation_id="op-a")
    ids_a = sorted(r["resource_id"] for r in a.resources)
    ids_b = sorted(r["resource_id"] for r in b.resources)
    assert ids_a == ids_b
    assert all(rid.startswith("fake-") for rid in ids_a)


def test_apply_is_idempotent():
    runner = FakeOpenTofuRunner()
    first = runner.apply(MANIFEST, operation_id="op-apply")
    second = runner.apply(MANIFEST, operation_id="op-apply")
    assert first.idempotent_noop is False
    assert second.idempotent_noop is True
    assert first.resources == second.resources


def test_destroy_is_idempotent():
    runner = FakeOpenTofuRunner()
    runner.apply(MANIFEST, operation_id="op-x")
    first = runner.destroy(MANIFEST, operation_id="op-x")
    second = runner.destroy(MANIFEST, operation_id="op-x")
    assert first.ok and first.idempotent_noop is False
    assert second.idempotent_noop is True


def test_status_reflects_state():
    runner = FakeOpenTofuRunner()
    assert runner.status("nope").exists is False
    runner.apply(MANIFEST, operation_id="op-s")
    st = runner.status("op-s")
    assert st.exists is True and st.state == "applied"


def test_invalid_manifest_raises_redacted_error():
    runner = FakeOpenTofuRunner()
    with pytest.raises(RunnerError) as exc:
        runner.apply({"manifest_version": "x"}, operation_id="op-bad")
    assert "redacted" in str(exc.value).lower()
    # no secret-like content in the message
    assert "token" not in str(exc.value).lower()


def test_runner_module_has_no_io_imports():
    import secp_worker.provisioning.fake_opentofu as fake

    src = __import__("inspect").getsource(fake)
    for forbidden in (
        "import subprocess",
        "import socket",
        "import httpx",
        "import requests",
        "os.system",
        "subprocess.",
    ):
        assert forbidden not in src
