"""Slice 3 — provider inventory snapshots: lifecycle, immutability, org scope."""

from __future__ import annotations

import pytest
from secp_api.enums import AuditAction, SnapshotStatus
from secp_api.errors import AuthorizationError, ImmutableResourceError
from secp_api.models import AuditEvent


def _target(session, actor):
    from secp_api.services import targets

    return targets.register_target(
        session,
        actor,
        display_name="Lab",
        plugin_name="proxmox",
        config={"base_url": "https://proxmox.example.test:8006"},
        secret_ref="env:SECP_PROVIDER_SECRET__T",
        address_spaces=[],
    )


def test_request_creates_queued_snapshot_and_audit(session, principal):
    from secp_api.services import inventory

    target = _target(session, principal)
    snap = inventory.request_discovery(session, principal, target.id)
    session.commit()
    assert snap.status == SnapshotStatus.queued
    assert snap.target_config_hash == target.config_hash
    actions = {e.action for e in session.query(AuditEvent).all()}
    assert AuditAction.discovery_requested.value in actions


def test_complete_finalizes_and_is_immutable(session, principal):
    from secp_api.services import inventory

    target = _target(session, principal)
    snap = inventory.request_discovery(session, principal, target.id)
    inventory.mark_running(session, snap.id)
    inventory.complete_snapshot(
        session,
        snap.id,
        resources=[
            {"resource_type": "node", "provider_external_id": "n1", "display_name": "n1"},
            {"resource_type": "vm", "provider_external_id": "n1/100", "display_name": "vm-a"},
        ],
        summary={"total": 2, "by_type": {"node": 1, "vm": 1}},
        plugin_version="0.1.0",
    )
    session.commit()
    assert snap.status == SnapshotStatus.completed
    assert snap.finalized is True
    rows = inventory.list_snapshot_resources(session, principal, snap.id)
    assert {r.resource_type for r in rows} == {"node", "vm"}

    # Immutable after completion.
    snap.summary = {"tampered": True}
    with pytest.raises(ImmutableResourceError):
        session.flush()


def test_fail_snapshot_records_redacted_error(session, principal):
    from secp_api.services import inventory

    target = _target(session, principal)
    snap = inventory.request_discovery(session, principal, target.id)
    inventory.fail_snapshot(session, snap.id, error="discovery failed (redacted)")
    session.commit()
    assert snap.status == SnapshotStatus.failed
    assert snap.finalized is True
    assert "redacted" in (snap.error or "")


def test_cross_org_snapshot_access_denied(session, principal, other_org_principal):
    from secp_api.services import inventory

    target = _target(session, principal)
    snap = inventory.request_discovery(session, principal, target.id)
    session.commit()
    with pytest.raises(AuthorizationError):
        inventory.get_snapshot(session, other_org_principal, snap.id)
