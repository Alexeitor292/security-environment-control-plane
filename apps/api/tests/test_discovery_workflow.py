"""Proof #5 — worker discovery records immutable snapshots + audit events.

Runs the worker-side ``run_discovery`` with a fake Proxmox transport and a fake
secret resolver. No real endpoint is contacted; no real secret is read.
"""

from __future__ import annotations

import pytest
from secp_api.enums import AuditAction, SnapshotStatus
from secp_api.errors import ImmutableResourceError
from secp_api.models import AuditEvent, ProviderInventoryResource
from secp_plugin_proxmox import ProxmoxPlugin
from secp_worker.discovery import run_discovery
from secp_worker.secrets import FakeSecretResolver

SECRET_REF = "env:SECP_PROVIDER_SECRET__DISCO"

FAKE_INVENTORY = {
    "/nodes": [{"node": "node-a", "status": "online"}],
    "/nodes/node-a/qemu": [{"vmid": 100, "name": "vm-a", "status": "running"}],
    "/nodes/node-a/lxc": [],
    "/nodes/node-a/storage": [{"storage": "store-x", "active": 1, "type": "dir"}],
}


class FakeTransport:
    def __init__(self, data):
        self.data = data

    def get(self, path, params=None):
        return self.data.get(path, [])


def _factory(config, token):
    return FakeTransport(FAKE_INVENTORY)


def _target_and_snapshot(session, principal, *, secret_ref=SECRET_REF):
    from secp_api.services import inventory, targets

    target = targets.register_target(
        session,
        principal,
        display_name="Lab (placeholder)",
        plugin_name="proxmox",
        config={"base_url": "https://proxmox.example.test:8006/api2/json", "verify_tls": False},
        secret_ref=secret_ref,
        scope_policy={"resource_types": ["node", "vm", "storage"]},
        address_spaces=[],
    )
    snap = inventory.request_discovery(session, principal, target.id)
    session.commit()
    return target, snap


def test_run_discovery_records_immutable_snapshot_and_audit(session, principal):
    _target, snap = _target_and_snapshot(session, principal)
    plugin = ProxmoxPlugin(transport_factory=_factory)
    resolver = FakeSecretResolver({SECRET_REF: "fake-token"})

    run_discovery(session, snap.id, plugin=plugin, resolver=resolver)
    session.commit()

    assert snap.status == SnapshotStatus.completed
    assert snap.finalized is True
    resources = (
        session.query(ProviderInventoryResource)
        .filter(ProviderInventoryResource.snapshot_id == snap.id)
        .all()
    )
    types = {r.resource_type for r in resources}
    assert types == {"node", "vm", "storage"}

    actions = {e.action for e in session.query(AuditEvent).all()}
    assert AuditAction.discovery_started.value in actions
    assert AuditAction.discovery_completed.value in actions

    # Snapshot is immutable after completion.
    snap.summary = {"tampered": True}
    with pytest.raises(ImmutableResourceError):
        session.flush()


def test_run_discovery_secret_failure_is_redacted_and_audited(session, principal):
    _target, snap = _target_and_snapshot(session, principal)
    plugin = ProxmoxPlugin(transport_factory=_factory)
    # Resolver does NOT know the reference -> resolution fails.
    resolver = FakeSecretResolver({})

    run_discovery(session, snap.id, plugin=plugin, resolver=resolver)
    session.commit()

    assert snap.status == SnapshotStatus.failed
    assert snap.finalized is True
    assert "redacted" in (snap.error or "")
    # No secret value anywhere in the error.
    assert "fake-token" not in (snap.error or "")
    actions = {e.action for e in session.query(AuditEvent).all()}
    assert AuditAction.secret_resolution_failed.value in actions
    assert AuditAction.discovery_failed.value in actions


def test_discovery_never_persists_secret(session, principal):
    _target, snap = _target_and_snapshot(session, principal)
    plugin = ProxmoxPlugin(transport_factory=_factory)
    resolver = FakeSecretResolver({SECRET_REF: "top-secret-token"})
    run_discovery(session, snap.id, plugin=plugin, resolver=resolver)
    session.commit()

    # The secret value appears in no audit event, snapshot, or resource.
    blob = " ".join(str(e.data) for e in session.query(AuditEvent).all())
    blob += str(snap.summary) + str(snap.error)
    for r in session.query(ProviderInventoryResource).all():
        blob += str(r.attributes)
    assert "top-secret-token" not in blob
