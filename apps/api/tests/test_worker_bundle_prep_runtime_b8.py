"""SECP-B8 — worker bundle-prep runtime integration ("smoke") test.

Exercises the WORKER side of the automation end to end (minus SSH): with a fully-bound target whose
host public key was captured, ``discovery_bundle_runtime.prepare_once``:
  * generates + owns the worker keypairs,
  * publishes ONLY the PUBLIC material to the control plane (a WorkerDiscoveryNode row), and
  * assembles the four-file mounted bundle at the fixed mount from the secret-free descriptor.

On POSIX it additionally proves the written bundle passes the strict worker-managed mounted-bundle
validator — i.e. the worker's own output is exactly what the (previously ``probe_source_sealed``)
live composition needs. This is the closed loop that turns SEALED into a valid, gated bundle.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import os
import threading
import uuid
from types import SimpleNamespace

import pytest


def _pubkey(comment: str = "worker@secp") -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    line = (
        ed25519.Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        .decode()
    )
    return f"{line} {comment}"


def _host_key_and_fp() -> tuple[str, str]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    line = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        .decode()
    )
    blob = line.split()[1]
    fp = "SHA256:" + base64.b64encode(
        hashlib.sha256(base64.b64decode(blob)).digest()
    ).decode().rstrip("=")
    return line, fp


def _worker_key_fingerprint(public_key: str) -> str:
    from secp_api.discovery_bootstrap_contract import validate_public_ssh_key

    _normalized, fingerprint = validate_public_ssh_key(public_key)
    return fingerprint


def _bound_enrollment(session_scope, *, worker_ssh_public_key: str | None = None):
    """Commit a proxmox target that is active-onboarded, substrate-eligible, bootstrap
    completed+bound with the host public key captured, and enrolled. Returns (host_line, fp)."""
    from conftest import VALID_PROVISIONING_SCOPE, onboard_and_activate
    from secp_api.enums import ProxmoxBootstrapStatus
    from secp_api.seed import bootstrap_dev
    from secp_api.services import bootstrap_discovery, staging_labs, targets
    from secp_api.services import target_discovery as td

    host_line, fp = _host_key_and_fp()
    with session_scope() as s:
        p = bootstrap_dev(s)
        target = targets.register_target(
            s,
            p,
            display_name="Lab",
            plugin_name="proxmox",
            config={"base_url": "https://proxmox.example.test:8006/api2/json", "verify_tls": True},
            secret_ref="env:SECP_PROVIDER_SECRET__LAB",
            scope_policy={"provisioning": copy.deepcopy(VALID_PROVISIONING_SCOPE)},
            address_spaces=[{"cidr_block": "10.60.0.0/16", "subnet_prefix": 24}],
        )
        onboard_and_activate(s, p, target)
        staging_labs.grant_substrate_eligibility(s, p, execution_target_id=target.id)
        sess = bootstrap_discovery.create_bootstrap_session(
            s,
            p,
            execution_target_id=target.id,
            worker_ssh_public_key=worker_ssh_public_key or _pubkey(),
        )
        proof = f"selftest_ok=1\nhost_public_key={host_line}"
        bootstrap_discovery.complete_bootstrap_session(
            s, p, sess.id, host_key_fingerprint=fp, proof_text=proof
        )
        assert sess.status == ProxmoxBootstrapStatus.completed
        bootstrap_discovery.bind_bootstrap_session(s, p, sess.id)
        td.request_discovery(s, p, execution_target_id=target.id)
    return host_line, fp


def _settings(tmp_path) -> SimpleNamespace:
    return SimpleNamespace(
        discovery_worker_managed_bundle=True,
        discovery_worker_key_dir=str(tmp_path / "keys"),
        discovery_bootstrap_mount=str(tmp_path / "state" / "discovery-bundle"),
        discovery_worker_node_organization="",  # single org -> auto-detected
        discovery_worker_node_label="test-worker",
    )


def test_prepare_once_publishes_key_and_writes_bundle(engine, tmp_path):
    from secp_api.db import session_scope
    from secp_worker import bundle_manager, discovery_bundle_runtime

    settings = _settings(tmp_path)
    worker_public = bundle_manager.ensure_worker_keys(
        settings.discovery_worker_key_dir
    ).ssh_public_key
    host_line, _fp = _bound_enrollment(session_scope, worker_ssh_public_key=worker_public)

    discovery_bundle_runtime.prepare_once(settings=settings, session_scope=session_scope)

    # 1. The worker published ONLY its PUBLIC key material.
    from secp_api.models import WorkerDiscoveryNode
    from sqlalchemy import select

    with session_scope() as s:
        nodes = list(s.execute(select(WorkerDiscoveryNode)).scalars())
        assert len(nodes) == 1
        node = nodes[0]
        assert node.node_label == "test-worker"
        assert node.ssh_public_key.startswith("ssh-ed25519 ")
        assert "PRIVATE" not in node.ssh_public_key
        assert len(node.admission_anchor_hex) == 64

    # 2. The four-file mounted bundle was assembled at the fixed mount from the descriptor.
    mount = settings.discovery_bootstrap_mount
    assert bundle_manager.bundle_is_present(mount)
    known_hosts = open(os.path.join(mount, "known_hosts")).read()
    assert known_hosts.split()[1] == host_line.split()[0]  # keytype matches the host's own key
    # The id_key is the worker's OWN private key (never uploaded) — present locally only.
    assert "PRIVATE KEY" in open(os.path.join(mount, "id_key")).read()


def test_prepare_once_refuses_bootstrap_bound_to_prior_worker_key(engine, tmp_path, caplog):
    from secp_api.db import session_scope
    from secp_worker import bundle_manager, discovery_bundle_runtime

    # This session authorized an unrelated prior worker key.  Preparing a fresh persistent key set
    # may publish its public material, but must not combine its private key with the stale binding.
    _bound_enrollment(session_scope, worker_ssh_public_key=_pubkey("old-worker@secp"))
    settings = _settings(tmp_path)

    discovery_bundle_runtime.prepare_once(settings=settings, session_scope=session_scope)

    assert not bundle_manager.bundle_is_present(settings.discovery_bootstrap_mount)
    assert "worker_ssh_binding_mismatch" in caplog.text


def test_prepare_once_is_idempotent_and_stable(engine, tmp_path):
    from secp_api.db import session_scope
    from secp_worker import bundle_manager, discovery_bundle_runtime

    settings = _settings(tmp_path)
    worker_public = bundle_manager.ensure_worker_keys(
        settings.discovery_worker_key_dir
    ).ssh_public_key
    _bound_enrollment(session_scope, worker_ssh_public_key=worker_public)

    discovery_bundle_runtime.prepare_once(settings=settings, session_scope=session_scope)
    pub1 = bundle_manager.ensure_worker_keys(settings.discovery_worker_key_dir).ssh_public_key
    # A second tick must not rotate the worker identity/key nor duplicate the published node.
    discovery_bundle_runtime.prepare_once(settings=settings, session_scope=session_scope)
    pub2 = bundle_manager.ensure_worker_keys(settings.discovery_worker_key_dir).ssh_public_key
    assert pub1 == pub2

    from secp_api.models import WorkerDiscoveryNode
    from sqlalchemy import select

    with session_scope() as s:
        count = len(list(s.execute(select(WorkerDiscoveryNode)).scalars()))
    assert count == 1  # upsert, not duplicate


def test_prepare_once_writes_no_bundle_when_nothing_bound(engine, tmp_path):
    """No fully-bound+host-key-captured target -> the worker publishes its key but writes NO bundle
    (it never fabricates one)."""
    from secp_api.db import session_scope
    from secp_api.seed import bootstrap_dev
    from secp_worker import bundle_manager, discovery_bundle_runtime

    with session_scope() as s:
        bootstrap_dev(s)
    settings = _settings(tmp_path)
    discovery_bundle_runtime.prepare_once(settings=settings, session_scope=session_scope)
    assert not bundle_manager.bundle_is_present(settings.discovery_bootstrap_mount)


def test_malformed_explicit_organization_fails_closed_before_state_or_db(tmp_path, caplog):
    from secp_worker import discovery_bundle_runtime

    settings = _settings(tmp_path)
    settings.discovery_worker_node_organization = "not-a-uuid"

    def forbidden_scope():
        raise AssertionError("malformed organization must not open a database session")

    discovery_bundle_runtime.prepare_once(settings=settings, session_scope=forbidden_scope)

    assert not os.path.lexists(settings.discovery_worker_key_dir)
    assert not os.path.lexists(settings.discovery_bootstrap_mount)
    assert "worker_node_organization_invalid" in caplog.text
    assert "not-a-uuid" not in caplog.text


def test_multiple_ready_descriptors_refuse_without_selecting_first(tmp_path, monkeypatch, caplog):
    from contextlib import contextmanager

    from secp_api.services import bootstrap_discovery, worker_nodes
    from secp_worker import bundle_manager, discovery_bundle_runtime

    settings = _settings(tmp_path)
    organization_id = uuid.uuid4()
    worker_fingerprint = _worker_key_fingerprint(_pubkey("current-worker@secp"))
    descriptors = [
        {
            "organization_id": str(organization_id),
            "enrollment_id": "first",
            "worker_ssh_public_key_fingerprint": worker_fingerprint,
        },
        {
            "organization_id": str(organization_id),
            "enrollment_id": "second",
            "worker_ssh_public_key_fingerprint": worker_fingerprint,
        },
    ]
    monkeypatch.setattr(
        bootstrap_discovery,
        "resolve_ready_bundle_descriptors",
        lambda _session, _organization_id: descriptors,
    )
    monkeypatch.setattr(
        worker_nodes,
        "resolve_publication_organizations",
        lambda _session, _configured_org: [organization_id],
    )

    @contextmanager
    def scope():
        yield object()

    def forbidden_write(*_args, **_kwargs):
        raise AssertionError("ambiguous descriptors must not touch the mounted bundle")

    monkeypatch.setattr(bundle_manager, "write_bundle", forbidden_write)
    assert (
        discovery_bundle_runtime._write_ready_bundles(
            settings,
            scope,
            worker_ssh_public_key_fingerprint=worker_fingerprint,
        )
        == 0
    )
    assert "bundle_descriptor_ambiguous" in caplog.text
    assert "first" not in caplog.text and "second" not in caplog.text
    assert not os.path.lexists(settings.discovery_bootstrap_mount)


def test_legacy_resolver_is_supported_but_worker_filters_exact_organization(tmp_path, monkeypatch):
    from contextlib import contextmanager

    from secp_api.services import bootstrap_discovery, worker_nodes
    from secp_worker import bundle_manager, discovery_bundle_runtime

    settings = _settings(tmp_path)
    organization_id = uuid.uuid4()
    foreign_organization_id = uuid.uuid4()
    worker_fingerprint = _worker_key_fingerprint(_pubkey("current-worker@secp"))
    descriptors = [
        {
            "organization_id": str(foreign_organization_id),
            "enrollment_id": "foreign",
            "worker_ssh_public_key_fingerprint": worker_fingerprint,
        },
        {
            "organization_id": str(organization_id),
            "enrollment_id": "local",
            "worker_ssh_public_key_fingerprint": worker_fingerprint,
        },
    ]
    # The reviewed pinned worker image carries this legacy one-argument API helper.
    monkeypatch.setattr(
        bootstrap_discovery,
        "resolve_ready_bundle_descriptors",
        lambda _session: descriptors,
    )
    monkeypatch.setattr(
        worker_nodes,
        "resolve_publication_organizations",
        lambda _session, _configured_org: [organization_id],
    )

    @contextmanager
    def scope():
        yield object()

    written: list[dict] = []
    monkeypatch.setattr(
        bundle_manager,
        "write_bundle",
        lambda descriptor, **_kwargs: written.append(descriptor),
    )

    assert (
        discovery_bundle_runtime._write_ready_bundles(
            settings,
            scope,
            worker_ssh_public_key_fingerprint=worker_fingerprint,
        )
        == 1
    )
    assert [descriptor["enrollment_id"] for descriptor in written] == ["local"]


def test_runtime_marker_lives_exactly_as_long_as_the_enabled_loop(monkeypatch):
    from secp_api import config
    from secp_worker import bundle_loop_marker, discovery_bundle_runtime

    settings = SimpleNamespace(
        discovery_worker_managed_bundle=True,
        discovery_worker_bundle_poll_seconds=15.0,
    )
    stop_event = threading.Event()
    stop_event.set()
    calls: list[str] = []
    monkeypatch.setattr(config, "get_settings", lambda: settings)
    monkeypatch.setattr(bundle_loop_marker, "mark_started", lambda: calls.append("mark"))
    monkeypatch.setattr(bundle_loop_marker, "clear_started", lambda: calls.append("clear"))

    discovery_bundle_runtime.run_forever(stop_event)

    assert calls == ["mark", "clear"]


def test_disabled_runtime_clears_stale_marker_without_preparation(monkeypatch):
    from secp_api import config
    from secp_worker import bundle_loop_marker, discovery_bundle_runtime

    settings = SimpleNamespace(discovery_worker_managed_bundle=False)
    calls: list[str] = []
    monkeypatch.setattr(config, "get_settings", lambda: settings)
    monkeypatch.setattr(bundle_loop_marker, "clear_started", lambda: calls.append("clear"))
    monkeypatch.setattr(
        discovery_bundle_runtime,
        "prepare_once",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("disabled loop must stay inert")),
    )

    discovery_bundle_runtime.run_forever(threading.Event())

    assert calls == ["clear"]


@pytest.mark.skipif(os.name != "posix", reason="strict mounted-bundle validation is POSIX-only")
def test_worker_written_bundle_passes_strict_worker_managed_validator(engine, tmp_path):
    """The closed loop: the worker's OWN output validates under the strict worker-managed mounted
    source — exactly what the live composition consumes (no more ``probe_source_sealed``)."""
    from secp_api.db import session_scope
    from secp_worker import bundle_manager
    from secp_worker.discovery_bundle_runtime import prepare_once
    from secp_worker.mounted_bundle import MountedWorkerBootstrapBundleSource

    settings = _settings(tmp_path)
    worker_public = bundle_manager.ensure_worker_keys(
        settings.discovery_worker_key_dir
    ).ssh_public_key
    _bound_enrollment(session_scope, worker_ssh_public_key=worker_public)
    prepare_once(settings=settings, session_scope=session_scope)

    src = MountedWorkerBootstrapBundleSource(
        settings.discovery_bootstrap_mount, strict=True, require_read_only_mount=False
    )
    prepared = src.prepare_metadata()
    assert prepared.endpoint.account == "secpdisc"
    src.finalize_key_material()
    assert src.acquire().ssh_host  # a usable SSH bundle was produced
    src.dispose()
