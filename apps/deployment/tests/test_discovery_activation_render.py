"""Deterministic, non-mutating PR5F worker and admission-proxy artifact rendering."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime

import pytest
import yaml
from secp_discovery_activation import PACKAGE_CONTRACT_VERSION
from secp_discovery_activation.layout import (
    ADMISSION_PROXY_CONTAINER_PORT,
    ADMISSION_PROXY_SERVICE,
    ADMISSION_ROUTES,
    CONTROLLER_API_SERVICE,
    MAX_ADMISSION_REQUEST_BYTES,
    MAX_ADMISSION_RESPONSE_BYTES,
    ORDINARY_WORKER_SERVICE,
    PRODUCTION_LAYOUT,
)
from secp_discovery_activation.profile import parse_deployment_profile
from secp_discovery_activation.render import RenderError, render_activation
from secp_discovery_activation.tls import generate_tls_material

NOW = datetime(2026, 7, 19, 12, 0, tzinfo=UTC)


def _profile(*, enabled: bool = False):  # noqa: ANN202
    return parse_deployment_profile(
        {
            "contract_version": PACKAGE_CONTRACT_VERSION,
            "activation_enabled": enabled,
            "ordinary_worker_image_digest": "sha256:" + "1" * 64,
            "worker_runtime_overlay_digest": "sha256:" + "5" * 64,
            "ordinary_runtime_uid": 1001,
            "ordinary_runtime_gid": 1001,
            "worker_node_organization": "11111111-1111-4111-8111-111111111111",
            "worker_node_label": "site-worker-01",
            "admission_endpoint": "https://admission.internal.test:8443",
            "admission_listener_bind": "10.20.30.40:8443",
            "controller_api_upstream": "http://api:8080",
            "controller_compose_project": "secp-controller",
            "worker_compose_project": "secp-worker",
            "admission_certificate_dns_name": "admission.internal.test",
            "admission_proxy_image": (
                "registry.internal.test/secp/admission-proxy@sha256:" + "2" * 64
            ),
            "admission_proxy_runtime_image_digest": "sha256:" + "8" * 64,
            "controller_api_baseline_image_digest": "sha256:" + "7" * 64,
            "controller_api_runtime_image_digest": "sha256:" + "9" * 64,
            "controller_api_image": "registry.internal.test/secp/api@sha256:" + "6" * 64,
            "admission_proxy_runtime_uid": 1002,
            "admission_proxy_runtime_gid": 1002,
            "container_runtime_executable": "/usr/bin/docker",
            "container_runtime_executable_digest": "sha256:" + "3" * 64,
            "compose_executable": "/usr/libexec/docker/cli-plugins/docker-compose",
            "compose_executable_digest": "sha256:" + "4" * 64,
        }
    )


@pytest.fixture(scope="module")
def tls_material():  # noqa: ANN201
    return generate_tls_material(dns_identity="admission.internal.test", validity_days=30, now=NOW)


def _artifact(rendered, name: str):  # noqa: ANN001, ANN202
    return next(item for item in rendered.artifacts if item.name == name)


def test_worker_override_contains_exact_b8_environment_and_only_worker_mounts(
    tls_material,
) -> None:  # noqa: ANN001
    profile = _profile()
    rendered = render_activation(profile, tls_material.metadata)
    document = yaml.safe_load(_artifact(rendered, "worker_compose_override").content)
    assert set(document["services"]) == {ORDINARY_WORKER_SERVICE}
    worker = document["services"][ORDINARY_WORKER_SERVICE]
    assert worker["user"] == "1001:1001"
    assert "image" not in worker
    assert "command" not in worker
    assert "healthcheck" not in worker

    environment = worker["environment"]
    assert environment == {
        "SECP_DISCOVERY_CONTROLLED_INTEGRATION_ENABLED": "true",
        "SECP_DISCOVERY_WORKER_MANAGED_BUNDLE": "true",
        "SECP_DISCOVERY_WORKER_KEY_DIR": "/var/run/secp/worker-keys",
        "SECP_DISCOVERY_BOOTSTRAP_MOUNT": "/var/run/secp/discovery-bundle",
        "SECP_DISCOVERY_WORKER_IDENTITY_KEY": ("/var/run/secp/worker-keys/admission_key"),
        "SECP_DISCOVERY_WORKER_IDENTITY_ANCHOR": ("/var/run/secp/worker-keys/admission_anchor"),
        "SECP_DISCOVERY_WORKER_NODE_ORGANIZATION": ("11111111-1111-4111-8111-111111111111"),
        "SECP_DISCOVERY_WORKER_NODE_LABEL": "site-worker-01",
        "SECP_DISCOVERY_ADMISSION_ENDPOINT": "https://admission.internal.test:8443",
        "SECP_DISCOVERY_ADMISSION_CA": "/etc/secp/admission-ca.pem",
        "PYTHONPATH": PRODUCTION_LAYOUT.worker_runtime_overlay_container_path,
        "SECP_DISCOVERY_RUNTIME_OVERLAY_SHA256": "sha256:" + "5" * 64,
    }
    assert "SECP_TEMPORAL_TASK_QUEUE" not in environment
    assert "SECP_TEMPORAL_OPERATOR_TASK_QUEUE" not in environment

    assert worker["extra_hosts"] == {"admission.internal.test": "10.20.30.40"}
    state_mount, ca_mount, overlay_mount = worker["volumes"]
    assert state_mount == {
        "type": "bind",
        "source": PRODUCTION_LAYOUT.worker_state_host_path,
        "target": "/var/run/secp",
        "read_only": False,
        "bind": {"create_host_path": False},
    }
    assert ca_mount["source"] == PRODUCTION_LAYOUT.ca_certificate_path
    assert ca_mount["target"] == "/etc/secp/admission-ca.pem"
    assert ca_mount["read_only"] is True
    assert overlay_mount == {
        "type": "bind",
        "source": PRODUCTION_LAYOUT.worker_runtime_overlay_path,
        "target": PRODUCTION_LAYOUT.worker_runtime_overlay_container_path,
        "read_only": True,
        "bind": {"create_host_path": False},
    }


def test_proxy_contract_allows_only_four_exact_post_routes_and_bounds_io(tls_material) -> None:  # noqa: ANN001
    rendered = render_activation(_profile(), tls_material.metadata)
    contract = json.loads(_artifact(rendered, "admission_proxy_contract").content)
    allowed = contract["upstream"]["allowed_requests"]
    assert allowed == [{"method": "POST", "path": path} for path in ADMISSION_ROUTES]
    assert contract["upstream"]["deny_unmatched"] is True
    assert contract["upstream"]["follow_redirects"] is False
    assert contract["upstream"]["reject_upstream_redirects"] is True
    assert contract["upstream"]["trust_env"] is False
    assert contract["upstream"]["origin"] == "http://api:8080"
    assert contract["limits"]["max_request_bytes"] == MAX_ADMISSION_REQUEST_BYTES
    assert contract["limits"]["max_response_bytes"] == MAX_ADMISSION_RESPONSE_BYTES
    assert contract["limits"]["connect_timeout_seconds"] > 0
    assert contract["limits"]["request_timeout_seconds"] > 0
    assert contract["listener"]["public_exposure"] is False
    assert contract["listener"]["container_port"] == ADMISSION_PROXY_CONTAINER_PORT
    assert contract["listener"]["tls"]["ca_certificate_path"] == (
        PRODUCTION_LAYOUT.proxy_ca_certificate_container_path
    )
    assert contract["worker_authentication"] == {
        "mechanism": "ed25519-signed-nonce",
        "client_certificate_required": False,
    }
    assert contract["origin_gate"] == {
        "header_name": "X-SECP-Admission-Proxy-Gate",
        "secret_path": PRODUCTION_LAYOUT.admission_proxy_gate_container_path,
    }


def test_controller_override_is_private_pinned_and_hardened(tls_material) -> None:  # noqa: ANN001
    rendered = render_activation(_profile(), tls_material.metadata)
    artifact = _artifact(rendered, "controller_compose_override")
    document = yaml.safe_load(artifact.content)
    assert set(document["services"]) == {CONTROLLER_API_SERVICE, ADMISSION_PROXY_SERVICE}

    api = document["services"][CONTROLLER_API_SERVICE]
    assert api["image"] == "registry.internal.test/secp/api@sha256:" + "6" * 64
    assert api["environment"] == {"SECP_DISCOVERY_CONTROLLED_INTEGRATION_ENABLED": "true"}
    assert api["group_add"] == ["1002"]
    assert api["volumes"] == [
        {
            "type": "bind",
            "source": PRODUCTION_LAYOUT.admission_proxy_gate_path,
            "target": PRODUCTION_LAYOUT.admission_proxy_gate_container_path,
            "read_only": True,
            "bind": {"create_host_path": False},
        }
    ]
    proxy = document["services"][ADMISSION_PROXY_SERVICE]
    assert proxy["image"].endswith("@sha256:" + "2" * 64)
    assert proxy["user"] == "1002:1002"
    assert proxy["read_only"] is True
    assert proxy["tmpfs"] == ["/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777"]
    assert proxy["cap_drop"] == ["ALL"]
    assert proxy["security_opt"] == ["no-new-privileges:true"]
    assert proxy["pids_limit"] == 128
    assert proxy["command"] == ["/usr/local/bin/secp-admission-proxy"]
    assert proxy["ports"] == [
        {
            "target": 8443,
            "published": "8443",
            "host_ip": "10.20.30.40",
            "protocol": "tcp",
            "mode": "host",
        }
    ]
    assert set(proxy["environment"].values()) == {""}
    assert len(proxy["volumes"]) == 5
    assert all(mount["type"] == "bind" and mount["read_only"] for mount in proxy["volumes"])
    assert all(mount["bind"] == {"create_host_path": False} for mount in proxy["volumes"])
    assert any(
        mount["target"] == PRODUCTION_LAYOUT.proxy_ca_certificate_container_path
        and mount["source"] == PRODUCTION_LAYOUT.ca_certificate_path
        for mount in proxy["volumes"]
    )
    assert any(
        mount["target"] == PRODUCTION_LAYOUT.admission_proxy_gate_container_path
        and mount["source"] == PRODUCTION_LAYOUT.admission_proxy_gate_path
        for mount in proxy["volumes"]
    )
    rendered_text = artifact.text().lower()
    assert "docker.sock" not in rendered_text
    assert "privileged" not in proxy
    assert PRODUCTION_LAYOUT.worker_state_host_path not in rendered_text


def test_render_is_byte_deterministic_and_manifest_binds_every_artifact(tls_material) -> None:  # noqa: ANN001
    profile = _profile()
    first = render_activation(profile, tls_material.metadata)
    second = render_activation(profile, tls_material.metadata)
    assert [artifact.content for artifact in first.artifacts] == [
        artifact.content for artifact in second.artifacts
    ]
    assert first.manifest.canonical() == second.manifest.canonical()
    assert first.manifest.sha256 == second.manifest.sha256
    assert first.manifest.activation_enabled is False
    assert first.manifest.ordinary_worker_image_digest == "sha256:" + "1" * 64
    assert first.manifest.worker_runtime_overlay_digest == "sha256:" + "5" * 64
    assert first.manifest.controller_api_image == (
        "registry.internal.test/secp/api@sha256:" + "6" * 64
    )
    assert first.manifest.profile_sha256.startswith("sha256:")
    for artifact, entry in zip(first.artifacts, first.manifest.artifacts, strict=True):
        assert entry.sha256 == "sha256:" + hashlib.sha256(artifact.content).hexdigest()
        assert entry.size_bytes == len(artifact.content)
        assert entry.path == artifact.path
    entries = {entry.name: entry for entry in first.manifest.artifacts}
    assert entries["admission_proxy_contract"].gid == 1002
    assert entries["worker_compose_override"].gid == 0


def test_safe_manifest_and_reprs_never_contain_raw_tls_or_deployment_values(tls_material) -> None:  # noqa: ANN001
    rendered = render_activation(_profile(), tls_material.metadata)
    safe = json.dumps(rendered.manifest.canonical(), sort_keys=True)
    private_digest = hashlib.sha256(tls_material.server_private_key_pem()).hexdigest()
    ca_private_digest = hashlib.sha256(tls_material.ca_private_key_pem()).hexdigest()
    assert "BEGIN CERTIFICATE" not in safe
    assert "PRIVATE KEY" not in safe
    assert private_digest not in safe
    assert ca_private_digest not in safe
    assert "https://admission.internal.test:8443" not in safe
    assert "http://api:8080" not in safe
    assert "11111111-1111-4111-8111-111111111111" not in safe
    assert tls_material.metadata.server_certificate_fingerprint in safe
    assert tls_material.metadata.server_dns_identity in safe
    assert "admission_endpoint" not in repr(rendered)
    assert "SECP_DISCOVERY" not in repr(rendered.artifacts[0])


def test_manifest_records_explicit_activation_without_changing_render_contract(
    tls_material,
) -> None:  # noqa: ANN001
    disabled = render_activation(_profile(enabled=False), tls_material.metadata)
    enabled = render_activation(_profile(enabled=True), tls_material.metadata)
    assert disabled.manifest.activation_enabled is False
    assert enabled.manifest.activation_enabled is True
    assert [item.content for item in disabled.artifacts] == [
        item.content for item in enabled.artifacts
    ]
    assert disabled.manifest.profile_sha256 != enabled.manifest.profile_sha256


def test_render_refuses_forged_or_wrong_identity_tls_metadata(tls_material) -> None:  # noqa: ANN001
    wrong = replace(
        tls_material.metadata,
        server_dns_identity="other.internal.test",
        server_dns_sans=("other.internal.test",),
    )
    with pytest.raises(RenderError) as exc:
        render_activation(_profile(), wrong)
    assert exc.value.reason_code == "tls_metadata_identity_mismatch"


def test_render_performs_no_filesystem_or_network_io(monkeypatch, tls_material) -> None:  # noqa: ANN001
    def forbidden(*_args, **_kwargs):  # noqa: ANN002, ANN003, ANN202
        raise AssertionError("external I/O attempted")

    monkeypatch.setattr("builtins.open", forbidden)
    monkeypatch.setattr("socket.socket", forbidden)
    rendered = render_activation(_profile(), tls_material.metadata)
    assert len(rendered.artifacts) == 3
