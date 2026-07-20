"""Strict, side-effect-free PR5F activation profile validation."""

from __future__ import annotations

import json

import pytest
from secp_discovery_activation import PACKAGE_CONTRACT_VERSION
from secp_discovery_activation.layout import PRODUCTION_LAYOUT
from secp_discovery_activation.profile import (
    ProfileError,
    parse_deployment_profile,
    parse_profile_bytes,
)


def _valid_raw(**overrides):  # noqa: ANN003, ANN202
    raw = {
        "contract_version": PACKAGE_CONTRACT_VERSION,
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
        "admission_proxy_image": ("registry.internal.test/secp/admission-proxy@sha256:" + "2" * 64),
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
    raw.update(overrides)
    return raw


def test_activation_is_false_by_default_and_profile_is_canonical() -> None:
    profile = parse_deployment_profile(_valid_raw())
    assert profile.activation_enabled is False
    assert str(profile.worker_node_organization) == "11111111-1111-4111-8111-111111111111"
    assert profile.canonical()["activation_enabled"] is False


def test_activation_requires_a_strict_boolean() -> None:
    with pytest.raises(ProfileError):
        parse_deployment_profile(_valid_raw(activation_enabled="true"))
    assert parse_deployment_profile(_valid_raw(activation_enabled=True)).activation_enabled is True


@pytest.mark.parametrize(
    "missing",
    [
        "controller_api_baseline_image_digest",
        "controller_api_image",
        "controller_api_runtime_image_digest",
        "worker_runtime_overlay_digest",
    ],
)
def test_enabled_activation_requires_reviewed_runtime_pins(missing: str) -> None:
    raw = _valid_raw(activation_enabled=True)
    raw.pop(missing)
    with pytest.raises(ProfileError):
        parse_deployment_profile(raw)


def test_schema_is_closed_and_secret_fields_are_refused() -> None:
    with pytest.raises(ProfileError):
        parse_deployment_profile(_valid_raw(unexpected=True))
    with pytest.raises(ProfileError) as exc:
        parse_deployment_profile(_valid_raw(server_private_key="not-even-a-key"))
    assert exc.value.reason_code == "profile_forbidden_secret"
    assert "not-even-a-key" not in repr(exc.value)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("ordinary_worker_image_digest", "1" * 64),
        ("container_runtime_executable_digest", "sha256:" + "A" * 64),
        ("compose_executable_digest", "sha256:short"),
        ("ordinary_runtime_uid", 0),
        ("ordinary_runtime_gid", 65534),
        ("admission_proxy_runtime_uid", True),
        ("admission_proxy_runtime_gid", "1002"),
    ],
)
def test_exact_digests_and_nonroot_runtime_ids_are_required(field: str, value: object) -> None:
    with pytest.raises(ProfileError):
        parse_deployment_profile(_valid_raw(**{field: value}))


@pytest.mark.parametrize(
    "organization",
    [
        "not-a-uuid",
        "00000000-0000-0000-0000-000000000000",
        "11111111111141118111111111111111",
        "11111111-1111-4111-8111-11111111111A",
    ],
)
def test_organization_must_be_a_nonzero_canonical_uuid(organization: str) -> None:
    with pytest.raises(ProfileError):
        parse_deployment_profile(_valid_raw(worker_node_organization=organization))


@pytest.mark.parametrize("label", ["", " bad", "bad label", "a" * 64, "bad/label"])
def test_worker_label_is_stable_and_bounded(label: str) -> None:
    with pytest.raises(ProfileError):
        parse_deployment_profile(_valid_raw(worker_node_label=label))


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://admission.internal.test:8443",
        "https://user@admission.internal.test:8443",
        "https://admission.internal.test:8443/path",
        "https://admission.internal.test:8443?query=yes",
        "https://admission.internal.test:0",
        "https://*.internal.test:8443",
        "https://10.20.30.40:8443",
        " HTTPS://admission.internal.test:8443",
    ],
)
def test_admission_endpoint_is_an_exact_https_dns_origin(endpoint: str) -> None:
    with pytest.raises(ProfileError):
        parse_deployment_profile(_valid_raw(admission_endpoint=endpoint))


@pytest.mark.parametrize(
    "listener",
    [
        "0.0.0.0:8443",
        "127.0.0.1:8443",
        "169.254.10.1:8443",
        "8.8.8.8:8443",
        "internal.test:8443",
        "10.20.30.40",
        "10.20.30.40:0",
        "10.020.030.040:8443",
    ],
)
def test_listener_requires_a_canonical_private_literal(listener: str) -> None:
    with pytest.raises(ProfileError):
        parse_deployment_profile(_valid_raw(admission_listener_bind=listener))


def test_endpoint_certificate_and_listener_port_must_agree() -> None:
    with pytest.raises(ProfileError):
        parse_deployment_profile(_valid_raw(admission_certificate_dns_name="other.internal.test"))
    with pytest.raises(ProfileError):
        parse_deployment_profile(_valid_raw(admission_listener_bind="10.20.30.40:9443"))


@pytest.mark.parametrize(
    "upstream",
    [
        "https://api:8080",
        "http://api",
        "http://api:0",
        "http://user@api:8080",
        "http://api:8080/path",
        "http://public.example.test:8080",
        "http://8.8.8.8:8080",
        "http://127.0.0.1:8080",
    ],
)
def test_controller_upstream_is_only_the_local_api_or_private_ip(upstream: str) -> None:
    with pytest.raises(ProfileError):
        parse_deployment_profile(_valid_raw(controller_api_upstream=upstream))


def test_private_ip_controller_upstream_cannot_bypass_exact_compose_service() -> None:
    with pytest.raises(ProfileError):
        parse_deployment_profile(_valid_raw(controller_api_upstream="http://10.20.30.41:8080"))


@pytest.mark.parametrize(
    "image",
    [
        "registry.internal.test/secp/proxy:latest",
        "registry.internal.test/secp/proxy:tag@sha256:" + "2" * 64,
        "Registry.internal.test/secp/proxy@sha256:" + "2" * 64,
        "registry.internal.test/secp/proxy@sha256:" + "Z" * 64,
    ],
)
def test_proxy_image_requires_an_exact_lowercase_digest_pin(image: str) -> None:
    with pytest.raises(ProfileError):
        parse_deployment_profile(_valid_raw(admission_proxy_image=image))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("container_runtime_executable", "docker"),
        ("compose_executable", "../docker-compose"),
        ("compose_executable", "/usr/libexec/../bin/docker-compose"),
        ("compose_executable", "/usr/libexec/./docker-compose"),
        ("compose_executable", "/usr//bin/docker-compose"),
        ("compose_executable", "/usr/bin/docker compose"),
        ("compose_executable", "/usr/libexec\\docker-compose"),
    ],
)
def test_executable_pins_use_clean_absolute_paths(field: str, value: str) -> None:
    with pytest.raises(ProfileError):
        parse_deployment_profile(_valid_raw(**{field: value}))


def test_json_parser_rejects_duplicates_invalid_utf8_and_oversize() -> None:
    body = json.dumps(_valid_raw())
    duplicate = (body[:-1] + ',"activation_enabled":true,"activation_enabled":false}').encode()
    with pytest.raises(ProfileError) as exc:
        parse_profile_bytes(duplicate)
    assert exc.value.reason_code == "profile_duplicate_key"
    with pytest.raises(ProfileError) as exc:
        parse_profile_bytes(b"\xff")
    assert exc.value.reason_code == "profile_not_utf8"
    with pytest.raises(ProfileError) as exc:
        parse_profile_bytes(b" " * (64 * 1024 + 1))
    assert exc.value.reason_code == "profile_size_invalid"


def test_production_layout_has_one_fixed_profile_and_no_input_paths() -> None:
    assert PRODUCTION_LAYOUT.profile_path == "/etc/secp/discovery-activation/profile.json"
    raw_fields = set(_valid_raw())
    assert not any("path" in field for field in raw_fields)
    for path in PRODUCTION_LAYOUT.__dict__.values():
        assert path.startswith("/")
        assert ".." not in path.split("/")
