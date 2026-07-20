"""Deterministic, side-effect-free rendering for production B8 activation.

The worker artifact is an overlay only: it deliberately omits image, command, healthcheck, and
Temporal queue so the reviewed base deployment retains them.  The controller artifact enables the
existing admission route and adds one digest-pinned, capability-free proxy service.  No rendered
service receives the Docker socket, and only the ordinary worker receives discovery state.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import yaml

from secp_discovery_activation import (
    PACKAGE_CONTRACT_VERSION,
    PACKAGE_IMPLEMENTATION_ID,
    PACKAGE_VERSION,
    DiscoveryActivationError,
)
from secp_discovery_activation.layout import (
    ADMISSION_CONNECT_TIMEOUT_SECONDS,
    ADMISSION_PROXY_CONTAINER,
    ADMISSION_PROXY_CONTAINER_PORT,
    ADMISSION_PROXY_EXECUTABLE,
    ADMISSION_PROXY_SERVICE,
    ADMISSION_REQUEST_TIMEOUT_SECONDS,
    ADMISSION_ROUTES,
    CONTROLLER_API_SERVICE,
    MAX_ADMISSION_REQUEST_BYTES,
    MAX_ADMISSION_RESPONSE_BYTES,
    ORDINARY_WORKER_SERVICE,
    PRODUCTION_LAYOUT,
    WORKER_ADMISSION_PRIVATE_KEY,
    WORKER_ADMISSION_PUBLIC_ANCHOR,
)
from secp_discovery_activation.profile import DeploymentProfile, parse_private_listener
from secp_discovery_activation.tls import TLSMaterialMetadata

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_PROXY_CONTRACT_VERSION = "secp.discovery-admission-proxy/v1alpha1"
_RENDER_MANIFEST_VERSION = "secp.discovery-activation-render/v1alpha1"


class RenderError(DiscoveryActivationError):
    """Artifact rendering was refused with a bounded reason code."""


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )


def _compose_yaml(value: dict[str, Any]) -> bytes:
    return yaml.safe_dump(
        value,
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=False,
        width=1000,
    ).encode("utf-8")


@dataclass(frozen=True, repr=False)
class RenderedArtifact:
    """One fixed-path in-memory artifact; repr exposes only safe metadata."""

    name: str
    path: str
    content: bytes = field(repr=False)
    mode: int
    uid: int
    gid: int
    sha256: str

    def __post_init__(self) -> None:
        if self.sha256 != _sha256(self.content):
            raise ValueError("rendered artifact digest mismatch")

    def __repr__(self) -> str:
        return (
            f"RenderedArtifact(name={self.name!r}, path={self.path!r}, "
            f"size={len(self.content)}, mode={oct(self.mode)!r}, sha256={self.sha256!r})"
        )

    def text(self) -> str:
        return self.content.decode("utf-8")


@dataclass(frozen=True)
class ArtifactManifestEntry:
    name: str
    path: str
    sha256: str
    size_bytes: int
    mode: int
    uid: int
    gid: int

    def canonical(self) -> dict[str, object]:
        return {
            "name": self.name,
            "path": self.path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "mode": self.mode,
            "uid": self.uid,
            "gid": self.gid,
        }


@dataclass(frozen=True, repr=False)
class SafeRenderManifest:
    """Secret-free content bindings for rendered artifacts and validated TLS identity."""

    schema: str
    package_contract_version: str
    package_version: str
    package_implementation_id: str
    activation_enabled: bool
    profile_sha256: str
    ordinary_worker_image_digest: str
    worker_runtime_overlay_digest: str | None
    controller_api_image: str | None
    artifacts: tuple[ArtifactManifestEntry, ...]
    tls: TLSMaterialMetadata

    def canonical(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "package_contract_version": self.package_contract_version,
            "package_version": self.package_version,
            "package_implementation_id": self.package_implementation_id,
            "activation_enabled": self.activation_enabled,
            "profile_sha256": self.profile_sha256,
            "ordinary_worker_image_digest": self.ordinary_worker_image_digest,
            "worker_runtime_overlay_digest": self.worker_runtime_overlay_digest,
            "controller_api_image": self.controller_api_image,
            "artifacts": [entry.canonical() for entry in self.artifacts],
            "tls": self.tls.canonical(),
        }

    @property
    def sha256(self) -> str:
        return _sha256(_canonical_json(self.canonical()))

    def __repr__(self) -> str:
        return (
            f"SafeRenderManifest(schema={self.schema!r}, artifacts={len(self.artifacts)}, "
            f"sha256={self.sha256!r})"
        )


@dataclass(frozen=True, repr=False)
class ActivationRender:
    artifacts: tuple[RenderedArtifact, ...]
    manifest: SafeRenderManifest

    def __repr__(self) -> str:
        return (
            f"ActivationRender(artifacts={len(self.artifacts)}, "
            f"manifest_sha256={self.manifest.sha256!r})"
        )


def _artifact(*, name: str, path: str, content: bytes, mode: int, gid: int = 0) -> RenderedArtifact:
    return RenderedArtifact(
        name=name,
        path=path,
        content=content,
        mode=mode,
        uid=0,
        gid=gid,
        sha256=_sha256(content),
    )


def _require_profile(profile: DeploymentProfile) -> None:
    if type(profile) is not DeploymentProfile:
        raise RenderError("profile_type_invalid")


def _require_tls_metadata(profile: DeploymentProfile, metadata: TLSMaterialMetadata) -> None:
    if type(metadata) is not TLSMaterialMetadata:
        raise RenderError("tls_metadata_type_invalid")
    if (
        not _DIGEST.fullmatch(metadata.ca_certificate_fingerprint)
        or not _DIGEST.fullmatch(metadata.server_certificate_fingerprint)
        or not _DIGEST.fullmatch(metadata.server_public_key_fingerprint)
    ):
        raise RenderError("tls_metadata_fingerprint_invalid")
    if (
        metadata.server_dns_identity != profile.admission_certificate_dns_name
        or metadata.server_dns_sans != (profile.admission_certificate_dns_name,)
    ):
        raise RenderError("tls_metadata_identity_mismatch")
    if not (
        metadata.ca_certificate_present
        and metadata.server_certificate_present
        and metadata.server_private_key_present
    ):
        raise RenderError("tls_material_incomplete")
    if any(
        type(value) is not bool
        for value in (
            metadata.ca_certificate_present,
            metadata.server_certificate_present,
            metadata.server_private_key_present,
            metadata.ca_private_key_present,
        )
    ):
        raise RenderError("tls_metadata_presence_invalid")
    try:
        ca_before = datetime.fromisoformat(metadata.ca_not_before.replace("Z", "+00:00"))
        ca_after = datetime.fromisoformat(metadata.ca_not_after.replace("Z", "+00:00"))
        server_before = datetime.fromisoformat(metadata.server_not_before.replace("Z", "+00:00"))
        server_after = datetime.fromisoformat(metadata.server_not_after.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        raise RenderError("tls_metadata_validity_invalid") from None
    if (
        any(
            value.utcoffset() is None
            for value in (ca_before, ca_after, server_before, server_after)
        )
        or not ca_before <= server_before < server_after <= ca_after
    ):
        raise RenderError("tls_metadata_validity_invalid")


def render_worker_compose_override(profile: DeploymentProfile) -> RenderedArtifact:
    """Render the worker-only state/CA mounts and the exact ten B8 deployment settings."""
    _require_profile(profile)
    environment = {
        # Exactly the six code-owned B8 activation settings.
        "SECP_DISCOVERY_CONTROLLED_INTEGRATION_ENABLED": "true",
        "SECP_DISCOVERY_WORKER_MANAGED_BUNDLE": "true",
        "SECP_DISCOVERY_WORKER_KEY_DIR": PRODUCTION_LAYOUT.worker_keys_container_path,
        "SECP_DISCOVERY_BOOTSTRAP_MOUNT": PRODUCTION_LAYOUT.discovery_bundle_container_path,
        "SECP_DISCOVERY_WORKER_IDENTITY_KEY": WORKER_ADMISSION_PRIVATE_KEY,
        "SECP_DISCOVERY_WORKER_IDENTITY_ANCHOR": WORKER_ADMISSION_PUBLIC_ANCHOR,
        # Deployment-local non-secret bindings.
        "SECP_DISCOVERY_WORKER_NODE_ORGANIZATION": str(profile.worker_node_organization),
        "SECP_DISCOVERY_WORKER_NODE_LABEL": profile.worker_node_label,
        "SECP_DISCOVERY_ADMISSION_ENDPOINT": profile.admission_endpoint,
        "SECP_DISCOVERY_ADMISSION_CA": PRODUCTION_LAYOUT.worker_ca_container_path,
    }
    volumes: list[dict[str, Any]] = [
        {
            "type": "bind",
            "source": PRODUCTION_LAYOUT.worker_state_host_path,
            "target": PRODUCTION_LAYOUT.worker_state_container_path,
            "read_only": False,
            "bind": {"create_host_path": False},
        },
        {
            "type": "bind",
            "source": PRODUCTION_LAYOUT.ca_certificate_path,
            "target": PRODUCTION_LAYOUT.worker_ca_container_path,
            "read_only": True,
            "bind": {"create_host_path": False},
        },
    ]
    if profile.worker_runtime_overlay_digest is not None:
        # The exact old worker image remains the base image, while this reviewed content-addressed
        # ZIP supplies one internally consistent PR5F secp_api+secp_worker import closure.  The
        # fixed PYTHONPATH contains no caller-selected path and the archive is mounted read-only.
        environment["PYTHONPATH"] = PRODUCTION_LAYOUT.worker_runtime_overlay_container_path
        environment["SECP_DISCOVERY_RUNTIME_OVERLAY_SHA256"] = profile.worker_runtime_overlay_digest
        volumes.append(
            {
                "type": "bind",
                "source": PRODUCTION_LAYOUT.worker_runtime_overlay_path,
                "target": PRODUCTION_LAYOUT.worker_runtime_overlay_container_path,
                "read_only": True,
                "bind": {"create_host_path": False},
            }
        )
    document: dict[str, Any] = {
        "services": {
            ORDINARY_WORKER_SERVICE: {
                "user": f"{profile.ordinary_runtime_uid}:{profile.ordinary_runtime_gid}",
                "environment": environment,
                "extra_hosts": {
                    profile.admission_certificate_dns_name: parse_private_listener(
                        profile.admission_listener_bind
                    )[0]
                },
                "volumes": volumes,
            }
        }
    }
    return _artifact(
        name="worker_compose_override",
        path=PRODUCTION_LAYOUT.worker_compose_override_path,
        content=_compose_yaml(document),
        mode=0o640,
    )


def render_proxy_contract(
    profile: DeploymentProfile, metadata: TLSMaterialMetadata
) -> RenderedArtifact:
    """Render the closed reverse-proxy contract consumed by the pinned proxy image."""
    _require_profile(profile)
    _require_tls_metadata(profile, metadata)
    _listener_host, published_port = parse_private_listener(profile.admission_listener_bind)
    contract = {
        "schema": _PROXY_CONTRACT_VERSION,
        "listener": {
            "container_port": ADMISSION_PROXY_CONTAINER_PORT,
            "published_port": published_port,
            "public_exposure": False,
            "tls": {
                "ca_certificate_path": PRODUCTION_LAYOUT.proxy_ca_certificate_container_path,
                "certificate_path": PRODUCTION_LAYOUT.proxy_server_certificate_container_path,
                "private_key_path": PRODUCTION_LAYOUT.proxy_server_private_key_container_path,
                "expected_dns_identity": profile.admission_certificate_dns_name,
                "certificate_fingerprint": metadata.server_certificate_fingerprint,
                "minimum_tls_version": "TLSv1.2",
            },
        },
        "upstream": {
            "origin": profile.controller_api_upstream,
            "allowed_requests": [{"method": "POST", "path": path} for path in ADMISSION_ROUTES],
            "deny_unmatched": True,
            "required_request_content_type": "application/json",
            "required_response_content_type": "application/json",
            "follow_redirects": False,
            "reject_upstream_redirects": True,
            "trust_env": False,
        },
        "limits": {
            "max_request_bytes": MAX_ADMISSION_REQUEST_BYTES,
            "max_response_bytes": MAX_ADMISSION_RESPONSE_BYTES,
            "connect_timeout_seconds": ADMISSION_CONNECT_TIMEOUT_SECONDS,
            "request_timeout_seconds": ADMISSION_REQUEST_TIMEOUT_SECONDS,
        },
        "worker_authentication": {
            "mechanism": "ed25519-signed-nonce",
            "client_certificate_required": False,
        },
        "origin_gate": {
            "header_name": "X-SECP-Admission-Proxy-Gate",
            "secret_path": PRODUCTION_LAYOUT.admission_proxy_gate_container_path,
        },
    }
    return _artifact(
        name="admission_proxy_contract",
        path=PRODUCTION_LAYOUT.proxy_contract_path,
        content=_canonical_json(contract),
        mode=0o640,
        gid=profile.admission_proxy_runtime_gid,
    )


def render_controller_compose_override(profile: DeploymentProfile) -> RenderedArtifact:
    """Render API enablement plus the hardened digest-pinned admission proxy service."""
    _require_profile(profile)
    listener_host, published_port = parse_private_listener(profile.admission_listener_bind)
    proxy_service: dict[str, Any] = {
        "image": profile.admission_proxy_image,
        "container_name": ADMISSION_PROXY_CONTAINER,
        "user": f"{profile.admission_proxy_runtime_uid}:{profile.admission_proxy_runtime_gid}",
        "command": [ADMISSION_PROXY_EXECUTABLE],
        "depends_on": {CONTROLLER_API_SERVICE: {"condition": "service_started"}},
        "restart": "unless-stopped",
        "read_only": True,
        "tmpfs": ["/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777"],
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "init": True,
        "pids_limit": 128,
        "environment": {
            "HTTP_PROXY": "",
            "HTTPS_PROXY": "",
            "ALL_PROXY": "",
            "NO_PROXY": "",
            "http_proxy": "",
            "https_proxy": "",
            "all_proxy": "",
            "no_proxy": "",
        },
        "ports": [
            {
                "target": ADMISSION_PROXY_CONTAINER_PORT,
                "published": str(published_port),
                "host_ip": listener_host,
                "protocol": "tcp",
                "mode": "host",
            }
        ],
        "volumes": [
            {
                "type": "bind",
                "source": PRODUCTION_LAYOUT.proxy_contract_path,
                "target": PRODUCTION_LAYOUT.proxy_contract_container_path,
                "read_only": True,
                "bind": {"create_host_path": False},
            },
            {
                "type": "bind",
                "source": PRODUCTION_LAYOUT.ca_certificate_path,
                "target": PRODUCTION_LAYOUT.proxy_ca_certificate_container_path,
                "read_only": True,
                "bind": {"create_host_path": False},
            },
            {
                "type": "bind",
                "source": PRODUCTION_LAYOUT.server_certificate_path,
                "target": PRODUCTION_LAYOUT.proxy_server_certificate_container_path,
                "read_only": True,
                "bind": {"create_host_path": False},
            },
            {
                "type": "bind",
                "source": PRODUCTION_LAYOUT.server_private_key_path,
                "target": PRODUCTION_LAYOUT.proxy_server_private_key_container_path,
                "read_only": True,
                "bind": {"create_host_path": False},
            },
            {
                "type": "bind",
                "source": PRODUCTION_LAYOUT.admission_proxy_gate_path,
                "target": PRODUCTION_LAYOUT.admission_proxy_gate_container_path,
                "read_only": True,
                "bind": {"create_host_path": False},
            },
        ],
    }
    document: dict[str, Any] = {
        "services": {
            CONTROLLER_API_SERVICE: {
                **({"image": profile.controller_api_image} if profile.controller_api_image else {}),
                "environment": {"SECP_DISCOVERY_CONTROLLED_INTEGRATION_ENABLED": "true"},
                "group_add": [str(profile.admission_proxy_runtime_gid)],
                "volumes": [
                    {
                        "type": "bind",
                        "source": PRODUCTION_LAYOUT.admission_proxy_gate_path,
                        "target": PRODUCTION_LAYOUT.admission_proxy_gate_container_path,
                        "read_only": True,
                        "bind": {"create_host_path": False},
                    }
                ],
            },
            ADMISSION_PROXY_SERVICE: proxy_service,
        }
    }
    return _artifact(
        name="controller_compose_override",
        path=PRODUCTION_LAYOUT.controller_compose_override_path,
        content=_compose_yaml(document),
        mode=0o640,
    )


def render_activation(
    profile: DeploymentProfile, tls_metadata: TLSMaterialMetadata
) -> ActivationRender:
    """Render all non-secret activation artifacts and their safe deterministic manifest."""
    _require_profile(profile)
    _require_tls_metadata(profile, tls_metadata)
    artifacts = (
        render_worker_compose_override(profile),
        render_proxy_contract(profile, tls_metadata),
        render_controller_compose_override(profile),
    )
    entries = tuple(
        ArtifactManifestEntry(
            name=artifact.name,
            path=artifact.path,
            sha256=artifact.sha256,
            size_bytes=len(artifact.content),
            mode=artifact.mode,
            uid=artifact.uid,
            gid=artifact.gid,
        )
        for artifact in artifacts
    )
    manifest = SafeRenderManifest(
        schema=_RENDER_MANIFEST_VERSION,
        package_contract_version=PACKAGE_CONTRACT_VERSION,
        package_version=PACKAGE_VERSION,
        package_implementation_id=PACKAGE_IMPLEMENTATION_ID,
        activation_enabled=profile.activation_enabled,
        profile_sha256=_sha256(_canonical_json(profile.canonical())),
        ordinary_worker_image_digest=profile.ordinary_worker_image_digest,
        worker_runtime_overlay_digest=profile.worker_runtime_overlay_digest,
        controller_api_image=profile.controller_api_image,
        artifacts=entries,
        tls=tls_metadata,
    )
    return ActivationRender(artifacts=artifacts, manifest=manifest)


__all__ = [
    "RenderError",
    "RenderedArtifact",
    "ArtifactManifestEntry",
    "SafeRenderManifest",
    "ActivationRender",
    "render_worker_compose_override",
    "render_proxy_contract",
    "render_controller_compose_override",
    "render_activation",
]
