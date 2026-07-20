"""Strict, secret-free deployment-local profile for production B8 activation.

The module parses bytes or already-decoded objects only.  It performs no file read, DNS lookup,
socket operation, or other host observation.  Production callers read the single fixed path from
``layout.PRODUCTION_LAYOUT`` through their hardened filesystem adapter.
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator, model_validator
from secp_commissioning.descriptor import scan_forbidden

from secp_discovery_activation import PACKAGE_CONTRACT_VERSION, DiscoveryActivationError
from secp_discovery_activation.layout import CONTROLLER_API_CONTAINER_PORT, CONTROLLER_API_SERVICE

MAX_PROFILE_BYTES = 64 * 1024
_MAX_UID = 65533
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
_COMPOSE_PROJECT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_ABSOLUTE_PATH = re.compile(r"^/[A-Za-z0-9._/+:-]{1,254}$")


class ProfileError(DiscoveryActivationError):
    """The activation profile failed closed without echoing deployment-local values."""


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


def validate_dns_identity(value: str) -> str:
    """Return a canonical exact DNS identity or raise ``ValueError`` without DNS resolution."""
    if not isinstance(value, str) or value != value.strip() or value != value.lower():
        raise ValueError("DNS identity must be canonical lowercase text")
    if not (1 <= len(value) <= 253) or value.endswith(".") or "*" in value:
        raise ValueError("DNS identity has an invalid shape")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError("DNS identity must not be an IP literal")
    labels = value.split(".")
    if len(labels) < 2 or any(not _DNS_LABEL.fullmatch(label) for label in labels):
        raise ValueError("DNS identity must be a fully-qualified DNS name")
    return value


def parse_https_endpoint(value: str) -> tuple[str, str, int]:
    """Validate a strict HTTPS origin and return ``(canonical, host, effective_port)``."""
    if not isinstance(value, str) or value != value.strip() or len(value) > 320:
        raise ValueError("admission endpoint is not canonical")
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        raise ValueError("admission endpoint is malformed") from None
    if parts.scheme != "https":
        raise ValueError("admission endpoint must use HTTPS")
    if parts.username is not None or parts.password is not None:
        raise ValueError("admission endpoint userinfo is forbidden")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ValueError("admission endpoint must be an origin")
    if not parts.hostname:
        raise ValueError("admission endpoint host is required")
    host = validate_dns_identity(parts.hostname)
    effective_port = port if port is not None else 443
    if not (1 <= effective_port <= 65535):
        raise ValueError("admission endpoint port is invalid")
    netloc = host if port is None else f"{host}:{port}"
    canonical = f"https://{netloc}"
    if value.rstrip("/") != canonical:
        raise ValueError("admission endpoint is not canonical")
    return canonical, host, effective_port


def parse_private_listener(value: str) -> tuple[str, int]:
    """Validate ``private-IP:port`` (or ``[private-v6]:port``), without DNS resolution."""
    if not isinstance(value, str) or value != value.strip() or not value:
        raise ValueError("listener bind is invalid")
    try:
        parts = urlsplit("//" + value)
        port = parts.port
        host = parts.hostname
    except ValueError:
        raise ValueError("listener bind is invalid") from None
    if parts.username is not None or parts.password is not None or parts.path not in ("",):
        raise ValueError("listener bind is invalid")
    if not host or port is None:
        raise ValueError("listener bind requires an address and port")
    if not (1 <= port <= 65535):
        raise ValueError("listener bind port is invalid")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        raise ValueError("listener bind must use a private IP literal") from None
    if (
        not address.is_private
        or address.is_unspecified
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or getattr(address, "ipv4_mapped", None) is not None
    ):
        raise ValueError("listener bind must use a private non-loopback IP")
    canonical_host = address.compressed
    canonical = f"[{canonical_host}]:{port}" if address.version == 6 else f"{canonical_host}:{port}"
    if value != canonical:
        raise ValueError("listener bind is not canonical")
    return canonical_host, port


def parse_controller_upstream(value: str) -> tuple[str, str, int]:
    """Validate the exact code-owned Compose API service origin."""
    if not isinstance(value, str) or value != value.strip() or len(value) > 320:
        raise ValueError("controller upstream is invalid")
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        raise ValueError("controller upstream is malformed") from None
    if parts.scheme != "http" or port is None:
        raise ValueError("controller upstream must be explicit local HTTP")
    if not (1 <= port <= 65535):
        raise ValueError("controller upstream port is invalid")
    if parts.username is not None or parts.password is not None:
        raise ValueError("controller upstream userinfo is forbidden")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ValueError("controller upstream must be an origin")
    host = parts.hostname
    if not host:
        raise ValueError("controller upstream host is required")
    if host != CONTROLLER_API_SERVICE or port != CONTROLLER_API_CONTAINER_PORT:
        raise ValueError("controller upstream must be the exact API service origin")
    canonical_host = f"[{host}]" if ":" in host else host
    canonical = f"http://{canonical_host}:{port}"
    if value.rstrip("/") != canonical:
        raise ValueError("controller upstream is not canonical")
    return canonical, host, port


def _validate_digest(value: str) -> str:
    if not _SHA256.fullmatch(value):
        raise ValueError("expected a sha256 content digest")
    return value


def _validate_pinned_image(value: str) -> str:
    if not isinstance(value, str) or not (1 <= len(value) <= 320):
        raise ValueError("proxy image pin is invalid")
    if value != value.strip() or value != value.lower() or any(ch.isspace() for ch in value):
        raise ValueError("proxy image pin is invalid")
    if value.count("@sha256:") != 1:
        raise ValueError("proxy image must be pinned by digest")
    repository, digest_hex = value.rsplit("@sha256:", 1)
    if not re.fullmatch(r"[0-9a-f]{64}", digest_hex):
        raise ValueError("proxy image digest is invalid")
    if not re.fullmatch(r"[a-z0-9][a-z0-9._/:-]*[a-z0-9]", repository):
        raise ValueError("proxy image repository is invalid")
    segments = repository.split("/")
    if (
        any(not segment or segment in {".", ".."} for segment in segments)
        or ".." in repository
        or ":" in segments[-1]
    ):
        raise ValueError("proxy image tag is forbidden")
    if ":" in segments[0]:
        registry, registry_port = segments[0].rsplit(":", 1)
        if not registry or not registry_port.isdigit() or not (1 <= int(registry_port) <= 65535):
            raise ValueError("proxy image registry port is invalid")
    return value


class DeploymentProfile(_StrictModel):
    """Secret-free deployment identities required to render and later verify activation."""

    contract_version: str
    activation_enabled: bool = False

    ordinary_worker_image_digest: str
    worker_runtime_overlay_digest: str | None = None
    ordinary_runtime_uid: int
    ordinary_runtime_gid: int

    worker_node_organization: UUID
    worker_node_label: str

    admission_endpoint: str
    admission_listener_bind: str
    controller_api_upstream: str
    controller_compose_project: str
    worker_compose_project: str
    admission_certificate_dns_name: str

    admission_proxy_image: str
    admission_proxy_runtime_image_digest: str
    controller_api_image: str | None = None
    controller_api_runtime_image_digest: str | None = None
    controller_api_baseline_image_digest: str | None = None
    admission_proxy_runtime_uid: int
    admission_proxy_runtime_gid: int

    # Deployment-coordination trust pins.  The corresponding public key may travel with a signed
    # handoff, but it is trusted only when its digest matches this independently reviewed profile.
    # They are optional while activation is disabled so key preparation can precede final review;
    # every split-host install requires both.
    controller_evidence_key_id: str | None = None
    worker_evidence_key_id: str | None = None

    container_runtime_executable: str
    container_runtime_executable_digest: str
    compose_executable: str
    compose_executable_digest: str

    @field_validator("contract_version")
    @classmethod
    def _v_contract(cls, value: str) -> str:
        if value != PACKAGE_CONTRACT_VERSION:
            raise ValueError("unexpected activation profile contract")
        return value

    @field_validator(
        "ordinary_worker_image_digest",
        "worker_runtime_overlay_digest",
        "admission_proxy_runtime_image_digest",
        "controller_api_runtime_image_digest",
        "controller_api_baseline_image_digest",
        "container_runtime_executable_digest",
        "compose_executable_digest",
    )
    @classmethod
    def _v_digest(cls, value: str | None) -> str | None:
        return _validate_digest(value) if value is not None else None

    @field_validator("controller_evidence_key_id", "worker_evidence_key_id")
    @classmethod
    def _v_evidence_key_id(cls, value: str | None) -> str | None:
        return _validate_digest(value) if value is not None else None

    @field_validator(
        "ordinary_runtime_uid",
        "ordinary_runtime_gid",
        "admission_proxy_runtime_uid",
        "admission_proxy_runtime_gid",
    )
    @classmethod
    def _v_runtime_id(cls, value: int) -> int:
        if isinstance(value, bool) or not (1 <= value <= _MAX_UID):
            raise ValueError("runtime identity must be non-root and bounded")
        return value

    @field_validator("worker_node_label")
    @classmethod
    def _v_label(cls, value: str) -> str:
        if not _LABEL.fullmatch(value):
            raise ValueError("worker node label is invalid")
        return value

    @field_validator("controller_compose_project", "worker_compose_project")
    @classmethod
    def _v_compose_project(cls, value: str) -> str:
        if not _COMPOSE_PROJECT.fullmatch(value):
            raise ValueError("Compose project name is invalid")
        return value

    @field_validator("worker_node_organization", mode="before")
    @classmethod
    def _v_organization(cls, value: object) -> object:
        # JSON has no UUID scalar. Accept only its exact canonical lowercase text form, then hand a
        # real UUID to pydantic's otherwise-strict model.
        if isinstance(value, str):
            try:
                parsed = UUID(value)
            except ValueError:
                raise ValueError("worker organization UUID is invalid") from None
            if str(parsed) != value or parsed.int == 0:
                raise ValueError("worker organization UUID is not canonical")
            return parsed
        return value

    @field_validator("admission_endpoint")
    @classmethod
    def _v_endpoint(cls, value: str) -> str:
        return parse_https_endpoint(value)[0]

    @field_validator("admission_listener_bind")
    @classmethod
    def _v_listener(cls, value: str) -> str:
        parse_private_listener(value)
        return value

    @field_validator("controller_api_upstream")
    @classmethod
    def _v_upstream(cls, value: str) -> str:
        return parse_controller_upstream(value)[0]

    @field_validator("admission_certificate_dns_name")
    @classmethod
    def _v_certificate_identity(cls, value: str) -> str:
        return validate_dns_identity(value)

    @field_validator("admission_proxy_image", "controller_api_image")
    @classmethod
    def _v_pinned_image(cls, value: str | None) -> str | None:
        return _validate_pinned_image(value) if value is not None else None

    @field_validator("container_runtime_executable", "compose_executable")
    @classmethod
    def _v_executable(cls, value: str) -> str:
        segments = value.split("/")
        if not _ABSOLUTE_PATH.fullmatch(value) or any(
            segment in {"", ".", ".."} for segment in segments[1:]
        ):
            raise ValueError("executable must be a clean absolute path")
        return value

    @model_validator(mode="after")
    def _v_endpoint_listener_identity_agreement(self) -> DeploymentProfile:
        _endpoint, endpoint_host, endpoint_port = parse_https_endpoint(self.admission_endpoint)
        _listener_host, listener_port = parse_private_listener(self.admission_listener_bind)
        if endpoint_host != self.admission_certificate_dns_name:
            raise ValueError("admission endpoint and certificate identity disagree")
        if endpoint_port != listener_port:
            raise ValueError("admission endpoint and private listener ports disagree")
        if self.activation_enabled and (
            self.controller_api_image is None
            or self.controller_api_runtime_image_digest is None
            or self.controller_api_baseline_image_digest is None
            or self.worker_runtime_overlay_digest is None
        ):
            raise ValueError(
                "enabled activation requires reviewed baseline, API, and worker runtime pins"
            )
        return self

    def canonical(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


def parse_deployment_profile(raw: object) -> DeploymentProfile:
    """Validate an already parsed profile and surface bounded reason codes only."""
    if not isinstance(raw, dict):
        raise ProfileError("profile_not_object")
    try:
        scan_forbidden(raw)
    except Exception:
        raise ProfileError("profile_forbidden_secret") from None
    try:
        return DeploymentProfile.model_validate(raw)
    except ValidationError as exc:
        errors = exc.errors()
        location = errors[0].get("loc", ()) if errors else ()
        field = ".".join(str(part) for part in location if isinstance(part, str)) or "profile"
        safe_field = re.sub(r"[^A-Za-z0-9_.]", "", field)[:60]
        raise ProfileError("profile_invalid:" + safe_field) from None


class _DuplicateKey(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey()
        result[key] = value
    return result


def parse_profile_bytes(raw_bytes: bytes) -> DeploymentProfile:
    """Decode bounded UTF-8 JSON, rejecting duplicate keys at every nesting level."""
    if not isinstance(raw_bytes, bytes) or len(raw_bytes) > MAX_PROFILE_BYTES:
        raise ProfileError("profile_size_invalid")
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise ProfileError("profile_not_utf8") from None
    try:
        raw = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except _DuplicateKey:
        raise ProfileError("profile_duplicate_key") from None
    except ValueError:
        raise ProfileError("profile_not_json") from None
    return parse_deployment_profile(raw)


__all__ = [
    "MAX_PROFILE_BYTES",
    "ProfileError",
    "DeploymentProfile",
    "parse_deployment_profile",
    "parse_profile_bytes",
    "parse_https_endpoint",
    "parse_private_listener",
    "parse_controller_upstream",
    "validate_dns_identity",
]
