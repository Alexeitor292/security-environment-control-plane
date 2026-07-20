"""Closed internal HTTPS reverse proxy for worker-discovery admission.

This executable has one fixed configuration path, one fixed TLS port, four exact POST routes, and
one validated controller-API upstream.  It has no generic forwarding, shell, path, trust-store, or
TLS-disable option.  Request/response bodies and all timeouts are bounded; redirects and ambient
proxy settings are rejected.  Importing this module or constructing the ASGI application performs
no filesystem access or network contact.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import ssl
import stat
from dataclasses import dataclass, field
from typing import Annotated

import httpx
import uvicorn
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from secp_discovery_activation import DiscoveryActivationError
from secp_discovery_activation.layout import (
    ADMISSION_CONNECT_TIMEOUT_SECONDS,
    ADMISSION_PROXY_CONTAINER_PORT,
    ADMISSION_REQUEST_TIMEOUT_SECONDS,
    ADMISSION_ROUTES,
    MAX_ADMISSION_REQUEST_BYTES,
    MAX_ADMISSION_RESPONSE_BYTES,
    PRODUCTION_LAYOUT,
)
from secp_discovery_activation.profile import parse_controller_upstream, validate_dns_identity
from secp_discovery_activation.tls import import_tls_material

_CONTRACT_VERSION = "secp.discovery-admission-proxy/v1alpha1"
_MAX_CONTRACT_BYTES = 64 * 1024
_MAX_CERTIFICATE_BYTES = 32 * 1024
_MAX_SERVER_KEY_BYTES = 64 * 1024
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_GATE_SECRET = re.compile(rb"^[0-9a-f]{64}\n$")
_GATE_HEADER = "X-SECP-Admission-Proxy-Gate"
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)


class AdmissionProxyError(DiscoveryActivationError):
    """Proxy setup was refused with a bounded reason code."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class _TLSContract(_Strict):
    certificate_path: str
    private_key_path: str
    ca_certificate_path: str
    expected_dns_identity: str
    certificate_fingerprint: str
    minimum_tls_version: str

    @model_validator(mode="after")
    def _v_tls(self) -> _TLSContract:
        if self.certificate_path != PRODUCTION_LAYOUT.proxy_server_certificate_container_path:
            raise ValueError("certificate path invalid")
        if self.private_key_path != PRODUCTION_LAYOUT.proxy_server_private_key_container_path:
            raise ValueError("server key path invalid")
        if self.ca_certificate_path != PRODUCTION_LAYOUT.proxy_ca_certificate_container_path:
            raise ValueError("CA path invalid")
        if self.minimum_tls_version != "TLSv1.2":
            raise ValueError("minimum TLS version invalid")
        if not _DIGEST.fullmatch(self.certificate_fingerprint):
            raise ValueError("certificate fingerprint invalid")
        try:
            validate_dns_identity(self.expected_dns_identity)
        except ValueError:
            raise ValueError("certificate identity invalid") from None
        return self


class _ListenerContract(_Strict):
    container_port: Annotated[int, Field(ge=1, le=65535, strict=True)]
    published_port: Annotated[int, Field(ge=1, le=65535, strict=True)]
    public_exposure: bool
    tls: _TLSContract

    @model_validator(mode="after")
    def _v_listener(self) -> _ListenerContract:
        if (
            self.container_port != ADMISSION_PROXY_CONTAINER_PORT
            or self.public_exposure is not False
        ):
            raise ValueError("listener topology invalid")
        return self


class _AllowedRequest(_Strict):
    method: str
    path: str


class _UpstreamContract(_Strict):
    origin: str
    allowed_requests: tuple[_AllowedRequest, ...]
    deny_unmatched: bool
    required_request_content_type: str
    required_response_content_type: str
    follow_redirects: bool
    reject_upstream_redirects: bool
    trust_env: bool

    @field_validator("allowed_requests", mode="before")
    @classmethod
    def _v_tuple(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _v_upstream(self) -> _UpstreamContract:
        try:
            canonical = parse_controller_upstream(self.origin)[0]
        except ValueError:
            raise ValueError("upstream origin invalid") from None
        if canonical != self.origin:
            raise ValueError("upstream origin invalid")
        allowed = tuple((item.method, item.path) for item in self.allowed_requests)
        if allowed != tuple(("POST", path) for path in ADMISSION_ROUTES):
            raise ValueError("route allowlist invalid")
        if (
            self.deny_unmatched is not True
            or self.required_request_content_type != "application/json"
            or self.required_response_content_type != "application/json"
            or self.follow_redirects is not False
            or self.reject_upstream_redirects is not True
            or self.trust_env is not False
        ):
            raise ValueError("upstream safety posture invalid")
        return self


class _LimitsContract(_Strict):
    max_request_bytes: Annotated[int, Field(ge=1, le=1024 * 1024, strict=True)]
    max_response_bytes: Annotated[int, Field(ge=1, le=1024 * 1024, strict=True)]
    connect_timeout_seconds: Annotated[int, Field(ge=1, le=60, strict=True)]
    request_timeout_seconds: Annotated[int, Field(ge=1, le=60, strict=True)]

    @model_validator(mode="after")
    def _v_limits(self) -> _LimitsContract:
        if (
            self.max_request_bytes != MAX_ADMISSION_REQUEST_BYTES
            or self.max_response_bytes != MAX_ADMISSION_RESPONSE_BYTES
            or self.connect_timeout_seconds != ADMISSION_CONNECT_TIMEOUT_SECONDS
            or self.request_timeout_seconds != ADMISSION_REQUEST_TIMEOUT_SECONDS
        ):
            raise ValueError("proxy limits invalid")
        return self


class _AuthenticationContract(_Strict):
    mechanism: str
    client_certificate_required: bool

    @model_validator(mode="after")
    def _v_authentication(self) -> _AuthenticationContract:
        if (
            self.mechanism != "ed25519-signed-nonce"
            or self.client_certificate_required is not False
        ):
            raise ValueError("worker authentication contract invalid")
        return self


class _OriginGateContract(_Strict):
    header_name: str
    secret_path: str

    @model_validator(mode="after")
    def _v_origin_gate(self) -> _OriginGateContract:
        if (
            self.header_name != _GATE_HEADER
            or self.secret_path != PRODUCTION_LAYOUT.admission_proxy_gate_container_path
        ):
            raise ValueError("origin gate contract invalid")
        return self


class AdmissionProxyContract(_Strict):
    schema_version: str = Field(alias="schema")
    listener: _ListenerContract
    upstream: _UpstreamContract
    limits: _LimitsContract
    worker_authentication: _AuthenticationContract
    origin_gate: _OriginGateContract

    @field_validator("schema_version")
    @classmethod
    def _v_schema(cls, value: str) -> str:
        if value != _CONTRACT_VERSION:
            raise ValueError("proxy contract version invalid")
        return value


class _DuplicateKey(ValueError):
    pass


def _reject_duplicate_keys(items: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in items:
        if key in result:
            raise _DuplicateKey()
        result[key] = value
    return result


def parse_proxy_contract_bytes(raw: bytes) -> AdmissionProxyContract:
    """Strict bounded parser for the renderer-owned contract."""

    if not isinstance(raw, bytes) or not (1 <= len(raw) <= _MAX_CONTRACT_BYTES):
        raise AdmissionProxyError("proxy_contract_size_invalid")
    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except _DuplicateKey:
        raise AdmissionProxyError("proxy_contract_duplicate_key") from None
    except (UnicodeDecodeError, ValueError):
        raise AdmissionProxyError("proxy_contract_malformed") from None
    if not isinstance(parsed, dict):
        raise AdmissionProxyError("proxy_contract_not_object")
    try:
        return AdmissionProxyContract.model_validate(parsed)
    except ValidationError:
        raise AdmissionProxyError("proxy_contract_invalid") from None


class ProxyGateSecret:
    """Validated origin credential whose string representations are always redacted."""

    __slots__ = ("__value",)

    def __init__(self, value: bytes) -> None:
        if not isinstance(value, bytes) or re.fullmatch(rb"[0-9a-f]{64}", value) is None:
            raise AdmissionProxyError("proxy_gate_secret_invalid")
        self.__value = value

    def __repr__(self) -> str:
        return "ProxyGateSecret(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"

    def header_value(self) -> str:
        return self.__value.decode("ascii")


def parse_proxy_gate_secret(raw: bytes) -> ProxyGateSecret:
    if not isinstance(raw, bytes) or _GATE_SECRET.fullmatch(raw) is None:
        raise AdmissionProxyError("proxy_gate_secret_invalid")
    return ProxyGateSecret(raw[:-1])


@dataclass(frozen=True, repr=False)
class LoadedAdmissionProxyConfig:
    contract: AdmissionProxyContract
    gate_secret: ProxyGateSecret = field(repr=False)

    def __repr__(self) -> str:
        return "LoadedAdmissionProxyConfig(contract=<validated>, gate_secret=<redacted>)"


def _read_fixed_regular(
    path: str,
    *,
    expected_path: str,
    max_bytes: int,
    key_material: bool,
) -> bytes:
    if path != expected_path:
        raise AdmissionProxyError("proxy_artifact_path_invalid")
    try:
        fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC)
    except OSError:
        raise AdmissionProxyError("proxy_artifact_open_failed") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise AdmissionProxyError("proxy_artifact_metadata_invalid")
        mode = st.st_mode & 0o7777
        if key_material:
            # root-controlled, group-readable only for the dedicated proxy group, never world.
            if st.st_uid != 0 or st.st_gid <= 0 or mode != 0o640:
                raise AdmissionProxyError("proxy_server_key_metadata_invalid")
        elif st.st_uid != 0 or mode not in (0o640, 0o644):
            raise AdmissionProxyError("proxy_certificate_metadata_invalid")
        if not (0 < st.st_size <= max_bytes):
            raise AdmissionProxyError("proxy_artifact_size_invalid")
        raw = bytearray()
        while len(raw) <= max_bytes:
            chunk = os.read(fd, min(8192, max_bytes + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        if len(raw) != st.st_size or not raw or len(raw) > max_bytes:
            raise AdmissionProxyError("proxy_artifact_read_invalid")
        return bytes(raw)
    finally:
        os.close(fd)


def load_and_validate_fixed_contract() -> LoadedAdmissionProxyConfig:
    """Read the fixed contract and validate the exact imported TLS material before listening."""

    contract_raw = _read_fixed_regular(
        PRODUCTION_LAYOUT.proxy_contract_container_path,
        expected_path=PRODUCTION_LAYOUT.proxy_contract_container_path,
        max_bytes=_MAX_CONTRACT_BYTES,
        key_material=False,
    )
    contract = parse_proxy_contract_bytes(contract_raw)
    tls = contract.listener.tls
    ca = _read_fixed_regular(
        tls.ca_certificate_path,
        expected_path=PRODUCTION_LAYOUT.proxy_ca_certificate_container_path,
        max_bytes=_MAX_CERTIFICATE_BYTES,
        key_material=False,
    )
    certificate = _read_fixed_regular(
        tls.certificate_path,
        expected_path=PRODUCTION_LAYOUT.proxy_server_certificate_container_path,
        max_bytes=_MAX_CERTIFICATE_BYTES,
        key_material=False,
    )
    server_key = _read_fixed_regular(
        tls.private_key_path,
        expected_path=PRODUCTION_LAYOUT.proxy_server_private_key_container_path,
        max_bytes=_MAX_SERVER_KEY_BYTES,
        key_material=True,
    )
    material = import_tls_material(
        ca_certificate_pem=ca,
        server_certificate_pem=certificate,
        server_private_key_pem=server_key,
        expected_dns_identity=tls.expected_dns_identity,
    )
    if material.metadata.server_certificate_fingerprint != tls.certificate_fingerprint:
        raise AdmissionProxyError("proxy_server_certificate_substituted")
    gate_raw = _read_fixed_regular(
        contract.origin_gate.secret_path,
        expected_path=PRODUCTION_LAYOUT.admission_proxy_gate_container_path,
        max_bytes=65,
        key_material=True,
    )
    return LoadedAdmissionProxyConfig(
        contract=contract, gate_secret=parse_proxy_gate_secret(gate_raw)
    )


def _json_error(status_code: int, reason: str) -> JSONResponse:
    return JSONResponse({"detail": reason}, status_code=status_code)


def _raw_header_values(request: Request, name: bytes) -> tuple[bytes, ...]:
    return tuple(
        value for raw_name, value in request.scope.get("headers", ()) if raw_name.lower() == name
    )


async def _read_request_body(
    request: Request,
    limit: int,
    declared_length: int | None,
    *,
    timeout_seconds: float,
) -> bytes | None:
    body = bytearray()
    try:
        # The ASGI server's keep-alive timeout does not bound a client that slow-drips an
        # already-started request body.  Keep the entire body-consumption interval under the
        # contract's fixed deadline and let cancellation propagate into the receive coroutine.
        async with asyncio.timeout(float(timeout_seconds)):
            async for chunk in request.stream():
                if len(chunk) > limit - len(body):
                    return None
                body.extend(chunk)
    except Exception:
        return None
    if declared_length is not None and declared_length != len(body):
        return None
    return bytes(body)


def create_proxy_app(contract: AdmissionProxyContract, gate_secret: ProxyGateSecret) -> Starlette:
    """Construct the exact-route ASGI app without reading files or opening a connection."""

    if type(contract) is not AdmissionProxyContract:
        raise AdmissionProxyError("proxy_contract_type_invalid")
    if type(gate_secret) is not ProxyGateSecret:
        raise AdmissionProxyError("proxy_gate_secret_type_invalid")

    async def forward(request: Request) -> Response:
        raw_path = request.scope.get("raw_path")
        query = request.scope.get("query_string", b"")
        try:
            decoded_path = request.url.path.encode("ascii")
        except UnicodeEncodeError:
            return _json_error(404, "not_found")
        if (
            type(raw_path) is not bytes
            or raw_path != decoded_path
            or raw_path not in {path.encode("ascii") for path in ADMISSION_ROUTES}
            or query != b""
        ):
            return _json_error(404, "not_found")
        if _raw_header_values(request, _GATE_HEADER.lower().encode("ascii")):
            return _json_error(404, "not_found")
        content_types = _raw_header_values(request, b"content-type")
        if len(content_types) != 1:
            return _json_error(415, "content_type_refused")
        try:
            content_type = content_types[0].decode("ascii").split(";", 1)[0].strip().lower()
        except UnicodeDecodeError:
            return _json_error(415, "content_type_refused")
        if content_type != contract.upstream.required_request_content_type:
            return _json_error(415, "content_type_refused")
        lengths = _raw_header_values(request, b"content-length")
        if len(lengths) > 1:
            return _json_error(400, "content_length_refused")
        declared_length: int | None = None
        if lengths:
            if re.fullmatch(rb"(?:0|[1-9][0-9]*)", lengths[0]) is None:
                return _json_error(400, "content_length_refused")
            declared_length = int(lengths[0], 10)
            if declared_length > contract.limits.max_request_bytes:
                return _json_error(413, "request_too_large_or_malformed")
        body = await _read_request_body(
            request,
            contract.limits.max_request_bytes,
            declared_length,
            timeout_seconds=contract.limits.request_timeout_seconds,
        )
        if body is None:
            return _json_error(413, "request_too_large_or_malformed")
        timeout = httpx.Timeout(
            connect=float(contract.limits.connect_timeout_seconds),
            read=float(contract.limits.request_timeout_seconds),
            write=float(contract.limits.request_timeout_seconds),
            pool=float(contract.limits.connect_timeout_seconds),
        )
        limits = httpx.Limits(max_connections=32, max_keepalive_connections=8)
        try:
            # httpx's read timeout is an inactivity timeout: an upstream that sends one byte
            # before each interval could otherwise retain a proxy slot indefinitely.  Apply a
            # wall-clock deadline to the complete upstream exchange as well.
            async with asyncio.timeout(float(contract.limits.request_timeout_seconds)):
                async with httpx.AsyncClient(
                    trust_env=False,
                    follow_redirects=False,
                    timeout=timeout,
                    limits=limits,
                ) as client:
                    async with client.stream(
                        "POST",
                        contract.upstream.origin + request.url.path,
                        headers={
                            "content-type": "application/json",
                            "accept": "application/json",
                            "accept-encoding": "identity",
                            contract.origin_gate.header_name: gate_secret.header_value(),
                        },
                        content=body,
                    ) as upstream:
                        if 300 <= upstream.status_code < 400:
                            return _json_error(502, "upstream_redirect_refused")
                        response_type = (
                            upstream.headers.get("content-type", "")
                            .split(";", 1)[0]
                            .strip()
                            .lower()
                        )
                        if response_type != contract.upstream.required_response_content_type:
                            return _json_error(502, "upstream_content_type_refused")
                        content_encodings = upstream.headers.get_list("content-encoding")
                        if len(content_encodings) > 1 or any(
                            value.strip().lower() != "identity" for value in content_encodings
                        ):
                            return _json_error(502, "upstream_content_encoding_refused")
                        payload = bytearray()
                        async for chunk in upstream.aiter_raw():
                            if len(chunk) > contract.limits.max_response_bytes - len(payload):
                                return _json_error(502, "upstream_response_too_large")
                            payload.extend(chunk)
                        return Response(
                            bytes(payload),
                            status_code=upstream.status_code,
                            media_type="application/json",
                        )
        except TimeoutError:
            return _json_error(502, "upstream_timeout")
        except httpx.HTTPError:
            return _json_error(502, "upstream_unavailable")

    app = Starlette(
        debug=False,
        routes=[Route(path, endpoint=forward, methods=["POST"]) for path in ADMISSION_ROUTES],
    )
    # Exact-route isolation includes refusing slash variants.  Starlette otherwise emits a 307
    # canonicalization redirect before our route allowlist can reject the request.
    app.router.redirect_slashes = False
    return app


def _strict_tls_context(contract: AdmissionProxyContract) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
    context.options |= ssl.OP_NO_COMPRESSION
    try:
        context.load_cert_chain(
            certfile=contract.listener.tls.certificate_path,
            keyfile=contract.listener.tls.private_key_path,
        )
    except (OSError, ssl.SSLError):
        raise AdmissionProxyError("proxy_tls_context_failed") from None
    return context


def main() -> int:
    """Validate fixed local artifacts, then serve the dedicated private TLS listener."""

    try:
        loaded = load_and_validate_fixed_contract()
        contract = loaded.contract
        app = create_proxy_app(contract, loaded.gate_secret)
        config = uvicorn.Config(
            app,
            host="0.0.0.0",
            port=ADMISSION_PROXY_CONTAINER_PORT,
            access_log=False,
            server_header=False,
            proxy_headers=False,
            log_level="error",
            limit_concurrency=128,
            timeout_keep_alive=5,
            h11_max_incomplete_event_size=MAX_ADMISSION_REQUEST_BYTES,
        )
        config.load()
        config.ssl = _strict_tls_context(contract)
        uvicorn.Server(config).run()
        return 0
    except AdmissionProxyError:
        return 2


__all__ = [
    "AdmissionProxyError",
    "AdmissionProxyContract",
    "ProxyGateSecret",
    "LoadedAdmissionProxyConfig",
    "parse_proxy_contract_bytes",
    "parse_proxy_gate_secret",
    "load_and_validate_fixed_contract",
    "create_proxy_app",
    "main",
]
