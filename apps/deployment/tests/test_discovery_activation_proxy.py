"""Hermetic exact-route admission-proxy tests using only ``httpx.MockTransport``."""

from __future__ import annotations

import asyncio
import gzip
import json
from datetime import UTC, datetime

import httpx
import pytest
from secp_discovery_activation import PACKAGE_CONTRACT_VERSION
from secp_discovery_activation.layout import (
    ADMISSION_ROUTES,
    MAX_ADMISSION_REQUEST_BYTES,
    MAX_ADMISSION_RESPONSE_BYTES,
)
from secp_discovery_activation.profile import parse_deployment_profile
from secp_discovery_activation.proxy import (
    AdmissionProxyError,
    ProxyGateSecret,
    _read_request_body,
    create_proxy_app,
    parse_proxy_contract_bytes,
    parse_proxy_gate_secret,
)
from secp_discovery_activation.render import render_activation
from secp_discovery_activation.tls import generate_tls_material
from starlette.requests import Request
from starlette.testclient import TestClient

NOW = datetime(2026, 7, 19, 12, 0, tzinfo=UTC)


class _AsyncBytesStream(httpx.AsyncByteStream):
    def __init__(self, content: bytes) -> None:
        self._content = content

    async def __aiter__(self):  # noqa: ANN202
        yield self._content

    async def aclose(self) -> None:
        return None


def _profile():  # noqa: ANN202
    return parse_deployment_profile(
        {
            "contract_version": PACKAGE_CONTRACT_VERSION,
            "activation_enabled": True,
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
def contract_bytes() -> bytes:
    material = generate_tls_material(
        dns_identity="admission.internal.test", validity_days=30, now=NOW
    )
    rendered = render_activation(_profile(), material.metadata)
    return next(
        artifact.content
        for artifact in rendered.artifacts
        if artifact.name == "admission_proxy_contract"
    )


@pytest.fixture
def contract(contract_bytes: bytes):  # noqa: ANN201
    return parse_proxy_contract_bytes(contract_bytes)


@pytest.fixture
def gate_secret() -> ProxyGateSecret:
    return parse_proxy_gate_secret(b"a" * 64 + b"\n")


def _install_mock_client(monkeypatch, handler, captures: list[dict[str, object]]) -> None:  # noqa: ANN001
    # Save the real class before patching the shared httpx module object. TestClient is constructed
    # first by every caller, so only the proxy's upstream AsyncClient uses this replacement.
    real_async_client = httpx.AsyncClient
    transport = httpx.MockTransport(handler)

    def factory(**kwargs):  # noqa: ANN003, ANN202
        captures.append(dict(kwargs))
        return real_async_client(transport=transport, **kwargs)

    import secp_discovery_activation.proxy as proxy_module

    monkeypatch.setattr(proxy_module.httpx, "AsyncClient", factory)


def test_only_four_exact_post_routes_are_forwarded(  # noqa: ANN001
    contract, gate_secret, monkeypatch
) -> None:
    seen: list[tuple[str, str, bytes]] = []

    def upstream(request: httpx.Request) -> httpx.Response:
        assert request.headers.get_list("X-SECP-Admission-Proxy-Gate") == ["a" * 64]
        assert request.headers.get_list("Accept-Encoding") == ["identity"]
        seen.append((request.method, request.url.path, request.content))
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            stream=_AsyncBytesStream(b'{"ok":true}'),
        )

    app = create_proxy_app(contract, gate_secret)
    captures: list[dict[str, object]] = []
    with TestClient(app) as client:
        _install_mock_client(monkeypatch, upstream, captures)
        for path in ADMISSION_ROUTES:
            response = client.post(path, json={"proof": "public-only"})
            assert response.status_code == 200 and response.json() == {"ok": True}

        assert client.post("/api/v1/users", json={}).status_code == 404
        assert client.post("/internal/worker-discovery-admission", json={}).status_code == 404
        assert client.get(ADMISSION_ROUTES[0]).status_code == 405
        for path in ADMISSION_ROUTES:
            slash_variant = client.post(path + "/", json={}, follow_redirects=False)
            assert slash_variant.status_code == 404
            assert "location" not in slash_variant.headers

    assert [path for _method, path, _body in seen] == list(ADMISSION_ROUTES)
    assert all(method == "POST" for method, _path, _body in seen)
    assert len(captures) == len(ADMISSION_ROUTES)
    assert all(item["trust_env"] is False for item in captures)
    assert all(item["follow_redirects"] is False for item in captures)


def test_redirect_is_not_followed_and_is_returned_as_closed_502(  # noqa: ANN001
    contract, gate_secret, monkeypatch
) -> None:
    seen: list[str] = []

    def upstream(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(
            307,
            headers={"content-type": "application/json", "location": "http://untrusted.invalid"},
            json={"redirect": True},
        )

    app = create_proxy_app(contract, gate_secret)
    captures: list[dict[str, object]] = []
    with TestClient(app) as client:
        _install_mock_client(monkeypatch, upstream, captures)
        response = client.post(ADMISSION_ROUTES[0], json={})

    assert response.status_code == 502
    assert response.json() == {"detail": "upstream_redirect_refused"}
    assert len(seen) == 1
    assert captures[0]["follow_redirects"] is False
    assert captures[0]["trust_env"] is False


def test_request_content_type_and_size_refuse_before_upstream(  # noqa: ANN001
    contract, gate_secret, monkeypatch
) -> None:
    calls = 0

    def upstream(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, headers={"content-type": "application/json"}, json={})

    app = create_proxy_app(contract, gate_secret)
    captures: list[dict[str, object]] = []
    with TestClient(app) as client:
        _install_mock_client(monkeypatch, upstream, captures)
        wrong_type = client.post(
            ADMISSION_ROUTES[0], content=b"{}", headers={"content-type": "text/plain"}
        )
        oversized = client.post(
            ADMISSION_ROUTES[0],
            content=b"x" * (MAX_ADMISSION_REQUEST_BYTES + 1),
            headers={"content-type": "application/json"},
        )

    assert wrong_type.status_code == 415
    assert oversized.status_code == 413
    assert calls == 0 and captures == []


@pytest.mark.parametrize(
    ("response", "reason"),
    [
        (
            httpx.Response(200, headers={"content-type": "text/plain"}, content=b"{}"),
            "upstream_content_type_refused",
        ),
        (
            httpx.Response(
                200,
                headers={"content-type": "application/json"},
                stream=_AsyncBytesStream(b"x" * (MAX_ADMISSION_RESPONSE_BYTES + 1)),
            ),
            "upstream_response_too_large",
        ),
        (
            httpx.Response(
                200,
                headers={
                    "content-type": "application/json",
                    "content-encoding": "gzip",
                },
                content=gzip.compress(b"x" * (MAX_ADMISSION_RESPONSE_BYTES * 16)),
            ),
            "upstream_content_encoding_refused",
        ),
    ],
)
def test_upstream_content_type_and_response_size_are_bounded(
    contract,
    gate_secret,
    monkeypatch,
    response: httpx.Response,
    reason: str,  # noqa: ANN001
) -> None:
    app = create_proxy_app(contract, gate_secret)
    captures: list[dict[str, object]] = []
    with TestClient(app) as client:
        _install_mock_client(monkeypatch, lambda _request: response, captures)
        result = client.post(ADMISSION_ROUTES[0], json={})

    assert result.status_code == 502
    assert result.json() == {"detail": reason}


def test_upstream_transport_error_is_closed_and_never_exposes_origin(  # noqa: ANN001
    contract, gate_secret, monkeypatch
) -> None:
    def unavailable(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("credential@internal-host", request=request)

    app = create_proxy_app(contract, gate_secret)
    captures: list[dict[str, object]] = []
    with TestClient(app) as client:
        _install_mock_client(monkeypatch, unavailable, captures)
        response = client.post(ADMISSION_ROUTES[0], json={})

    assert response.status_code == 502
    assert response.json() == {"detail": "upstream_unavailable"}
    assert "credential" not in response.text
    timeout = captures[0]["timeout"]
    assert isinstance(timeout, httpx.Timeout)
    assert timeout.connect == contract.limits.connect_timeout_seconds
    assert timeout.read == contract.limits.request_timeout_seconds


def test_slow_drip_upstream_is_cancelled_at_the_wall_clock_deadline(
    contract,
    gate_secret,
    monkeypatch,  # noqa: ANN001
) -> None:
    class SlowDripStream(httpx.AsyncByteStream):
        cancelled = False
        closed = False

        async def __aiter__(self):  # noqa: ANN202
            yield b"{"
            try:
                await asyncio.Event().wait()
            finally:
                self.cancelled = True

        async def aclose(self) -> None:
            self.closed = True

    stream = SlowDripStream()

    def upstream(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            stream=stream,
        )

    # model_copy deliberately bypasses the fixed production-value validator so this hermetic
    # regression test can exercise the deadline without waiting for the ten-second deployment
    # value.  The application still receives the exact production contract model type.
    limits = contract.limits.model_copy(update={"request_timeout_seconds": 0.01})
    short_contract = contract.model_copy(update={"limits": limits})
    app = create_proxy_app(short_contract, gate_secret)
    captures: list[dict[str, object]] = []
    with TestClient(app) as client:
        _install_mock_client(monkeypatch, upstream, captures)
        response = client.post(ADMISSION_ROUTES[0], json={})

    assert response.status_code == 502
    assert response.json() == {"detail": "upstream_timeout"}
    assert stream.cancelled
    assert stream.closed


@pytest.mark.parametrize(
    ("mutate", "label"),
    [
        (lambda raw: raw["upstream"].__setitem__("trust_env", True), "ambient proxy"),
        (lambda raw: raw["upstream"].__setitem__("follow_redirects", True), "redirect"),
        (lambda raw: raw["upstream"].__setitem__("deny_unmatched", False), "route deny"),
        (
            lambda raw: raw["upstream"]["allowed_requests"].append(
                {"method": "POST", "path": "/api/v1/users"}
            ),
            "extra route",
        ),
        (
            lambda raw: raw["limits"].__setitem__(
                "max_response_bytes", MAX_ADMISSION_RESPONSE_BYTES + 1
            ),
            "response bound",
        ),
        (lambda raw: raw["listener"].__setitem__("public_exposure", True), "public listener"),
        (
            lambda raw: raw["worker_authentication"].__setitem__("mechanism", "mtls"),
            "false mTLS",
        ),
        (
            lambda raw: raw["origin_gate"].__setitem__("secret_path", "/tmp/gate"),
            "gate path",
        ),
        (
            lambda raw: raw["origin_gate"].__setitem__("header_name", "Authorization"),
            "gate header",
        ),
    ],
)
def test_contract_cannot_relax_route_proxy_redirect_bound_or_identity_posture(
    contract_bytes: bytes,
    mutate,
    label: str,  # noqa: ANN001
) -> None:
    document = json.loads(contract_bytes)
    mutate(document)

    with pytest.raises(AdmissionProxyError) as exc:
        parse_proxy_contract_bytes(json.dumps(document).encode())

    assert exc.value.reason_code == "proxy_contract_invalid", label


def test_proxy_construction_is_pure_and_opens_no_upstream(  # noqa: ANN001
    contract, gate_secret, monkeypatch
) -> None:
    def forbidden(*_args, **_kwargs):
        raise AssertionError("app construction must not construct an HTTP client")

    import secp_discovery_activation.proxy as proxy_module

    monkeypatch.setattr(proxy_module.httpx, "AsyncClient", forbidden)
    app = create_proxy_app(contract, gate_secret)
    assert {route.path for route in app.routes} == set(ADMISSION_ROUTES)


def test_noncanonical_request_target_and_inbound_gate_are_refused_before_upstream(
    contract,
    gate_secret,
    monkeypatch,  # noqa: ANN001
) -> None:
    calls = 0

    def upstream(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, headers={"content-type": "application/json"}, json={})

    app = create_proxy_app(contract, gate_secret)
    captures: list[dict[str, object]] = []
    with TestClient(app) as client:
        _install_mock_client(monkeypatch, upstream, captures)
        assert client.post(ADMISSION_ROUTES[0] + "?x=1", json={}).status_code == 404
        encoded = ADMISSION_ROUTES[0].replace("begin", "%62egin")
        assert client.post(encoded, json={}).status_code == 404
        assert (
            client.post(
                ADMISSION_ROUTES[0],
                json={},
                headers={"X-SECP-Admission-Proxy-Gate": "client-controlled"},
            ).status_code
            == 404
        )
    assert calls == 0 and captures == []


def test_non_ascii_decoded_path_is_closed_without_an_exception(contract, gate_secret) -> None:  # noqa: ANN001
    app = create_proxy_app(contract, gate_secret)
    route = next(route for route in app.routes if route.path == ADMISSION_ROUTES[0])
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "scheme": "https",
            "server": ("admission.internal.test", 8443),
            "path": ADMISSION_ROUTES[0] + "\N{LATIN SMALL LETTER E WITH ACUTE}",
            "raw_path": ADMISSION_ROUTES[0].encode("ascii") + b"%c3%a9",
            "query_string": b"",
            "headers": (),
        }
    )

    response = asyncio.run(route.endpoint(request))

    assert response.status_code == 404


def test_stalled_request_body_is_cancelled_at_the_application_deadline() -> None:
    class StalledRequest:
        cancelled = False

        async def stream(self):  # noqa: ANN202
            try:
                await asyncio.Event().wait()
                yield b"unreachable"
            finally:
                self.cancelled = True

    request = StalledRequest()
    result = asyncio.run(
        _read_request_body(request, 1024, None, timeout_seconds=0.01)  # type: ignore[arg-type]
    )

    assert result is None
    assert request.cancelled


def test_duplicate_sensitive_headers_are_refused_before_upstream(
    contract,
    gate_secret,
    monkeypatch,  # noqa: ANN001
) -> None:
    calls = 0

    def upstream(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, headers={"content-type": "application/json"}, json={})

    app = create_proxy_app(contract, gate_secret)
    captures: list[dict[str, object]] = []
    with TestClient(app) as client:
        _install_mock_client(monkeypatch, upstream, captures)
        duplicate_type = client.request(
            "POST",
            ADMISSION_ROUTES[0],
            content=b"{}",
            headers=[
                ("content-type", "application/json"),
                ("Content-Type", "application/json"),
            ],
        )
        duplicate_length = client.request(
            "POST",
            ADMISSION_ROUTES[0],
            content=b"{}",
            headers=[
                ("content-type", "application/json"),
                ("content-length", "2"),
                ("Content-Length", "3"),
            ],
        )
    assert duplicate_type.status_code == 415
    assert duplicate_length.status_code == 400
    assert calls == 0 and captures == []


def test_gate_secret_is_strict_and_never_represented() -> None:
    secret = parse_proxy_gate_secret(b"f" * 64 + b"\n")
    assert secret.header_value() == "f" * 64
    assert "f" * 8 not in repr(secret)
    for malformed in (b"f" * 64, b"F" * 64 + b"\n", b"g" * 64 + b"\n"):
        with pytest.raises(AdmissionProxyError):
            parse_proxy_gate_secret(malformed)
