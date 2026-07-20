"""SECP-B6 MB-1 item-1 — admission-transport hardening (strict HTTPS + CA pin + strict responses).

The live worker may trust ONLY a control-plane admission endpoint that is (a) reached over HTTPS,
(b) verified against an explicit deployment-local CA (never system trust, never ambient proxy/env),
and (c) returns an exactly-shaped response for the requested admission id + lifecycle phase.
Everything else fails closed before any request, key-material read, or SSH. These tests exercise the
real ``HttpxAdmissionTransport`` + ``HttpWorkerAdmissionClient`` against a threaded fake server.
"""

from __future__ import annotations

import asyncio
import gzip
import os
import secrets
import ssl
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from _admission_tls_util import FakeAdmissionServer, IssuedTls, write_ca_only
from secp_api.config import Settings
from secp_api.worker_admission_contract import generate_ed25519_keypair
from secp_worker import bundle_manager as bm
from secp_worker.admission_http_transport import AdmissionTransportError, HttpxAdmissionTransport
from secp_worker.hardened_http import MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES
from secp_worker.target_discovery.admission_client import (
    HttpWorkerAdmissionClient,
    SealedWorkerAdmissionClient,
    WorkerAdmissionUnavailable,
)
from secp_worker.target_discovery.composition import _build_admission_client

_EBH = "sha256:" + "ab" * 32


@pytest.fixture(scope="module")
def shared_tls(tmp_path_factory):
    # One CA + server cert generated ONCE per module (EC keygen is the dominant cost).
    return IssuedTls(tmp_path_factory.mktemp("admission-tls"))


# --- 1 + 2: strict URL validation at construction (before any request) -------


@pytest.mark.parametrize(
    "url",
    [
        "http://control-plane.example:8443",  # plain HTTP
        "http://control-plane.example",  # plain HTTP, no port
        "file:///etc/passwd",  # file scheme
        "unix:///var/run/admit.sock",  # unix socket url
        "ftp://control-plane.example",  # other scheme
        "//control-plane.example",  # scheme-relative
        "https://user:pass@control-plane.example",  # userinfo
        "https://control-plane.example?x=1",  # query string
        "https://control-plane.example#frag",  # fragment
        "https://control-plane.example/admit",  # non-root path
        "https://control-plane.example/",  # accepted (root path) — sanity handled separately
        "https://control-plane.example:99999",  # malformed/out-of-range port
        "https://control-plane.example:notaport",  # non-numeric port
        "https://:8443",  # missing host
        "https:// space.example",  # whitespace in host
        "",  # empty
        "   ",  # blank
    ],
)
def test_transport_rejects_non_strict_endpoints(url):
    # URL validation happens at construction BEFORE the CA is read, so a non-empty dummy CA is fine.
    ca = "dummy-ca-path"
    if url == "https://control-plane.example/":
        # Root path is the one allowed form — it must NOT raise (normalized, path dropped).
        t = HttpxAdmissionTransport(base_url=url, ca_path=ca)
        assert t.base_url == "https://control-plane.example"
        return
    with pytest.raises(AdmissionTransportError) as exc:
        HttpxAdmissionTransport(base_url=url, ca_path=ca)
    # The closed reason code never leaks the raw URL (skip the trivially-empty cases).
    if url.strip():
        assert url.strip() not in str(exc.value)


def test_transport_requires_ca(tmp_path):
    with pytest.raises(AdmissionTransportError) as exc:
        HttpxAdmissionTransport(base_url="https://control-plane.example:8443", ca_path="")
    assert exc.value.reason_code == "admission_ca_required"


def test_transport_repr_and_error_do_not_leak_endpoint():
    ca = "dummy-ca-path"
    t = HttpxAdmissionTransport(base_url="https://secret-cp.example:8443", ca_path=ca)
    assert "secret-cp" not in repr(t)
    assert repr(t) == "HttpxAdmissionTransport(<redacted>)"
    with pytest.raises(AdmissionTransportError) as exc:
        HttpxAdmissionTransport(base_url="http://secret-cp.example:8443", ca_path=ca)
    assert "secret-cp" not in str(exc.value)


def test_transport_refuses_unreviewed_path_and_oversized_request_before_ca_read():
    transport = HttpxAdmissionTransport(
        base_url="https://control-plane.example:8443", ca_path="does-not-exist"
    )
    with pytest.raises(AdmissionTransportError) as path_exc:
        transport.post("/api/v1/unrelated", {})
    assert path_exc.value.reason_code == "admission_path_forbidden"

    with pytest.raises(AdmissionTransportError) as size_exc:
        transport.post(
            "/internal/worker-discovery-admission/begin",
            {"padding": "x" * MAX_REQUEST_BYTES},
        )
    assert size_exc.value.reason_code == "admission_request_too_large"


def test_transport_refuses_invalid_or_unbounded_timeout():
    for timeout in (True, 0, -1, 31, float("inf"), float("nan")):
        with pytest.raises(AdmissionTransportError) as exc:
            HttpxAdmissionTransport(
                base_url="https://control-plane.example:8443",
                ca_path="dummy-ca",
                timeout=timeout,
            )
        assert exc.value.reason_code == "admission_timeout_invalid"


class _AsyncBytesStream(httpx.AsyncByteStream):
    def __init__(self, chunks: tuple[bytes, ...]) -> None:
        self._chunks = chunks
        self.iterated = False
        self.closed = False

    async def __aiter__(self):  # noqa: ANN202
        self.iterated = True
        for chunk in self._chunks:
            yield chunk

    async def aclose(self) -> None:
        self.closed = True


def _install_async_mock_client(monkeypatch, handler, captures):  # noqa: ANN001, ANN202
    real_async_client = httpx.AsyncClient
    mock_transport = httpx.MockTransport(handler)

    def factory(**kwargs):  # noqa: ANN003, ANN202
        captures.append(dict(kwargs))
        return real_async_client(transport=mock_transport, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)


def _install_mock_ssl_context(monkeypatch):  # noqa: ANN001, ANN202
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    seen: list[str] = []

    def factory(*, cafile):  # noqa: ANN001, ANN202
        seen.append(cafile)
        return context

    monkeypatch.setattr(ssl, "create_default_context", factory)
    return context, seen


def test_transport_enforces_total_deadline_on_a_slow_drip_response(monkeypatch):  # noqa: ANN001
    class SlowDripStream(httpx.AsyncByteStream):
        cancelled = False
        closed = False

        async def __aiter__(self):  # noqa: ANN202
            try:
                while True:
                    await asyncio.sleep(0.001)
                    yield b" "
            finally:
                self.cancelled = True

        async def aclose(self) -> None:
            self.closed = True

    stream = SlowDripStream()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get_list("Accept-Encoding") == ["identity"]
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            stream=stream,
        )

    captures: list[dict[str, object]] = []
    _install_async_mock_client(monkeypatch, handler, captures)
    context, seen_ca_paths = _install_mock_ssl_context(monkeypatch)
    transport = HttpxAdmissionTransport(
        base_url="https://control-plane.example:8443",
        ca_path="fixed-ca.pem",
        timeout=0.02,
    )

    with pytest.raises(AdmissionTransportError) as exc:
        transport.post("/internal/worker-discovery-admission/begin", {})

    assert exc.value.reason_code == "admission_transport_failed"
    assert stream.cancelled and stream.closed
    assert seen_ca_paths == ["fixed-ca.pem"]
    assert captures == [
        {
            "verify": context,
            "trust_env": False,
            "follow_redirects": False,
            "timeout": 0.02,
        }
    ]


@pytest.mark.parametrize(
    "encoding_headers",
    [
        (("content-encoding", "gzip"),),
        (("content-encoding", "identity"), ("content-encoding", "identity")),
    ],
)
def test_transport_refuses_encoded_or_duplicate_encoding_without_reading_body(
    monkeypatch,
    encoding_headers,
):  # noqa: ANN001
    compressed = gzip.compress(b"x" * (MAX_RESPONSE_BYTES * 16))
    assert len(compressed) < MAX_RESPONSE_BYTES
    stream = _AsyncBytesStream((compressed,))

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get_list("Accept-Encoding") == ["identity"]
        return httpx.Response(
            200,
            headers=(("content-type", "application/json"), *encoding_headers),
            stream=stream,
        )

    captures: list[dict[str, object]] = []
    _install_async_mock_client(monkeypatch, handler, captures)
    _install_mock_ssl_context(monkeypatch)
    transport = HttpxAdmissionTransport(
        base_url="https://control-plane.example:8443", ca_path="fixed-ca.pem"
    )

    with pytest.raises(AdmissionTransportError) as exc:
        transport.post("/internal/worker-discovery-admission/begin", {})

    assert exc.value.reason_code == "admission_response_invalid"
    assert not stream.iterated
    assert stream.closed


def test_transport_accepts_explicit_identity_encoding_and_reads_raw_bytes(monkeypatch):  # noqa: ANN001
    stream = _AsyncBytesStream((b'{"ok":', b"true}"))

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get_list("Accept-Encoding") == ["identity"]
        return httpx.Response(
            200,
            headers={"content-type": "application/json", "content-encoding": "identity"},
            stream=stream,
        )

    captures: list[dict[str, object]] = []
    _install_async_mock_client(monkeypatch, handler, captures)
    _install_mock_ssl_context(monkeypatch)
    transport = HttpxAdmissionTransport(
        base_url="https://control-plane.example:8443", ca_path="fixed-ca.pem"
    )

    assert transport.post("/internal/worker-discovery-admission/begin", {}) == (200, {"ok": True})
    assert stream.iterated and stream.closed


def test_sync_transport_refuses_calls_from_a_running_event_loop(monkeypatch):  # noqa: ANN001
    def forbidden_context(*_args, **_kwargs):  # noqa: ANN002, ANN003, ANN202
        raise AssertionError("CA material must not be read after the async-context refusal")

    monkeypatch.setattr(ssl, "create_default_context", forbidden_context)
    transport = HttpxAdmissionTransport(
        base_url="https://control-plane.example:8443", ca_path="fixed-ca.pem"
    )

    async def invoke() -> None:
        with pytest.raises(AdmissionTransportError) as exc:
            transport.post("/internal/worker-discovery-admission/begin", {})
        assert exc.value.reason_code == "admission_async_context_forbidden"

    asyncio.run(invoke())


# --- 3: composition requires an explicit, usable CA bundle -------------------


def _live_settings(*, endpoint, key, anchor, ca):
    return Settings(
        discovery_controlled_integration_enabled=True,
        discovery_admission_endpoint=endpoint,
        discovery_worker_identity_key=key,
        discovery_worker_identity_anchor=anchor,
        discovery_admission_ca=ca,
    )


def _write_identity(tmp_path):
    key_dir = tmp_path / "worker-keys"
    bm.ensure_worker_keys(str(key_dir))
    return str(key_dir / "admission_key"), str(key_dir / "admission_anchor")


def test_composition_valid_ca_and_https_builds_http_client(tmp_path):
    key, anchor = _write_identity(tmp_path)
    ca = write_ca_only(tmp_path)
    settings = _live_settings(
        endpoint="https://control-plane.example:8443", key=key, anchor=anchor, ca=ca
    )
    client = _build_admission_client(settings)
    assert isinstance(client, HttpWorkerAdmissionClient)


@pytest.mark.parametrize("ca_kind", ["missing_setting", "nonexistent", "empty", "malformed", "dir"])
def test_composition_seals_on_bad_ca(ca_kind, tmp_path):
    key, anchor = _write_identity(tmp_path)
    if ca_kind == "missing_setting":
        ca = ""
    elif ca_kind == "nonexistent":
        ca = str(tmp_path / "nope.pem")
    elif ca_kind == "empty":
        (tmp_path / "empty.pem").write_text("")
        ca = str(tmp_path / "empty.pem")
    elif ca_kind == "malformed":
        (tmp_path / "bad.pem").write_text("-----BEGIN CERTIFICATE-----\nnot base64\n----END----\n")
        ca = str(tmp_path / "bad.pem")
    else:  # a directory, not a file
        ca = str(tmp_path)
    settings = _live_settings(
        endpoint="https://control-plane.example:8443", key=key, anchor=anchor, ca=ca
    )
    assert isinstance(_build_admission_client(settings), SealedWorkerAdmissionClient)


def test_composition_seals_on_http_endpoint_even_with_valid_ca(tmp_path):
    key, anchor = _write_identity(tmp_path)
    ca = write_ca_only(tmp_path)
    settings = _live_settings(
        endpoint="http://control-plane.example:8443", key=key, anchor=anchor, ca=ca
    )
    assert isinstance(_build_admission_client(settings), SealedWorkerAdmissionClient)


def test_composition_validates_endpoint_before_identity_read(tmp_path, monkeypatch):
    key, anchor = _write_identity(tmp_path)
    ca = write_ca_only(tmp_path)
    settings = _live_settings(
        endpoint="http://control-plane.example:8443", key=key, anchor=anchor, ca=ca
    )
    called = False

    def forbidden_read(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("identity files must not be read for an invalid endpoint")

    monkeypatch.setattr(bm, "read_worker_admission_identity", forbidden_read)
    assert isinstance(_build_admission_client(settings), SealedWorkerAdmissionClient)
    assert called is False


def test_composition_requires_colocated_bounded_identity_files(tmp_path):
    key, anchor = _write_identity(tmp_path)
    ca = write_ca_only(tmp_path)
    alternate_dir = tmp_path / "alternate-keys"
    alternate_dir.mkdir(mode=0o700)
    alternate = alternate_dir / "alternate-name"
    alternate.write_bytes((tmp_path / "worker-keys" / "admission_key").read_bytes())
    if os.name == "posix":
        os.chmod(alternate_dir, 0o700)
        os.chmod(alternate, 0o600)
    wrong_name = _live_settings(
        endpoint="https://control-plane.example:8443",
        key=str(alternate),
        anchor=anchor,
        ca=ca,
    )
    assert isinstance(_build_admission_client(wrong_name), SealedWorkerAdmissionClient)

    (tmp_path / "worker-keys" / "admission_key").write_bytes(b"a" * 257)
    oversized = _live_settings(
        endpoint="https://control-plane.example:8443", key=key, anchor=anchor, ca=ca
    )
    assert isinstance(_build_admission_client(oversized), SealedWorkerAdmissionClient)


def test_composition_seals_without_ca_setting(tmp_path):
    key, anchor = _write_identity(tmp_path)
    settings = _live_settings(
        endpoint="https://control-plane.example:8443", key=key, anchor=anchor, ca=""
    )
    assert isinstance(_build_admission_client(settings), SealedWorkerAdmissionClient)


# --- valid + adversarial handshakes over a real fake TLS admission server ----


def _valid_responder(
    *, job_id, ebh, admission_id=None, reg_id=None, identity_version=2, ttl=90, override=None
):
    admission_id = admission_id or str(uuid.uuid4())
    reg_id = reg_id or str(uuid.uuid4())
    org_id = str(uuid.uuid4())

    def responder(path, body):
        now = datetime.now(UTC)
        if path.endswith("/begin"):
            resp = {
                "admission_id": admission_id,
                "nonce": secrets.token_hex(16),
                "organization_id": org_id,
                "discovery_job_id": str(job_id),
                "worker_registration_id": reg_id,
                "identity_version": identity_version,
                "endpoint_binding_hash": ebh,
                "expires_at": (now + timedelta(seconds=ttl)).isoformat(),
            }
            phase = "begin"
        elif path.endswith("/complete"):
            resp = {"status": "admitted", "admission_id": body.get("admission_id")}
            phase = "complete"
        elif path.endswith("/assert"):
            resp = {
                "status": "valid",
                "admission_id": body.get("admission_id"),
                "registration_id": reg_id,
                "identity_version": identity_version,
            }
            phase = "assert"
        elif path.endswith("/consume"):
            resp = {
                "status": "consumed",
                "admission_id": body.get("admission_id"),
                "registration_id": reg_id,
                "identity_version": identity_version,
            }
            phase = "consume"
        else:
            return 404, {}
        status = 200
        if override is not None:
            status, resp = override(phase, status, resp)
        return status, resp

    return responder


def _client(server, ca_path):
    priv, pub = generate_ed25519_keypair()
    transport = HttpxAdmissionTransport(base_url=server.base_url, ca_path=ca_path)
    return HttpWorkerAdmissionClient(
        transport=transport, private_key_hex=priv, public_anchor_hex=pub
    )


class _StubTransport:
    """An in-memory transport (no TLS/network) for exercising the CLIENT's strict response
    validation — the malformed-response cases are transport-agnostic and need no real handshake."""

    def __init__(self, responder):
        self._responder = responder

    def post(self, path, payload):
        return self._responder(path, payload)


def _stub_client(responder):
    priv, pub = generate_ed25519_keypair()
    return HttpWorkerAdmissionClient(
        transport=_StubTransport(responder), private_key_hex=priv, public_anchor_hex=pub
    )


def test_full_valid_handshake_over_real_tls(shared_tls):
    tls = shared_tls
    job_id = uuid.uuid4()
    responder = _valid_responder(job_id=job_id, ebh=_EBH)
    with FakeAdmissionServer(
        responder=responder, certfile=tls.server_cert_path, keyfile=tls.server_key_path
    ) as server:
        client = _client(server, tls.ca_path)
        admission_id = client.admit(
            discovery_job_id=job_id,
            authorization_id=uuid.uuid4(),
            authorization_version=1,
            endpoint_binding_hash=_EBH,
        )
        grant = client.assert_valid(
            admission_id=admission_id, discovery_job_id=job_id, endpoint_binding_hash=_EBH
        )
        consumed = client.consume(
            admission_id=admission_id, discovery_job_id=job_id, endpoint_binding_hash=_EBH
        )
    assert grant.identity_version == 2
    assert consumed.registration_id == grant.registration_id


def test_transport_streams_and_refuses_oversized_response(shared_tls):
    tls = shared_tls

    def responder(_path, _body):
        return 200, {"padding": "x" * (MAX_RESPONSE_BYTES + 1)}

    with FakeAdmissionServer(
        responder=responder, certfile=tls.server_cert_path, keyfile=tls.server_key_path
    ) as server:
        transport = HttpxAdmissionTransport(base_url=server.base_url, ca_path=tls.ca_path)
        with pytest.raises(AdmissionTransportError) as exc:
            transport.post("/internal/worker-discovery-admission/begin", {})
    assert exc.value.reason_code == "admission_response_too_large"


def test_transport_refuses_overdeep_json_response(shared_tls):
    tls = shared_tls
    nested: dict = {"leaf": "ok"}
    for _ in range(30):
        nested = {"nested": nested}

    def responder(_path, _body):
        return 200, nested

    with FakeAdmissionServer(
        responder=responder, certfile=tls.server_cert_path, keyfile=tls.server_key_path
    ) as server:
        transport = HttpxAdmissionTransport(base_url=server.base_url, ca_path=tls.ca_path)
        with pytest.raises(AdmissionTransportError) as exc:
            transport.post("/internal/worker-discovery-admission/begin", {})
    assert exc.value.reason_code == "admission_response_invalid"


def test_wrong_ca_tls_fails_closed(tmp_path):
    tls_a = IssuedTls(tmp_path, label="a")  # server cert signed by CA-A
    tls_b = IssuedTls(tmp_path, label="b")  # worker trusts CA-B (does NOT sign the server cert)
    job_id = uuid.uuid4()
    with FakeAdmissionServer(
        responder=_valid_responder(job_id=job_id, ebh=_EBH),
        certfile=tls_a.server_cert_path,
        keyfile=tls_a.server_key_path,
    ) as server:
        client = _client(server, tls_b.ca_path)  # wrong trust anchor
        with pytest.raises(WorkerAdmissionUnavailable) as exc:
            client.admit(
                discovery_job_id=job_id,
                authorization_id=uuid.uuid4(),
                authorization_version=1,
                endpoint_binding_hash=_EBH,
            )
    assert exc.value.reason_code == "admission_endpoint_unreachable"


def test_proxy_env_cannot_alter_routing(shared_tls, monkeypatch):
    # With trust_env=False, an ambient HTTPS proxy env var is ignored: the request still reaches the
    # fake TLS server directly. If the proxy were honored it would route to a dead address and fail.
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:9")
    tls = shared_tls
    job_id = uuid.uuid4()
    with FakeAdmissionServer(
        responder=_valid_responder(job_id=job_id, ebh=_EBH),
        certfile=tls.server_cert_path,
        keyfile=tls.server_key_path,
    ) as server:
        client = _client(server, tls.ca_path)
        admission_id = client.admit(
            discovery_job_id=job_id,
            authorization_id=uuid.uuid4(),
            authorization_version=1,
            endpoint_binding_hash=_EBH,
        )
    assert isinstance(admission_id, uuid.UUID)


def test_redirect_is_refused_not_followed(shared_tls):
    tls = shared_tls
    job_id = uuid.uuid4()

    def override(phase, status, resp):
        if phase == "begin":
            return 302, {}  # would-redirect to a 'would-admit' Location
        return status, resp

    responder = _valid_responder(job_id=job_id, ebh=_EBH, override=override)
    with FakeAdmissionServer(
        responder=responder, certfile=tls.server_cert_path, keyfile=tls.server_key_path
    ) as server:
        client = _client(server, tls.ca_path)
        with pytest.raises(WorkerAdmissionUnavailable):
            client.admit(
                discovery_job_id=job_id,
                authorization_id=uuid.uuid4(),
                authorization_version=1,
                endpoint_binding_hash=_EBH,
            )
        # The 302 was received once and NOT followed (no second request to the redirect target).
        assert server.request_count == 1


# --- 7: a generic 200 with wrong/missing/inconsistent content fails closed ---

_MALFORMED_CASES = {
    "begin_missing_admission_id": ("begin", lambda r: {**r, "admission_id": None}),
    "begin_bad_admission_id": ("begin", lambda r: {**r, "admission_id": "not-a-uuid"}),
    "begin_wrong_job_echo": ("begin", lambda r: {**r, "discovery_job_id": str(uuid.uuid4())}),
    "begin_wrong_ebh_echo": (
        "begin",
        lambda r: {**r, "endpoint_binding_hash": "sha256:" + "cd" * 32},
    ),
    "begin_zero_version": ("begin", lambda r: {**r, "identity_version": 0}),
    "begin_negative_version": ("begin", lambda r: {**r, "identity_version": -1}),
    "begin_bool_version": ("begin", lambda r: {**r, "identity_version": True}),
    "begin_missing_nonce": ("begin", lambda r: {k: v for k, v in r.items() if k != "nonce"}),
    "begin_past_expiry": (
        "begin",
        lambda r: {**r, "expires_at": (datetime.now(UTC) - timedelta(seconds=5)).isoformat()},
    ),
    "begin_malformed_expiry": ("begin", lambda r: {**r, "expires_at": "not-a-date"}),
    "complete_wrong_status": ("complete", lambda r: {**r, "status": "ok"}),
    "complete_missing_status": (
        "complete",
        lambda r: {k: v for k, v in r.items() if k != "status"},
    ),
    "complete_wrong_admission_id": ("complete", lambda r: {**r, "admission_id": str(uuid.uuid4())}),
    "assert_wrong_status": ("assert", lambda r: {**r, "status": "consumed"}),
    "assert_wrong_admission_id": ("assert", lambda r: {**r, "admission_id": str(uuid.uuid4())}),
    "assert_zero_version": ("assert", lambda r: {**r, "identity_version": 0}),
    "assert_bad_registration": ("assert", lambda r: {**r, "registration_id": "nope"}),
    "consume_wrong_status": ("consume", lambda r: {**r, "status": "valid"}),
    "consume_wrong_admission_id": ("consume", lambda r: {**r, "admission_id": str(uuid.uuid4())}),
}


@pytest.mark.parametrize("case", list(_MALFORMED_CASES))
def test_generic_200_with_bad_content_fails_closed(case):
    # Client-side strict validation is transport-agnostic — exercised over an in-memory stub (fast).
    target_phase, mutate = _MALFORMED_CASES[case]
    job_id = uuid.uuid4()

    def override(phase, status, resp):
        if phase == target_phase:
            return 200, mutate(resp)
        return status, resp

    client = _stub_client(_valid_responder(job_id=job_id, ebh=_EBH, override=override))
    with pytest.raises(WorkerAdmissionUnavailable) as exc:
        admission_id = client.admit(
            discovery_job_id=job_id,
            authorization_id=uuid.uuid4(),
            authorization_version=1,
            endpoint_binding_hash=_EBH,
        )
        # assert/consume phases only reached if begin+complete validated:
        client.assert_valid(
            admission_id=admission_id, discovery_job_id=job_id, endpoint_binding_hash=_EBH
        )
        client.consume(
            admission_id=admission_id, discovery_job_id=job_id, endpoint_binding_hash=_EBH
        )
    assert exc.value.reason_code == "admission_response_malformed"


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-q"])
