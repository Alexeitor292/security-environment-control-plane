"""The fixed enrollment-signer RUNTIME READINESS surface (SECP-PR5H-B2, 2b-3c-c, review R4).

Review 4803080223 R4: the management observer could not tell the API's ACTUAL effective signer from
the installer's own marker intent, and it never proved the running API could reach the broker. This
suite drives the API-side surface that supplies both facts.

It proves: the effective signer is classified from the app's REAL dependency by EXACT type identity
(a sealed default, a subclass, and a test double are all refused as ``fixed_uds``); the broker probe
is a bounded NO-SIGN exchange that never sends ``sign_offer``; every transport/protocol/peer defect
fails closed to a closed status token; a REAL AF_UNIX listener round-trip passes end to end (POSIX);
the payload is strict, versioned, canonical, bounded and secret-free; and the route is a fixed
read-only GET that mutates nothing.
"""

from __future__ import annotations

import json
import os
import socket
import threading
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from secp_api import activate_controller_identity_once as activation
from secp_api import signer_readiness as sr
from secp_api.controller_identity_dev import build_test_verified_controller_identity
from secp_api.db import get_sessionmaker
from secp_api.enrollment_signer_client import (
    SealedEnrollmentOfferSignerClient,
    UnixSocketEnrollmentOfferSignerClient,
)
from secp_commissioning.canonical import canonical_json, sha256_bytes
from secp_commissioning.controller_enrollment_signer import ENROLLMENT_SIGNER_SOCKET_PATH
from secp_commissioning.enrollment_signer_marker import render_marker_bytes
from secp_commissioning.enrollment_signer_role import ENROLLMENT_SIGNER_DB_ROLE

_POSIX_UDS = hasattr(socket, "AF_UNIX")
_T0 = "2026-07-28T00:00:00Z"
_NOW = datetime(2026, 7, 28, 0, 1, 0, tzinfo=UTC)
_API_UID = 10001
_API_GID = 10001
_CA_DIGEST = "sha256:" + "b" * 64

_REQUEST_INVALID = b'{"error":"enrollment_signer_request_invalid"}'
_PEER_UNAUTHORIZED = b'{"error":"enrollment_signer_peer_unauthorized"}'


# --------------------------------------------------------------------------- fixtures / builders


def _activate_identity() -> dict:
    """Seed a REAL active controller identity + durable activation receipt through the reviewed
    activation one-shot (never a hand-built row), so the readiness surface reads genuine state."""
    proof = build_test_verified_controller_identity()
    fields = {f: getattr(proof, f) for f in activation._IDENTITY_FIELDS}
    handoff = canonical_json(
        {
            "schema": activation.CONTROLLER_IDENTITY_ACTIVATION_SCHEMA,
            "operation_id": "op-readiness-1",
            "candidate_digest": sha256_bytes(canonical_json(dict(fields)).encode()),
            "expected_predecessor_row_id": None,
            "expected_predecessor_activation_token": None,
            "generation": 0,
            "handoff_created_at": _T0,
            **fields,
        }
    ).encode()
    code, receipt = activation.run_activation(
        read_handoff=lambda: handoff, session_factory=get_sessionmaker(), now=_NOW
    )
    assert code == activation.EXIT_OK, receipt
    return receipt


def _marker_file(tmp_path, receipt: dict, **over: object) -> str:
    proof = build_test_verified_controller_identity()
    values: dict[str, object] = {
        "installation_id": proof.controller_installation_id,
        "release_digest": proof.release_digest,
        "active_identity_row_id": receipt["resulting_row_id"],
        "activation_token": receipt["activation_token"],
        "controller_key_id": proof.controller_key_id,
        "uds_contract_identity": ENROLLMENT_SIGNER_SOCKET_PATH,
        "api_uid": _API_UID,
        "api_gid": _API_GID,
        "signer_role_name": ENROLLMENT_SIGNER_DB_ROLE,
        "locator_ca_digest": _CA_DIGEST,
        "management_identity_digest": proof.management_identity_digest,
        "bootstrap_evidence_digest": proof.bootstrap_evidence_digest,
        "recorded_at": _T0,
    }
    values.update(over)
    path = tmp_path / "enrollment-signer.enabled"
    path.write_bytes(render_marker_bytes(**values))  # type: ignore[arg-type]
    return str(path)


def _ok_exchange(request: bytes, timeout: float) -> bytes:
    """The reviewed broker's reply to a NON-signing op from an AUTHORIZED peer."""
    assert json.loads(request.decode())["op"] != "sign_offer"
    return _REQUEST_INVALID


@pytest.fixture
def clean_env(monkeypatch):
    for name in list(os.environ):
        if "ENROLLMENT" in name.upper() and "SIGNER" in name.upper():
            monkeypatch.delenv(name, raising=False)
    return None


@pytest.fixture
def posix_process(monkeypatch):
    """Present the reviewed non-root API peer ids (the dev host may be non-POSIX)."""
    monkeypatch.setattr(sr, "_process_ids", lambda: (_API_UID, _API_GID))
    return None


def _observe(session, signer, marker_path, *, exchange=_ok_exchange) -> dict:
    return sr.observe_signer_readiness(session, signer, marker_path=marker_path, exchange=exchange)


# --------------------------------------------------------------------------- effective signer


def test_effective_signer_is_the_real_object_not_the_marker() -> None:
    fixed = sr.classify_effective_signer(UnixSocketEnrollmentOfferSignerClient())
    assert fixed.identifier == sr.SIGNER_FIXED_UDS
    assert fixed.transport == sr.TRANSPORT_AF_UNIX
    assert fixed.bound_socket_path == ENROLLMENT_SIGNER_SOCKET_PATH
    assert fixed.selectable_socket is False

    sealed = sr.classify_effective_signer(SealedEnrollmentOfferSignerClient())
    assert sealed.identifier == sr.SIGNER_SEALED
    assert sealed.transport == sr.TRANSPORT_NONE


def test_a_subclass_or_double_is_never_the_reviewed_fixed_uds_client() -> None:
    class _Sneaky(UnixSocketEnrollmentOfferSignerClient):
        pass

    class _Fake:
        def sign_offer(self, context, *, now):  # noqa: ANN001, ANN201, D102
            raise AssertionError("never")

    assert sr.classify_effective_signer(_Sneaky()).identifier == sr.SIGNER_UNAVAILABLE
    assert sr.classify_effective_signer(_Fake()).identifier == sr.SIGNER_UNAVAILABLE
    assert sr.classify_effective_signer(None).identifier == sr.SIGNER_UNAVAILABLE


def test_process_environment_enablement_is_reported(clean_env) -> None:
    assert sr.no_process_env_enablement({"PATH": "/usr/bin"}) is True
    assert sr.no_process_env_enablement({"SECP_ENROLLMENT_SIGNER_ENABLED": "true"}) is False
    assert sr.no_process_env_enablement({"X_ENROLLMENT_SIGNER_ENABLE": "1"}) is False
    assert sr.no_process_env_enablement({"SECP_ENROLLMENT_SIGNER_ENABLED": "false"}) is True


# --------------------------------------------------------------------------- the no-sign probe


def test_the_probe_never_sends_a_signing_request() -> None:
    request = json.loads(sr._PROBE_REQUEST_BYTES.decode())
    assert request == {"op": sr.PROBE_OP}
    assert request["op"] != "sign_offer"
    assert "context" not in request and "now" not in request


def test_probe_ok_proves_peer_authorization_and_protocol_identity() -> None:
    result = sr.probe_broker_no_sign(exchange=_ok_exchange)
    assert result.status == sr.PROBE_OK
    assert result.peer_authorized is True
    assert result.protocol == sr.ENROLLMENT_SIGNER_BROKER_PROTOCOL


@pytest.mark.parametrize(
    ("reply", "status"),
    [
        (_PEER_UNAUTHORIZED, sr.PROBE_PEER_UNAUTHORIZED),
        (b'{"error":"enrollment_signer_peer_credentials_unavailable"}', sr.PROBE_PEER_UNAUTHORIZED),
        (b'{"error":"internal"}', sr.PROBE_PROTOCOL_MISMATCH),
        (b'{"offer":{}}', sr.PROBE_PROTOCOL_MISMATCH),
        (b'{"error": "enrollment_signer_request_invalid"}', sr.PROBE_PROTOCOL_MISMATCH),  # spaced
        (b'{"error":"enrollment_signer_request_invalid","x":1}', sr.PROBE_PROTOCOL_MISMATCH),
        (b"not json at all", sr.PROBE_PROTOCOL_MISMATCH),
        (b"", sr.PROBE_PROTOCOL_MISMATCH),
        (b'{"error":1}', sr.PROBE_PROTOCOL_MISMATCH),
    ],
)
def test_every_non_conforming_broker_reply_fails_closed(reply: bytes, status: str) -> None:
    result = sr.probe_broker_no_sign(exchange=lambda _r, _t: reply)
    assert result.status == status
    assert result.peer_authorized is (status == sr.PROBE_OK)
    assert result.protocol == ""


@pytest.mark.parametrize(
    "status",
    [
        sr.PROBE_NO_LISTENER,
        sr.PROBE_TIMEOUT,
        sr.PROBE_SOCKET_ABSENT,
        sr.PROBE_ENDPOINT_UNSAFE,
        sr.PROBE_UNSUPPORTED,
    ],
)
def test_every_transport_refusal_is_a_closed_status(status: str) -> None:
    def _refuse(_request: bytes, _timeout: float) -> bytes:
        raise sr._ProbeUnavailable(status)

    result = sr.probe_broker_no_sign(exchange=_refuse)
    assert result == sr.BrokerProbeResult(status, False, "")


def test_an_unexpected_transport_fault_fails_closed_without_raising() -> None:
    def _boom(_request: bytes, _timeout: float) -> bytes:
        raise RuntimeError("injected")

    assert sr.probe_broker_no_sign(exchange=_boom).status == sr.PROBE_NO_LISTENER


@pytest.mark.skipif(not _POSIX_UDS, reason="AF_UNIX is POSIX-only")
def test_the_fixed_listener_transport_probe_passes_end_to_end(tmp_path, monkeypatch) -> None:
    """The POSITIVE transport proof: a REAL AF_UNIX listener speaking the reviewed broker reply is
    reached over the fixed socket constant and classified ok/authorized/protocol-identified."""
    path = str(tmp_path / "broker.sock")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    listener.listen(1)
    seen: list[bytes] = []

    def _serve() -> None:
        conn, _ = listener.accept()
        with conn:
            chunks = []
            while True:
                chunk = conn.recv(1024)
                if not chunk:
                    break
                chunks.append(chunk)
            seen.append(b"".join(chunks))
            conn.sendall(_REQUEST_INVALID)

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    monkeypatch.setattr(sr, "ENROLLMENT_SIGNER_SOCKET_PATH", path)
    monkeypatch.setattr(sr, "_assert_fixed_endpoint", lambda: None)
    try:
        result = sr.probe_broker_no_sign(timeout=5.0)
    finally:
        thread.join(timeout=5)
        listener.close()
    assert result == sr.BrokerProbeResult(sr.PROBE_OK, True, sr.ENROLLMENT_SIGNER_BROKER_PROTOCOL)
    assert seen == [sr._PROBE_REQUEST_BYTES]  # exactly the no-sign document, nothing else


@pytest.mark.skipif(not _POSIX_UDS, reason="AF_UNIX is POSIX-only")
def test_a_stale_socket_inode_with_no_listener_fails_closed(tmp_path, monkeypatch) -> None:
    path = str(tmp_path / "stale.sock")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(path)  # bound but NEVER listening -> a stale inode with no accept loop
    sock.close()
    monkeypatch.setattr(sr, "ENROLLMENT_SIGNER_SOCKET_PATH", path)
    monkeypatch.setattr(sr, "_assert_fixed_endpoint", lambda: None)
    assert sr.probe_broker_no_sign(timeout=1.0).status == sr.PROBE_NO_LISTENER


@pytest.mark.skipif(os.name != "posix", reason="the endpoint posture gate is POSIX-only")
def test_an_alternate_endpoint_object_fails_closed(tmp_path, monkeypatch) -> None:
    regular = tmp_path / "not-a-socket"
    regular.write_bytes(b"")
    monkeypatch.setattr(sr, "ENROLLMENT_SIGNER_SOCKET_PATH", str(regular))
    with pytest.raises(sr._ProbeUnavailable) as exc:
        sr._assert_fixed_endpoint()
    assert exc.value.status == sr.PROBE_ENDPOINT_UNSAFE
    monkeypatch.setattr(sr, "ENROLLMENT_SIGNER_SOCKET_PATH", str(tmp_path / "absent.sock"))
    with pytest.raises(sr._ProbeUnavailable) as absent:
        sr._assert_fixed_endpoint()
    assert absent.value.status == sr.PROBE_SOCKET_ABSENT


# --------------------------------------------------------------------------- the observation


def test_ready_when_the_running_process_genuinely_proves_everything(
    session, tmp_path, clean_env, posix_process
) -> None:
    receipt = _activate_identity()
    payload = _observe(
        session, UnixSocketEnrollmentOfferSignerClient(), _marker_file(tmp_path, receipt)
    )
    assert payload["schema"] == sr.SIGNER_READINESS_SCHEMA
    assert payload["status"] == sr.STATUS_READY
    assert payload["effective_signer"] == sr.SIGNER_FIXED_UDS
    assert payload["signer_transport"] == sr.TRANSPORT_AF_UNIX
    assert payload["no_alternate_signer_activation"] is True
    assert payload["marker_present"] is True
    assert payload["marker_binding_matches_runtime"] is True
    assert payload["active_identity_present"] is True
    assert payload["active_identity_row_id"] == receipt["resulting_row_id"]
    assert payload["active_identity_activation_token"] == receipt["activation_token"]
    assert payload["activation_generation"] == 0
    assert payload["broker_probe"] == sr.PROBE_OK
    assert payload["broker_peer_authorized"] is True
    assert payload["broker_protocol"] == sr.ENROLLMENT_SIGNER_BROKER_PROTOCOL
    assert payload["process_uid"] == _API_UID and payload["process_gid"] == _API_GID
    sr.render_signer_readiness(payload)  # re-validates against its own strict closed schema


def test_marker_says_fixed_uds_but_the_effective_signer_is_sealed(
    session, tmp_path, clean_env, posix_process
) -> None:
    """The R4 defect, directly: a perfectly good marker must NOT make the surface report fixed-UDS
    when the app's real dependency is the sealed default — and the probe is not even attempted."""
    receipt = _activate_identity()
    payload = _observe(
        session, SealedEnrollmentOfferSignerClient(), _marker_file(tmp_path, receipt)
    )
    assert payload["marker_present"] is True and payload["marker_binding_matches_runtime"] is True
    assert payload["effective_signer"] == sr.SIGNER_SEALED
    assert payload["signer_transport"] == sr.TRANSPORT_NONE
    assert payload["broker_probe"] == sr.PROBE_NOT_ATTEMPTED
    assert payload["broker_peer_authorized"] is False
    assert payload["status"] == sr.STATUS_SEALED


def test_a_fake_signer_double_reports_unavailable(
    session, tmp_path, clean_env, posix_process
) -> None:
    class _Fake:
        def sign_offer(self, context, *, now):  # noqa: ANN001, ANN201, D102
            raise AssertionError("never")

    receipt = _activate_identity()
    payload = _observe(session, _Fake(), _marker_file(tmp_path, receipt))
    assert payload["effective_signer"] == sr.SIGNER_UNAVAILABLE
    assert payload["status"] == sr.STATUS_SEALED


def test_env_enablement_in_the_running_process_refuses_the_ready_status(
    session, tmp_path, monkeypatch, posix_process
) -> None:
    monkeypatch.setenv("SECP_ENROLLMENT_SIGNER_ENABLED", "true")
    receipt = _activate_identity()
    payload = _observe(
        session, UnixSocketEnrollmentOfferSignerClient(), _marker_file(tmp_path, receipt)
    )
    assert payload["no_alternate_signer_activation"] is False
    assert payload["status"] == sr.STATUS_SEALED


def test_absent_marker_is_reported_absent(session, tmp_path, clean_env, posix_process) -> None:
    _activate_identity()
    payload = _observe(
        session, UnixSocketEnrollmentOfferSignerClient(), str(tmp_path / "no-such-marker")
    )
    assert payload["marker_present"] is False
    assert payload["marker_binding_matches_runtime"] is False
    assert payload["marker_installation_id"] == "" and payload["marker_api_uid"] == 0
    assert payload["status"] == sr.STATUS_SEALED


def test_marker_binding_disagreeing_with_the_live_identity_fails_closed(
    session, tmp_path, clean_env, posix_process
) -> None:
    receipt = _activate_identity()
    drifted = _marker_file(tmp_path, receipt, installation_id="controller-other01")
    payload = _observe(session, UnixSocketEnrollmentOfferSignerClient(), drifted)
    assert payload["marker_present"] is True
    assert payload["marker_binding_matches_runtime"] is False
    assert payload["status"] == sr.STATUS_SEALED


def test_a_marker_bound_to_a_different_api_peer_fails_closed(
    session, tmp_path, clean_env, posix_process
) -> None:
    receipt = _activate_identity()
    other = _marker_file(tmp_path, receipt, api_uid=999, api_gid=999)
    payload = _observe(session, UnixSocketEnrollmentOfferSignerClient(), other)
    assert payload["marker_binding_matches_runtime"] is False
    assert payload["status"] == sr.STATUS_SEALED


def test_no_active_identity_leaves_the_generation_unproven(
    session, tmp_path, clean_env, posix_process
) -> None:
    receipt = {
        "resulting_row_id": "00000000-0000-0000-0000-000000000001",
        "activation_token": "00000000-0000-0000-0000-000000000001|2026-07-28 00:00:00+00:00",
    }
    payload = _observe(
        session, UnixSocketEnrollmentOfferSignerClient(), _marker_file(tmp_path, receipt)
    )
    assert payload["active_identity_present"] is False
    assert payload["activation_generation"] == -1
    assert payload["marker_binding_matches_runtime"] is False
    assert payload["status"] == sr.STATUS_SEALED


def test_a_failed_broker_probe_refuses_the_ready_status(
    session, tmp_path, clean_env, posix_process
) -> None:
    receipt = _activate_identity()
    payload = _observe(
        session,
        UnixSocketEnrollmentOfferSignerClient(),
        _marker_file(tmp_path, receipt),
        exchange=lambda _r, _t: _PEER_UNAUTHORIZED,
    )
    assert payload["broker_probe"] == sr.PROBE_PEER_UNAUTHORIZED
    assert payload["broker_peer_authorized"] is False
    assert payload["broker_protocol"] == ""
    assert payload["status"] == sr.STATUS_SEALED


# --------------------------------------------------------------------------- the payload contract


def test_the_payload_is_closed_canonical_bounded_and_versioned(
    session, tmp_path, clean_env, posix_process
) -> None:
    receipt = _activate_identity()
    payload = _observe(
        session, UnixSocketEnrollmentOfferSignerClient(), _marker_file(tmp_path, receipt)
    )
    assert set(payload) == set(sr.SIGNER_READINESS_FIELDS)
    raw = sr.render_signer_readiness(payload)
    assert raw == canonical_json(payload).encode("utf-8")
    assert len(raw) <= sr.SIGNER_READINESS_MAX_BYTES
    assert json.loads(raw.decode())["schema"] == "secp.api.enrollment-signer-readiness/v1"


def test_a_payload_that_fails_its_own_schema_is_never_served(
    session, tmp_path, clean_env, posix_process
) -> None:
    receipt = _activate_identity()
    payload = _observe(
        session, UnixSocketEnrollmentOfferSignerClient(), _marker_file(tmp_path, receipt)
    )
    for broken in (
        {**payload, "extra": 1},
        {k: v for k, v in payload.items() if k != "status"},
        {**payload, "schema": "secp.api.enrollment-signer-readiness/v2"},
        {**payload, "effective_signer": "root"},
        {**payload, "activation_generation": -2},
    ):
        with pytest.raises(ValueError):
            sr.render_signer_readiness(broken)


def test_the_payload_carries_no_secret_material(
    session, tmp_path, clean_env, posix_process
) -> None:
    receipt = _activate_identity()
    raw = sr.render_signer_readiness(
        _observe(session, UnixSocketEnrollmentOfferSignerClient(), _marker_file(tmp_path, receipt))
    ).decode()
    for forbidden in (
        "BEGIN",
        "PRIVATE",
        "password",
        "secret",
        "credential",
        "dsn",
        "postgresql://",
        "Authorization",
    ):
        assert forbidden.lower() not in raw.lower(), forbidden


# --------------------------------------------------------------------------- the route


@pytest.fixture
def app(engine):
    from secp_api.main import create_app

    return create_app()


@pytest.fixture
def client(app):
    return TestClient(app)


def test_the_route_is_one_fixed_read_only_get(app) -> None:
    paths = app.openapi()["paths"]
    assert sr.SIGNER_READINESS_PATH == "/internal/enrollment-signer/readiness"
    assert sr.SIGNER_READINESS_PATH in paths
    operations = paths[sr.SIGNER_READINESS_PATH]
    assert set(operations) == {"get"}  # read-only; no mutating verb exists on the surface
    # a FIXED surface: no path/query parameter, no body — nothing is caller-selectable
    assert "{" not in sr.SIGNER_READINESS_PATH
    assert not operations["get"].get("parameters")
    assert "requestBody" not in operations["get"]
    # it is NOT part of the public /api/v1 surface
    assert not sr.SIGNER_READINESS_PATH.startswith("/api/v1")


def test_the_route_returns_the_canonical_payload(app, client, tmp_path, monkeypatch) -> None:
    receipt = _activate_identity()
    marker = _marker_file(tmp_path, receipt)
    monkeypatch.setattr(sr, "MARKER_PATH", marker)
    monkeypatch.setattr(sr, "_process_ids", lambda: (_API_UID, _API_GID))
    monkeypatch.setattr(
        sr,
        "probe_broker_no_sign",
        lambda **_k: sr.BrokerProbeResult(sr.PROBE_OK, True, sr.ENROLLMENT_SIGNER_BROKER_PROTOCOL),
    )
    monkeypatch.delenv("SECP_ENROLLMENT_SIGNER_ENABLED", raising=False)

    from secp_api.deps import get_enrollment_offer_signer

    app.dependency_overrides[get_enrollment_offer_signer] = UnixSocketEnrollmentOfferSignerClient
    try:
        response = client.get(sr.SIGNER_READINESS_PATH)
    finally:
        app.dependency_overrides.pop(get_enrollment_offer_signer, None)
    assert response.status_code == 200
    body = json.loads(response.content.decode())
    assert set(body) == set(sr.SIGNER_READINESS_FIELDS)
    assert response.content == canonical_json(body).encode("utf-8")
    assert body["effective_signer"] == sr.SIGNER_FIXED_UDS
    assert body["status"] == sr.STATUS_READY


def test_the_route_defaults_to_the_sealed_signer_and_mutates_nothing(client) -> None:
    response = client.get(sr.SIGNER_READINESS_PATH)
    assert response.status_code == 200
    body = json.loads(response.content.decode())
    # the shipped default is the sealed client; no marker/identity exists in a bare test app
    assert body["effective_signer"] == sr.SIGNER_SEALED
    assert body["broker_probe"] == sr.PROBE_NOT_ATTEMPTED
    assert body["status"] == sr.STATUS_SEALED
    # calling it twice is identical: it is a pure read
    assert client.get(sr.SIGNER_READINESS_PATH).content == response.content


def test_the_route_refuses_every_mutating_method(client) -> None:
    for method in ("post", "put", "patch", "delete"):
        assert getattr(client, method)(sr.SIGNER_READINESS_PATH).status_code == 405
