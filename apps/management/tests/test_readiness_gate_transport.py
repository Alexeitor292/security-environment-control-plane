"""The readiness transport AUTHENTICATES to the fixed readiness route (SECP-PR5H-B2, 2b-3c-c, D).

Adversarial review of `11a7a6d` found the fixed enrollment-signer readiness route reachable by any
party that could reach the controller API at all (Defect 3). The route is now behind a dedicated
secret-backed MACHINE-ORIGIN gate, and this suite proves the management side of that contract:

* the gate value comes ONLY from the FIXED root-owned host path, read through the hardened
  filesystem seam -- never from a CLI flag, an environment variable, a caller argument, an operator
  token, or anything a browser could supply;
* it is sent as EXACTLY ONE header value on the single CA-pinned GET (the route refuses a duplicate
  header, so more than one would be a self-inflicted 404);
* the reviewed transport posture from `HttpsEnrollmentControllerClient` is unchanged: pinned CA
  context, ``trust_env=False``, no redirects, ``Accept-Encoding: identity``, bounded response;
* a missing, unsafe, or malformed gate fails the observation CLOSED rather than falling back to an
  unauthenticated request;
* the 256-bit value never appears in a refusal, a reason code, or any returned object.

Offline: a fake ``httpx.Client`` and the hardened in-memory filesystem. No network, no TLS, no host.
"""

from __future__ import annotations

import ssl

import httpx
import pytest
from secp_commissioning.enrollment_signer_binding_digest import (
    ENROLLMENT_SIGNER_READINESS_GATE_HEADER,
    ENROLLMENT_SIGNER_READINESS_GATE_HOST_PATH,
)
from secp_commissioning.runtime import InMemoryFilesystem
from secp_management import ManagementError
from secp_management.controller_api_locator import ControllerApiLocator
from secp_management.enrollment_signer_runtime_observer import (
    API_READINESS_PATH,
    build_readiness_transport,
)
from secp_management.layout import ManagementLocations
from secp_management.real_adapters import PinnedExecutables, RealAdapterContext
from secp_operator_deployment.pinned_exec import ExecutablePin

_ORIGIN = "https://controller.secp.internal:8443"
_CA = "/etc/secp/controller/tls/ca.crt"
_GATE_VALUE = "9f" * 32  # 64 lowercase hex characters == 256 bits
_GATE_FILE = (_GATE_VALUE + "\n").encode("ascii")


class _Locator:
    def locate(self) -> ControllerApiLocator:
        return ControllerApiLocator(canonical_origin=_ORIGIN, ca_bundle_path=_CA)


class _FakeResp:
    def __init__(self, status: int = 200, raw: bytes = b"{}") -> None:
        self.status_code = status
        self._raw = raw
        self.is_redirect = False
        self.headers = httpx.Headers({})

    @property
    def content(self) -> bytes:
        return self._raw


class _FakeClient:
    captured: dict = {}
    resp = _FakeResp()

    def __init__(self, **kw: object) -> None:
        _FakeClient.captured = {"init": kw}

    def __enter__(self) -> _FakeClient:
        return self

    def __exit__(self, *a: object) -> bool:
        return False

    def get(self, url: str, *, headers: dict) -> _FakeResp:
        _FakeClient.captured.update(url=url, headers=headers)
        return _FakeClient.resp


@pytest.fixture
def patched(monkeypatch: pytest.MonkeyPatch) -> type[_FakeClient]:
    monkeypatch.setattr(
        ssl, "create_default_context", lambda *, cafile: ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    )
    monkeypatch.setattr(httpx, "Client", _FakeClient)
    _FakeClient.captured = {}
    _FakeClient.resp = _FakeResp()
    return _FakeClient


def _fs(*, gate: bytes | None = _GATE_FILE, uid: int = 0, mode: int = 0o640) -> InMemoryFilesystem:
    fs = InMemoryFilesystem()
    for d in ("/etc", "/etc/secp", "/etc/secp/controller"):
        fs.seed_dir(d, uid=0, gid=0, mode=0o755)
    if gate is not None:
        fs.seed_file(
            ENROLLMENT_SIGNER_READINESS_GATE_HOST_PATH, gate, uid=uid, gid=10001, mode=mode
        )
    return fs


def _ctx(fs: InMemoryFilesystem) -> RealAdapterContext:
    pin = ExecutablePin(path="/usr/bin/docker", digest="sha256:" + "0" * 64)
    return RealAdapterContext(
        locations=ManagementLocations(),
        fs=fs,  # type: ignore[arg-type]
        runner=None,  # type: ignore[arg-type]
        executables=PinnedExecutables(
            container_runtime=pin, compose_runtime=pin, service_manager=pin
        ),
    )


def _transport(fs: InMemoryFilesystem):  # noqa: ANN202
    return build_readiness_transport(_ctx(fs), locator_provider=_Locator())


# ------------------------------------------------------------------ the gate reaches the route


def test_exactly_one_gate_header_carries_the_fixed_host_secret(patched) -> None:
    status, _ = _transport(_fs())()
    assert status == 200
    headers = patched.captured["headers"]
    # a dict key renders once: the route's "exactly one value" rule holds by construction.
    assert headers[ENROLLMENT_SIGNER_READINESS_GATE_HEADER] == _GATE_VALUE
    assert sum(1 for k in headers if k == ENROLLMENT_SIGNER_READINESS_GATE_HEADER) == 1
    assert patched.captured["url"] == _ORIGIN + API_READINESS_PATH


def test_the_trailing_newline_is_never_sent_as_part_of_the_header_value(patched) -> None:
    _transport(_fs())()
    value = patched.captured["headers"][ENROLLMENT_SIGNER_READINESS_GATE_HEADER]
    assert value == _GATE_VALUE and "\n" not in value and value == value.strip()


def test_no_operator_credential_cookie_or_authorization_is_ever_attached(patched) -> None:
    _transport(_fs())()
    headers = patched.captured["headers"]
    assert set(headers) == {
        "Accept",
        "Accept-Encoding",
        ENROLLMENT_SIGNER_READINESS_GATE_HEADER,
    }
    assert "Authorization" not in headers and "Cookie" not in headers


def test_the_reviewed_pinned_posture_is_unchanged_by_the_gate(patched) -> None:
    _transport(_fs())()
    init = patched.captured["init"]
    assert isinstance(init["verify"], ssl.SSLContext)  # pinned CA, never True/False/system trust
    assert init["trust_env"] is False
    assert init["follow_redirects"] is False
    assert init["timeout"] > 0
    assert patched.captured["headers"]["Accept-Encoding"] == "identity"


# ------------------------------------------------------------------ every gate fault fails CLOSED


@pytest.mark.parametrize(
    "gate,uid,mode",
    [
        (None, 0, 0o640),  # absent
        (_GATE_FILE, 1000, 0o640),  # not root-owned
        (_GATE_FILE, 0, 0o644),  # world-readable
        ((("A" * 64) + "\n").encode("ascii"), 0, 0o640),  # not lowercase hex
        (b"9f" * 32, 0, 0o640),  # no trailing newline
        ((("9f" * 31) + "\n").encode("ascii"), 0, 0o640),  # short of 256 bits
        ((_GATE_VALUE + "\n" + _GATE_VALUE + "\n").encode("ascii"), 0, 0o640),  # two secrets
    ],
)
def test_an_unusable_gate_refuses_instead_of_sending_an_unauthenticated_request(
    patched, gate, uid, mode
) -> None:
    with pytest.raises(ManagementError) as exc:
        _transport(_fs(gate=gate, uid=uid, mode=mode))()
    assert exc.value.reason_code == "api_signer_readiness_gate_invalid"
    # the decisive property: no request was ever issued without the gate.
    assert "headers" not in patched.captured


def test_a_gate_fault_never_echoes_the_secret_or_the_path_contents(patched) -> None:
    with pytest.raises(ManagementError) as exc:
        _transport(_fs(gate=(("bad" * 30) + "\n").encode("ascii")))()
    rendered = f"{exc.value!r} {exc.value.reason_code}"
    assert _GATE_VALUE not in rendered and "bad" * 30 not in rendered


def test_the_gate_value_is_absent_from_the_returned_response(patched) -> None:
    _FakeClient.resp = _FakeResp(200, b'{"schema": "x"}')
    status, raw = _transport(_fs())()
    assert status == 200
    assert _GATE_VALUE.encode("ascii") not in raw
