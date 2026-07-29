"""The private signer-READINESS surface's origin gate (SECP-PR5H-B2, 2b-3c-c, Defect-3 B).

Defect-3 B: the readiness surface — the ONE authoritative report of the API's ACTUAL effective
signer, and the ONE thing that performs a live no-sign exchange against the root-owned broker
socket — was reachable by ANY peer that could reach the controller API's origin.

This suite drives the fix end to end through the REAL ASGI app:

* the gate is a ROUTER-level dependency, so it runs BEFORE any route body on the prefix. An
  unauthorized request never reaches the observation, never opens or connects the broker socket, and
  never performs the no-sign exchange — proven with tripwires that are themselves proven wired;
* missing / duplicated / malformed / wrong / cross-domain gate values are ALL the same bare 404, and
  an unconfigured controller with no gate file is that SAME 404 — the surface discloses nothing,
  not even whether it exists here;
* a PRESENT gate that cannot be proven safe is a bounded 503 instead, so a configured control that
  fails to load never degrades into an open surface;
* the worker-admission gate cannot authenticate readiness and the readiness gate cannot admit a
  worker, even with byte-identical secrets;
* the gate value never appears in a response body, a response header, a log record, a repr/str, or
  an exception.
"""

from __future__ import annotations

import inspect
import json
import logging

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from secp_api import signer_readiness as sr
from secp_api import signer_readiness_origin as sro
from secp_api.config import Settings
from secp_api.deps import settings_dep
from secp_api.fixed_origin_gate import FixedOriginGate
from secp_api.routers import signer_readiness as readiness_router
from secp_api.worker_admission_origin import (
    WORKER_ADMISSION_PROXY_GATE_HEADER,
    WorkerAdmissionProxyGateSecret,
    worker_admission_proxy_gate_secret,
)

_HEX = "d" * 64
_GATE = sro.EnrollmentSignerReadinessGateSecret(_HEX.encode())
_HEADER = sro.ENROLLMENT_SIGNER_READINESS_GATE_HEADER
_PATH = sr.SIGNER_READINESS_PATH
_NOT_FOUND = {"detail": {"code": "not_found"}}


@pytest.fixture
def bare_app(engine):
    """The REAL app with NO gate override — the production loader runs against the fixed path."""
    from secp_api.main import create_app

    return create_app()


@pytest.fixture
def app(bare_app):
    """The app with the root installer's authenticated hop modelled (no root-owned file needed)."""
    bare_app.dependency_overrides[sro.enrollment_signer_readiness_gate_secret] = lambda: _GATE
    return bare_app


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.fixture
def tripwires(monkeypatch):
    """Trip on ANY work the route body would do. Each records its name and then fails loudly, so a
    request that reaches the body can never be mistaken for one that was refused at the gate."""
    tripped: list[str] = []

    def _trip(name: str):
        def _fn(*_a: object, **_k: object):
            tripped.append(name)
            raise AssertionError(f"an unauthorized request reached {name}")

        return _fn

    monkeypatch.setattr(readiness_router, "observe_signer_readiness", _trip("observe"))
    monkeypatch.setattr(sr, "observe_signer_readiness", _trip("observe"))
    monkeypatch.setattr(sr, "probe_broker_no_sign", _trip("probe"))
    monkeypatch.setattr(sr, "_real_uds_exchange", _trip("uds_exchange"))
    monkeypatch.setattr(sr, "_assert_fixed_endpoint", _trip("endpoint_stat"))
    monkeypatch.setattr(sr, "load_valid_marker", _trip("marker_read"))
    return tripped


# --------------------------------------------------------------------------- router-level wiring


def _readiness_routes(app) -> list[APIRoute]:
    """EVERY compiled ``APIRoute`` the mounted app serves for the fixed readiness path.

    There is more than one: the supported GET, plus the explicit refusal handler that binds every
    other verb so an unauthorized caller cannot distinguish this path from an absent one by method
    (Starlette resolves the method BEFORE dependencies, so an unbound verb would answer 405)."""
    candidates = list(app.routes)
    for entry in list(candidates):
        original = getattr(entry, "original_router", None)
        if original is not None:
            candidates.extend(original.routes)
    return [r for r in candidates if isinstance(r, APIRoute) and getattr(r, "path", None) == _PATH]


def _readiness_route(app) -> APIRoute:
    """The compiled ``APIRoute`` serving the one SUPPORTED verb."""
    return next(r for r in _readiness_routes(app) if "GET" in r.methods)


def test_the_gate_is_a_router_level_dependency(app) -> None:
    """Router-level, not endpoint-level: it is declared once on the prefix and compiled into every
    route's dependant tree, so a future route added under the prefix cannot forget it."""
    declared = [d.dependency for d in readiness_router.router.dependencies]
    assert sro.require_enrollment_signer_readiness_origin in declared

    # the dependant tree the REAL mounted app walks per request (not merely the declaration)
    route = _readiness_route(app)
    resolved = [d.call for d in route.dependant.dependencies]
    assert resolved[0] is sro.require_enrollment_signer_readiness_origin
    # ... ahead of the DB session and the signer dependency the body needs
    assert len(resolved) > 1
    # the endpoint itself takes no gate parameter — the router owns the control, not the body
    assert "gate" not in inspect.signature(readiness_router.signer_readiness).parameters

    # EVERY route compiled under the prefix carries the gate FIRST, including the verb-refusal
    # handler — the property that makes the surface indistinguishable from an absent one.
    routes = _readiness_routes(app)
    assert len(routes) > 1
    for compiled in routes:
        first = [d.call for d in compiled.dependant.dependencies][0]
        assert first is sro.require_enrollment_signer_readiness_origin


def test_the_gate_domain_is_fixed_and_not_caller_selectable() -> None:
    gate = sro.ENROLLMENT_SIGNER_READINESS_GATE
    assert isinstance(gate, FixedOriginGate)
    assert gate.header == "X-SECP-Enrollment-Signer-Readiness-Gate"
    assert gate.container_path == "/run/secp/enrollment-signer-readiness-gate.secret"
    assert sro.ENROLLMENT_SIGNER_READINESS_GATE_HOST_PATH == (
        "/etc/secp/controller/enrollment-signer-readiness-gate.secret"
    )
    assert sro.ENROLLMENT_SIGNER_READINESS_GATE_FILE_BYTES == 65
    # neither the loader nor the dependency accepts a path/selector of any kind
    assert sro.load_fixed_enrollment_signer_readiness_gate.__code__.co_argcount == 0
    assert sro.enrollment_signer_readiness_gate_secret.__code__.co_argcount == 0
    # there is NO feature flag on this surface — the gate FILE is the configuration
    assert not hasattr(Settings(app_env="dev"), "enrollment_signer_readiness_enabled")


# --------------------------------------------------------------------------- refusals


def test_a_missing_gate_header_hides_the_surface(client, tripwires) -> None:
    response = client.get(_PATH)
    assert response.status_code == 404
    assert response.json() == _NOT_FOUND
    assert tripwires == []


@pytest.mark.parametrize(
    "value",
    [
        "e" * 64,  # a well-formed but WRONG value
        _HEX.upper(),  # the right value, wrong case
        _HEX[:-1],  # truncated
        _HEX + "d",  # extended
        _HEX + "\\n",  # the on-disk form, not the header form
        "",  # empty
        "not-a-gate-value",  # malformed
    ],
)
def test_every_wrong_or_malformed_gate_header_hides_the_surface(client, tripwires, value) -> None:
    response = client.get(_PATH, headers={_HEADER: value})
    assert response.status_code == 404
    assert response.json() == _NOT_FOUND
    assert tripwires == []


def test_a_duplicated_gate_header_hides_the_surface(client, tripwires) -> None:
    """Two identical CORRECT values still refuse: exactly one is accepted, so a header-injection
    that appends a second copy can never be collapsed into a single passing value."""
    response = client.get(_PATH, headers=[(_HEADER, _HEX), (_HEADER, _HEX)])
    assert response.status_code == 404
    assert response.json() == _NOT_FOUND
    assert tripwires == []


def test_every_refusal_is_byte_identical(client) -> None:
    """No oracle: absent, wrong, malformed and duplicated are indistinguishable to the caller."""
    responses = [
        client.get(_PATH),
        client.get(_PATH, headers={_HEADER: "e" * 64}),
        client.get(_PATH, headers={_HEADER: "malformed"}),
        client.get(_PATH, headers=[(_HEADER, _HEX), (_HEADER, _HEX)]),
    ]
    assert {r.status_code for r in responses} == {404}
    assert len({r.content for r in responses}) == 1
    assert all("gate" not in " ".join(r.headers.keys()).lower() for r in responses)


def test_no_verb_reveals_that_the_path_exists(client, tripwires) -> None:
    """Starlette resolves the METHOD before dependencies, so an unbound verb would answer 405 --
    telling an anonymous prober the path exists while GET returns 404. Every verb is bound, so an
    unauthorized caller sees the SAME refusal whatever it sends."""
    unauthorized = [
        client.get(_PATH),
        client.post(_PATH),
        client.put(_PATH),
        client.patch(_PATH),
        client.delete(_PATH),
        client.options(_PATH),
    ]
    assert {r.status_code for r in unauthorized} == {404}
    assert len({r.content for r in unauthorized}) == 1
    # and nothing ran: no observation, no broker socket, no no-sign exchange.
    assert tripwires == []


def test_an_AUTHORIZED_caller_still_gets_the_honest_method_refusal(client) -> None:
    """The indistinguishability above must not cost truthfulness for a party that holds the gate."""
    response = client.post(_PATH, headers={_HEADER: _HEX})
    assert response.status_code == 405
    assert response.json()["error"]["code"] == "signer_readiness_method_not_supported"


def test_an_unconfigured_controller_simply_has_no_surface(bare_app, tripwires) -> None:
    """No override: the REAL loader runs against the fixed container path, which does not exist on a
    controller that was never configured with a readiness gate. That is a plain 404, not a 503."""
    response = TestClient(bare_app).get(_PATH, headers={_HEADER: _HEX})
    assert response.status_code == 404
    assert response.json() == _NOT_FOUND
    assert tripwires == []


def test_a_present_but_unprovable_gate_is_a_bounded_503(bare_app, tmp_path, monkeypatch) -> None:
    """A PRESENT gate file that fails the root-owned/0640/one-link/exact-size posture is a bounded
    unavailability — a configured control that cannot be proven never silently opens the surface."""
    path = tmp_path / "gate.secret"
    path.write_bytes(b"d" * 64 + b"\n")  # present, correct bytes, ordinary (unsafe) posture
    monkeypatch.setattr(
        sro,
        "ENROLLMENT_SIGNER_READINESS_GATE",
        FixedOriginGate(
            header=_HEADER,
            container_path=str(path),
            secret_class=sro.EnrollmentSignerReadinessGateSecret,
        ),
    )
    response = TestClient(bare_app).get(_PATH, headers={_HEADER: _HEX})
    assert response.status_code == 503
    assert response.json() == {"detail": {"code": "enrollment_signer_readiness_gate_unavailable"}}
    assert _HEX not in response.text


def test_an_inconsistent_absent_gate_still_refuses(bare_app) -> None:
    """Defence in depth: even if the gate dependency yields ``None`` while a caller presents a
    perfectly good value, the surface stays hidden."""
    bare_app.dependency_overrides[sro.enrollment_signer_readiness_gate_secret] = lambda: None
    response = TestClient(bare_app).get(_PATH, headers={_HEADER: _HEX})
    assert response.status_code == 404
    assert response.json() == _NOT_FOUND


# --------------------------------------------------------------------------- the authorized path


def test_the_authorized_request_gets_the_strict_payload(client) -> None:
    response = client.get(_PATH, headers={_HEADER: _HEX})
    assert response.status_code == 200
    body = json.loads(response.content.decode())
    assert set(body) == set(sr.SIGNER_READINESS_FIELDS)
    assert body["schema"] == sr.SIGNER_READINESS_SCHEMA
    # a bare test app resolves the SHIPPED sealed signer; the gate authorizes, it never enables
    assert body["effective_signer"] == sr.SIGNER_SEALED
    assert body["status"] == sr.STATUS_SEALED


def test_the_tripwires_are_genuinely_wired(client, tripwires) -> None:
    """The control on the refusal tests above: with the SAME tripwires installed, an AUTHORIZED
    request DOES reach the observation. An empty tripwire list therefore means "never invoked",
    not "never instrumented"."""
    response = client.get(_PATH, headers={_HEADER: _HEX})
    assert tripwires == ["observe"]
    # the route turns the tripwire's fault into its own bounded closed refusal
    assert response.status_code == 503
    assert response.json() == {"error": {"code": "signer_readiness_unavailable"}}


def test_mutating_verbs_never_reach_a_body_authorized_or_not(client, tripwires) -> None:
    for method in ("post", "put", "patch", "delete"):
        assert getattr(client, method)(_PATH, headers={_HEADER: _HEX}).status_code == 405
        assert getattr(client, method)(_PATH).status_code in (404, 405)
    assert tripwires == []


# --------------------------------------------------------------------------- no cross-acceptance


def test_the_worker_admission_secret_cannot_authenticate_readiness(bare_app, tripwires) -> None:
    """Byte-identical material, presented under the readiness header, backed by the ADMISSION secret
    type: still 404. The domains share the mechanism, never the authority."""
    bare_app.dependency_overrides[sro.enrollment_signer_readiness_gate_secret] = lambda: (
        WorkerAdmissionProxyGateSecret(_HEX.encode())
    )
    client = TestClient(bare_app)
    assert client.get(_PATH, headers={_HEADER: _HEX}).status_code == 404
    # ... and presenting the correct readiness value under the ADMISSION header is equally refused
    bare_app.dependency_overrides[sro.enrollment_signer_readiness_gate_secret] = lambda: _GATE
    refused = client.get(_PATH, headers={WORKER_ADMISSION_PROXY_GATE_HEADER: _HEX})
    assert refused.status_code == 404 and refused.json() == _NOT_FOUND
    assert tripwires == []


def test_the_readiness_secret_cannot_admit_a_worker(bare_app) -> None:
    """The mirror image, over HTTP: the READINESS secret injected at the worker-admission gate does
    not admit. A gate that had passed would reach body validation (422), not a 404."""
    bare_app.dependency_overrides[settings_dep] = lambda: Settings(
        discovery_controlled_integration_enabled=True
    )
    bare_app.dependency_overrides[worker_admission_proxy_gate_secret] = lambda: _GATE
    response = TestClient(bare_app).post(
        "/internal/worker-discovery-admission/begin",
        json={},
        headers={
            WORKER_ADMISSION_PROXY_GATE_HEADER: _HEX,
            _HEADER: _HEX,
        },
    )
    assert response.status_code == 404
    assert response.json() == _NOT_FOUND


# --------------------------------------------------------------------------- non-disclosure


def test_the_gate_value_never_leaves_the_process(client, caplog) -> None:
    caplog.set_level(logging.DEBUG)
    responses = [
        client.get(_PATH),
        client.get(_PATH, headers={_HEADER: _HEX}),
        client.get(_PATH, headers={_HEADER: "e" * 64}),
    ]
    for response in responses:
        assert _HEX not in response.text
        assert _HEX not in str(dict(response.headers))
    assert _HEX not in caplog.text
    # the material itself is opaque in every rendering, and in a raised refusal
    assert _HEX not in repr(_GATE) and _HEX not in str(_GATE) and _HEX not in f"{_GATE}"
    with pytest.raises(sro.EnrollmentSignerReadinessGateError) as exc:
        sro.parse_enrollment_signer_readiness_gate(_HEX.encode() + b"XX")
    assert _HEX not in f"{exc.value!r} {exc.value} {exc.value.args!r}"
