"""B1B-PR5B — the reviewed CONCRETE backend transports + exact-implementation binding (ADR-022 §10).

These prove that the committed tree contains ACTUAL concrete production transports (not merely
Protocols / sealed defaults / fakes): a hardened OpenBao HTTPS transport and a hardened HTTP
state-control transport. They exercise the hardening (HTTPS-only origin, exact-CA TLS, no proxy
inheritance, no redirects, bounded size/depth, method/path allowlist, no state body, closed reason
codes with no leakage) fully OFFLINE via an injected ``httpx.MockTransport`` — nothing contacts a
network. They also prove the controlled-live composition binds the EXACT concrete implementations by
un-forgeable identity + registration and refuses every duck-typed / foreign / sealed / test
substitute.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import httpx
import pytest
from secp_worker.hardened_http import (
    HardenedTransportError,
    SealedWorkerAuthMaterialProvider,
    WorkerAuthMaterialUnavailable,
    parse_bounded_json,
    validate_https_origin,
    validate_relative_control_path,
)
from secp_worker.openbao_plan_http_transport import (
    OPENBAO_PLAN_HTTP_TRANSPORT_REGISTRATION,
    OpenBaoHttpTransport,
    openbao_plan_http_transport_digest,
)
from secp_worker.plan_gen.openbao_plan_resolver import (
    ConcreteOpenBaoPlanSecretClient,
    OpenBaoPlanSecretResolver,
    SealedPlanSecretBackendTransport,
    assert_concrete_openbao_plan_resolver,
)
from secp_worker.readiness.http_state_adapter import (
    HttpRemoteStateReadinessAdapter,
    assert_concrete_state_adapter,
)
from secp_worker.readiness.http_state_probe import (
    ConcreteHttpStateControlProbe,
    SealedStateBackendControlTransport,
)
from secp_worker.reviewed_identity import ReviewedIdentityError
from secp_worker.state_control_http_transport import (
    STATE_CONTROL_HTTP_TRANSPORT_REGISTRATION,
    HttpStateControlTransport,
    StateBackendControlEndpoints,
    state_control_http_transport_digest,
)

NOW = datetime(2026, 7, 15, tzinfo=UTC)


class _FakeAuth:
    """Non-serializable test auth provider (yields an inert non-secret header)."""

    def __getstate__(self):  # noqa: ANN204
        raise TypeError("cannot serialize")

    def auth_headers(self, *, now):  # noqa: ANN001, ANN201
        return {"X-Vault-Token": "TEST-TOKEN"}


def _patch_httpx(monkeypatch, handler):
    """Route every hardened client's requests to ``handler`` (offline) while capturing the exact
    hardened kwargs the transport passed to ``httpx.Client``. Also stubs the CA-bundle load (a local
    file read) so tests need no real CA on disk; the returned context is unused by the mock."""
    captured: dict = {}
    real_client = httpx.Client  # capture BEFORE patching (else _fake_client recurses into itself)

    def _fake_client(**kwargs):  # noqa: ANN003, ANN202
        captured.update(kwargs)
        return real_client(transport=httpx.MockTransport(handler), timeout=kwargs.get("timeout"))

    def _fake_ssl(ca_path):  # noqa: ANN001, ANN202
        import ssl

        return ssl.create_default_context()

    monkeypatch.setattr(httpx, "Client", _fake_client)
    monkeypatch.setattr("secp_worker.openbao_plan_http_transport.build_ssl_context", _fake_ssl)
    monkeypatch.setattr("secp_worker.state_control_http_transport.build_ssl_context", _fake_ssl)
    return captured


def _openbao_transport(**over):
    base = dict(
        origin="https://vault.example",
        ca_path="/etc/ssl/certs/reviewed-ca.pem",
        auth_provider=_FakeAuth(),
    )
    base.update(over)
    return OpenBaoHttpTransport(**base)


def _state_endpoints(**over):
    base = dict(
        namespace_metadata_path="/v1/state/meta",
        capabilities_path="/v1/auth/token/lookup-self",
        readiness_lock_path="/v1/state/readiness-lock",
    )
    base.update(over)
    return StateBackendControlEndpoints(**base)


def _state_transport(**over):
    base = dict(
        state_address="https://state.example/lab",
        plan_lock_address="https://state.example/lab?lock",
        plan_unlock_address="https://state.example/lab?unlock",
        ca_path="/etc/ssl/certs/reviewed-ca.pem",
        auth_provider=_FakeAuth(),
        endpoints=_state_endpoints(),
        readiness_lock_id=str(uuid.uuid4()),
    )
    base.update(over)
    return HttpStateControlTransport(**base)


# --- the concrete transports exist and are identity/registration/digest-pinned -------------------


def test_concrete_transport_classes_exist_with_pinned_identity_and_digest():
    ob = _openbao_transport()
    assert type(ob).__module__ == "secp_worker.openbao_plan_http_transport"
    assert ob.IMPLEMENTATION_ID == OPENBAO_PLAN_HTTP_TRANSPORT_REGISTRATION
    assert ob.implementation_registration == OPENBAO_PLAN_HTTP_TRANSPORT_REGISTRATION
    assert ob.implementation_digest == openbao_plan_http_transport_digest()
    assert ob.implementation_digest.startswith("sha256:")

    st = _state_transport()
    assert type(st).__module__ == "secp_worker.state_control_http_transport"
    assert st.IMPLEMENTATION_ID == STATE_CONTROL_HTTP_TRANSPORT_REGISTRATION
    assert st.implementation_digest == state_control_http_transport_digest()


def test_pinned_identities_match_actual_classes_no_drift():
    from secp_worker.plan_gen import openbao_plan_resolver as r
    from secp_worker.readiness import http_state_adapter as a
    from secp_worker.readiness.http_state_probe import CONCRETE_HTTP_STATE_PROBE_REGISTRATION

    assert r._TRANSPORT_IDENTITY == "secp_worker.openbao_plan_http_transport.OpenBaoHttpTransport"
    assert r._TRANSPORT_REGISTRATION == OpenBaoHttpTransport.IMPLEMENTATION_ID
    assert a._PROBE_REGISTRATION == CONCRETE_HTTP_STATE_PROBE_REGISTRATION
    assert (
        a._PROBE_IDENTITY == "secp_worker.readiness.http_state_probe.ConcreteHttpStateControlProbe"
    )
    assert (
        a._STATE_TRANSPORT_IDENTITY
        == "secp_worker.state_control_http_transport.HttpStateControlTransport"
    )
    assert a._STATE_TRANSPORT_REGISTRATION == HttpStateControlTransport.IMPLEMENTATION_ID


def test_transports_construct_without_contact_and_are_non_serializable():
    import pickle

    for transport in (_openbao_transport(), _state_transport()):
        with pytest.raises(TypeError):
            pickle.dumps(transport)
        # Redacted repr — never the origin / CA path.
        assert "vault.example" not in repr(transport)
        assert "state.example" not in repr(transport)


# --- origin + path validation --------------------------------------------------------------------


@pytest.mark.parametrize(
    "origin",
    [
        "http://vault.example",  # not https
        "https://user:pw@vault.example",  # userinfo
        "https://vault.example/?q=1",  # query
        "https://vault.example/#frag",  # fragment
        "https://vault.example/some/path",  # non-root path
        "https://vault.example:99999",  # bad port
        "ftp://vault.example",  # wrong scheme
        "",  # empty
    ],
)
def test_https_origin_validation_fails_closed(origin):
    with pytest.raises(HardenedTransportError):
        validate_https_origin(origin)
    # Constructing a transport with a bad origin fails closed at construction (no contact).
    with pytest.raises(HardenedTransportError):
        _openbao_transport(origin=origin)


@pytest.mark.parametrize(
    "path", ["v1/no/leading/slash", "/v1/../escape", "/v1/state?x=1", "/v1/ space", "https://x/y"]
)
def test_relative_control_path_validation_fails_closed(path):
    with pytest.raises(HardenedTransportError):
        validate_relative_control_path(path)


# --- OpenBao transport: hardening + happy path + adversarial responses ----------------------------


def _ok_kv(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"data": {"data": {"value": "SECRET-TOKEN"}}})


def test_openbao_reads_the_exact_kv_path_and_returns_only_the_value(monkeypatch):
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["method"] = request.method
        seen["url"] = str(request.url)
        seen["token"] = request.headers.get("X-Vault-Token")
        return _ok_kv(request)

    captured = _patch_httpx(monkeypatch, handler)
    transport = _openbao_transport()
    result = transport.read(locator="secret/proxmox/plan", now=NOW)
    assert result == {"value": "SECRET-TOKEN"}
    # Exactly one hardened GET to the exact KV-v2 data path; the token header was sent.
    assert seen["method"] == "GET"
    assert seen["url"] == "https://vault.example/v1/secret/data/proxmox/plan"
    assert seen["token"] == "TEST-TOKEN"
    # The client was opened hardened: exact CA verifier (an SSLContext), no env, no redirects,
    # bounded.
    import ssl

    assert isinstance(captured["verify"], ssl.SSLContext)
    assert captured["trust_env"] is False
    assert captured["follow_redirects"] is False
    assert captured["timeout"] is not None


def test_openbao_sealed_auth_never_contacts_the_backend(monkeypatch):
    called = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover - must never run
        called["n"] += 1
        return _ok_kv(request)

    _patch_httpx(monkeypatch, handler)
    transport = _openbao_transport(auth_provider=SealedWorkerAuthMaterialProvider())
    with pytest.raises(WorkerAuthMaterialUnavailable):
        transport.read(locator="secret/x", now=NOW)
    assert called["n"] == 0  # auth material is obtained BEFORE any contact


@pytest.mark.parametrize(
    ("response", "reason"),
    [
        (httpx.Response(302, headers={"location": "https://evil.example"}), "redirect_forbidden"),
        (httpx.Response(404), "reference_unknown"),
        (httpx.Response(403), "authentication_failed"),
        (httpx.Response(500), "backend_status_error"),
    ],
)
def test_openbao_maps_backend_status_to_closed_reasons(monkeypatch, response, reason):
    _patch_httpx(monkeypatch, lambda request: response)
    transport = _openbao_transport()
    with pytest.raises(HardenedTransportError) as exc:
        transport.read(locator="secret/x", now=NOW)
    assert exc.value.reason_code == reason
    # No origin / host leaks in the closed message.
    assert "vault.example" not in str(exc.value)


def test_openbao_refuses_oversized_and_deeply_nested_responses(monkeypatch):
    _patch_httpx(monkeypatch, lambda request: httpx.Response(200, content=b"x" * (128 * 1024)))
    with pytest.raises(HardenedTransportError, match="response_too_large"):
        _openbao_transport().read(locator="secret/x", now=NOW)

    deep = b"[" * 40 + b"]" * 40
    _patch_httpx(monkeypatch, lambda request: httpx.Response(200, content=deep))
    with pytest.raises(HardenedTransportError):  # too deep / malformed → closed
        _openbao_transport().read(locator="secret/x", now=NOW)


def test_openbao_connect_failure_is_closed_and_leaks_nothing(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection to vault.example refused")

    _patch_httpx(monkeypatch, handler)
    with pytest.raises(HardenedTransportError) as exc:
        _openbao_transport().read(locator="secret/x", now=NOW)
    assert exc.value.reason_code == "backend_unreachable"
    assert "vault.example" not in str(exc.value)


def test_openbao_through_the_concrete_client_yields_secret(monkeypatch):
    _patch_httpx(monkeypatch, _ok_kv)
    client = ConcreteOpenBaoPlanSecretClient(transport=_openbao_transport())
    assert client.read_plan_secret(reference="openbao://secret/x", scheme="openbao", now=NOW) == (
        "SECRET-TOKEN"
    )


def test_bounded_json_rejects_pathological_shapes():
    with pytest.raises(HardenedTransportError, match="response_too_large"):
        parse_bounded_json(b"x" * (128 * 1024))
    with pytest.raises(HardenedTransportError, match="response_too_deep"):
        parse_bounded_json(b"[" * 40 + b"]" * 40)
    with pytest.raises(HardenedTransportError, match="response_string_too_long"):
        parse_bounded_json(b'"' + b"a" * (9 * 1024) + b'"')
    assert parse_bounded_json(b'{"value": "ok"}') == {"value": "ok"}


# --- state-control transport: control-metadata only; no state body; method/URL allowlist ----------


def test_state_transport_exposes_no_state_body_method():
    st = _state_transport()
    for forbidden in (
        "get_state",
        "read_state",
        "download_state",
        "upload_state",
        "write_state",
        "put_state",
        "restore_state",
        "delete_state",
        "force_unlock",
        "request",
        "get",
        "post",
    ):
        assert not hasattr(st, forbidden), forbidden


def test_state_transport_send_enforces_exact_method_to_endpoint_policy():
    st = _state_transport()
    # A method valid for a DIFFERENT endpoint (or a wholly invalid method) refuses before any
    # contact.
    for method, endpoint in [
        ("DELETE", "metadata"),  # no arbitrary method
        ("GET", "readiness_lock"),  # GET is capabilities-only, never the lock endpoint
        ("GET", "metadata"),  # GET is capabilities-only, never metadata (which is HEAD-only)
        ("HEAD", "capabilities"),  # HEAD is metadata-only
        ("LOCK", "metadata"),  # LOCK is readiness-lock-only
        ("GET", "state"),  # there is no 'state' endpoint key at all
    ]:
        with pytest.raises(HardenedTransportError, match="method_endpoint_forbidden"):
            st._send(method, endpoint, now=NOW, read_body=False)


def test_state_namespace_occupancy_uses_head_and_maps_status(monkeypatch):
    seen: list = []
    status_box = {"s": 404}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, str(request.url)))
        return httpx.Response(status_box["s"])

    _patch_httpx(monkeypatch, handler)
    st = _state_transport()
    assert st.namespace_occupied(now=NOW) is False
    assert seen[-1] == ("HEAD", "https://state.example/v1/state/meta")
    status_box["s"] = 200
    assert st.namespace_occupied(now=NOW) is True
    status_box["s"] = 500
    assert st.namespace_occupied(now=NOW) is None


def test_state_granted_actions_parses_bounded_capabilities(monkeypatch):
    body_box = {"json": {"actions": ["Read", "write", "lock"]}}
    _patch_httpx(monkeypatch, lambda request: httpx.Response(200, json=body_box["json"]))
    st = _state_transport()
    assert st.granted_actions(now=NOW) == ("read", "write", "lock")
    body_box["json"] = {"nope": []}
    assert st.granted_actions(now=NOW) is None


def test_state_lock_probe_acquires_detects_contention_and_releases(monkeypatch):
    calls: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.method)
        if request.method == "LOCK":
            # First LOCK grants (200); a second LOCK conflicts (423).
            return httpx.Response(200 if calls.count("LOCK") == 1 else 423)
        return httpx.Response(200)  # UNLOCK

    _patch_httpx(monkeypatch, handler)
    st = _state_transport()
    handle = st.acquire_readiness_lock(now=NOW)
    assert handle is not None and handle.caller_supplied_owner is False
    assert st.probe_contention(now=NOW) is True  # second lock correctly refused
    assert st.release_readiness_lock(handle, now=NOW) is True


def test_state_force_unlock_and_local_fallback_are_never_available():
    st = _state_transport()
    assert st.force_unlock_available(now=NOW) is False
    assert st.local_fallback_reachable(now=NOW) is False
    posture = st.security_posture(now=NOW)
    assert posture.tls_verified and posture.certificate_validation_enabled
    assert posture.proxy_inheritance_enabled is False and posture.redirect_observed is False


def test_state_redirect_on_a_control_endpoint_fails_that_facet(monkeypatch):
    _patch_httpx(
        monkeypatch, lambda request: httpx.Response(302, headers={"location": "https://evil"})
    )
    # A redirect on the metadata HEAD is not a 200/404 → occupancy undeterminable (fails closed).
    assert _state_transport().namespace_occupied(now=NOW) is None


# --- controlled-live composition binding refuses every non-concrete substitute --------------------


def _concrete_state_adapter():
    transport = _state_transport()
    probe = ConcreteHttpStateControlProbe(transport=transport, lock_issuer=uuid.uuid4())
    return HttpRemoteStateReadinessAdapter(probe=probe)


class _DuckResolver:
    IMPLEMENTATION_ID = "secp-002b-1b-pr5b/openbao-plan-resolver/v1"  # forged registration

    def resolve(self, *a, **k):  # noqa: ANN002, ANN003, ANN201
        raise AssertionError


def test_assert_concrete_openbao_resolver_refuses_every_substitute():
    from tests.test_plan_execution_components import production_bound_openbao_plan_resolver

    assert_concrete_openbao_plan_resolver(production_bound_openbao_plan_resolver())  # ok

    # Duck-typed object that forges the registration → refused by un-forgeable identity.
    with pytest.raises(ReviewedIdentityError, match="plan_resolver_not_concrete"):
        assert_concrete_openbao_plan_resolver(_DuckResolver())
    # The sealed resolver (no client) → not concrete.
    with pytest.raises(ReviewedIdentityError, match="plan_resolver_not_concrete"):
        assert_concrete_openbao_plan_resolver(SealedPlanSecretResolver_impl())
    # The concrete resolver over a SEALED transport → not production bound.
    sealed_chain = OpenBaoPlanSecretResolver(
        client=ConcreteOpenBaoPlanSecretClient(transport=SealedPlanSecretBackendTransport())
    )
    with pytest.raises(ReviewedIdentityError, match="not_production_bound"):
        assert_concrete_openbao_plan_resolver(sealed_chain)
    # The concrete resolver over a fake client → not production bound.
    with pytest.raises(ReviewedIdentityError, match="not_production_bound"):
        assert_concrete_openbao_plan_resolver(OpenBaoPlanSecretResolver(client=object()))


def SealedPlanSecretResolver_impl():  # noqa: N802 - a tiny helper returning the sealed resolver
    from secp_worker.plan_gen.plan_secret_resolution import SealedPlanSecretResolver

    return SealedPlanSecretResolver()


def test_assert_concrete_state_adapter_refuses_every_substitute():
    assert_concrete_state_adapter(_concrete_state_adapter())  # ok

    # The sealed adapter (sealed probe) → not production bound.
    with pytest.raises(ReviewedIdentityError, match="not_production_bound"):
        assert_concrete_state_adapter(HttpRemoteStateReadinessAdapter())
    # The concrete adapter over a probe with a SEALED transport → not production bound.
    sealed_probe = ConcreteHttpStateControlProbe(
        transport=SealedStateBackendControlTransport(), lock_issuer=uuid.uuid4()
    )
    with pytest.raises(ReviewedIdentityError, match="not_production_bound"):
        assert_concrete_state_adapter(HttpRemoteStateReadinessAdapter(probe=sealed_probe))
    # A foreign object claiming to be an adapter → refused by identity.
    with pytest.raises(ReviewedIdentityError, match="state_adapter_not_concrete"):
        assert_concrete_state_adapter(object())


def test_controlled_live_plan_composition_refuses_a_sealed_resolver():
    from secp_worker.plan_gen.composition import (
        PlanExecutionCompositionError,
        verify_plan_execution_composition,
    )
    from secp_worker.plan_gen.plan_secret_resolution import SealedPlanSecretResolver
    from tests.test_plan_execution_components import _activated_composition

    # The concrete controlled-live composition verifies; swapping in a sealed resolver is refused.
    verify_plan_execution_composition(_activated_composition(classification="controlled_live"))
    with pytest.raises(PlanExecutionCompositionError, match="not_concrete"):
        verify_plan_execution_composition(
            _activated_composition(
                classification="controlled_live", provider_resolver=SealedPlanSecretResolver()
            )
        )


def test_controlled_live_readiness_provider_refuses_a_sealed_or_fake_state_adapter():
    from secp_worker.readiness.composition import ReadinessComposition, ReadinessGate
    from secp_worker.readiness.composition_provider import (
        ControlledLiveReadinessCompositionProvider,
        ReadinessCompositionProviderError,
    )
    from secp_worker.readiness.state_adapter import SealedRemoteStateReadinessAdapter

    gate = ReadinessGate(enabled=True)
    # A concrete adapter is accepted.
    ControlledLiveReadinessCompositionProvider(
        ReadinessComposition(gate=gate, state_adapter=_concrete_state_adapter())
    )
    # No adapter (toolchain-only controlled-live) is allowed — state readiness then refuses at seal.
    ControlledLiveReadinessCompositionProvider(ReadinessComposition(gate=gate))
    # The sealed adapter is refused.
    with pytest.raises(ReadinessCompositionProviderError, match="not_concrete"):
        ControlledLiveReadinessCompositionProvider(
            ReadinessComposition(gate=gate, state_adapter=SealedRemoteStateReadinessAdapter())
        )
    # A foreign/duck-typed adapter is refused.
    with pytest.raises(ReadinessCompositionProviderError, match="not_concrete"):
        ControlledLiveReadinessCompositionProvider(
            ReadinessComposition(gate=gate, state_adapter=object())
        )


# --- the atomic operator worker registration -----------------------------------------------------


def _settings(**over):
    from secp_api.config import Settings

    base = dict(temporal_task_queue="secp-orchestration", temporal_operator_task_queue="secp-op")
    base.update(over)
    return Settings(**base)


def _compositions():
    from tests.test_operator_bootstrap import (
        _controlled_live_eligibility_composition,
        _controlled_live_plan_composition,
        _controlled_live_readiness_composition,
    )

    return dict(
        plan_execution_composition=_controlled_live_plan_composition(),
        readiness_composition=_controlled_live_readiness_composition(),
        eligibility_composition=_controlled_live_eligibility_composition(),
    )


def test_operator_registration_is_atomic_queue_five_workflows_five_activities():
    from secp_worker.operator_bootstrap import (
        OperatorWorkerRegistration,
        build_operator_worker_registration,
    )

    reg = build_operator_worker_registration(settings=_settings(), **_compositions())
    assert isinstance(reg, OperatorWorkerRegistration)
    # Queue equals resolve_operator_task_queue(settings) and differs from the shipped queue.
    from secp_api.workflow_routing import resolve_operator_task_queue

    assert reg.task_queue == resolve_operator_task_queue(_settings()) == "secp-op"
    assert reg.task_queue != _settings().temporal_task_queue
    # Exactly five workflows + five activities + five stable, unique names.
    assert len(reg.workflows) == len(reg.activities) == len(reg.activity_names) == 5
    assert len(set(reg.activity_names)) == 5
    # No deploy/reset/destroy/discovery workflow is present.
    names = {w.__name__ for w in reg.workflows}
    assert not (names & {"DeployWorkflow", "ResetWorkflow", "DestroyWorkflow", "DiscoverWorkflow"})
    # Immutable tuples (no mutable list is returned).
    assert isinstance(reg.workflows, tuple)
    assert isinstance(reg.activities, tuple)
    assert isinstance(reg.activity_names, tuple)


def test_operator_registration_fails_closed_without_a_distinct_queue():
    from secp_api.workflow_routing import OperatorTaskQueueUnavailable
    from secp_worker.operator_bootstrap import build_operator_worker_registration

    with pytest.raises(OperatorTaskQueueUnavailable):
        build_operator_worker_registration(
            settings=_settings(temporal_operator_task_queue=""), **_compositions()
        )
