"""B1B-PR5B — authoritative destination binding (ADR-022 §5/§6) — destination-binding defect fix.

Proves the provider endpoint is bound to the approved ``ExecutionTarget`` and the HTTP state backend
(readiness transport + OpenTofu runtime inputs) is bound to the immutable
``ToolchainProfile.state_backend.reference`` — so readiness can never validate backend A while
OpenTofu plans against backend B, and the provider endpoint can never differ from the approved
Proxmox target. Every mismatch refuses with a bounded, closed reason BEFORE any resolver, process,
or
network contact. All checks are pure / offline.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from secp_scenario_schema import content_hash
from secp_worker.hardened_http import HardenedTransportError
from secp_worker.plan_gen.destination_binding import (
    AuthoritativeStateBackendBinding,
    DestinationBindingError,
    assert_provider_endpoint_bound,
    assert_readiness_backend_equals,
    assert_state_runtime_bound,
    canonical_provider_endpoint,
    derive_state_backend_binding,
)
from secp_worker.readiness.http_state_probe import ConcreteHttpStateControlProbe
from secp_worker.readiness.state_adapter import RemoteStateReadinessBinding
from secp_worker.state_control_http_transport import (
    HttpStateControlTransport,
    StateBackendControlEndpoints,
)
from tests.test_concrete_state_adapter import _readiness_binding
from tests.test_concrete_transports import _FakeAuth, _state_endpoints

NOW = datetime(2026, 7, 15, tzinfo=UTC)


class _Target:
    def __init__(self, config, *, plugin_name="proxmox", config_hash=None):  # noqa: ANN001
        self.plugin_name = plugin_name
        self.config = config
        self.config_hash = config_hash if config_hash is not None else content_hash(config)


class _StateSrc:
    def __init__(self, address, lock_address, unlock_address, username="svc"):  # noqa: ANN001
        self.address = address
        self.lock_address = lock_address
        self.unlock_address = unlock_address
        self.username = username


# --- 1. provider endpoint bound to the authoritative target --------------------------------------


def test_provider_endpoint_binds_to_the_authoritative_target():
    target = _Target({"base_url": "https://pve.example:8006/api2/json", "verify_tls": True})
    provider_input = assert_provider_endpoint_bound(
        target=target, composition_endpoint="https://pve.example:8006/api2/json"
    )
    assert provider_input.endpoint == "https://pve.example:8006/api2/json"


def test_provider_default_port_and_hostname_case_are_canonically_equivalent():
    # Omitted port == :443, and hostname case is normalized — deliberate canonical equivalence.
    target = _Target({"base_url": "https://API.example/tf"})
    assert (
        assert_provider_endpoint_bound(
            target=target, composition_endpoint="https://api.example:443/tf"
        ).endpoint
        == "https://api.example:443/tf"
    )
    assert canonical_provider_endpoint("https://x.example/a/") == "https://x.example:443/a"


@pytest.mark.parametrize(
    "composition_endpoint",
    [
        "https://pve.example:8006/DIFFERENT",  # path mismatch
        "https://other.example:8006/api2/json",  # host mismatch
        "https://pve.example:9000/api2/json",  # port mismatch
        "http://pve.example:8006/api2/json",  # scheme mismatch (also not https)
    ],
)
def test_provider_endpoint_mismatch_refuses(composition_endpoint):
    target = _Target({"base_url": "https://pve.example:8006/api2/json"})
    with pytest.raises(DestinationBindingError) as exc:
        assert_provider_endpoint_bound(target=target, composition_endpoint=composition_endpoint)
    assert exc.value.reason_code in {"provider_endpoint_mismatch", "provider_endpoint_not_https"}
    # The endpoint never leaks in the closed reason.
    assert "pve.example" not in str(exc.value)


def test_provider_non_proxmox_plugin_and_stale_config_hash_refuse():
    ok = {"base_url": "https://pve.example:8006/api2/json"}
    with pytest.raises(DestinationBindingError, match="provider_plugin_not_proxmox"):
        assert_provider_endpoint_bound(
            target=_Target(ok, plugin_name="aws"),
            composition_endpoint="https://pve.example:8006/api2/json",
        )
    with pytest.raises(DestinationBindingError, match="target_config_hash_stale"):
        assert_provider_endpoint_bound(
            target=_Target(ok, config_hash="sha256:" + "0" * 64),
            composition_endpoint="https://pve.example:8006/api2/json",
        )


# --- 2. one authoritative HTTP state-backend binding ---------------------------------------------


def _binding(reference="https://state.example/lab"):  # noqa: ANN001
    return derive_state_backend_binding(
        reference=reference,
        backend_kind="http",
        toolchain_profile_id=uuid.uuid4(),
        toolchain_profile_hash="sha256:" + "a" * 64,
        state_namespace_identity="sha256:" + "b" * 64,
    )


def test_state_binding_derives_addresses_from_the_toolchain_reference():
    b = _binding()
    assert isinstance(b, AuthoritativeStateBackendBinding)
    assert b.state_address == "https://state.example:443/lab"
    assert b.lock_address == "https://state.example:443/lab?lock"
    assert b.unlock_address == "https://state.example:443/lab?unlock"
    assert b.control_origin == "https://state.example:443"
    # Redacted — the raw address never leaks.
    assert "state.example" not in repr(b)


def test_state_runtime_equals_the_authoritative_binding():
    b = _binding()
    src = _StateSrc(
        "https://state.example/lab",
        "https://state.example/lab?lock",
        "https://state.example/lab?unlock",
    )
    state_input = assert_state_runtime_bound(binding=b, composition_state_source=src)
    assert state_input.address == b.state_address


@pytest.mark.parametrize(
    ("src", "reason"),
    [
        # The composition points OpenTofu at a DIFFERENT backend (B) than readiness validated (A).
        (
            _StateSrc(
                "https://backendB.example/lab",
                "https://backendB.example/lab?lock",
                "https://backendB.example/lab?unlock",
            ),
            "state_address_mismatch",
        ),
        (
            _StateSrc(
                "https://state.example/lab",
                "https://state.example/lab?WRONG",
                "https://state.example/lab?unlock",
            ),
            "state_lock_mismatch",
        ),
        (
            _StateSrc(
                "https://state.example/lab",
                "https://state.example/lab?lock",
                "https://state.example/lab?WRONG",
            ),
            "state_unlock_mismatch",
        ),
    ],
)
def test_state_runtime_mismatch_refuses(src, reason):
    with pytest.raises(DestinationBindingError, match=reason):
        assert_state_runtime_bound(binding=_binding(), composition_state_source=src)


def test_readiness_backend_equality_anchor():
    b = _binding()
    assert_readiness_backend_equals(
        binding=b, readiness_toolchain_profile_hash=b.toolchain_profile_hash
    )
    with pytest.raises(DestinationBindingError, match="readiness_backend_mismatch"):
        assert_readiness_backend_equals(
            binding=b, readiness_toolchain_profile_hash="sha256:" + "9" * 64
        )


# --- 3. control-path collision impossibility -----------------------------------------------------


def _transport(**over):
    base = dict(
        state_address="https://state.example/lab",
        plan_lock_address="https://state.example/lab?lock",
        plan_unlock_address="https://state.example/lab?unlock",
        ca_path="/etc/ssl/certs/ca.pem",
        auth_provider=_FakeAuth(),
        endpoints=_state_endpoints(),
        readiness_lock_id="rid",
    )
    base.update(over)
    return HttpStateControlTransport(**base)


@pytest.mark.parametrize(
    ("endpoints", "reason"),
    [
        # capabilities GET would read the state object itself.
        (
            StateBackendControlEndpoints("/v1/state/meta", "/lab", "/v1/state/rlock"),
            "capabilities_path_is_state_object",
        ),
        # metadata HEAD would target the state address.
        (
            StateBackendControlEndpoints("/lab", "/v1/cap", "/v1/state/rlock"),
            "metadata_path_is_state_object",
        ),
        # readiness lock equals the deployment (plan) lock/state object — not a dedicated namespace.
        (
            StateBackendControlEndpoints("/v1/state/meta", "/v1/cap", "/lab"),
            "readiness_lock_is_state_object",
        ),
        # two control paths collide.
        (
            StateBackendControlEndpoints("/v1/same", "/v1/same", "/v1/state/rlock"),
            "control_path_collision",
        ),
    ],
)
def test_control_path_collisions_refuse_at_construction(endpoints, reason):
    with pytest.raises(HardenedTransportError, match=reason):
        _transport(endpoints=endpoints)


def test_transport_origin_must_be_stable_across_state_lock_unlock():
    with pytest.raises(HardenedTransportError, match="state_origin_mismatch"):
        _transport(plan_lock_address="https://other.example/lab?lock")


# --- 4. readiness transport bound to the authoritative reference; no contact on drift ------------


def _adapter_binding(reference: str) -> RemoteStateReadinessBinding:
    return RemoteStateReadinessBinding(
        binding=_readiness_binding(),
        state_backend_kind="http",
        state_backend_reference=reference,
    )


def test_readiness_probe_refuses_when_transport_points_at_a_different_backend():
    # Transport bound to backend A; the readiness binding references backend B → drift, no contact.
    transport_a = _transport()  # control_origin https://state.example:443
    probe = ConcreteHttpStateControlProbe(transport=transport_a, lock_issuer=uuid.uuid4())
    obs = probe.observe(_adapter_binding("https://backend-b.example/lab"), now=NOW)
    assert obs.locking is None
    assert "state_backend_reference_drift" in obs.reason_codes


def test_readiness_probe_refuses_a_non_https_reference_without_contact():
    probe = ConcreteHttpStateControlProbe(transport=_transport(), lock_issuer=uuid.uuid4())
    obs = probe.observe(_adapter_binding("opaque-ref"), now=NOW)
    assert "state_backend_reference_drift" in obs.reason_codes


def test_readiness_probe_accepts_a_matching_backend_origin(monkeypatch):
    # A MATCHING backend origin is NOT refused as drift (the probe then proceeds to the bounded
    # control-metadata contact — routed here to an offline mock so nothing hits a real network).
    import httpx
    from tests.test_concrete_transports import _patch_httpx

    _patch_httpx(monkeypatch, lambda request: httpx.Response(404))
    probe = ConcreteHttpStateControlProbe(transport=_transport(), lock_issuer=uuid.uuid4())
    obs = probe.observe(_adapter_binding("https://state.example/lab"), now=NOW)
    assert "state_backend_reference_drift" not in obs.reason_codes
    assert obs.namespace_present is False  # the mocked 404 → namespace empty (a real contact path)


def test_sealed_transport_control_origin_is_empty_and_refuses_binding():
    from secp_worker.readiness.http_state_probe import SealedStateBackendControlTransport

    probe = ConcreteHttpStateControlProbe(transport=SealedStateBackendControlTransport())
    obs = probe.observe(_adapter_binding("https://state.example/lab"), now=NOW)
    # The sealed transport's control_origin is "" → never matches a real reference → drift refusal.
    assert "state_backend_reference_drift" in obs.reason_codes
