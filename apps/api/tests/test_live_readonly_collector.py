"""SECP-002B-1B-4 — dormant, default-disabled live read-only Proxmox collector.

Fakes only. Proves the collector is unreachable unless an explicitly-enabled gate + a valid
immutable binding + injected fake resolver + injected fake transport are all supplied; that a
disabled gate or invalid binding fails BEFORE secret resolution or transport construction; that
the collector issues only canonical allowlisted GETs, never infers isolation, and returns an
in-memory observed dict; that the hardened HttpxReadOnlyTransport applies the closed policy
before any client activity and cannot be misused; and that no API/persistence/live-activation
path was introduced and the sealed collector stays sealed. Nothing real is contacted.
"""

from __future__ import annotations

import inspect
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from secp_api.enums import EvidenceStatus, VerificationLevel
from secp_api.target_evidence import (
    CHECK_ISOLATION,
    SIMULATED_EVIDENCE_SOURCE,
    TARGET_EVIDENCE_SCHEMA_VERSION,
    compare_boundary_to_evidence,
    findings_pass,
    summarize_findings,
)
from secp_plugin_api.v1 import ProviderCredential
from secp_plugin_proxmox import (
    LIVE_READ_COLLECTOR_CONTRACT_VERSION,
    LIVE_READ_EVIDENCE_SOURCE,
    PROXMOX_READONLY_POLICY_VERSION,
    HttpxReadOnlyTransport,
    LiveReadOnlyProxmoxCollector,
    MutatingRequestRefused,
    RedirectRefused,
    UnknownPathRefused,
    path_is_allowed,
)
from secp_plugin_proxmox.readonly_transport import FakeProxmoxReadOnlyTransport
from secp_worker.onboarding.live_readonly import (
    InvalidLiveReadBinding,
    LiveReadCollectionBinding,
    LiveReadCollectionDisabled,
    LiveReadCollectionGate,
    run_live_readonly_collection,
)
from tests.conftest import VALID_ONBOARDING_BOUNDARY  # type: ignore

NOW = datetime(2026, 7, 2, tzinfo=UTC)
BOUNDARY = VALID_ONBOARDING_BOUNDARY

FAKE_INV = {
    "/nodes": [
        {"node": "pve-node-1", "status": "online", "description": "lab", "password": "hunter2"},
        {"node": "pve-node-2", "status": "online", "tags": "t"},
    ],
    "/cluster/sdn/vnets": [{"vnet": "vmbr0", "cidr": "10.60.0.0/16", "notes": "n"}],
    "/nodes/pve-node-1/storage": [{"storage": "local-lvm", "type": "lvmthin"}],
    "/nodes/pve-node-2/storage": [{"storage": "local-lvm"}],
}


class RecordingResolver:
    """Fake worker SecretResolver that records every resolve() call."""

    def __init__(self, token: str = "fake-token") -> None:
        self.calls: list[str] = []
        self._token = token

    def resolve(self, secret_ref: str) -> ProviderCredential:
        self.calls.append(secret_ref)
        return ProviderCredential.from_secret(self._token)


def _recording_factory(responses):
    created: list[tuple[str, FakeProxmoxReadOnlyTransport]] = []

    def factory(token: str) -> FakeProxmoxReadOnlyTransport:
        t = FakeProxmoxReadOnlyTransport(responses)
        created.append((token, t))
        return t

    return factory, created


def _binding(**over) -> LiveReadCollectionBinding:
    base = dict(
        execution_target_id="t-1",
        target_config_hash="sha256:cfg",
        onboarding_id="ob-1",
        boundary_hash="sha256:boundary",
        authorization_id="auth-1",
        authorization_version=1,
        authorization_expiry="2999-01-01T00:00:00Z",
        evidence_source=LIVE_READ_EVIDENCE_SOURCE,
        verification_level=VerificationLevel.live_verified.value,
        collector_contract_version=LIVE_READ_COLLECTOR_CONTRACT_VERSION,
        endpoint_allowlist_version=PROXMOX_READONLY_POLICY_VERSION,
    )
    base.update(over)
    return LiveReadCollectionBinding(**base)


def _sim_payload(observed: dict) -> dict:
    """TEST-ONLY: wrap observed data in the simulated evidence schema to exercise comparison.
    This is not a runtime collection path and creates no evidence record."""
    return {
        "schema_version": TARGET_EVIDENCE_SCHEMA_VERSION,
        "evidence_source": SIMULATED_EVIDENCE_SOURCE,
        "verification_level": VerificationLevel.simulated.value,
        "observed": observed,
    }


# --- default-disabled gate --------------------------------------------------------


def test_disabled_gate_refuses_before_resolver_and_transport():
    resolver = RecordingResolver()
    factory, created = _recording_factory(FAKE_INV)
    with pytest.raises(LiveReadCollectionDisabled):
        run_live_readonly_collection(
            gate=LiveReadCollectionGate(),  # default disabled
            binding=_binding(),
            secret_ref="env:SECP_PROVIDER_SECRET__FAKE",
            secret_resolver=resolver,
            transport_factory=factory,
            declared_boundary=BOUNDARY,
            now=NOW,
        )
    assert resolver.calls == []  # no secret resolution
    assert created == []  # no transport construction


def test_gate_default_is_disabled():
    assert LiveReadCollectionGate().enabled is False


# --- immutable binding validation (before resolver / transport) -------------------


@pytest.mark.parametrize(
    "over",
    [
        {"execution_target_id": ""},  # missing field
        {"onboarding_id": "  "},  # blank field
        {"authorization_version": 0},  # non-positive
        {"authorization_version": "1"},  # wrong type
        {"authorization_expiry": "2000-01-01T00:00:00Z"},  # expired
        {"authorization_expiry": "2999-01-01 00:00:00"},  # malformed (no 'Z')
        {"authorization_expiry": "not-a-time"},  # malformed
        {"verification_level": "simulated"},  # inconsistent (not live)
        {"evidence_source": "simulated_target_evidence"},  # wrong source
        {"collector_contract_version": "bogus/v0"},  # contract mismatch
        {"endpoint_allowlist_version": "bogus/v0"},  # allowlist mismatch
    ],
)
def test_invalid_binding_refuses_before_resolver_and_transport(over):
    resolver = RecordingResolver()
    factory, created = _recording_factory(FAKE_INV)
    with pytest.raises(InvalidLiveReadBinding):
        run_live_readonly_collection(
            gate=LiveReadCollectionGate(enabled=True),  # gate enabled: reach binding check
            binding=_binding(**over),
            secret_ref="env:SECP_PROVIDER_SECRET__FAKE",
            secret_resolver=resolver,
            transport_factory=factory,
            declared_boundary=BOUNDARY,
            now=NOW,
        )
    assert resolver.calls == []
    assert created == []


# --- explicitly enabled test-only path (fake resolver + fake transport) -----------


def test_enabled_gate_with_fakes_returns_in_memory_observed():
    resolver = RecordingResolver()
    factory, created = _recording_factory(FAKE_INV)
    observed = run_live_readonly_collection(
        gate=LiveReadCollectionGate(enabled=True),
        binding=_binding(),
        secret_ref="env:SECP_PROVIDER_SECRET__FAKE",
        secret_resolver=resolver,
        transport_factory=factory,
        declared_boundary=BOUNDARY,
        now=NOW,
    )
    assert resolver.calls == ["env:SECP_PROVIDER_SECRET__FAKE"]  # resolved once
    assert created and created[0][0] == "fake-token"  # transport built with resolved token
    assert observed["nodes"] == ["pve-node-1", "pve-node-2"]
    assert observed["storage"] == ["local-lvm"]
    assert observed["network_segments"] == ["vmbr0"]
    assert "isolation" not in observed  # never inferred
    blob = str(observed).lower()
    for leak in ("description", "password", "hunter2", "tags", "notes"):
        assert leak not in blob


# --- collector: canonical allowlisted GETs, no isolation inference ----------------


def test_collector_issues_only_canonical_allowlisted_gets():
    t = FakeProxmoxReadOnlyTransport(FAKE_INV)
    LiveReadOnlyProxmoxCollector().collect(t, declared_boundary=BOUNDARY)
    assert t.calls, "collector should have issued GETs"
    assert {method for (method, _p) in t.calls} == {"GET"}
    for _method, path in t.calls:
        assert path_is_allowed(path), path


def test_generic_inventory_cannot_pass_fully_segregated():
    observed = LiveReadOnlyProxmoxCollector().collect(
        FakeProxmoxReadOnlyTransport(FAKE_INV), declared_boundary=BOUNDARY
    )
    findings = compare_boundary_to_evidence(BOUNDARY, _sim_payload(observed))
    by_check = {f["check"]: f["status"] for f in findings}
    assert by_check[CHECK_ISOLATION] == EvidenceStatus.unverifiable.value
    assert findings_pass(findings) is False


@pytest.mark.parametrize(
    "responses",
    [
        {},  # nothing observed
        {"/nodes": {"node": "pve-node-1"}},  # malformed (non-list) node response
    ],
)
def test_missing_or_malformed_observations_are_unverifiable(responses):
    observed = LiveReadOnlyProxmoxCollector().collect(
        FakeProxmoxReadOnlyTransport(responses), declared_boundary=BOUNDARY
    )
    findings = compare_boundary_to_evidence(BOUNDARY, _sim_payload(observed))
    assert summarize_findings(findings) == EvidenceStatus.unverifiable
    assert findings_pass(findings) is False


# --- hardened HttpxReadOnlyTransport ----------------------------------------------


class _FakeResp:
    def __init__(self, status_code=200, json_data=None, headers=None, is_redirect=False):
        self.status_code = status_code
        self._json = {"data": []} if json_data is None else json_data
        self.headers = headers or {}
        self.is_redirect = is_redirect

    def raise_for_status(self):
        if self.status_code >= 400:  # pragma: no cover - not exercised
            raise RuntimeError("http error")

    def json(self):
        return self._json


class _FakeClient:
    def __init__(self, resp: _FakeResp | None = None):
        self.resp = resp or _FakeResp()
        self.get_calls: list[tuple] = []

    def get(self, url, params=None, headers=None):
        self.get_calls.append((url, params, headers))
        return self.resp

    def close(self):
        pass


def test_httptransport_applies_policy_before_injected_client():
    client = _FakeClient()
    t = HttpxReadOnlyTransport("https://proxmox.example.test:8006/api2/json", "tok", client=client)
    with pytest.raises(MutatingRequestRefused):
        t.request("POST", "/nodes")
    with pytest.raises(UnknownPathRefused):
        t.request("GET", "/nodes/pve-node-1/qemu/9000/config")
    assert client.get_calls == []  # policy refused before any client activity


def test_httptransport_refuses_and_never_follows_redirect():
    redirect = _FakeResp(status_code=302, headers={"location": "https://elsewhere/nodes"})
    client = _FakeClient(redirect)
    t = HttpxReadOnlyTransport("https://proxmox.example.test:8006", "tok", client=client)
    with pytest.raises(RedirectRefused):
        t.get("/nodes")
    assert len(client.get_calls) == 1  # issued once, redirect NOT followed


def test_httptransport_tls_cannot_be_disabled():
    with pytest.raises(ValueError, match="verify_tls"):
        HttpxReadOnlyTransport("https://proxmox.example.test:8006", "tok", verify_tls=False)


@pytest.mark.parametrize(
    "base_url",
    [
        "http://proxmox.example.test:8006",  # not https
        "https://user:pass@proxmox.example.test:8006",  # userinfo
        "https://proxmox.example.test:8006/api2/json?x=1",  # query
        "https://proxmox.example.test:8006/api2/json#frag",  # fragment
        "https://proxmox.example.test:8006/api2/%2e%2e",  # escape/traversal
    ],
)
def test_httptransport_base_url_validation(base_url):
    with pytest.raises(ValueError):
        HttpxReadOnlyTransport(base_url, "tok")


def test_httptransport_own_client_uses_verify_trustenv_noredirect(monkeypatch):
    captured: dict = {}

    class _CapturingClient(_FakeClient):
        def __init__(self, **kwargs):
            super().__init__(_FakeResp(200, {"data": [{"node": "pve-node-1"}]}))
            captured.update(kwargs)

    monkeypatch.setattr(httpx, "Client", _CapturingClient)
    t = HttpxReadOnlyTransport("https://proxmox.example.test:8006/api2/json", "tok")
    data = t.get("/nodes")  # no injected client -> constructs its own (captured)
    assert captured.get("verify") is True
    assert captured.get("trust_env") is False
    assert captured.get("follow_redirects") is False
    assert data == [{"node": "pve-node-1"}]


# --- boundary / no-network-imports / sealed / no-persistence ----------------------


def test_api_package_does_not_import_live_readonly_paths():
    api_pkg = Path(__file__).resolve().parents[1] / "secp_api"
    needles = (
        "live_readonly",
        "LiveReadOnlyProxmoxCollector",
        "run_live_readonly_collection",
        "LiveReadCollection",
        "secp_plugin_proxmox",
    )
    for py in api_pkg.rglob("*.py"):
        if "__pycache__" in py.parts:
            continue
        text = py.read_text(encoding="utf-8")
        for needle in needles:
            assert needle not in text, f"{py.name} references {needle!r}"


def test_new_code_has_no_network_capable_imports():
    import secp_plugin_proxmox.live_collector as lc
    import secp_worker.onboarding.live_readonly as lr

    forbidden = (
        "import httpx",
        "from httpx",
        "import requests",
        "from requests",
        "import aiohttp",
        "import socket",
        "from socket",
        "import ssl",
        "import subprocess",
        "from subprocess",
        "import http.client",
        "import urllib.request",
        "import paramiko",
    )
    for module in (lc, lr):
        src = inspect.getsource(module)
        for token in forbidden:
            assert token not in src, f"{module.__name__} must not use `{token}`"


def test_no_evidence_persistence_in_live_run():
    import secp_worker.onboarding.live_readonly as lr

    src = inspect.getsource(lr)
    if lr.__doc__:  # strip the module docstring so prose is not mistaken for code
        src = src.replace(lr.__doc__, "")
    for token in (
        "TargetEvidenceRecord",
        "record_target_evidence",
        "session.add",
        "session.commit",
        "sessionmaker",
    ):
        assert token not in src, f"live run must not persist evidence ({token})"


def test_sealed_provider_collector_remains_sealed():
    from secp_api.errors import LiveEvidenceSealedError
    from secp_api.onboarding import B1B0_LIVE_EVIDENCE_SEALED
    from secp_worker.onboarding.target_evidence import SealedProviderTargetEvidenceCollector

    assert B1B0_LIVE_EVIDENCE_SEALED is True
    with pytest.raises(LiveEvidenceSealedError):
        SealedProviderTargetEvidenceCollector().collect(declared_boundary={})


def test_simulated_collector_unchanged():
    from secp_worker.onboarding.target_evidence import SimulatedTargetEvidenceCollector

    assert (
        SimulatedTargetEvidenceCollector().verification_level == VerificationLevel.simulated.value
    )
